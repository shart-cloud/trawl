/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package contract

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	trawlv1alpha1 "trawl.cloud/trawl/api/v1alpha1"
	"trawl.cloud/trawl/internal/config"
	"trawl.cloud/trawl/internal/controller"
)

// The controller renders one argument set for every analyzer, because the
// arguments describe the tap rather than the tool. Nothing checked that the
// analyzers accept them, and they did not:
//
//	$ zeek --interface=eth0
//	ERROR: Unrecognized option --interface=eth0
//
//	$ suricata --interface=eth0 --content-dir=/x --log-dir=/y
//	To run Suricata with default configuration on interface eth0 [...]
//
// Both images had the raw binary as their ENTRYPOINT, so both containers
// CrashLooped and no traffic was ever analyzed. The existing workload tests
// asserted the containers existed, which they did.
//
// Each image now carries an entrypoint that translates. This is the seam
// between the two, and it is checked by parsing the scripts rather than by
// running them, so it holds even where Docker is unavailable.

// analyzerEntrypoints maps an analyzer to the script that must handle its args.
// Keyed by container name, which the renderer lowercases from the analyzer.
var analyzerEntrypoints = map[string]string{
	"suricata": "images/suricata/entrypoint.sh",
	"zeek":     "images/zeek/entrypoint.sh",
}

func renderAnalyzerContainers(t *testing.T) []corev1.Container {
	t.Helper()

	digest := func(c string) string {
		return "ghcr.io/trawl/x@sha256:" + strings.Repeat(c, 64)
	}
	cfg := &config.Config{
		ClusterID:       "homelab",
		SystemNamespace: "trawl-system",
		SensorAgentResources: config.ResourceRequirements{
			RequestsCPU: "50m", RequestsMemory: "64Mi",
			LimitsCPU: "200m", LimitsMemory: "256Mi",
		},
		Content: config.ContentConfig{
			SuricataFeedURL: "https://rules.example/emerging.rules.tar.gz",
			ZeekScriptRepo:  "https://github.com/zeek/packages",
		},
		Images: config.ImageConfig{
			Suricata: digest("a"), Zeek: digest("b"), SensorAgent: digest("c"),
			CaptureRunner: digest("d"), ContentInit: digest("e"),
		},
	}

	tap := &trawlv1alpha1.NetworkTap{
		ObjectMeta: metav1.ObjectMeta{
			Name: "contract-tap", Namespace: "trawl-system", UID: "contract-uid",
		},
		Spec: trawlv1alpha1.NetworkTapSpec{
			Mode:            trawlv1alpha1.TapModePassive,
			Type:            trawlv1alpha1.TapSourceMirrorInterface,
			MirrorInterface: &trawlv1alpha1.InterfaceSource{Interface: "eth0"},
			Analyzers: trawlv1alpha1.AnalyzerSelection{
				Suricata: trawlv1alpha1.AnalyzerConfig{Enabled: true},
				Zeek:     trawlv1alpha1.AnalyzerConfig{Enabled: true},
			},
		},
	}

	r := &controller.WorkloadRenderer{Config: cfg}
	pod := r.PodSpec(tap)

	out := make([]corev1.Container, 0, 2)
	for _, c := range pod.Containers {
		if _, ok := analyzerEntrypoints[c.Name]; ok {
			out = append(out, c)
		}
	}
	return out
}

func TestEveryAnalyzerArgumentIsHandledByItsEntrypoint(t *testing.T) {
	containers := renderAnalyzerContainers(t)
	if len(containers) != len(analyzerEntrypoints) {
		t.Fatalf("rendered %d analyzer containers, want %d", len(containers), len(analyzerEntrypoints))
	}

	root := repoRoot(t)
	for _, c := range containers {
		script := analyzerEntrypoints[c.Name]
		data, err := os.ReadFile(filepath.Join(root, script))
		if err != nil {
			t.Fatalf("%s: reading %s: %v", c.Name, script, err)
		}
		body := string(data)

		if len(c.Args) == 0 {
			t.Errorf("%s: renders no arguments", c.Name)
		}
		for _, arg := range c.Args {
			flag, _, ok := strings.Cut(arg, "=")
			if !ok {
				t.Errorf("%s: argument %q is not in --flag=value form, which the entrypoints parse", c.Name, arg)
				continue
			}
			// The entrypoint's case statement is the contract. An argument it
			// does not name falls to the catch-all and exits non-zero, which is
			// the behaviour that turns this class of mistake into a startup
			// failure rather than a silently misconfigured analyzer.
			if !strings.Contains(body, flag+"=*)") {
				t.Errorf("%s renders %s but %s does not handle it", c.Name, flag, script)
			}
		}
	}
}

func TestAnalyzerEntrypointsRejectUnknownArguments(t *testing.T) {
	// The catch-all is what makes the test above meaningful. Without it, an
	// argument the entrypoint does not understand would be ignored, and the
	// analyzer would start with the wrong interface or write logs where the
	// sensor is not looking - both of which report healthy.
	root := repoRoot(t)
	for name, script := range analyzerEntrypoints {
		data, err := os.ReadFile(filepath.Join(root, script))
		if err != nil {
			t.Fatalf("%s: %v", script, err)
		}
		body := string(data)
		if !strings.Contains(body, "unrecognized argument") {
			t.Errorf("%s (%s) does not reject unknown arguments", script, name)
		}
		if !strings.Contains(body, "exit 2") {
			t.Errorf("%s (%s) does not exit non-zero on a bad argument", script, name)
		}
	}
}

func TestAnalyzerImagesInvokeTheirEntrypoint(t *testing.T) {
	// A translating entrypoint that the image does not use is no better than
	// none. Both images previously had the raw binary as ENTRYPOINT.
	root := repoRoot(t)
	for _, tc := range []struct{ containerfile, entrypoint string }{
		{"images/zeek/Containerfile", "/usr/local/bin/trawl-zeek"},
		{"images/suricata/Containerfile", "/usr/local/bin/trawl-suricata"},
	} {
		data, err := os.ReadFile(filepath.Join(root, tc.containerfile))
		if err != nil {
			t.Fatalf("%s: %v", tc.containerfile, err)
		}
		if !strings.Contains(string(data), `ENTRYPOINT ["`+tc.entrypoint+`"]`) {
			t.Errorf("%s does not use %s as its entrypoint", tc.containerfile, tc.entrypoint)
		}
	}
}

func TestZeekIgnoresChecksumsOnCapturedTraffic(t *testing.T) {
	// Every interface Trawl taps is a veth or a bridge member, where checksum
	// offload means the kernel has not computed the checksums Zeek would
	// validate. Zeek discards those packets by default, and the symptom is
	// silence rather than an error: connections log with conn_state OTH and
	// zero packets, and no protocol analyzer engages at all.
	root := repoRoot(t)
	data, err := os.ReadFile(filepath.Join(root, "images/zeek/entrypoint.sh"))
	if err != nil {
		t.Fatalf("reading zeek entrypoint: %v", err)
	}
	if !strings.Contains(string(data), "-C") {
		t.Error("Zeek is not run with -C, so it will discard checksum-offloaded packets")
	}
}
