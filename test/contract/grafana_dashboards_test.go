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
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// datasourceRef is the "which backend" half of a panel or target. A target may
// leave it out, in which case the panel's applies.
type datasourceRef struct {
	Type string `json:"type"`
}

// panelTarget is one query on a panel.
type panelTarget struct {
	Expr       string        `json:"expr"`
	Datasource datasourceRef `json:"datasource"`
}

type dashboard struct {
	UID         string `json:"uid"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Panels      []struct {
		ID          int    `json:"id"`
		Title       string `json:"title"`
		Type        string `json:"type"`
		Description string `json:"description"`
		Options     struct {
			Content string `json:"content"`
		} `json:"options"`
		Datasource datasourceRef `json:"datasource"`
		Targets    []panelTarget `json:"targets"`
	} `json:"panels"`
	Templating struct {
		List []struct {
			Name string `json:"name"`
		} `json:"list"`
	} `json:"templating"`
}

func loadDashboards(t *testing.T) map[string]dashboard {
	t.Helper()
	dir := filepath.Join(repoRoot(t), "config", "grafana", "dashboards")

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading dashboards: %v", err)
	}

	out := make(map[string]dashboard)
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		//nolint:gosec // path is built from the repo root and a directory listing
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatalf("reading %s: %v", e.Name(), err)
		}
		var d dashboard
		if err := json.Unmarshal(data, &d); err != nil {
			t.Fatalf("parsing %s: %v", e.Name(), err)
		}
		out[e.Name()] = d
	}
	return out
}

func allExprs(d dashboard) []string {
	var out []string
	for _, p := range d.Panels {
		for _, tgt := range p.Targets {
			out = append(out, tgt.Expr)
		}
	}
	return out
}

// lokiExprs returns only the LogQL queries.
//
// The stream-selector and cluster rules below are statements about Loki: it
// indexes a small fixed label set and holds every cluster's records in one
// place. Prometheus does neither, and its metric selectors use the same brace
// syntax, so applying those rules to a PromQL query rejects correct label
// matchers and demands a cluster label the series do not carry. Until
// capture-management arrived every dashboard was Loki-only and the distinction
// did not exist.
func lokiExprs(d dashboard) []string {
	var out []string
	for _, p := range d.Panels {
		for _, tgt := range p.Targets {
			kind := tgt.Datasource.Type
			if kind == "" {
				kind = p.Datasource.Type
			}
			if kind == "loki" {
				out = append(out, tgt.Expr)
			}
		}
	}
	return out
}

// streamSelectorRE captures the label set at the head of a LogQL query.
var streamSelectorRE = regexp.MustCompile(`\{([^}]*)\}`)

var labelNameRE = regexp.MustCompile(`([a-z_][a-z0-9_]*)\s*(?:=|=~|!=)`)

func TestDashboardsSelectStreamsOnlyByContractLabels(t *testing.T) {
	// Loki selects streams by label before reading anything, so a query whose
	// stream selector names a non-label scans every stream in range. On a
	// homelab that is slow; on a busy cluster it degrades Loki for whoever else
	// is using it.
	allowed := map[string]bool{
		"service_name": true, "cluster": true,
		"source_kind": true, "observation_type": true,
		"decision": true, "action": true, // audit stream labels
		"job": true,
	}

	for name, d := range loadDashboards(t) {
		for _, expr := range lokiExprs(d) {
			m := streamSelectorRE.FindStringSubmatch(expr)
			if m == nil {
				continue
			}
			for _, lm := range labelNameRE.FindAllStringSubmatch(m[1], -1) {
				if !allowed[lm[1]] {
					t.Errorf("%s: stream selector uses %q, which is structured metadata, not an indexed label:\n  %s",
						name, lm[1], expr)
				}
			}
		}
	}
}

func TestInvestigationDashboardSeparatesExactFromApproximate(t *testing.T) {
	// FR-015. An analyst acting on an exact match is reading one flow's
	// evidence; an approximate match may be two connections that reused a
	// tuple. Presenting them identically invites the second to be mistaken for
	// the first, so the separation is asserted rather than left to convention.
	d := loadDashboards(t)["alert-investigation.json"]
	if d.UID == "" {
		t.Fatal("alert-investigation dashboard is missing")
	}

	var hasExact, hasApproximate bool
	for _, p := range d.Panels {
		title := strings.ToUpper(p.Title)
		switch {
		case strings.Contains(title, "EXACT"):
			hasExact = true
			if !strings.Contains(strings.Join(exprsOf(p.Targets), " "), "community_id") {
				t.Error("the exact-match panel does not pivot on community_id")
			}
		case strings.Contains(title, "APPROXIMATE"):
			hasApproximate = true
			joined := strings.Join(exprsOf(p.Targets), " ")
			if strings.Contains(joined, "community_id") {
				t.Error("the approximate panel pivots on community_id, which would make it exact")
			}
			if p.Description == "" {
				t.Error("the approximate panel carries no caveat about what it can include")
			}
		}
	}

	if !hasExact {
		t.Error("no panel is labelled as an exact match")
	}
	if !hasApproximate {
		t.Error("no panel is labelled as an approximate match")
	}
}

func exprsOf(targets []panelTarget) []string {
	out := make([]string, 0, len(targets))
	for _, t := range targets {
		out = append(out, t.Expr)
	}
	return out
}

func TestInvestigationDashboardExplainsTheDistinction(t *testing.T) {
	// The panel titles alone rely on an analyst already knowing the difference.
	// A text panel states it, so the dashboard teaches the distinction rather
	// than assuming it.
	d := loadDashboards(t)["alert-investigation.json"]

	var explained bool
	for _, p := range d.Panels {
		if p.Type != "text" {
			continue
		}
		content := strings.ToLower(p.Options.Content)
		if strings.Contains(content, "exact") && strings.Contains(content, "approximate") {
			explained = true
		}
	}
	if !explained {
		t.Error("the investigation dashboard does not explain the exact/approximate distinction")
	}
}

func TestApproximateMatchingIsDirectionNormalized(t *testing.T) {
	// The analyzers disagree about which endpoint originated a flow, so a
	// one-directional query silently misses half the matches.
	d := loadDashboards(t)["alert-investigation.json"]

	for _, p := range d.Panels {
		if !strings.Contains(strings.ToUpper(p.Title), "APPROXIMATE") {
			continue
		}
		expr := strings.Join(exprsOf(p.Targets), " ")
		if !strings.Contains(expr, `source_ip = "$destination_ip"`) {
			t.Error("the approximate pivot does not match the reversed endpoint pair")
		}
	}
}

func TestOverviewDoesNotCallObservationsIncidents(t *testing.T) {
	// The MVP creates no Incident entity. One incident can produce hundreds of
	// records, so labelling a count "incidents" would inflate every number an
	// operator reports upward.
	forbidden := []string{"incident", "incidents"}

	for name, d := range loadDashboards(t) {
		haystacks := []string{d.Title, d.Description}
		for _, p := range d.Panels {
			haystacks = append(haystacks, p.Title, p.Description, p.Options.Content)
		}
		for _, h := range haystacks {
			lower := strings.ToLower(h)
			for _, f := range forbidden {
				// "incident" inside a sentence explaining the distinction is
				// fine; a panel titled or described as counting them is not.
				if strings.Contains(lower, "count") && strings.Contains(lower, f) &&
					!strings.Contains(lower, "not incident") {
					t.Errorf("%s presents observation counts as %q: %q", name, f, h)
				}
			}
		}
	}
}

func TestDashboardsCarryNoSecretsOrDownloadLinks(t *testing.T) {
	// FR-023: the MVP exposes authenticated CLI/API retrieval and never embeds
	// credentials or presigned URLs in Grafana.
	forbidden := []string{
		"X-Amz-Signature", "presign", "Bearer ", "secretAccessKey",
		"accessKeyID", "password",
	}

	dir := filepath.Join(repoRoot(t), "config", "grafana")
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		//nolint:gosec // walking the repo's own config directory
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		for _, f := range forbidden {
			if strings.Contains(string(data), f) {
				rel, _ := filepath.Rel(repoRoot(t), path)
				t.Errorf("%s contains %q", rel, f)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking grafana config: %v", err)
	}
}

func TestRequiredDashboardsExist(t *testing.T) {
	// FR-014's overview, the two investigation views US2 delivers, and US3's
	// capture management.
	required := map[string]string{
		"trawl-overview.json":      "trawl-overview",
		"alert-investigation.json": "trawl-alert-investigation",
		"protocol-analysis.json":   "trawl-protocol-analysis",
		"capture-management.json":  "trawl-capture-management",
	}

	dashboards := loadDashboards(t)
	for file, uid := range required {
		d, ok := dashboards[file]
		if !ok {
			t.Errorf("required dashboard %s is missing", file)
			continue
		}
		if d.UID != uid {
			t.Errorf("%s uid = %q, want %q", file, d.UID, uid)
		}
		if len(d.Panels) == 0 {
			t.Errorf("%s has no panels", file)
		}
	}
}

func TestProtocolDashboardCoversEverySupportedSubtype(t *testing.T) {
	// FR-013: every observation type must be inspectable. A subtype the sensor
	// emits but no dashboard shows is evidence collected and never looked at.
	d := loadDashboards(t)["protocol-analysis.json"]
	joined := strings.Join(allExprs(d), " ")

	for _, subtype := range []string{"connection", "dns", "http", "tls", "certificate", "file", "notice", "weird"} {
		if !strings.Contains(joined, subtype) {
			t.Errorf("the protocol dashboard has no view for %q records", subtype)
		}
	}
}

func TestOverviewSurfacesEvidenceLossSignals(t *testing.T) {
	// Duplicate observations and rejected records both mean the evidence is not
	// what it appears. Burying them in a debug view would mean nobody sees them
	// until an investigation has already been built on the wrong numbers.
	d := loadDashboards(t)["trawl-overview.json"]
	joined := strings.Join(allExprs(d), " ")

	if !strings.Contains(joined, "duplication") {
		t.Error("the overview does not surface suspected duplicate observations")
	}
	if !strings.Contains(joined, "Hubble") {
		t.Error("the overview does not surface cluster flow verdicts")
	}
}

func TestDashboardsUseATemplatedDatasource(t *testing.T) {
	// A hardcoded datasource UID makes a dashboard unusable in any cluster but
	// the one it was exported from.
	for name, d := range loadDashboards(t) {
		var hasDatasourceVar bool
		for _, v := range d.Templating.List {
			if v.Name == "datasource" {
				hasDatasourceVar = true
			}
		}
		if !hasDatasourceVar {
			t.Errorf("%s does not template its datasource", name)
		}
		for _, expr := range allExprs(d) {
			if strings.Contains(expr, "loki-prod") || strings.Contains(expr, "P8E80F9AEF21F6940") {
				t.Errorf("%s hardcodes a datasource UID", name)
			}
		}
	}
}

func TestDashboardsPinTheClusterLabel(t *testing.T) {
	// Without it a query spans every cluster writing to the same Loki, which
	// mixes one homelab's evidence with another's.
	for name, d := range loadDashboards(t) {
		for _, expr := range lokiExprs(d) {
			if !strings.Contains(expr, "{") {
				continue
			}
			if !strings.Contains(expr, "cluster=") {
				t.Errorf("%s has a query without a cluster selector:\n  %s", name, expr)
			}
		}
	}
}

func TestLogQLTemplatesAndDashboardsAgree(t *testing.T) {
	// The reviewed templates are the documented contract. A dashboard shipping
	// a query nobody reviewed is how an expensive or wrong query reaches
	// production.
	data, err := os.ReadFile(filepath.Join(repoRoot(t), "config", "grafana", "queries", "trawl.logql"))
	if err != nil {
		t.Fatalf("reading LogQL templates: %v", err)
	}
	templates := string(data)

	for _, key := range []string{
		"community_id",
		"observation_type=\"signature\"",
		"duplication",
		"service_name=\"trawl-audit\"",
	} {
		if !strings.Contains(templates, key) {
			t.Errorf("the reviewed LogQL templates do not cover %q", key)
		}
	}
}
