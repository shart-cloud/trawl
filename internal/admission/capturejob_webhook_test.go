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

package admission

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	admissionv1 "k8s.io/api/admission/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	trawlv1alpha1 "trawl.cloud/trawl/api/v1alpha1"
	"trawl.cloud/trawl/internal/audit"
	"trawl.cloud/trawl/internal/config"
)

// The CRD's CEL rules already enforce shape and immutability. What is tested
// here is what CEL cannot know: who is asking, what the installation permits,
// and whether the mutation was durably recorded before it was admitted.

type recordingCommitter struct {
	records []audit.Record
	err     error
}

func (c *recordingCommitter) Commit(_ context.Context, rec audit.Record) (audit.CommitResult, error) {
	if c.err != nil {
		return audit.CommitResult{Result: audit.ResultUnavailable}, c.err
	}
	c.records = append(c.records, rec)
	return audit.CommitResult{Result: audit.ResultSuccess}, nil
}

func captureConfig() *config.Config {
	c := &config.Config{
		SystemNamespace:         "trawl-system",
		CaptureRetentionCeiling: config.Duration(7 * 24 * time.Hour),
	}
	c.Capture.EventWorkerServiceAccount = "event-worker"
	c.Capture.RetentionAdminGroups = []string{"trawl:retention-admins"}
	c.Capture.RetentionAdminUsers = []string{"alice"}
	return c
}

func captureWebhook(t *testing.T) (*CaptureJobWebhook, *recordingCommitter) {
	t.Helper()
	committer := &recordingCommitter{}
	w := &CaptureJobWebhook{
		Gate:   &Gate{SystemNamespace: "trawl-system", Audit: committer},
		Config: captureConfig(),
	}
	return w, committer
}

func manualJob() *trawlv1alpha1.CaptureJob {
	return &trawlv1alpha1.CaptureJob{
		ObjectMeta: metav1.ObjectMeta{Name: "manual-tls", Namespace: "trawl-system", UID: "job-uid"},
		Spec: trawlv1alpha1.CaptureJobSpec{
			RequestType: trawlv1alpha1.CaptureRequestManual,
			TapRef:      corev1.LocalObjectReference{Name: "north-south-mirror"},
			TargetNode:  "talos-sensor-01",
			Filter:      "host 10.0.0.50 and tcp port 443",
			Duration:    "2m",
			MaxSize:     resource.MustParse("50Mi"),
			Retention:   "7d",
		},
	}
}

func policyJob() *trawlv1alpha1.CaptureJob {
	job := manualJob()
	job.Spec.RequestType = trawlv1alpha1.CaptureRequestPolicy
	job.Spec.PolicyRef = &trawlv1alpha1.ImmutablePolicyReference{Name: "p", UID: "p-uid", Generation: 1}
	job.Spec.Trigger = &trawlv1alpha1.TriggerSnapshot{
		Source:      trawlv1alpha1.TriggerSourceSuricataAlert,
		Fingerprint: strings.Repeat("a", 64),
		EventTime:   metav1.Now(),
		ObservedAt:  metav1.Now(),
		Flow:        &trawlv1alpha1.FlowSnapshot{Protocol: "tcp"},
		Suricata:    &trawlv1alpha1.SuricataTriggerContext{RuleID: 1},
	}
	job.Spec.DeduplicationKey = "dedupe"
	return job
}

func requestCtx(op admissionv1.Operation, username string, groups ...string) context.Context {
	req := admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{
		UID:       types.UID("req-" + string(op)),
		Kind:      metav1.GroupVersionKind{Group: "trawl.cloud", Version: "v1alpha1", Kind: KindCaptureJob},
		Resource:  metav1.GroupVersionResource{Group: "trawl.cloud", Version: "v1alpha1", Resource: "capturejobs"},
		Name:      "manual-tls",
		Namespace: "trawl-system",
		Operation: op,
		UserInfo:  authenticationv1.UserInfo{Username: username, UID: "u", Groups: groups},
	}}
	return admission.NewContextWithRequest(context.Background(), req)
}

func TestCaptureJobDefaultStampsRequesterAndClampsRetention(t *testing.T) {
	w, _ := captureWebhook(t)
	job := manualJob()
	job.Spec.RequestType = ""
	job.Spec.Retention = ""

	if err := w.Default(requestCtx(admissionv1.Create, "bob"), job); err != nil {
		t.Fatalf("Default: %v", err)
	}
	if job.Spec.RequestType != trawlv1alpha1.CaptureRequestManual {
		t.Errorf("requestType = %q, want Manual", job.Spec.RequestType)
	}
	// The API default is 30d; the installation ceiling is 7d and wins.
	if job.Spec.Retention != "7d" {
		t.Errorf("retention = %q, want ceiling 7d", job.Spec.Retention)
	}
	if got := job.Annotations[trawlv1alpha1.AnnotationRequester]; got != "bob" {
		t.Errorf("requester annotation = %q, want bob", got)
	}
}

func TestCaptureJobDefaultDoesNotOverwriteRequesterOnUpdate(t *testing.T) {
	w, _ := captureWebhook(t)
	job := manualJob()
	job.Annotations = map[string]string{trawlv1alpha1.AnnotationRequester: "bob"}
	if err := w.Default(requestCtx(admissionv1.Update, "alice"), job); err != nil {
		t.Fatalf("Default: %v", err)
	}
	if got := job.Annotations[trawlv1alpha1.AnnotationRequester]; got != "bob" {
		t.Errorf("requester rewritten to %q", got)
	}
}

func TestCaptureJobCreateIsAuditedAsManual(t *testing.T) {
	w, committer := captureWebhook(t)
	if _, err := w.ValidateCreate(requestCtx(admissionv1.Create, "bob"), manualJob()); err != nil {
		t.Fatalf("manual create refused: %v", err)
	}
	if len(committer.records) != 1 || committer.records[0].Action != audit.ActionCaptureJobManualCreate {
		t.Fatalf("records = %+v, want one %s", committer.records, audit.ActionCaptureJobManualCreate)
	}
}

func TestCaptureJobCreateRefusesOutsideSystemNamespace(t *testing.T) {
	w, committer := captureWebhook(t)
	job := manualJob()
	job.Namespace = "default"
	if _, err := w.ValidateCreate(requestCtx(admissionv1.Create, "bob"), job); err == nil {
		t.Fatal("create in another namespace admitted")
	}
	if len(committer.records) != 0 {
		t.Errorf("a refused request was audited as a mutation: %+v", committer.records)
	}
}

func TestCaptureJobPolicyCreateRequiresEventWorkerIdentity(t *testing.T) {
	w, committer := captureWebhook(t)

	_, err := w.ValidateCreate(requestCtx(admissionv1.Create, "bob"), policyJob())
	if err == nil || !strings.Contains(err.Error(), "requestType") {
		t.Fatalf("policy request from a user admitted: %v", err)
	}

	worker := "system:serviceaccount:trawl-system:event-worker"
	if _, err := w.ValidateCreate(requestCtx(admissionv1.Create, worker), policyJob()); err != nil {
		t.Fatalf("policy request from the event worker refused: %v", err)
	}
	if len(committer.records) != 1 || committer.records[0].Action != audit.ActionCaptureJobPolicyCreate {
		t.Fatalf("records = %+v, want one %s", committer.records, audit.ActionCaptureJobPolicyCreate)
	}

	// Same service account name in another namespace is a different identity.
	other := "system:serviceaccount:default:event-worker"
	if _, err := w.ValidateCreate(requestCtx(admissionv1.Create, other), policyJob()); err == nil {
		t.Fatal("policy request from a same-named account elsewhere admitted")
	}
}

func TestCaptureJobCreateRefusesWhenAuditUnavailable(t *testing.T) {
	w, committer := captureWebhook(t)
	committer.err = errors.New("ledger down")
	_, err := w.ValidateCreate(requestCtx(admissionv1.Create, "bob"), manualJob())
	if !errors.Is(err, ErrAuditUnavailable) {
		t.Fatalf("err = %v, want ErrAuditUnavailable", err)
	}
}

func TestValidateCaptureJobSpecRejectsRetentionAboveCeiling(t *testing.T) {
	spec := manualJob().Spec
	spec.Retention = "8d"
	errs := ValidateCaptureJobSpec(&spec, 7*24*time.Hour)
	if len(errs) != 1 || errs[0].Field != "spec.retention" {
		t.Fatalf("errs = %v, want one spec.retention error", errs)
	}
}

func TestValidateCaptureJobSpecRejectsNonPrintableFilter(t *testing.T) {
	spec := manualJob().Spec
	spec.Filter = "host 10.0.0.1\x00and tcp"
	errs := ValidateCaptureJobSpec(&spec, 7*24*time.Hour)
	if len(errs) != 1 || errs[0].Field != "spec.filter" {
		t.Fatalf("errs = %v, want one spec.filter error", errs)
	}
	// The rejected value is not echoed: a filter can carry an internal address.
	if strings.Contains(errs[0].Error(), "10.0.0.1") {
		t.Errorf("filter value echoed in error: %v", errs[0])
	}
}

func TestValidateCaptureJobSpecRechecksBoundsCELAlreadyEnforces(t *testing.T) {
	// A stored object may predate the CEL rules or have been restored into
	// etcd directly, so the bounds are re-checked in Go.
	cases := map[string]func(*trawlv1alpha1.CaptureJobSpec){
		"spec.duration": func(s *trawlv1alpha1.CaptureJobSpec) { s.Duration = "2h" },
		"spec.maxSize":  func(s *trawlv1alpha1.CaptureJobSpec) { s.MaxSize = resource.MustParse("2Gi") },
		"spec.snaplen":  func(s *trawlv1alpha1.CaptureJobSpec) { s.Snaplen = 32 },
	}
	for want, mutate := range cases {
		spec := manualJob().Spec
		mutate(&spec)
		errs := ValidateCaptureJobSpec(&spec, 7*24*time.Hour)
		found := false
		for _, e := range errs {
			if e.Field == want {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: no error in %v", want, errs)
		}
	}
}

func TestCaptureJobUpdateAllowsOnlyRetentionByRetentionAdmin(t *testing.T) {
	w, committer := captureWebhook(t)
	old := manualJob()
	old.Annotations = map[string]string{trawlv1alpha1.AnnotationRequester: "bob"}
	updated := old.DeepCopy()
	updated.Spec.Retention = "2d"

	// The requester is not a retention admin.
	if _, err := w.ValidateUpdate(requestCtx(admissionv1.Update, "bob"), old, updated); err == nil {
		t.Fatal("retention change by the requester admitted")
	}
	if len(committer.records) != 0 {
		t.Fatalf("refused change audited: %+v", committer.records)
	}

	// A user in the admin group may.
	ctx := requestCtx(admissionv1.Update, "carol", "trawl:retention-admins")
	if _, err := w.ValidateUpdate(ctx, old, updated); err != nil {
		t.Fatalf("retention change by admin group refused: %v", err)
	}
	// So may a listed user.
	if _, err := w.ValidateUpdate(requestCtx(admissionv1.Update, "alice"), old, updated); err != nil {
		t.Fatalf("retention change by admin user refused: %v", err)
	}
	if len(committer.records) != 2 {
		t.Fatalf("records = %d, want 2", len(committer.records))
	}
	for _, rec := range committer.records {
		if rec.Action != audit.ActionRetentionChange {
			t.Errorf("action = %s, want %s", rec.Action, audit.ActionRetentionChange)
		}
	}
}

func TestCaptureJobUpdateWithoutSpecChangeNeedsNoAdmin(t *testing.T) {
	// Label edits and finalizer removal by the controller are not retention
	// changes and must not require the admin role or an audit record.
	w, committer := captureWebhook(t)
	old := manualJob()
	updated := old.DeepCopy()
	updated.Labels = map[string]string{"team": "blue"}
	if _, err := w.ValidateUpdate(requestCtx(admissionv1.Update, "bob"), old, updated); err != nil {
		t.Fatalf("metadata-only update refused: %v", err)
	}
	if len(committer.records) != 0 {
		t.Errorf("metadata-only update audited: %+v", committer.records)
	}
}

func TestCaptureJobUpdateRefusesRequesterRewrite(t *testing.T) {
	w, _ := captureWebhook(t)
	old := manualJob()
	old.Annotations = map[string]string{trawlv1alpha1.AnnotationRequester: "bob"}
	updated := old.DeepCopy()
	updated.Annotations[trawlv1alpha1.AnnotationRequester] = "alice"
	if _, err := w.ValidateUpdate(requestCtx(admissionv1.Update, "alice"), old, updated); err == nil {
		t.Fatal("requester annotation rewrite admitted")
	}
}

func TestCaptureJobUpdateRefusesRetentionChangeAfterDeadlineOrExpiry(t *testing.T) {
	w, _ := captureWebhook(t)
	ctx := requestCtx(admissionv1.Update, "alice")

	old := manualJob()
	old.Status.Phase = trawlv1alpha1.CapturePhaseCompleted
	old.Status.RetentionDeadline = &metav1.Time{Time: time.Now().Add(-time.Minute)}
	updated := old.DeepCopy()
	updated.Spec.Retention = "2d"
	if _, err := w.ValidateUpdate(ctx, old, updated); err == nil {
		t.Fatal("retention change after the deadline admitted")
	}

	old = manualJob()
	old.Status.Phase = trawlv1alpha1.CapturePhaseExpired
	updated = old.DeepCopy()
	updated.Spec.Retention = "2d"
	if _, err := w.ValidateUpdate(ctx, old, updated); err == nil {
		t.Fatal("retention change on an expired capture admitted")
	}

	old = manualJob()
	old.Status.Phase = trawlv1alpha1.CapturePhaseCompleted
	old.Status.RetentionDeadline = &metav1.Time{Time: time.Now().Add(time.Hour)}
	updated = old.DeepCopy()
	updated.Spec.Retention = "8d"
	if _, err := w.ValidateUpdate(ctx, old, updated); err == nil {
		t.Fatal("retention above the ceiling admitted on update")
	}
}

func TestCaptureJobDeleteIsNamespaceGatedOnly(t *testing.T) {
	// Deletion is recorded by the controller's finalizer as artifact.expire
	// records with the outcome; admission has nothing to add.
	w, committer := captureWebhook(t)
	if _, err := w.ValidateDelete(requestCtx(admissionv1.Delete, "bob"), manualJob()); err != nil {
		t.Fatalf("delete refused: %v", err)
	}
	if len(committer.records) != 0 {
		t.Errorf("delete audited at admission: %+v", committer.records)
	}
	job := manualJob()
	job.Namespace = "default"
	if _, err := w.ValidateDelete(requestCtx(admissionv1.Delete, "bob"), job); err == nil {
		t.Fatal("delete outside the system namespace admitted")
	}
}
