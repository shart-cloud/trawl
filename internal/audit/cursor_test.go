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

package audit

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func newCursorScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := corev1.AddToScheme(s); err != nil {
		t.Fatalf("building scheme: %v", err)
	}
	return s
}

func newConfigMapCursor(t *testing.T, objs ...client.Object) (*ConfigMapCursor, client.Client) {
	t.Helper()
	c := fake.NewClientBuilder().WithScheme(newCursorScheme(t)).WithObjects(objs...).Build()
	return &ConfigMapCursor{Client: c, Namespace: "trawl-system"}, c
}

func TestCursorIsAbsentNotFailedBeforeItIsFirstWritten(t *testing.T) {
	// A fresh install has no cursor ConfigMap. Reporting that as an error would
	// stop replay from ever starting; reporting it as the beginning re-forwards
	// a ledger that is empty anyway.
	cursor, _ := newConfigMapCursor(t)

	got, err := cursor.Load(t.Context())
	if err != nil {
		t.Fatalf("Load on a fresh install: %v", err)
	}
	if got != "" {
		t.Errorf("Load returned %q with no stored cursor, want the empty string", got)
	}
}

func TestCursorSurvivesAWriteAndAReadBack(t *testing.T) {
	cursor, c := newConfigMapCursor(t)

	const key = "audit/v1/records/20260829T120000.000000000Z-abc.json"
	if err := cursor.Save(t.Context(), key); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, err := cursor.Load(t.Context())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got != key {
		t.Errorf("Load returned %q, want %q", got, key)
	}

	// The stored form matters: an operator reads this ConfigMap to answer "how
	// far behind is the audit stream", and a cursor buried in an opaque
	// encoding answers nothing.
	var cm corev1.ConfigMap
	if err := c.Get(t.Context(), types.NamespacedName{
		Namespace: "trawl-system", Name: DefaultCursorConfigMap,
	}, &cm); err != nil {
		t.Fatalf("reading the cursor ConfigMap: %v", err)
	}
	if cm.Data[cursorKey] != key {
		t.Errorf("ConfigMap holds %q under %q, want %q", cm.Data[cursorKey], cursorKey, key)
	}
}

func TestCursorOverwritesAnEarlierValue(t *testing.T) {
	cursor, _ := newConfigMapCursor(t)

	if err := cursor.Save(t.Context(), "audit/v1/records/first.json"); err != nil {
		t.Fatalf("first Save: %v", err)
	}
	if err := cursor.Save(t.Context(), "audit/v1/records/second.json"); err != nil {
		t.Fatalf("second Save: %v", err)
	}

	got, err := cursor.Load(t.Context())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got != "audit/v1/records/second.json" {
		t.Errorf("Load returned %q, want the later cursor", got)
	}
}

func TestCursorTreatsAnEmptyConfigMapAsTheBeginning(t *testing.T) {
	// An operator who cleared the key, or a ConfigMap created by something
	// else under the same name, must not stall replay.
	existing := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Namespace: "trawl-system", Name: DefaultCursorConfigMap},
	}
	cursor, _ := newConfigMapCursor(t, existing)

	got, err := cursor.Load(t.Context())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got != "" {
		t.Errorf("Load returned %q from a ConfigMap with no cursor key, want the empty string", got)
	}
}

func TestCursorRefusesAnIncompleteConfiguration(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(newCursorScheme(t)).Build()
	for name, cursor := range map[string]*ConfigMapCursor{
		"no client":    {Namespace: "trawl-system"},
		"no namespace": {Client: c},
	} {
		if _, err := cursor.Load(t.Context()); err == nil {
			t.Errorf("%s: Load accepted an incomplete cursor store", name)
		}
	}
}
