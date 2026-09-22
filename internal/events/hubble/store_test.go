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

package hubble_test

import (
	"context"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"trawl.cloud/trawl/internal/events/hubble"
)

func TestHubbleCursorRoundTripsItsWatermarkAndHandledIDs(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("adding core scheme: %v", err)
	}
	client := fake.NewClientBuilder().WithScheme(scheme).Build()
	store := &hubble.ConfigMapStore{Client: client, Namespace: "trawl-system"}
	at := time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)
	want := hubble.Cursor{
		Watermark: at.Add(time.Minute),
		Handled: map[string]time.Time{
			"flow-a": at,
			"flow-b": at.Add(time.Minute),
		},
	}

	if err := store.Save(context.Background(), want); err != nil {
		t.Fatalf("saving cursor: %v", err)
	}
	got, err := store.Load(context.Background())
	if err != nil {
		t.Fatalf("loading cursor: %v", err)
	}
	if !got.Watermark.Equal(want.Watermark) {
		t.Errorf("watermark = %s, want %s", got.Watermark, want.Watermark)
	}
	if len(got.Handled) != len(want.Handled) {
		t.Fatalf("handled IDs = %v, want %v", got.Handled, want.Handled)
	}
	for id, eventTime := range want.Handled {
		if !got.Handled[id].Equal(eventTime) {
			t.Errorf("handled[%q] = %s, want %s", id, got.Handled[id], eventTime)
		}
	}
}

func TestAnUnreadableHubbleCursorIsNotReportedAsAbsent(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("adding core scheme: %v", err)
	}
	client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(&corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: hubble.DefaultCursorConfigMap},
		Data:       map[string]string{"cursor.json": "{not json"},
	}).Build()
	store := &hubble.ConfigMapStore{Client: client, Namespace: "default"}

	if _, err := store.Load(context.Background()); err == nil {
		t.Error("an unreadable persisted cursor was reported as a clean absence")
	}
}
