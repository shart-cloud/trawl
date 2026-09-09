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

package loki_test

import (
	"context"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"trawl.cloud/trawl/internal/events/loki"
)

func newScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("building scheme: %v", err)
	}
	return scheme
}

func TestTheStoredCursorRoundTripsThroughTheConfigMap(t *testing.T) {
	// The worker keeps its place across restarts and leader handoffs here.
	// What matters is that the handled identities come back, not just the
	// timestamp: without them the first overlap after a restart re-triggers
	// every policy whose alert falls inside it.
	c := fake.NewClientBuilder().WithScheme(newScheme(t)).Build()
	store := &loki.ConfigMapStore{Client: c, Namespace: "trawl-system"}
	at := time.Date(2026, 9, 9, 21, 37, 59, 0, time.UTC)

	var cursor loki.Cursor
	cursor.Advance(at, "alert-a")
	cursor.Advance(at, "alert-tie")

	if err := store.Save(context.Background(), cursor); err != nil {
		t.Fatalf("saving: %v", err)
	}

	restored, err := store.Load(context.Background())
	if err != nil {
		t.Fatalf("loading: %v", err)
	}
	if !restored.Timestamp.Equal(at) {
		t.Errorf("timestamp = %s, want %s", restored.Timestamp, at)
	}
	if !restored.Handled("alert-a") || !restored.Handled("alert-tie") {
		t.Error("handled identities did not survive; a restart would re-trigger them")
	}
}

func TestSavingTwiceUpdatesRatherThanFailing(t *testing.T) {
	// The worker saves on every poll. The first save creates the ConfigMap and
	// every later one updates it, so a second save must not collide with the
	// object the first one created.
	c := fake.NewClientBuilder().WithScheme(newScheme(t)).Build()
	store := &loki.ConfigMapStore{Client: c, Namespace: "trawl-system"}
	at := time.Date(2026, 9, 9, 21, 37, 59, 0, time.UTC)

	var first loki.Cursor
	first.Advance(at, "alert-a")
	if err := store.Save(context.Background(), first); err != nil {
		t.Fatalf("first save: %v", err)
	}

	var second loki.Cursor
	second.Advance(at.Add(time.Minute), "alert-b")
	if err := store.Save(context.Background(), second); err != nil {
		t.Fatalf("second save: %v", err)
	}

	restored, err := store.Load(context.Background())
	if err != nil {
		t.Fatalf("loading: %v", err)
	}
	if !restored.Timestamp.Equal(at.Add(time.Minute)) {
		t.Errorf("timestamp = %s, want the second save's", restored.Timestamp)
	}
}

func TestAnAbsentCursorLoadsAsTheZeroValueNotAnError(t *testing.T) {
	// First start, or a wiped namespace. This is not a failure - it is the
	// cursor being genuinely absent, and Resume turns the zero value into a
	// bounded lookback plus a reported gap. Returning an error here would stop
	// the worker starting at all.
	c := fake.NewClientBuilder().WithScheme(newScheme(t)).Build()
	store := &loki.ConfigMapStore{Client: c, Namespace: "trawl-system"}

	cursor, err := store.Load(context.Background())
	if err != nil {
		t.Fatalf("an absent cursor was reported as an error: %v", err)
	}
	if !cursor.Timestamp.IsZero() {
		t.Errorf("absent cursor had timestamp %s, want the zero value", cursor.Timestamp)
	}

	// And the zero value must be the one Resume treats as a gap, so the two
	// halves agree about what "no cursor" means.
	if _, gap := cursor.Resume(time.Now(), time.Second, time.Minute); !gap {
		t.Error("the absent cursor did not resume with a reported gap")
	}
}
