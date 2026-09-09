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

package loki

import (
	"context"
	"encoding/json"
	"errors"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"trawl.cloud/trawl/internal/sanitize"
)

const (
	// DefaultCursorConfigMap is the ConfigMap the alert cursor is stored in.
	DefaultCursorConfigMap = "trawl-alert-cursor"

	// cursorKey is the ConfigMap data key. JSON rather than a bare timestamp,
	// because the handled identities travel with it.
	cursorKey = "cursor.json"
)

// ConfigMapStore persists the alert cursor in a ConfigMap.
//
// The same shape as the audit replay cursor (internal/audit/cursor.go), for the
// same reasons: it is per-installation state about a consumer rather than part
// of any evidence record, and it belongs somewhere an operator can read it with
// kubectl.
//
// Losing it is survivable but not free. Unlike the audit cursor, whose replay
// collapses duplicates by stable key, a lost alert cursor means the window
// before the bounded lookback was never examined - which is why Resume reports
// a gap rather than quietly starting over.
type ConfigMapStore struct {
	// Client reads and writes the ConfigMap.
	Client client.Client

	// Namespace is the Trawl system namespace.
	Namespace string

	// Name defaults to DefaultCursorConfigMap.
	Name string
}

// Load returns the stored cursor, or the zero cursor if none is stored.
func (s *ConfigMapStore) Load(ctx context.Context) (Cursor, error) {
	if err := s.validate(); err != nil {
		return Cursor{}, err
	}

	var cm corev1.ConfigMap
	err := s.Client.Get(ctx, types.NamespacedName{Namespace: s.Namespace, Name: s.name()}, &cm)
	switch {
	case apierrors.IsNotFound(err):
		// Genuinely absent - first start, or a wiped namespace. Distinct from a
		// failed read, which is an error so the worker waits rather than
		// resuming from a position it never actually read.
		return Cursor{}, nil
	case err != nil:
		return Cursor{}, sanitize.Errorf("reading the alert cursor: %v", err)
	}

	raw, ok := cm.Data[cursorKey]
	if !ok || raw == "" {
		return Cursor{}, nil
	}

	var cursor Cursor
	if err := json.Unmarshal([]byte(raw), &cursor); err != nil {
		// Present but unreadable. Treated as absent rather than fatal: the
		// worker resumes at the bounded lookback and reports the gap, which is
		// recoverable, where refusing to start is not.
		return Cursor{}, nil
	}
	return cursor, nil
}

// Save stores the cursor, creating the ConfigMap if it does not exist.
//
// The update is a read-modify-write against the resource version, so a
// concurrent writer loses with a conflict rather than silently overwriting.
// The conflict is returned: an unpersisted cursor must not be treated as
// persisted, or the next start would skip everything the failed write covered.
func (s *ConfigMapStore) Save(ctx context.Context, cursor Cursor) error {
	if err := s.validate(); err != nil {
		return err
	}

	encoded, err := json.Marshal(cursor)
	if err != nil {
		return sanitize.Errorf("encoding the alert cursor: %v", err)
	}

	var cm corev1.ConfigMap
	err = s.Client.Get(ctx, types.NamespacedName{Namespace: s.Namespace, Name: s.name()}, &cm)
	if apierrors.IsNotFound(err) {
		cm = corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Namespace: s.Namespace, Name: s.name()},
			Data:       map[string]string{cursorKey: string(encoded)},
		}
		if err := s.Client.Create(ctx, &cm); err != nil {
			return sanitize.Errorf("creating the alert cursor: %v", err)
		}
		return nil
	}
	if err != nil {
		return sanitize.Errorf("reading the alert cursor: %v", err)
	}

	if cm.Data == nil {
		cm.Data = map[string]string{}
	}
	cm.Data[cursorKey] = string(encoded)
	if err := s.Client.Update(ctx, &cm); err != nil {
		return sanitize.Errorf("updating the alert cursor: %v", err)
	}
	return nil
}

func (s *ConfigMapStore) name() string {
	if s.Name != "" {
		return s.Name
	}
	return DefaultCursorConfigMap
}

func (s *ConfigMapStore) validate() error {
	if s.Client == nil {
		return errors.New("alert cursor: no client")
	}
	if s.Namespace == "" {
		return errors.New("alert cursor: no namespace")
	}
	return nil
}
