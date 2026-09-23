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

package hubble

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
	// DefaultCursorConfigMap is the one ConfigMap holding the Hubble replay
	// boundary for the elected event worker.
	DefaultCursorConfigMap = "trawl-hubble-cursor"

	cursorKey = "cursor.json"
)

// ConfigMapStore persists the Hubble cursor in the system namespace.
type ConfigMapStore struct {
	Client    client.Client
	Namespace string
	Name      string
}

// Load returns the stored cursor, or the zero cursor on first use.
//
// A present unreadable value is an error, not an empty cursor. Treating corrupt
// persisted state as a clean first start would claim replay safety while
// discarding the only record of which IDs the previous leader handled.
func (s *ConfigMapStore) Load(ctx context.Context) (Cursor, error) {
	if err := s.validate(); err != nil {
		return Cursor{}, err
	}

	var cm corev1.ConfigMap
	err := s.Client.Get(ctx, types.NamespacedName{Namespace: s.Namespace, Name: s.name()}, &cm)
	switch {
	case apierrors.IsNotFound(err):
		return Cursor{}, nil
	case err != nil:
		return Cursor{}, sanitize.Errorf("reading the Hubble cursor: %v", err)
	}

	raw, ok := cm.Data[cursorKey]
	if !ok || raw == "" {
		return Cursor{}, nil
	}
	var cursor Cursor
	if err := json.Unmarshal([]byte(raw), &cursor); err != nil {
		return Cursor{}, sanitize.Errorf("decoding the Hubble cursor: %v", err)
	}
	return cursor, nil
}

// Save stores the complete bounded cursor with resource-version concurrency.
func (s *ConfigMapStore) Save(ctx context.Context, cursor Cursor) error {
	if err := s.validate(); err != nil {
		return err
	}
	encoded, err := json.Marshal(cursor)
	if err != nil {
		return sanitize.Errorf("encoding the Hubble cursor: %v", err)
	}

	var cm corev1.ConfigMap
	err = s.Client.Get(ctx, types.NamespacedName{Namespace: s.Namespace, Name: s.name()}, &cm)
	if apierrors.IsNotFound(err) {
		cm = corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Namespace: s.Namespace, Name: s.name()},
			Data:       map[string]string{cursorKey: string(encoded)},
		}
		if err := s.Client.Create(ctx, &cm); err != nil {
			return sanitize.Errorf("creating the Hubble cursor: %v", err)
		}
		return nil
	}
	if err != nil {
		return sanitize.Errorf("reading the Hubble cursor: %v", err)
	}
	if cm.Data == nil {
		cm.Data = map[string]string{}
	}
	cm.Data[cursorKey] = string(encoded)
	if err := s.Client.Update(ctx, &cm); err != nil {
		return sanitize.Errorf("updating the Hubble cursor: %v", err)
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
		return errors.New("hubble cursor: no client")
	}
	if s.Namespace == "" {
		return errors.New("hubble cursor: no namespace")
	}
	return nil
}
