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
	"context"
	"errors"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"trawl.cloud/trawl/internal/sanitize"
)

const (
	// DefaultCursorConfigMap is the ConfigMap the replay cursor is stored in.
	DefaultCursorConfigMap = "trawl-audit-cursor"

	// cursorKey is the ConfigMap data key. It is a plain ledger key so an
	// operator can read "how far has the audit stream got" straight out of
	// kubectl, and compare it against the ledger by eye.
	cursorKey = "cursor"
)

// ConfigMapCursor persists the replay cursor in a ConfigMap.
//
// A ConfigMap rather than the ledger itself: the cursor is per-installation
// state about a consumer, not part of the write-once audit record, and putting
// it in the ledger bucket would mean the one credential that must never rewrite
// history needs write access to a mutable object.
//
// Losing it is survivable by design. Load reports an absent ConfigMap as the
// empty cursor, which replays the ledger from the beginning: duplicates
// collapse by stable key, and a gap would not.
type ConfigMapCursor struct {
	// Client reads and writes the ConfigMap.
	Client client.Client

	// Namespace is the Trawl system namespace.
	Namespace string

	// Name defaults to DefaultCursorConfigMap.
	Name string
}

// Load returns the stored cursor, or the empty string if none is stored.
func (c *ConfigMapCursor) Load(ctx context.Context) (string, error) {
	if err := c.validate(); err != nil {
		return "", err
	}

	var cm corev1.ConfigMap
	err := c.Client.Get(ctx, types.NamespacedName{Namespace: c.Namespace, Name: c.name()}, &cm)
	switch {
	case apierrors.IsNotFound(err):
		// No cursor yet. Distinct from a failed read, which is returned as an
		// error so that replay waits rather than starting over.
		return "", nil
	case err != nil:
		return "", sanitize.Errorf("reading the audit replay cursor: %v", err)
	}
	return cm.Data[cursorKey], nil
}

// Save stores the cursor, creating the ConfigMap if it does not exist.
//
// The update is a read-modify-write against the resource version, so a
// concurrent writer loses with a conflict rather than silently overwriting.
// A conflict is returned: the caller must not treat an unpersisted cursor as
// persisted, or a restart would skip everything the failed write covered.
func (c *ConfigMapCursor) Save(ctx context.Context, cursor string) error {
	if err := c.validate(); err != nil {
		return err
	}

	var cm corev1.ConfigMap
	err := c.Client.Get(ctx, types.NamespacedName{Namespace: c.Namespace, Name: c.name()}, &cm)
	if apierrors.IsNotFound(err) {
		cm = corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Namespace: c.Namespace, Name: c.name()},
			Data:       map[string]string{cursorKey: cursor},
		}
		if err := c.Client.Create(ctx, &cm); err != nil {
			return sanitize.Errorf("creating the audit replay cursor: %v", err)
		}
		return nil
	}
	if err != nil {
		return sanitize.Errorf("reading the audit replay cursor: %v", err)
	}

	if cm.Data == nil {
		cm.Data = map[string]string{}
	}
	cm.Data[cursorKey] = cursor
	if err := c.Client.Update(ctx, &cm); err != nil {
		return sanitize.Errorf("updating the audit replay cursor: %v", err)
	}
	return nil
}

func (c *ConfigMapCursor) name() string {
	if c.Name != "" {
		return c.Name
	}
	return DefaultCursorConfigMap
}

func (c *ConfigMapCursor) validate() error {
	switch {
	case c.Client == nil:
		return errors.New("audit replay cursor requires a client")
	case c.Namespace == "":
		return errors.New("audit replay cursor requires a namespace")
	}
	return nil
}
