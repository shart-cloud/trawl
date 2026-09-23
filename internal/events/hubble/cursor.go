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
	"maps"
	"time"
)

// Cursor is the restart-safe Hubble replay boundary.
//
// Watermark determines where a replacement stream resumes. Handled carries
// stable observation identities inside that overlap so returning old evidence
// does not emit or evaluate it a second time. The client prunes Handled to the
// replay horizon before snapshots are persisted.
type Cursor struct {
	Watermark time.Time            `json:"watermark"`
	Handled   map[string]time.Time `json:"handled,omitempty"`
}

// CursorStore persists the Hubble cursor between worker leaders.
type CursorStore interface {
	Load(context.Context) (Cursor, error)
	Save(context.Context, Cursor) error
}

// SetCursorStore configures restart persistence. It must be called before Run.
func (c *Client) SetCursorStore(store CursorStore) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cursorStore = store
	c.cursorHealthy = false
}

// ReplaySafe reports whether the persisted replay boundary is currently
// trustworthy. A client without a store is useful in unit tests and retains
// its process-local reconnect guarantee; production configures one.
func (c *Client) ReplaySafe() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cursorStore == nil || c.cursorHealthy
}

func (c *Client) loadCursor(ctx context.Context) {
	c.mu.Lock()
	store := c.cursorStore
	c.mu.Unlock()
	if store == nil {
		return
	}

	cursor, err := store.Load(ctx)
	if err != nil {
		c.mu.Lock()
		c.cursorHealthy = false
		c.cursorLoadFailed = true
		c.mu.Unlock()
		c.reportGap(GapCursorUnavailable)
		c.reportCursorError("load", err)
		return
	}

	c.mu.Lock()
	c.watermark = cursor.Watermark
	c.handled = make(map[string]time.Time, len(cursor.Handled))
	maps.Copy(c.handled, cursor.Handled)
	c.pruneHandledLocked()
	c.cursorHealthy = true
	c.cursorLoadFailed = false
	c.mu.Unlock()
}

func (c *Client) saveCursor(ctx context.Context) {
	c.mu.Lock()
	store := c.cursorStore
	if store == nil {
		c.mu.Unlock()
		return
	}
	cursor := Cursor{
		Watermark: c.watermark,
		Handled:   make(map[string]time.Time, len(c.handled)),
	}
	maps.Copy(cursor.Handled, c.handled)
	c.mu.Unlock()

	if err := store.Save(ctx, cursor); err != nil {
		c.mu.Lock()
		c.cursorHealthy = false
		c.mu.Unlock()
		c.reportGap(GapCursorUnavailable)
		c.reportCursorError("save", err)
		return
	}

	c.mu.Lock()
	// A successful save repairs an earlier save failure because the snapshot
	// contains the complete current horizon. A failed load remains a known gap
	// for this process: it started without knowing which overlap IDs preceded
	// its first new watermark.
	if !c.cursorLoadFailed {
		c.cursorHealthy = true
	}
	c.mu.Unlock()
}

func (c *Client) reportCursorError(operation string, err error) {
	if c.OnCursorError != nil {
		c.OnCursorError(operation, err)
	}
}
