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

// Package loki reads Suricata alerts back out of the observation pipeline.
//
// The pipeline writes each observation with its event_time as the Loki
// timestamp, not its ingestion time, so records are ordered by the producer's
// clock. Everything about the cursor follows from that: producers are not
// ordered relative to each other, so resuming means overlapping and suppressing
// rather than seeking to an exact offset.
package loki

import (
	"encoding/json"
	"time"
)

// Cursor is the resume position in the alert stream.
//
// It holds a high-water mark and the identities handled near it. Both are
// needed and neither is sufficient: the mark alone cannot distinguish the
// several alerts Suricata writes at one timestamp, and identities alone give
// nothing to query from.
//
// The zero value is a cursor that has seen nothing.
type Cursor struct {
	// Timestamp is the newest event time handled so far. It only moves
	// forward - a record written late, with an older event time, is handled but
	// does not drag the resume point back, or every poll would re-read a
	// widening window.
	Timestamp time.Time

	// Handled identities, mapped to the event time they carried so the set can
	// be pruned to the overlap window rather than growing without bound.
	seen map[string]time.Time
}

// Advance records that a record at this time and ID has been handled.
func (c *Cursor) Advance(at time.Time, id string) {
	if c.seen == nil {
		c.seen = map[string]time.Time{}
	}
	c.seen[id] = at

	if at.After(c.Timestamp) {
		c.Timestamp = at
	}
}

// Handled says whether this record has already been processed.
//
// Identity, not time, is what decides. "Older than the cursor" cannot mean
// "already handled": the reason the query overlaps at all is that a record with
// an older event time can be written after a newer one, and treating age as
// proof of handling would discard exactly the alerts the overlap exists to
// catch.
func (c Cursor) Handled(id string) bool {
	_, ok := c.seen[id]
	return ok
}

// Resume returns where the next query should start and whether coverage was
// broken getting there.
//
// The gap is the important half. A worker that cannot read what it missed can
// still be correct about it, and saying so is what separates "the network was
// quiet" from "nobody was looking". Both produce no captures; only one is a
// reason to go and look elsewhere for the evidence.
func (c Cursor) Resume(now time.Time, overlap, maxLookback time.Duration) (time.Time, bool) {
	floor := now.Add(-maxLookback)

	// A cursor that has seen nothing carries the zero time. Querying from there
	// asks Loki for every record since year one, which it either refuses or
	// answers ruinously.
	if c.Timestamp.IsZero() {
		return floor, true
	}

	start := c.QueryStart(overlap)
	if start.Before(floor) {
		// Older than Loki is likely to still hold. Resuming from the stale
		// position would query a window already dropped, return nothing, and
		// look like quiet traffic rather than lost coverage.
		return floor, true
	}
	return start, false
}

// QueryStart is where the next range query should begin, ignoring bounds.
func (c Cursor) QueryStart(overlap time.Duration) time.Time {
	return c.Timestamp.Add(-overlap)
}

// Lag is how far behind the newest handled record the worker is running.
//
// It separates "keeping up with quiet traffic" from "falling behind and not
// noticing", which look identical from the outside: both produce few captures.
func (c Cursor) Lag(now time.Time) time.Duration {
	if c.Timestamp.IsZero() {
		return 0
	}
	return now.Sub(c.Timestamp)
}

// persistedCursor is the on-disk shape.
//
// The identity set is unexported, so without an explicit encoding it would be
// dropped silently on save. That failure would be invisible until a restart,
// when the first overlap re-delivers records already handled and every one of
// them re-triggers its policy - restarting the worker would manufacture
// duplicate captures, which is what the cursor exists to prevent.
type persistedCursor struct {
	Timestamp time.Time            `json:"timestamp"`
	Seen      map[string]time.Time `json:"seen,omitempty"`
}

// MarshalJSON encodes the cursor for persistence.
func (c Cursor) MarshalJSON() ([]byte, error) {
	return json.Marshal(persistedCursor{Timestamp: c.Timestamp, Seen: c.seen})
}

// UnmarshalJSON restores a persisted cursor.
func (c *Cursor) UnmarshalJSON(data []byte) error {
	var p persistedCursor
	if err := json.Unmarshal(data, &p); err != nil {
		return err
	}
	c.Timestamp = p.Timestamp
	c.seen = p.Seen
	if c.seen == nil {
		c.seen = map[string]time.Time{}
	}
	return nil
}

// Prune drops identities that have fallen out of the overlap window.
//
// Without it the set grows for as long as the worker runs. Anything older than
// the window cannot be returned by the next query, so remembering it buys
// nothing.
func (c *Cursor) Prune(overlap time.Duration) {
	cutoff := c.Timestamp.Add(-overlap)
	for id, at := range c.seen {
		if at.Before(cutoff) {
			delete(c.seen, id)
		}
	}
}
