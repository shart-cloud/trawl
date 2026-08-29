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

// Package sensor implements the trawl-sensor-agent that runs beside each
// analyzer: it tails analyzer output, normalizes records, marks suspected
// duplicates, and reports target health.
package sensor

import (
	"container/list"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	trawlv1alpha1 "trawl.cloud/trawl/api/v1alpha1"
	"trawl.cloud/trawl/internal/observation"
)

// Duplicate-detection bounds, fixed by plan.md "Observation processing".
const (
	// DuplicateWindow is how close in time two identical fingerprints must be
	// to count as a suspected duplicate.
	DuplicateWindow = time.Second

	// MaxFingerprints caps the per-target cache. A sensor on a busy mirror must
	// not trade unbounded memory for duplicate detection, so the cache evicts
	// and reports Unknown rather than growing.
	MaxFingerprints = 100_000

	// timeBucket is the event-time rounding applied before fingerprinting.
	// Mirrored copies of one packet arrive microseconds apart, so exact
	// timestamps would never match.
	timeBucket = time.Millisecond
)

// DuplicateCache marks suspected duplicate observations without discarding them.
//
// Mirrored and overlay traffic legitimately carries the same packet more than
// once. Trawl marks rather than drops, because deciding that two records are
// the same event is a judgement an analyst may need to overturn — and evidence
// deleted at ingest cannot be recovered.
//
// The cache is deliberately bounded and lossy. When a fingerprint is evicted or
// cannot be computed, the answer is Unknown, never NotDetected: reporting an
// absence of duplicates that was never established would mislead anyone
// counting observations.
type DuplicateCache struct {
	max     int
	window  time.Duration
	entries map[string]*list.Element
	order   *list.List

	// Counters feeding target status.
	suspected int64
	evicted   int64
	unknown   int64
}

type cacheEntry struct {
	fingerprint string
	seenAt      time.Time
}

// NewDuplicateCache returns a cache bounded to max entries.
func NewDuplicateCache(max int) *DuplicateCache {
	if max <= 0 {
		max = MaxFingerprints
	}
	return &DuplicateCache{
		max:     max,
		window:  DuplicateWindow,
		entries: make(map[string]*list.Element, min(max, 1024)),
		order:   list.New(),
	}
}

// Mark classifies one observation and records its fingerprint.
//
// It returns the duplication state for this record. The observation itself is
// never modified or withheld.
func (c *DuplicateCache) Mark(obs *observation.Observation) trawlv1alpha1.DuplicationState {
	fp, ok := fingerprint(obs)
	if !ok {
		// Missing fingerprint inputs mean we cannot tell. Saying NotDetected
		// would be a claim we have no basis for.
		c.unknown++
		return trawlv1alpha1.DuplicationUnknown
	}

	now := obs.EventTime
	if elem, seen := c.entries[fp]; seen {
		entry, _ := elem.Value.(*cacheEntry)
		if now.Sub(entry.seenAt).Abs() <= c.window {
			c.order.MoveToFront(elem)
			entry.seenAt = now
			c.suspected++
			return trawlv1alpha1.DuplicationSuspected
		}
		// Same fingerprint outside the window is a distinct event that happens
		// to look identical — a repeated scan, a periodic beacon — not a
		// duplicated packet.
		c.order.MoveToFront(elem)
		entry.seenAt = now
		return trawlv1alpha1.DuplicationNotDetected
	}

	c.insert(fp, now)
	return trawlv1alpha1.DuplicationNotDetected
}

func (c *DuplicateCache) insert(fp string, seenAt time.Time) {
	if c.order.Len() >= c.max {
		oldest := c.order.Back()
		if oldest != nil {
			entry, _ := oldest.Value.(*cacheEntry)
			delete(c.entries, entry.fingerprint)
			c.order.Remove(oldest)
			c.evicted++
		}
	}
	c.entries[fp] = c.order.PushFront(&cacheEntry{fingerprint: fp, seenAt: seenAt})
}

// Suspected returns how many records were marked as suspected duplicates.
func (c *DuplicateCache) Suspected() int64 { return c.suspected }

// Evicted returns how many fingerprints were dropped for capacity.
//
// A non-zero value means duplicate detection was operating beyond its window,
// so the target's state should be read as Unknown rather than trusted.
func (c *DuplicateCache) Evicted() int64 { return c.evicted }

// Unknown returns how many records could not be fingerprinted.
func (c *DuplicateCache) Unknown() int64 { return c.unknown }

// Len returns the current cache size.
func (c *DuplicateCache) Len() int { return c.order.Len() }

// State summarizes the target's duplication state for status reporting.
//
// Eviction or unfingerprintable records collapse the answer to Unknown, because
// once the window has overflowed a NotDetected result no longer means anything.
func (c *DuplicateCache) State() trawlv1alpha1.DuplicationState {
	switch {
	case c.suspected > 0:
		return trawlv1alpha1.DuplicationSuspected
	case c.evicted > 0 || c.unknown > 0:
		return trawlv1alpha1.DuplicationUnknown
	case c.order.Len() > 0:
		return trawlv1alpha1.DuplicationNotDetected
	default:
		return trawlv1alpha1.DuplicationUnknown
	}
}

// fingerprint derives a duplicate-detection key.
//
// It hashes the tap, target, source kind, observation type, a
// direction-normalized five-tuple, and the event time rounded to a millisecond.
// Direction is normalized so the same packet seen from either side of a mirror
// produces one fingerprint; time is rounded because mirrored copies arrive
// microseconds apart and exact timestamps would never collide.
func fingerprint(obs *observation.Observation) (string, bool) {
	if obs.Flow == nil {
		// Records with no flow (a certificate, a file) have no tuple to
		// normalize, so duplicate detection does not apply.
		return "", false
	}
	src, dst := obs.Flow.Source, obs.Flow.Destination
	if src.IP == "" && dst.IP == "" {
		return "", false
	}

	a := endpointKey(src)
	b := endpointKey(dst)
	if a > b {
		a, b = b, a
	}

	tapUID := ""
	if obs.Tap != nil {
		tapUID = obs.Tap.UID
	}

	h := sha256.New()
	for _, part := range []string{
		tapUID,
		obs.Target.Node,
		obs.Target.Interface,
		string(obs.Source.Kind),
		string(obs.ObservationType),
		obs.Flow.Protocol,
		a, b,
		obs.Flow.CommunityID,
	} {
		// Length-prefixed so field boundaries cannot be forged by content.
		_, _ = fmt.Fprintf(h, "%d:%s", len(part), part)
	}
	_, _ = fmt.Fprintf(h, "|%d", obs.EventTime.Round(timeBucket).UnixNano())

	return hex.EncodeToString(h.Sum(nil)), true
}

func endpointKey(e observation.Endpoint) string {
	var b strings.Builder
	b.WriteString(e.IP)
	b.WriteByte('/')
	if e.Port != nil {
		fmt.Fprintf(&b, "%d", *e.Port)
	}
	return b.String()
}
