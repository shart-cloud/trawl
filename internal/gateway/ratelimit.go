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

package gateway

import (
	"sync"
	"time"

	"golang.org/x/time/rate"

	"trawl.cloud/trawl/internal/authz"
)

// Rate-limit defaults.
//
// Downloading a capture is a deliberate act: an analyst fetches one artifact,
// looks at it, and comes back. These numbers are generous for that and mean
// something for the case they exist to bound - an authorized credential being
// used to sweep every capture in the cluster. They slow that from "as fast as
// the network allows" to a rate a human reviewing the audit ledger can notice.
const (
	// DefaultDownloadsPerMinute is the sustained per-caller rate.
	DefaultDownloadsPerMinute = 30

	// DefaultDownloadBurst is how many may arrive at once.
	DefaultDownloadBurst = 10

	// maxTrackedCallers bounds the limiter's memory. Every entry needs an
	// authenticated identity to create, so this is not reachable by an
	// anonymous flood; the cap is against slow growth over a long uptime.
	maxTrackedCallers = 4096

	// callerIdleTimeout is how long an unused entry is kept.
	callerIdleTimeout = 10 * time.Minute
)

// limiter applies a per-caller request rate.
//
// Keyed by authenticated identity rather than by source address: the address is
// a proxy or a node in this deployment, so limiting on it would either be
// useless or would let one busy analyst throttle everyone else.
type limiter struct {
	rate  rate.Limit
	burst int
	now   func() time.Time

	mu      sync.Mutex
	callers map[string]*callerLimit
}

type callerLimit struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

func newLimiter(perMinute, burst int, now func() time.Time) *limiter {
	if perMinute <= 0 {
		perMinute = DefaultDownloadsPerMinute
	}
	if burst <= 0 {
		burst = DefaultDownloadBurst
	}
	return &limiter{
		rate:    rate.Limit(float64(perMinute) / 60.0),
		burst:   burst,
		now:     now,
		callers: make(map[string]*callerLimit),
	}
}

// allow reports whether id may make a request now.
func (l *limiter) allow(id authz.Identity) bool {
	key := id.UID
	if key == "" {
		// A UID is stable across a service account being deleted and recreated
		// with the same name, so it is the better key — but an authenticator
		// need not supply one.
		key = id.Username
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	entry, ok := l.callers[key]
	if !ok {
		if len(l.callers) >= maxTrackedCallers {
			l.evictStaleLocked(now)
		}
		entry = &callerLimit{limiter: rate.NewLimiter(l.rate, l.burst)}
		l.callers[key] = entry
	}
	entry.lastSeen = now

	return entry.limiter.AllowN(now, 1)
}

// evictStaleLocked drops idle entries, and if none are idle, everything.
//
// Clearing wholesale is the deliberate choice for the pathological case: the
// alternative is to start refusing new callers, which would turn a memory bound
// into a denial of service against exactly the analyst who has not downloaded
// anything yet. Resetting costs a moment of unlimited requests from callers who
// were already within their limit.
func (l *limiter) evictStaleLocked(now time.Time) {
	for key, entry := range l.callers {
		if now.Sub(entry.lastSeen) > callerIdleTimeout {
			delete(l.callers, key)
		}
	}
	if len(l.callers) >= maxTrackedCallers {
		clear(l.callers)
	}
}
