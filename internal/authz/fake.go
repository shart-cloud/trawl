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

package authz

import (
	"context"
	"slices"
	"sync"
)

// Fake is an in-memory Reviewer for handler tests.
//
// The gateway's interesting behaviour is what it does with each answer — which
// status code, which audit record, whether it looks the CaptureJob up at all —
// so the tests need to drive every answer including the unavailable ones, which
// a live API server will not produce on demand.
type Fake struct {
	mu sync.Mutex

	// Tokens maps an accepted bearer token to the identity behind it. A token
	// absent from the map is rejected with ErrUnauthenticated.
	Tokens map[string]Identity

	// AuthenticateErr, when set, is returned instead of any decision — the
	// API server being unreachable rather than the token being bad.
	AuthenticateErr error

	// Allow decides an authorization. Nil allows everything, which keeps a test
	// that is about something else from having to say so.
	Allow func(Identity, Attributes) Decision

	// AuthorizeErr, when set, is returned instead of any decision.
	AuthorizeErr error

	// OnAuthenticate is called on every authentication attempt that reaches
	// this reviewer, so a test can count what would have been a TokenReview
	// against a real API server.
	OnAuthenticate func()

	authorized []Attributes
}

// Authenticate implements Reviewer.
func (f *Fake) Authenticate(_ context.Context, token string) (Identity, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.OnAuthenticate != nil {
		f.OnAuthenticate()
	}
	if f.AuthenticateErr != nil {
		return Identity{}, f.AuthenticateErr
	}
	id, ok := f.Tokens[token]
	if !ok {
		return Identity{}, ErrUnauthenticated
	}
	return id, nil
}

// Authorize implements Reviewer.
func (f *Fake) Authorize(_ context.Context, id Identity, attrs Attributes) (Decision, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.authorized = append(f.authorized, attrs)
	if f.AuthorizeErr != nil {
		return Decision{}, f.AuthorizeErr
	}
	if f.Allow == nil {
		return Decision{Allowed: true}, nil
	}
	return f.Allow(id, attrs), nil
}

// Authorized returns the attributes checked so far, in order.
//
// A handler that authorized the wrong resource, verb or namespace would still
// pass a test that only looked at the status code, because the fake would have
// allowed it. This is how a test says which question was asked.
func (f *Fake) Authorized() []Attributes {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.authorized)
}
