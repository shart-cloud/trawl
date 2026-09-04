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

// Package authz answers "who is this caller" and "may they do this" by asking
// the Kubernetes API server, rather than by holding any policy of its own.
//
// The artifact gateway serves packet captures, which are the most sensitive
// data Trawl holds. Delegating both questions to TokenReview and
// SubjectAccessReview means access is governed by ordinary RBAC that a cluster
// administrator can read, audit and revoke with the tools they already use —
// and that revoking a service account revokes its downloads, with no second
// list for anyone to forget.
package authz

import (
	"context"
	"errors"
)

// ErrUnauthenticated means the presented token was rejected: missing, expired,
// malformed, or valid but not for this audience.
//
// It is deliberately one error rather than several. Telling a caller which of
// those it was tells an attacker which tokens are worth guessing at.
var ErrUnauthenticated = errors.New("token was not accepted")

// Identity is an authenticated caller as the API server describes it.
type Identity struct {
	Username string
	UID      string
	Groups   []string
}

// Attributes name the action being authorized, in the API server's own terms.
type Attributes struct {
	Namespace   string
	Group       string
	Resource    string
	Subresource string
	Name        string
	Verb        string
}

// Decision is the outcome of an authorization check.
//
// Reason is the API server's own explanation. It is recorded in the audit
// ledger and never returned to the caller: it can name the roles and bindings
// that were consulted, which is exactly the cluster structure an unauthorized
// caller should not be able to map.
type Decision struct {
	Allowed bool
	Reason  string
}

// Reviewer authenticates bearer tokens and authorizes actions against them.
//
// Both methods return an error only for a failure to reach a decision — the API
// server was unreachable, or answered unusably. A caller must fail closed on
// that error rather than treating it as a denial, because "unavailable" and
// "denied" call for different responses: retry, versus stop.
type Reviewer interface {
	// Authenticate exchanges a bearer token for the identity behind it,
	// returning ErrUnauthenticated when the token is not accepted.
	Authenticate(ctx context.Context, token string) (Identity, error)

	// Authorize reports whether id may perform the action attrs describes.
	Authorize(ctx context.Context, id Identity, attrs Attributes) (Decision, error)
}
