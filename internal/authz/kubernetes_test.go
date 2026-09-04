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
	"errors"
	"strings"
	"testing"

	authenticationv1 "k8s.io/api/authentication/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

const testAudience = "trawl-artifact-gateway"

// reviewerWith builds a reviewer whose TokenReview answers come from respond.
// The submitted review is handed back so a test can assert what was asked, not
// only what was answered.
func reviewerWith(t *testing.T, respond func(*authenticationv1.TokenReview) (*authenticationv1.TokenReview, error)) (*KubernetesReviewer, *[]*authenticationv1.TokenReview) {
	t.Helper()
	client := fake.NewSimpleClientset()
	var submitted []*authenticationv1.TokenReview

	client.PrependReactor("create", "tokenreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
		review, ok := action.(k8stesting.CreateAction).GetObject().(*authenticationv1.TokenReview)
		if !ok {
			t.Fatalf("unexpected object %T", action)
		}
		submitted = append(submitted, review)
		out, err := respond(review)
		return true, out, err
	})

	r, err := NewKubernetesReviewer(client, testAudience)
	if err != nil {
		t.Fatalf("NewKubernetesReviewer: %v", err)
	}
	return r, &submitted
}

func TestAuthenticateBindsTheTokenToTheAudience(t *testing.T) {
	r, submitted := reviewerWith(t, func(in *authenticationv1.TokenReview) (*authenticationv1.TokenReview, error) {
		out := in.DeepCopy()
		out.Status = authenticationv1.TokenReviewStatus{
			Authenticated: true,
			Audiences:     []string{testAudience},
			User: authenticationv1.UserInfo{
				Username: "system:serviceaccount:trawl-system:analyst",
				UID:      "uid-1",
				Groups:   []string{"system:serviceaccounts"},
			},
		}
		return out, nil
	})

	id, err := r.Authenticate(t.Context(), "a-token")
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if id.Username != "system:serviceaccount:trawl-system:analyst" || id.UID != "uid-1" {
		t.Errorf("identity = %+v", id)
	}

	// The audience is the whole reason a token from an unrelated pod cannot be
	// replayed here, so the review must actually carry it.
	if len(*submitted) != 1 {
		t.Fatalf("submitted %d reviews, want 1", len(*submitted))
	}
	if got := (*submitted)[0].Spec.Audiences; len(got) != 1 || got[0] != testAudience {
		t.Errorf("review audiences = %v, want [%s]", got, testAudience)
	}
	if (*submitted)[0].Spec.Token != "a-token" {
		t.Error("review did not carry the presented token")
	}
}

func TestAuthenticateRejectsUnusableTokens(t *testing.T) {
	cases := map[string]struct {
		token   string
		respond func(*authenticationv1.TokenReview) (*authenticationv1.TokenReview, error)
	}{
		"empty token is not even submitted": {
			token: "   ",
			respond: func(*authenticationv1.TokenReview) (*authenticationv1.TokenReview, error) {
				return nil, errors.New("should not have been called")
			},
		},
		"not authenticated": {
			token: "bad",
			respond: func(in *authenticationv1.TokenReview) (*authenticationv1.TokenReview, error) {
				out := in.DeepCopy()
				out.Status = authenticationv1.TokenReviewStatus{Authenticated: false, Error: "invalid bearer token"}
				return out, nil
			},
		},
		// A token minted for the API server, or for another service, must not
		// open the gateway even if the API server were to report it as
		// authenticated.
		"authenticated for a different audience": {
			token: "wrong-audience",
			respond: func(in *authenticationv1.TokenReview) (*authenticationv1.TokenReview, error) {
				out := in.DeepCopy()
				out.Status = authenticationv1.TokenReviewStatus{
					Authenticated: true,
					Audiences:     []string{"https://kubernetes.default.svc"},
					User:          authenticationv1.UserInfo{Username: "system:serviceaccount:other:app"},
				}
				return out, nil
			},
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			r, _ := reviewerWith(t, tc.respond)
			if _, err := r.Authenticate(t.Context(), tc.token); !errors.Is(err, ErrUnauthenticated) {
				t.Errorf("error = %v, want ErrUnauthenticated", err)
			}
		})
	}
}

// An unreachable API server is not a denial. Collapsing the two would turn an
// authorization outage into a silent, cluster-wide denial of evidence with no
// signal that anything was wrong.
func TestAuthenticateDistinguishesUnavailableFromRejected(t *testing.T) {
	r, _ := reviewerWith(t, func(*authenticationv1.TokenReview) (*authenticationv1.TokenReview, error) {
		return nil, apierrors.NewServiceUnavailable("apiserver is down")
	})

	_, err := r.Authenticate(t.Context(), "a-token")
	if err == nil {
		t.Fatal("an unreachable API server was reported as success")
	}
	if errors.Is(err, ErrUnauthenticated) {
		t.Error("an unreachable API server was reported as a rejected token")
	}
}

// A client-go error can echo the request body, and for a TokenReview the
// request body is the caller's bearer token.
func TestAuthenticateErrorNeverCarriesTheToken(t *testing.T) {
	// A real service-account token: three base64url segments. The shape matters
	// — it is what sanitize recognises — so a two-segment stand-in would prove
	// nothing about the token the gateway actually handles.
	const token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhbmFseXN0In0.c2lnbmF0dXJlLXNlY3JldC1wYXJ0"
	r, _ := reviewerWith(t, func(*authenticationv1.TokenReview) (*authenticationv1.TokenReview, error) {
		return nil, errors.New("post failed for body containing " + token)
	})

	_, err := r.Authenticate(t.Context(), token)
	if err == nil {
		t.Fatal("expected an error")
	}
	if strings.Contains(err.Error(), "secret-part") || strings.Contains(err.Error(), token) {
		t.Errorf("error leaked the token: %q", err)
	}
}

func authorizerWith(t *testing.T, status authorizationv1.SubjectAccessReviewStatus, createErr error) (*KubernetesReviewer, *[]*authorizationv1.SubjectAccessReview) {
	t.Helper()
	client := fake.NewSimpleClientset()
	var submitted []*authorizationv1.SubjectAccessReview

	client.PrependReactor("create", "subjectaccessreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
		review, ok := action.(k8stesting.CreateAction).GetObject().(*authorizationv1.SubjectAccessReview)
		if !ok {
			t.Fatalf("unexpected object %T", action)
		}
		submitted = append(submitted, review)
		if createErr != nil {
			return true, nil, createErr
		}
		out := review.DeepCopy()
		out.Status = status
		return true, out, nil
	})

	r, err := NewKubernetesReviewer(client, testAudience)
	if err != nil {
		t.Fatalf("NewKubernetesReviewer: %v", err)
	}
	return r, &submitted
}

func TestAuthorizeAsksAboutTheDownloadSubresource(t *testing.T) {
	r, submitted := authorizerWith(t, authorizationv1.SubjectAccessReviewStatus{Allowed: true, Reason: "RBAC: allowed by RoleBinding"}, nil)

	id := Identity{Username: "system:serviceaccount:trawl-system:analyst", UID: "uid-1", Groups: []string{"g"}}
	attrs := Attributes{
		Namespace: "trawl-system", Group: "trawl.cloud", Resource: "capturejobs",
		Subresource: "download", Name: "manual-tls", Verb: "get",
	}
	got, err := r.Authorize(t.Context(), id, attrs)
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if !got.Allowed {
		t.Error("allowed = false, want true")
	}

	if len(*submitted) != 1 {
		t.Fatalf("submitted %d reviews, want 1", len(*submitted))
	}
	spec := (*submitted)[0].Spec
	if spec.User != id.Username || spec.UID != id.UID {
		t.Errorf("subject = %s/%s, want %s/%s", spec.User, spec.UID, id.Username, id.UID)
	}
	ra := spec.ResourceAttributes
	if ra == nil {
		t.Fatal("review carried no resource attributes")
	}
	// Asking the wrong question is the failure a status-code assertion cannot
	// see: an SAR on `get capturejobs` without the subresource would be
	// satisfied by ordinary read access to the CRD.
	if ra.Group != "trawl.cloud" || ra.Resource != "capturejobs" || ra.Subresource != "download" ||
		ra.Verb != "get" || ra.Namespace != "trawl-system" || ra.Name != "manual-tls" {
		t.Errorf("resource attributes = %+v", ra)
	}
}

func TestAuthorizeDeniesAndReportsUnavailability(t *testing.T) {
	t.Run("denied", func(t *testing.T) {
		r, _ := authorizerWith(t, authorizationv1.SubjectAccessReviewStatus{Allowed: false, Reason: "no binding"}, nil)
		got, err := r.Authorize(t.Context(), Identity{Username: "viewer"}, Attributes{Verb: "get"})
		if err != nil {
			t.Fatalf("Authorize: %v", err)
		}
		if got.Allowed {
			t.Error("allowed = true, want false")
		}
	})

	// An explicit Denied outranks Allowed. A webhook authorizer can set both.
	t.Run("explicitly denied outranks allowed", func(t *testing.T) {
		r, _ := authorizerWith(t, authorizationv1.SubjectAccessReviewStatus{Allowed: true, Denied: true}, nil)
		got, err := r.Authorize(t.Context(), Identity{Username: "viewer"}, Attributes{Verb: "get"})
		if err != nil {
			t.Fatalf("Authorize: %v", err)
		}
		if got.Allowed {
			t.Error("an explicitly denied subject was allowed")
		}
	})

	// An authorizer that could not decide is not an authorizer that said no.
	t.Run("evaluation error is not a denial", func(t *testing.T) {
		r, _ := authorizerWith(t, authorizationv1.SubjectAccessReviewStatus{
			Allowed:         false,
			EvaluationError: "webhook authorizer unreachable",
		}, nil)
		if _, err := r.Authorize(t.Context(), Identity{Username: "analyst"}, Attributes{Verb: "get"}); err == nil {
			t.Error("an undecidable authorization was reported as a clean denial")
		}
	})

	t.Run("unreachable api server", func(t *testing.T) {
		r, _ := authorizerWith(t, authorizationv1.SubjectAccessReviewStatus{}, apierrors.NewServiceUnavailable("down"))
		if _, err := r.Authorize(t.Context(), Identity{Username: "analyst"}, Attributes{Verb: "get"}); err == nil {
			t.Error("an unreachable API server was reported as a clean denial")
		}
	})
}

func TestNewKubernetesReviewerRequiresAnAudience(t *testing.T) {
	if _, err := NewKubernetesReviewer(fake.NewSimpleClientset(), "  "); err == nil {
		t.Error("an empty audience was accepted; every cluster token would be honoured")
	}
	if _, err := NewKubernetesReviewer(nil, testAudience); err == nil {
		t.Error("a nil client was accepted")
	}
}

// Keeps the unused-import guard honest about the schema import used by reactors.
var _ = schema.GroupVersionResource{}
