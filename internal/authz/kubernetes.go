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
	"errors"
	"slices"
	"strings"

	authenticationv1 "k8s.io/api/authentication/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"trawl.cloud/trawl/internal/sanitize"
)

// KubernetesReviewer implements Reviewer against a cluster's API server.
type KubernetesReviewer struct {
	client kubernetes.Interface

	// audience is the value tokens must be bound to.
	audience string
}

// NewKubernetesReviewer builds a Reviewer that accepts only tokens issued for
// audience.
//
// The audience is required, not optional. A service account's default token is
// bound to the API server itself, so accepting any audience would let a token
// scraped from any pod in the cluster — from a workload that has nothing to do
// with Trawl — be replayed here to fetch packet captures. Requiring a
// Trawl-specific audience means a token has to have been minted deliberately
// for this gateway.
func NewKubernetesReviewer(client kubernetes.Interface, audience string) (*KubernetesReviewer, error) {
	if client == nil {
		return nil, errors.New("authz requires a Kubernetes client")
	}
	if strings.TrimSpace(audience) == "" {
		return nil, errors.New("authz requires a token audience")
	}
	return &KubernetesReviewer{client: client, audience: audience}, nil
}

// Authenticate submits a TokenReview bound to the configured audience.
func (k *KubernetesReviewer) Authenticate(ctx context.Context, token string) (Identity, error) {
	if strings.TrimSpace(token) == "" {
		return Identity{}, ErrUnauthenticated
	}

	review := &authenticationv1.TokenReview{
		Spec: authenticationv1.TokenReviewSpec{
			Token:     token,
			Audiences: []string{k.audience},
		},
	}
	result, err := k.client.AuthenticationV1().TokenReviews().Create(ctx, review, metav1.CreateOptions{})
	if err != nil {
		// A client-go error can echo the request body, and the request body is
		// the caller's token.
		return Identity{}, sanitize.Errorf("submitting a token review: %v", err)
	}

	if !result.Status.Authenticated {
		return Identity{}, ErrUnauthenticated
	}

	// The API server rejects a token that is valid for none of the requested
	// audiences, so this is belt and braces — but it is cheap, and it is the
	// check that keeps working if a future caller passes more than one
	// audience and stops noticing which one matched.
	if len(result.Status.Audiences) > 0 && !slices.Contains(result.Status.Audiences, k.audience) {
		return Identity{}, ErrUnauthenticated
	}

	return Identity{
		Username: result.Status.User.Username,
		UID:      result.Status.User.UID,
		Groups:   slices.Clone(result.Status.User.Groups),
	}, nil
}

// Authorize submits a SubjectAccessReview for id against attrs.
func (k *KubernetesReviewer) Authorize(ctx context.Context, id Identity, attrs Attributes) (Decision, error) {
	review := &authorizationv1.SubjectAccessReview{
		Spec: authorizationv1.SubjectAccessReviewSpec{
			User:   id.Username,
			UID:    id.UID,
			Groups: id.Groups,
			ResourceAttributes: &authorizationv1.ResourceAttributes{
				Namespace:   attrs.Namespace,
				Group:       attrs.Group,
				Resource:    attrs.Resource,
				Subresource: attrs.Subresource,
				Name:        attrs.Name,
				Verb:        attrs.Verb,
			},
		},
	}
	result, err := k.client.AuthorizationV1().SubjectAccessReviews().Create(ctx, review, metav1.CreateOptions{})
	if err != nil {
		return Decision{}, sanitize.Errorf("submitting a subject access review: %v", err)
	}

	// EvaluationError means the authorizer could not decide. Treating it as a
	// denial would silently deny during an authorizer outage; treating it as an
	// allow would be worse. It is neither, so it is an error and the caller
	// fails closed with a retryable status.
	if result.Status.EvaluationError != "" && !result.Status.Allowed {
		return Decision{}, sanitize.Errorf("authorization could not be evaluated: %v", result.Status.EvaluationError)
	}

	return Decision{
		Allowed: result.Status.Allowed && !result.Status.Denied,
		Reason:  sanitize.String(result.Status.Reason),
	}, nil
}
