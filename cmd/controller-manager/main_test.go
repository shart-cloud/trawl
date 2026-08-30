package main

import (
	"testing"

	"k8s.io/apimachinery/pkg/runtime"

	trawlv1alpha1 "trawl.cloud/trawl/api/v1alpha1"
)

// The manager builds a client for NetworkTap, so the scheme has to recognize
// it. It did not: the scaffold registered client-go's types alone, and because
// nothing referenced the Trawl group until the controller and the webhook were
// registered, the gap only appeared as a startup failure in a deployed pod.
func TestSchemeRecognizesNetworkTap(t *testing.T) {
	s := runtime.NewScheme()
	registerSchemes(s)

	if !s.Recognizes(trawlv1alpha1.GroupVersion.WithKind("NetworkTap")) {
		t.Fatalf("the manager scheme does not recognize NetworkTap; the controller and webhook cannot register against it")
	}
}
