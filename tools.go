//go:build tools

// Package tools anchors dependencies that are pinned by the implementation plan
// but not yet imported by production code. Each blank import is removed as the
// corresponding Phase 2/3 package lands:
//
//	cilium/observer      -> internal/events/hubble (T059)
//	minio-go             -> internal/storage       (T018)
//	prometheus/client_golang -> internal/telemetry (T017)
//	grpc                 -> internal/events/hubble (T059)
package main

import (
	_ "github.com/cilium/cilium/api/v1/observer"
	_ "github.com/minio/minio-go/v7"
	_ "github.com/prometheus/client_golang/prometheus"
	_ "google.golang.org/grpc"
)
