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
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	flowpb "github.com/cilium/cilium/api/v1/flow"
)

var (
	errNilFlow     = errors.New("hubble flow is nil")
	errNoTimestamp = errors.New("hubble flow has no timestamp")
)

// idLen is the hex length of a record ID.
const idLen = 32

// flowID derives a stable identifier for a Hubble flow.
//
// It is content-derived because the stream is replayed after a reconnect: the
// worker deliberately re-reads around its watermark rather than risk a gap, so
// the same flow arrives more than once and must be recognisable as the same
// record rather than counted twice.
func flowID(f *flowpb.Flow, eventTime time.Time) string {
	h := sha256.New()

	ip := f.GetIP()
	parts := []string{
		f.GetNodeName(),
		ip.GetSource(),
		ip.GetDestination(),
		f.GetVerdict().String(),
		f.GetTraceObservationPoint().String(),
		protocolOf(f),
	}
	for _, p := range parts {
		// Length-prefixed so field boundaries cannot be forged by content.
		_, _ = fmt.Fprintf(h, "%d:%s", len(p), p)
	}
	if p := sourcePort(f); p != nil {
		_, _ = fmt.Fprintf(h, "|sp=%d", *p)
	}
	if p := destinationPort(f); p != nil {
		_, _ = fmt.Fprintf(h, "|dp=%d", *p)
	}
	_, _ = fmt.Fprintf(h, "|%d", eventTime.UnixNano())

	return hex.EncodeToString(h.Sum(nil))[:idLen]
}
