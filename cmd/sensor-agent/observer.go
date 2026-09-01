package main

import (
	"time"

	trawlv1alpha1 "trawl.cloud/trawl/api/v1alpha1"
	"trawl.cloud/trawl/internal/content"
	"trawl.cloud/trawl/internal/observation"
	"trawl.cloud/trawl/internal/sensor"
)

// analyzerObserver reports one analyzer's observed state to the status
// reporter.
//
// Zeek is tailed as one file per protocol, so an analyzer is a set of tailers
// rather than one: its counters are their sum and its last record is the most
// recent of them. Reporting per-file would describe the reader's plumbing
// rather than the analyzer an operator asked for.
type analyzerObserver struct {
	name       trawlv1alpha1.AnalyzerName
	version    observation.VersionSource
	contentDir string
	tailers    []*sensor.Tailer
}

func (o *analyzerObserver) Name() trawlv1alpha1.AnalyzerName { return o.name }

// Version is resolved on each report rather than held as a string, because the
// analyzer publishes it after the sensor starts; see versionFile.
func (o *analyzerObserver) Version() string { return o.version.Resolve() }

// Healthy reports observed liveness rather than desired state.
//
// A tailer that has accepted nothing is not evidence of ill health: an
// interface can legitimately be quiet, and claiming a fault for silence would
// make the status say something the sensor cannot know. Malformed records are
// different - those are records that arrived and could not be used.
func (o *analyzerObserver) Healthy() (bool, string) {
	c := o.Counters()
	if c.Accepted == 0 && c.Malformed > 0 {
		return false, "every record read was rejected"
	}
	return true, ""
}

func (o *analyzerObserver) LastRecord() (time.Time, bool) {
	var latest time.Time
	var found bool
	for _, t := range o.tailers {
		if ts, ok := t.LastRecord(); ok && ts.After(latest) {
			latest, found = ts, true
		}
	}
	return latest, found
}

func (o *analyzerObserver) Counters() sensor.Counters {
	var total sensor.Counters
	for _, t := range o.tailers {
		c := t.Counters()
		total.Accepted += c.Accepted
		total.Unsupported += c.Unsupported
		total.Malformed += c.Malformed
	}
	return total
}

// ContentStatus reports the detection content this analyzer loaded.
//
// An unreadable status file reports empty content rather than failing: not
// knowing which rules are loaded is worth surfacing, and it is not a reason to
// stop reporting everything else about the analyzer.
func (o *analyzerObserver) ContentStatus() content.Status {
	st, err := content.ReadStatus(o.contentDir)
	if err != nil {
		return content.Status{}
	}
	return st
}
