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

package controller

import (
	"context"
	"fmt"
	"math"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	trawlv1alpha1 "trawl.cloud/trawl/api/v1alpha1"
	"trawl.cloud/trawl/internal/audit"
	"trawl.cloud/trawl/internal/capture"
	"trawl.cloud/trawl/internal/observation"
	"trawl.cloud/trawl/internal/policy"
	"trawl.cloud/trawl/internal/sanitize"
	"trawl.cloud/trawl/internal/status"
	"trawl.cloud/trawl/internal/telemetry"
)

// PolicyOutcome is what the engine did about one observation for one policy.
//
// A closed set, mirroring the decision label in contracts/telemetry.md. Every
// evaluation ends in exactly one of these, including the ones that produce
// nothing: a policy that silently declined and a policy that failed are the
// same from the outside, and separating them is most of what makes an armed
// policy trustworthy.
type PolicyOutcome string

const (
	// OutcomeNotMatched means the event was evaluated and declined.
	OutcomeNotMatched PolicyOutcome = "NotMatched"

	// OutcomeDisarmed means the event would have matched, but the policy is
	// not armed. Nothing was created and nothing was recorded in the ledger.
	OutcomeDisarmed PolicyOutcome = "Disarmed"

	// OutcomeCreated means a CaptureJob was created for this event.
	OutcomeCreated PolicyOutcome = "Created"

	// OutcomeDuplicate means an equivalent capture already existed and this
	// event collapsed onto it.
	OutcomeDuplicate PolicyOutcome = "Duplicate"

	// OutcomeRateLimited means the policy's hourly ceiling refused the
	// capture. It recovers on its own as captures age out of the hour.
	OutcomeRateLimited PolicyOutcome = "RateLimited"

	// OutcomeFailed means a qualifying event produced no capture because
	// something went wrong. FailureReason says what.
	OutcomeFailed PolicyOutcome = "Failed"
)

// TelemetryDecision maps an outcome to the contract's decision label.
func (o PolicyOutcome) TelemetryDecision() string {
	switch o {
	case OutcomeNotMatched:
		return telemetry.PolicyNotMatched
	case OutcomeDisarmed:
		return telemetry.PolicyDisarmed
	case OutcomeCreated:
		return telemetry.PolicyCreated
	case OutcomeDuplicate:
		return telemetry.PolicyDuplicate
	case OutcomeRateLimited:
		return telemetry.PolicyRateLimited
	default:
		return telemetry.PolicyFailed
	}
}

// PolicyResult is one policy's decision about one observation.
//
// It carries the policy identity rather than the policy, so a caller can
// account for a decision without holding a copy of an object that may already
// have changed underneath it.
type PolicyResult struct {
	// Policy names the policy that decided.
	Policy types.NamespacedName

	// PolicyUID and Generation pin which policy, and which version of it.
	PolicyUID  types.UID
	Generation int64

	// TriggerType is the policy's trigger, which is the telemetry dimension
	// decisions are counted under.
	TriggerType trawlv1alpha1.CaptureTriggerType

	// TapUID is the tap bound for this evaluation, empty when it could not be
	// resolved.
	TapUID types.UID

	// Outcome is what happened.
	Outcome PolicyOutcome

	// Reason names why an event did not match. Set only for OutcomeNotMatched.
	Reason policy.NotMatchedReason

	// FailureReason is a status reason from internal/status, set only for
	// OutcomeFailed, so the caller can raise a condition without re-deriving
	// the cause from an error string.
	FailureReason string

	// CaptureName is the capture created or collapsed onto.
	CaptureName string

	// TriggerTime is when the worker saw the qualifying event. Set for every
	// outcome that followed a match, including the suppressed ones - a policy
	// that is matching and suppressing is working, and one that is not
	// matching at all is a different problem.
	TriggerTime time.Time

	// Err carries sanitized detail for OutcomeFailed, and for the case where a
	// capture was created but its outcome could not be recorded.
	Err error
}

// PolicyEngine evaluates observations against the armed policies and requests
// captures.
//
// One engine serves every trigger source. It holds no per-event state beyond
// the rolling threshold windows, and everything else it needs - the hourly
// count, whether an equivalent capture already exists - is read back from the
// CaptureJobs themselves, so a restart or a leader handoff resumes with the
// same answers rather than a clean slate it would blow straight through.
type PolicyEngine struct {
	// Client reads policies, taps and jobs, and creates captures. It is
	// expected to be cache-backed: an event stream evaluates every armed
	// policy per record, and uncached reads would put that load on the API
	// server.
	Client client.Client

	// Audit commits the intent and the outcome of every capture this engine
	// creates. Required: without it a capture would exist that the ledger
	// never authorized (FR-036).
	Audit audit.Committer

	// Actor is the worker's own workload identity. The policy behind an
	// automatic action travels as InitiatedBy rather than being impersonated
	// here.
	Actor audit.Actor

	// Namespace is the configured Trawl namespace. Policies elsewhere are not
	// evaluated; the admission gate already refuses them (FR-001).
	Namespace string

	// Metrics is optional.
	Metrics *telemetry.Metrics

	// Now is time.Now unless a test replaced it.
	Now func() time.Time

	// mu guards windows. The windows themselves are touched only by the
	// goroutine reading the source their policy's trigger type belongs to, so
	// a policy's events still arrive in sequence.
	mu      sync.Mutex
	windows map[types.UID]*policyWindow
}

// policyWindow is one policy's rolling threshold state, pinned to the threshold
// that configured it.
//
// Pinned because an operator who widens a window expects the new one to apply,
// and counts gathered under the old configuration would let a policy fire on a
// threshold nobody currently has written down.
//
// Keyed on the threshold rather than on the spec generation, which is what it
// used to be. A generation moves for any edit at all - arming the policy,
// changing its retention, raising its hourly limit - and each of those would
// have discarded a rolling window that might have been one flow from firing,
// with nothing recording that it happened. The threshold is the only part of
// the spec this state depends on.
type policyWindow struct {
	// threshold is the configuration this window was built for, rendered so two
	// generations carrying the same threshold compare equal.
	threshold string
	window    *policy.ThresholdWindow
}

// Evaluate offers one observation to every policy armed against its source.
//
// The error is reserved for "no policy could be evaluated at all" - the caller
// cannot tell that from an empty result, and the two mean opposite things: one
// is quiet traffic and the other is monitoring that has stopped.
func (e *PolicyEngine) Evaluate(ctx context.Context, obs *observation.Observation) ([]PolicyResult, error) {
	triggerType, ok := triggerTypeFor(obs)
	if !ok {
		// A record no trigger type is defined against - a Zeek connection, a
		// DNS answer. The worker reads one stream carrying every observation
		// type, so this is the ordinary case rather than an error.
		return nil, nil
	}

	var policies trawlv1alpha1.CapturePolicyList
	if err := e.Client.List(ctx, &policies, client.InNamespace(e.Namespace)); err != nil {
		return nil, sanitize.Errorf("listing capture policies: %v", err)
	}
	e.pruneWindows(policies.Items)

	var results []PolicyResult
	for i := range policies.Items {
		p := &policies.Items[i]
		if p.Spec.Trigger.Type != triggerType {
			continue
		}
		// A policy being deleted still exists for a while. Evaluating it would
		// create a capture attributed to a rule that is on its way out.
		if !p.DeletionTimestamp.IsZero() {
			continue
		}
		if res, ok := e.evaluateOne(ctx, p, obs); ok {
			e.count(res)
			results = append(results, res)
		}
	}
	return results, nil
}

// evaluateOne runs one policy against one observation.
//
// The second return says whether there is anything to report. A disarmed policy
// that did not match reports nothing: its counters would otherwise climb with
// ordinary traffic and say nothing about the rule.
func (e *PolicyEngine) evaluateOne(
	ctx context.Context, p *trawlv1alpha1.CapturePolicy, obs *observation.Observation,
) (PolicyResult, bool) {
	res := PolicyResult{
		Policy:      types.NamespacedName{Namespace: p.Namespace, Name: p.Name},
		PolicyUID:   p.UID,
		Generation:  p.Generation,
		TriggerType: p.Spec.Trigger.Type,
	}

	// Attribution first, and by name, before any read. An alert from another
	// tap is not this policy's traffic, and capturing on this policy's tap in
	// response would collect an unrelated conversation.
	if p.Spec.Trigger.Type == trawlv1alpha1.CaptureTriggerSuricataAlert &&
		!observedByTap(obs, p.Namespace, p.Spec.TapRef.Name) {
		return e.notMatched(res, p, policy.ReasonDifferentTap)
	}

	decision, count, err := e.match(p, obs)
	if err != nil {
		return e.failed(res, status.ReasonInvalidSpec, err), true
	}
	if !decision.Matched {
		return e.notMatched(res, p, decision.Reason)
	}

	res.TriggerTime = obs.ObservedAt
	if !p.Spec.Armed {
		// Evaluated but not armed. Nothing is created and nothing reaches the
		// ledger; the decision exists so an operator can see what a rule would
		// have collected before switching it on.
		res.Outcome = OutcomeDisarmed
		return res, true
	}

	tap, reason, err := resolveTap(ctx, e.Client, p)
	if err != nil {
		return e.failed(res, reason, err), true
	}
	res.TapUID = tap.UID

	// The strict half of attribution. A tap deleted and recreated keeps its
	// name and takes a new UID, so an observation still in flight from the old
	// one names a tap that no longer exists.
	if p.Spec.Trigger.Type == trawlv1alpha1.CaptureTriggerSuricataAlert &&
		obs.Tap.UID != string(tap.UID) {
		return e.notMatched(res, p, policy.ReasonDifferentTap)
	}

	key := policy.DeduplicationKey(
		string(tap.UID), obs.Flow, deduplicationTime(obs), p.Spec.RateLimit.Cooldown.Duration,
	)
	name := policy.CaptureJobName(key)

	// The get half of create-or-get. Cheap, and it is what collapses the
	// ordinary repeat - the same conversation alerting again inside the
	// cooldown, or a second policy wanting the same packets.
	var existing trawlv1alpha1.CaptureJob
	err = e.Client.Get(ctx, types.NamespacedName{Namespace: p.Namespace, Name: name}, &existing)
	switch {
	case err == nil:
		res.Outcome = OutcomeDuplicate
		res.CaptureName = name
		return res, true
	case !apierrors.IsNotFound(err):
		return e.failed(res, status.ReasonDependencyUnavailable,
			sanitize.Errorf("reading the existing capture: %v", err)), true
	}

	usage, err := e.usage(ctx, p)
	if err != nil {
		return e.failed(res, status.ReasonDependencyUnavailable, err), true
	}
	if policy.CheckLimits(usage, p.Spec.RateLimit) == policy.LimitRateLimited {
		res.Outcome = OutcomeRateLimited
		return res, true
	}

	job, err := e.buildJob(p, tap, obs, key, name, count)
	if err != nil {
		return e.failed(res, status.ReasonFilterInvalid, err), true
	}

	// Intent before work (FR-036). A capture the ledger does not know about is
	// evidence with no provenance, so this fails closed: no record, no capture.
	if err := e.commit(ctx, p, job, audit.DecisionAllowed, "request", ""); err != nil {
		return e.failed(res, status.ReasonAuditUnavailable, err), true
	}

	if err := e.Client.Create(ctx, job); err != nil {
		if apierrors.IsAlreadyExists(err) {
			// Another worker proposed the same name first. That is the
			// deduplication working, not a failure - both wanted one capture
			// of one conversation and there is one.
			//
			// The outcome record still has to be written. An intent was
			// committed above, and an intent with no outcome is the shape an
			// operator reads as "a capture was authorized and then went
			// missing" - the ledger would report this race as the one thing it
			// is not.
			res.Outcome = OutcomeDuplicate
			res.CaptureName = name
			// The outcome record is still written, and written identically to
			// the winner's. For two workers racing on one policy that means it
			// converges onto the winner's record rather than doubling it. For
			// two different policies racing it is the only outcome record this
			// policy's intent will ever have - and an intent with no outcome is
			// the shape an operator reads as "a capture was authorized and then
			// went missing", which is the one thing this race is not.
			if err := e.commit(ctx, p, job, audit.DecisionSucceeded, "outcome", ""); err != nil {
				res.Err = err
			}
			return res, true
		}
		failure := sanitize.Errorf("creating the capture: %v", err)
		_ = e.commit(ctx, p, job, audit.DecisionFailed, "outcome", failure.Error())
		return e.failed(res, status.ReasonDependencyUnavailable, failure), true
	}

	res.Outcome = OutcomeCreated
	res.CaptureName = name
	// The outcome half of the pair. The capture exists either way, so a failure
	// here is reported rather than rolled back - unmaking it would destroy
	// evidence to tidy up a ledger gap the intent record already covers.
	if err := e.commit(ctx, p, job, audit.DecisionSucceeded, "outcome", ""); err != nil {
		res.Err = err
	}
	return res, true
}

// deduplicationTime selects the immutable time that identifies one trigger
// occurrence before the pure key function buckets it.
//
// Hubble normalizes a fresh ObservedAt on every delivery, including deliberate
// reconnect replay, so its producer-stamped EventTime is the stable occurrence
// time. Loki replays the whole serialized Suricata observation and therefore
// preserves its original ObservedAt; retaining that choice avoids changing the
// established identity of alerts already represented by CaptureJobs.
func deduplicationTime(obs *observation.Observation) time.Time {
	if obs.Source.Kind == observation.SourceHubble {
		return obs.EventTime
	}
	return obs.ObservedAt
}

// notMatched finishes a declined evaluation, or reports nothing at all when the
// policy is not armed.
func (e *PolicyEngine) notMatched(res PolicyResult, p *trawlv1alpha1.CapturePolicy, reason policy.NotMatchedReason) (PolicyResult, bool) {
	if !p.Spec.Armed {
		return PolicyResult{}, false
	}
	res.Outcome = OutcomeNotMatched
	res.Reason = reason
	return res, true
}

func (e *PolicyEngine) failed(res PolicyResult, reason string, err error) PolicyResult {
	res.Outcome = OutcomeFailed
	res.FailureReason = reason
	res.Err = err
	return res
}

// match runs the trigger's matcher, and the threshold window behind it.
func (e *PolicyEngine) match(
	p *trawlv1alpha1.CapturePolicy, obs *observation.Observation,
) (policy.Decision, int32, error) {
	switch p.Spec.Trigger.Type {
	case trawlv1alpha1.CaptureTriggerSuricataAlert:
		t := p.Spec.Trigger.SuricataAlert
		if t == nil {
			// The union's CEL rules make this unreachable through the API, but
			// an object restored into etcd never passed through them. A nil
			// dereference here would take the worker down on one bad policy.
			return policy.Decision{}, 0, fmt.Errorf("trigger type SuricataAlert carries no suricataAlert body")
		}
		return policy.MatchSuricata(*t, obs), 1, nil

	case trawlv1alpha1.CaptureTriggerHubbleDrop:
		t := p.Spec.Trigger.HubbleDrop
		if t == nil {
			return policy.Decision{}, 0, fmt.Errorf("trigger type HubbleDrop carries no hubbleDrop body")
		}
		decision := policy.MatchHubbleDrop(*t, obs)
		if !decision.Matched || t.Threshold == nil {
			return decision, 1, nil
		}
		// Only qualifying flows are offered to the window. Counting the
		// declined ones would make the threshold a measure of cluster traffic
		// rather than of the denials the operator armed against.
		count := e.window(p).Observe(obs)
		if !count.Reached {
			return policy.Decision{Reason: policy.ReasonBelowThreshold}, snapshotCount(count.Count), nil
		}
		return policy.Decision{Matched: true}, snapshotCount(count.Count), nil
	}
	return policy.Decision{}, 0, fmt.Errorf("unsupported trigger type %q", sanitize.String(string(p.Spec.Trigger.Type)))
}

// snapshotCount narrows a window count to the snapshot's int32 field.
//
// The same reasoning as the signature revision in policy.SuricataSnapshot: a
// plain conversion of an implausible value wraps negative, the API bounds the
// field to a positive integer, and the whole CaptureJob is rejected over a
// field that only describes it. Losing precision on an absurd count costs a
// detail; losing the job costs the packets.
func snapshotCount(n int) int32 {
	if n < 0 {
		return 0
	}
	if n > math.MaxInt32 {
		return math.MaxInt32
	}
	return int32(n)
}

// window returns the policy's rolling threshold window, rebuilding it when the
// threshold that configured it has changed.
func (e *PolicyEngine) window(p *trawlv1alpha1.CapturePolicy) *policy.ThresholdWindow {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.windows == nil {
		e.windows = map[types.UID]*policyWindow{}
	}
	t := p.Spec.Trigger.HubbleDrop.Threshold
	threshold := fmt.Sprintf("%d/%s", t.Count, t.Window.Duration)

	held, ok := e.windows[p.UID]
	if !ok || held.threshold != threshold {
		held = &policyWindow{
			threshold: threshold,
			window:    policy.NewThresholdWindow(int(t.Count), t.Window.Duration),
		}
		e.windows[p.UID] = held
	}
	return held.window
}

// pruneWindows drops the state of policies that no longer exist.
//
// Without it the map keeps one window per policy ever seen, which on a cluster
// where policies are created and deleted routinely is a leak with a slow fuse -
// the same reason the windows themselves expire their events.
func (e *PolicyEngine) pruneWindows(policies []trawlv1alpha1.CapturePolicy) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.windows) == 0 {
		return
	}
	live := make(map[types.UID]struct{}, len(policies))
	for i := range policies {
		live[policies[i].UID] = struct{}{}
	}
	for uid := range e.windows {
		if _, ok := live[uid]; !ok {
			delete(e.windows, uid)
		}
	}
}

// resolveTap binds the policy's tap and confirms it is observing.
//
// A free function because the status tracker asks the same question on its own
// schedule: the engine asks it per matching event, and the tracker asks it for
// every policy whether or not anything matched.
//
// A tap that is missing, going away, or not accepting its own spec is a
// policy-level problem rather than a per-capture one: creating a capture
// against it would produce a job the controller can only fail. The reason
// returned is a status reason, so the caller can say which on the policy.
func resolveTap(
	ctx context.Context, c client.Client, p *trawlv1alpha1.CapturePolicy,
) (*trawlv1alpha1.NetworkTap, string, error) {
	var tap trawlv1alpha1.NetworkTap
	err := c.Get(ctx, types.NamespacedName{Namespace: p.Namespace, Name: p.Spec.TapRef.Name}, &tap)
	switch {
	case apierrors.IsNotFound(err):
		return nil, status.ReasonTapNotFound,
			fmt.Errorf("tap %q does not exist", sanitize.String(p.Spec.TapRef.Name))
	case err != nil:
		return nil, status.ReasonDependencyUnavailable, sanitize.Errorf("reading the tap: %v", err)
	}
	if !tap.DeletionTimestamp.IsZero() {
		return nil, status.ReasonTapNotActive,
			fmt.Errorf("tap %q is being deleted", sanitize.String(tap.Name))
	}
	// The same bar the capture controller uses, and the tap's own status uses,
	// for calling a tap usable: it has accepted its current spec and is
	// observing, even if only partially.
	observing := tap.Status.Phase == trawlv1alpha1.TapPhaseActive ||
		tap.Status.Phase == trawlv1alpha1.TapPhaseDegraded
	if !observing || !status.IsTrue(tap.Status.Conditions, status.TypeAccepted, tap.Generation) {
		return nil, status.ReasonTapNotActive,
			fmt.Errorf("tap %q is not observing", sanitize.String(tap.Name))
	}
	return &tap, "", nil
}

// usage summarizes what this policy's own captures say about its recent
// activity.
func (e *PolicyEngine) usage(ctx context.Context, p *trawlv1alpha1.CapturePolicy) (policy.Usage, error) {
	var jobs trawlv1alpha1.CaptureJobList
	if err := e.Client.List(ctx, &jobs, client.InNamespace(p.Namespace)); err != nil {
		return policy.Usage{}, sanitize.Errorf("listing captures: %v", err)
	}
	return policy.UsageFrom(jobs.Items, p.UID, e.now()), nil
}

// buildJob assembles the CaptureJob a matched policy is asking for.
func (e *PolicyEngine) buildJob(
	p *trawlv1alpha1.CapturePolicy,
	tap *trawlv1alpha1.NetworkTap,
	obs *observation.Observation,
	key, name string,
	count int32,
) (*trawlv1alpha1.CaptureJob, error) {
	snapshot, err := e.snapshot(p, obs, count)
	if err != nil {
		return nil, err
	}

	filter := ""
	if p.Spec.Capture.FilterTemplate != "" {
		// An event that cannot supply the placeholders is not a reason to fall
		// back to an unfiltered capture. That would collect every conversation
		// on the interface in response to one alert about one of them.
		filter, err = policy.RenderFilter(p.Spec.Capture.FilterTemplate, obs)
		if err != nil {
			return nil, err
		}
	}

	return &trawlv1alpha1.CaptureJob{
		// No owner reference, deliberately. A capture is evidence, and an
		// owner reference would have the API server delete it when the policy
		// that collected it is deleted. The policy reference below records the
		// relationship without handing it the object's lifetime.
		ObjectMeta: metav1.ObjectMeta{Namespace: p.Namespace, Name: name},
		Spec: trawlv1alpha1.CaptureJobSpec{
			RequestType: trawlv1alpha1.CaptureRequestPolicy,
			TapRef:      corev1.LocalObjectReference{Name: tap.Name},
			// Empty when no target was eligible. The job is still created, so
			// the failure is visible on an execution rather than only in the
			// policy's counters (FR-034).
			TargetNode:       e.eligibleTarget(tap, obs.Target.Node),
			Filter:           filter,
			Duration:         p.Spec.Capture.Duration,
			Snaplen:          p.Spec.Capture.Snaplen,
			MaxSize:          p.Spec.Capture.MaxSize,
			Retention:        p.Spec.Retention,
			DeduplicationKey: key,
			PolicyRef: &trawlv1alpha1.ImmutablePolicyReference{
				Name:       p.Name,
				UID:        p.UID,
				Generation: p.Generation,
			},
			Trigger: snapshot,
		},
	}, nil
}

// snapshot copies the triggering event into the job's immutable context.
func (e *PolicyEngine) snapshot(
	p *trawlv1alpha1.CapturePolicy, obs *observation.Observation, count int32,
) (*trawlv1alpha1.TriggerSnapshot, error) {
	fingerprint := policy.EventFingerprint(obs)
	if p.Spec.Trigger.Type == trawlv1alpha1.CaptureTriggerSuricataAlert {
		return policy.SuricataSnapshot(obs, fingerprint)
	}
	return policy.HubbleSnapshot(obs, fingerprint, count)
}

// eligibleTarget returns the node to capture on, or empty when none is.
//
// The bar is the node that observed the traffic, reported by a sensor that is
// still reporting. Sending a capture to a node whose sensor is gone would
// produce a job that waits and fails; sending it anywhere else would capture
// traffic that has nothing to do with the event.
//
// The comparison is exact, and deliberately so. Depending on the Cilium version
// and its cluster configuration, Hubble can report the observing node as
// "<cluster>/<node>" rather than "<node>" - this cluster reports it bare. It is
// tempting to strip the qualifier, and that would be wrong: under ClusterMesh
// the relay serves flows from peer clusters, node names repeat across them, and
// a stripped "prod-eu/worker-1" would match a healthy local target called
// "worker-1". The capture would then collect the local node's unrelated traffic
// and file it as evidence for a flow that happened in another cluster.
//
// Failing to resolve a target is loud: the job is created without one and the
// capture controller fails it naming the node. Capturing the wrong node's
// packets is silent, and it is silent in the direction that matters - it
// produces evidence rather than withholding it. Stripping the qualifier safely
// needs to know which cluster is ours, which nothing here does yet.
func (e *PolicyEngine) eligibleTarget(tap *trawlv1alpha1.NetworkTap, node string) string {
	if node == "" {
		return ""
	}
	now := e.now()
	for i := range tap.Status.Targets {
		t := &tap.Status.Targets[i]
		if t.NodeName == node && now.Sub(t.HeartbeatTime.Time) <= capture.StaleHeartbeat {
			return node
		}
	}
	return ""
}

// commit writes one audit record for a policy-created capture.
//
// The stable key covers the deduplication key, the step, the decision, and the
// policy. Each part earns its place:
//
//   - The deduplication key is what two workers racing on one event agree on
//     without having spoken, so their records converge instead of doubling.
//   - The policy, because two policies can want the same capture. Each one's
//     request is its own act, and collapsing them into one identity would make
//     the second one's record conflict with the first.
//   - The decision, for the same reason StableKeyForAdmission carries it: an
//     intent and its outcome are separate records for one request, and so are a
//     failed outcome and a succeeded one. Without it a worker whose create
//     failed and a worker whose create succeeded write different content under
//     one identity, and the sink reports the disagreement rather than the two
//     outcomes.
//
// What the key must not include is anything that varies between two workers
// performing the same act. A stable key is an identity claim, and the sink
// refuses a second claim on one identity with different content - so the
// message on the race path below is the same empty string the winner writes,
// deliberately, rather than a description of which side of the race this was.
func (e *PolicyEngine) commit(
	ctx context.Context,
	p *trawlv1alpha1.CapturePolicy,
	job *trawlv1alpha1.CaptureJob,
	decision, step, message string,
) error {
	rec := audit.Record{
		SchemaVersion: audit.SchemaVersion,
		RecordedAt:    e.now(),
		Action:        audit.ActionCaptureJobPolicyCreate,
		Decision:      decision,
		Message:       message,
		Actor:         e.Actor,
		// The policy is named rather than impersonated: the act was the
		// worker's, on the policy's behalf.
		InitiatedBy: p.Namespace + "/" + p.Name,
		Resource: audit.Resource{
			Group:     trawlv1alpha1.GroupVersion.Group,
			Kind:      "CaptureJob",
			Namespace: job.Namespace,
			Name:      job.Name,
		},
		StableKey: audit.StableKeyForAutomatic(
			audit.ActionCaptureJobPolicyCreate, job.Spec.DeduplicationKey,
			step+":"+decision+":"+string(p.UID)),
	}

	_, err := e.Audit.Commit(ctx, rec)
	if err != nil {
		return sanitize.Errorf("committing the capture audit record: %v", err)
	}
	return nil
}

// count records the decision against the trigger type it was made under.
func (e *PolicyEngine) count(res PolicyResult) {
	if e.Metrics == nil {
		return
	}
	e.Metrics.PolicyDecisionsTotal.
		WithLabelValues(triggerTypeLabel(res.TriggerType), res.Outcome.TelemetryDecision()).Inc()
}

func (e *PolicyEngine) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

// triggerTypeFor maps an observation's source to the trigger type armed against
// it.
func triggerTypeFor(obs *observation.Observation) (trawlv1alpha1.CaptureTriggerType, bool) {
	switch {
	case obs.Details.Signature != nil && obs.Source.Kind == observation.SourceSuricata:
		return trawlv1alpha1.CaptureTriggerSuricataAlert, true
	case obs.Details.ClusterFlow != nil && obs.Source.Kind == observation.SourceHubble:
		return trawlv1alpha1.CaptureTriggerHubbleDrop, true
	}
	return "", false
}

// Trigger-type metric dimensions. Low cardinality by construction: no policy
// or rule identifier ever becomes a label (contracts/telemetry.md).
const (
	triggerLabelSuricata = "suricata"
	triggerLabelHubble   = "hubble"
)

// triggerTypeLabel is the low-cardinality metric dimension for a trigger type.
func triggerTypeLabel(t trawlv1alpha1.CaptureTriggerType) string {
	if t == trawlv1alpha1.CaptureTriggerHubbleDrop {
		return triggerLabelHubble
	}
	return triggerLabelSuricata
}

// observedByTap says whether this record came from the named tap.
func observedByTap(obs *observation.Observation, namespace, name string) bool {
	return obs.Tap != nil && obs.Tap.Namespace == namespace && obs.Tap.Name == name
}
