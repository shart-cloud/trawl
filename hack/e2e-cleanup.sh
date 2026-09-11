#!/usr/bin/env bash
# hack/e2e-cleanup.sh — remove anything a killed acceptance run left behind.
#
# The failure-injection specs restore what they break through t.Cleanup, which
# covers a failing assertion, a panic and a timeout. It does not cover the test
# process being killed outright - an OOM kill, a Ctrl-C that gets escalated, a
# CI runner reclaiming the job - because SIGKILL runs no deferred code.
#
# That matters more here than for an ordinary test, because what is left behind
# is not a stray object but an injected fault: a NetworkPolicy that severs the
# event worker's egress, or a Deployment scaled to zero. An installation can sit
# in that state indefinitely, looking like a component that has failed on its
# own.
#
# This is the one command to run after a killed acceptance run. It is safe to
# run when nothing is wrong.

set -euo pipefail

NAMESPACE="${TRAWL_E2E_NAMESPACE:-trawl-system}"
KUBECTL="${KUBECTL:-kubectl}"

echo "e2e-cleanup: checking ${NAMESPACE} for injected faults"

# 1. A missing allow policy. The trigger-source injection severs the worker's
#    egress by *deleting* its NetworkPolicy, because Kubernetes policy is
#    additive-allow and a deny cannot be injected by adding one. A killed run
#    therefore leaves the worker isolated indefinitely, which looks exactly like
#    an event source that has failed on its own - and it is the one leftover
#    here that silently degrades detection rather than just leaving litter.
for np in trawl-event-worker trawl-controller-manager trawl-artifact-gateway; do
  if ! "${KUBECTL}" get networkpolicy "${np}" -n "${NAMESPACE}" >/dev/null 2>&1; then
    echo "e2e-cleanup: WARNING - NetworkPolicy ${np} is missing from ${NAMESPACE}."
    echo "e2e-cleanup: a killed injection run removes it and the namespace default-deny then"
    echo "e2e-cleanup: severs that component. Restore it with:"
    echo "    bin/kustomize build config/default | \\"
    echo "      ${KUBECTL} apply -f - --prune=false"
  fi
done

# Isolation policies from older runs, which added a deny rather than removing an
# allow. Kept because a cluster may still be carrying one.
for np in $("${KUBECTL}" get networkpolicy -n "${NAMESPACE}" \
    -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' 2>/dev/null | grep '^trawl-e2e-' || true); do
  echo "e2e-cleanup: removing leftover isolation policy ${np}"
  "${KUBECTL}" delete networkpolicy "${np}" -n "${NAMESPACE}" --ignore-not-found
done

# 2. Deployments scaled to zero. Every Trawl Deployment is meant to be running,
#    so a zero replica count in this namespace is either an injected fault or a
#    deliberate act somebody should be told about rather than silently undone -
#    hence the report rather than an automatic scale-up.
zeroed=""
for deploy in $("${KUBECTL}" get deploy -n "${NAMESPACE}" \
    -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' 2>/dev/null || true); do
  replicas="$("${KUBECTL}" get deploy "${deploy}" -n "${NAMESPACE}" -o jsonpath='{.spec.replicas}' 2>/dev/null || echo "")"
  if [ "${replicas}" = "0" ]; then
    zeroed="${zeroed} ${deploy}"
  fi
done
if [ -n "${zeroed}" ]; then
  echo "e2e-cleanup: WARNING - these deployments are scaled to zero:${zeroed}"
  echo "e2e-cleanup: if a killed run did that, scale them back with:"
  for deploy in ${zeroed}; do
    echo "    ${KUBECTL} scale deployment ${deploy} -n ${NAMESPACE} --replicas=<n>"
  done
fi

# 3. Leftover acceptance policies and their scratch namespaces. An armed policy
#    from a dead run evaluates the next run's events and wins its captures,
#    which shows up as a mysterious deduplication failure in an unrelated spec.
for policy in $("${KUBECTL}" get capturepolicies -n "${NAMESPACE}" \
    -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' 2>/dev/null | grep '^acc-' || true); do
  echo "e2e-cleanup: removing leftover acceptance policy ${policy}"
  "${KUBECTL}" delete capturepolicy "${policy}" -n "${NAMESPACE}" --ignore-not-found
done

for ns in $("${KUBECTL}" get namespaces \
    -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' 2>/dev/null | grep '^denied-acc-' || true); do
  echo "e2e-cleanup: removing leftover probe namespace ${ns}"
  "${KUBECTL}" delete namespace "${ns}" --ignore-not-found --wait=false
done

echo "e2e-cleanup: done"
