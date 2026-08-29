#!/usr/bin/env bash
# hack/verify-manifests.sh — reject deployment manifests that grant more than
# Trawl needs (T026, constitution "Privileged workload isolation").
#
# These checks exist because the failure they catch is silent. A wildcard RBAC
# verb, a floating image tag, or a stray hostPath does not break anything at
# install time; it just quietly widens what a compromise reaches. Catching it in
# review depends on someone noticing a single line in generated YAML.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

status=0
fail() {
  echo "manifest-security: $*" >&2
  status=1
}

manifests() {
  find config -name '*.yaml' -type f 2>/dev/null || true
}

# Wildcards in RBAC. The operator's verb list is short and known; a wildcard
# means nobody enumerated it.
if grep -rn --include='*.yaml' -E '^\s*-\s*["'"'"']?\*["'"'"']?\s*$' config/rbac 2>/dev/null | grep -v 'kustomization'; then
  fail "wildcard found in config/rbac (enumerate the verbs and resources instead)"
fi

# Floating image tags. A tag can be repointed after the review that approved it.
for tag in ':latest' ':main' ':master' ':edge' ':dev'; do
  if grep -rn --include='*.yaml' "image:.*${tag}" config 2>/dev/null; then
    fail "floating image tag ${tag} in config/ (use a digest)"
  fi
done

# hostPath. Capture artifacts and analyzer content live in emptyDir or object
# storage; a hostPath writes evidence to a node the operator cannot audit.
if grep -rn --include='*.yaml' 'hostPath' config 2>/dev/null; then
  fail "hostPath volume in config/ (use emptyDir or object storage)"
fi

# Blanket privilege. Capture needs CAP_NET_RAW and CAP_NET_ADMIN, never
# privileged: true (ADR-0004).
if grep -rn --include='*.yaml' -E 'privileged:\s*true' config 2>/dev/null; then
  fail "privileged: true in config/ (grant explicit capabilities instead)"
fi

# Host namespaces on control-plane manifests. Analyzer and capture pods are
# rendered by the operator, not shipped here, so nothing under config/ needs one.
if grep -rn --include='*.yaml' -E '(hostNetwork|hostPID|hostIPC):\s*true' config 2>/dev/null; then
  fail "host namespace requested in config/ (control-plane workloads must not need one)"
fi

# Inline credentials. Secrets come from the cluster's secret boundary.
if grep -rn --include='*.yaml' -iE '(secretAccessKey|accessKeyID|password|bearer)\s*:\s*[A-Za-z0-9+/=]{8,}' config 2>/dev/null; then
  fail "inline credential in config/ (mount a Secret instead)"
fi

# A default-deny NetworkPolicy must exist, or the allowlist policies grant
# nothing and every pod stays fully reachable.
if ! grep -rqs 'podSelector: {}' config/networkpolicy 2>/dev/null; then
  fail "no default-deny NetworkPolicy (podSelector: {}) in config/networkpolicy"
fi

if [[ "${status}" != 0 ]]; then
  echo "manifest-security: FAILED" >&2
  exit 1
fi
echo "manifest-security: no findings."
