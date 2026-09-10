#!/usr/bin/env bash
# hack/undeploy-manifests.sh — render the manifests `make undeploy` may delete.
#
# This exists to remove exactly one thing from the rendered install: the
# CustomResourceDefinitions.
#
# Deleting a CRD deletes every object of that kind. Piping the whole of
# config/default into `kubectl delete` therefore does not uninstall the
# operator, it uninstalls the operator *and every capture record the
# installation ever made* — the trigger snapshot that says why a capture was
# taken, the retention deadline, and the artifact key that says where the
# packets are. The pcap survives in the bucket with nothing left in the cluster
# that knows it exists.
#
# Removing the CRDs stays possible and stays one command: `make uninstall`.
# It is just no longer a side effect of removing the workloads.
#
# Asserted by TestUndeployingDoesNotTakeTheCustomResourceDefinitionsWithIt.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KUSTOMIZE="${KUSTOMIZE:-${REPO_ROOT}/bin/kustomize}"

if [ ! -x "${KUSTOMIZE}" ]; then
  echo "undeploy-manifests: ${KUSTOMIZE} not found; run \`make kustomize\`" >&2
  exit 1
fi

# Filtered with kubectl rather than by editing text: a `kind: CustomResourceDefinition`
# string match would also strike the RBAC rules that *name* the resource, and
# leaving those behind is the opposite of the intended effect.
"${KUSTOMIZE}" build "${REPO_ROOT}/config/default" |
  "${KUSTOMIZE}" cfg grep --annotate=false --invert-match 'kind=CustomResourceDefinition'
