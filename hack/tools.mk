# hack/tools.mk — single source of truth for build-tool versions (T003).
#
# Every version here is pinned to an exact tag. `hack/verify-tools.sh` asserts
# that the binaries in $(LOCALBIN) actually report these versions, so a stale or
# hand-installed tool cannot silently change generated output.
#
# Bumping a version here is a reviewable change: regenerate artifacts and run
# `make verify` so generated-artifact drift is caught in the same commit.

KUSTOMIZE_VERSION        ?= v5.8.1
CONTROLLER_TOOLS_VERSION ?= v0.21.0
GOLANGCI_LINT_VERSION    ?= v2.12.2
GOVULNCHECK_VERSION      ?= v1.1.4

# ENVTEST_VERSION tracks the controller-runtime version from go.mod.
# ENVTEST_K8S_VERSION tracks k8s.io/api from go.mod.
# Both are derived rather than pinned so they cannot drift from the module.

# logcheck plugin module built into the custom golangci-lint binary
# (.custom-gcl.yml). Pinned, not `latest`: a floating plugin version can change
# lint results between runs, which the constitution's immutable-supply-chain
# rule forbids.
LOGTOOLS_VERSION ?= v0.10.1
