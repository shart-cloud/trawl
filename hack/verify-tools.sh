#!/usr/bin/env bash
# hack/verify-tools.sh — assert that locally installed build tools match the
# versions pinned in hack/tools.mk (T003).
#
# Generated CRDs, RBAC, and install manifests are contract artifacts. A tool at
# an unexpected version can silently change that output, so CI runs this before
# any generation or drift check.
#
# Usage: hack/verify-tools.sh [--install]
#   --install  install any missing or mismatched tool at its pinned version

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOCALBIN="${LOCALBIN:-${REPO_ROOT}/bin}"
INSTALL=0
[[ "${1:-}" == "--install" ]] && INSTALL=1

# Read a pinned version out of hack/tools.mk so this script and the Makefile
# cannot disagree.
pinned() {
  local var="$1" val
  val="$(sed -n "s/^${var}[[:space:]]*?\?=[[:space:]]*\(.*\)$/\1/p" "${REPO_ROOT}/hack/tools.mk" | tr -d '[:space:]')"
  if [[ -z "${val}" ]]; then
    echo "verify-tools: ${var} is not pinned in hack/tools.mk" >&2
    return 1
  fi
  printf '%s' "${val}"
}

KUSTOMIZE_VERSION="$(pinned KUSTOMIZE_VERSION)"
CONTROLLER_TOOLS_VERSION="$(pinned CONTROLLER_TOOLS_VERSION)"
GOLANGCI_LINT_VERSION="$(pinned GOLANGCI_LINT_VERSION)"
GOVULNCHECK_VERSION="$(pinned GOVULNCHECK_VERSION)"

# Go itself is pinned by the `go` directive in go.mod; GOTOOLCHAIN=auto fetches
# the exact toolchain, so a mismatch here means the directive was edited.
GO_PINNED="$(sed -n 's/^go \([0-9.]*\)$/\1/p' "${REPO_ROOT}/go.mod")"

failed=0

report() {
  local name="$1" want="$2" got="$3"
  if [[ "${got}" == "${want}" ]]; then
    printf '  %-16s %-12s ok\n' "${name}" "${got}"
  else
    printf '  %-16s %-12s MISMATCH (want %s)\n' "${name}" "${got:-missing}" "${want}"
    failed=1
  fi
}

install_tool() {
  local bin="$1" pkg="$2" ver="$3"
  echo "  installing ${bin}@${ver}"
  GOBIN="${LOCALBIN}" go install "${pkg}@${ver}"
}

mkdir -p "${LOCALBIN}"

# controller-gen prints e.g. "Version: v0.21.0"
cg_ver=""
[[ -x "${LOCALBIN}/controller-gen" ]] && cg_ver="$("${LOCALBIN}/controller-gen" --version 2>/dev/null | awk '{print $2}')"
if [[ "${cg_ver}" != "${CONTROLLER_TOOLS_VERSION}" && "${INSTALL}" == 1 ]]; then
  install_tool controller-gen sigs.k8s.io/controller-tools/cmd/controller-gen "${CONTROLLER_TOOLS_VERSION}"
  cg_ver="$("${LOCALBIN}/controller-gen" --version 2>/dev/null | awk '{print $2}')"
fi

# kustomize prints either "v5.8.1" or "{kustomize/v5.8.1 ...}" depending on build.
kz_ver=""
[[ -x "${LOCALBIN}/kustomize" ]] && kz_ver="$("${LOCALBIN}/kustomize" version 2>/dev/null | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' | head -1)"
if [[ "${kz_ver}" != "${KUSTOMIZE_VERSION}" && "${INSTALL}" == 1 ]]; then
  install_tool kustomize sigs.k8s.io/kustomize/kustomize/v5 "${KUSTOMIZE_VERSION}"
  kz_ver="$("${LOCALBIN}/kustomize" version 2>/dev/null | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' | head -1)"
fi

# golangci-lint prints "golangci-lint has version v2.12.2 built with ...".
# When .custom-gcl.yml is present the binary is a plugin build and reports
# "v2.12.2-custom-gcl-<hash>"; the base version must still match the pin.
golangci_version() {
  [[ -x "${LOCALBIN}/golangci-lint" ]] || return 0
  "${LOCALBIN}/golangci-lint" version 2>/dev/null |
    grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' | head -1
}
install_golangci() {
  if [[ -f "${REPO_ROOT}/.custom-gcl.yml" ]]; then
    # Plugin build: the logcheck module is compiled in, so `go install` of the
    # upstream binary would silently drop a linter the config requires.
    echo "  building custom golangci-lint (plugins from .custom-gcl.yml)"
    ( cd "${REPO_ROOT}" && make golangci-lint >/dev/null )
  else
    install_tool golangci-lint github.com/golangci/golangci-lint/v2/cmd/golangci-lint "${GOLANGCI_LINT_VERSION}"
  fi
}
gl_ver="$(golangci_version)"
if [[ "${gl_ver}" != "${GOLANGCI_LINT_VERSION}" && "${INSTALL}" == 1 ]]; then
  install_golangci
  gl_ver="$(golangci_version)"
fi

# A plugin build must actually carry the plugins, or lint silently under-checks.
if [[ -f "${REPO_ROOT}/.custom-gcl.yml" && -x "${LOCALBIN}/golangci-lint" ]]; then
  if ! "${LOCALBIN}/golangci-lint" version 2>/dev/null | grep -q 'custom-gcl'; then
    echo "  golangci-lint    is not a plugin build, but .custom-gcl.yml requires one" >&2
    failed=1
  fi
fi

# govulncheck has no --version flag; read the module version stamped into the binary.
gv_ver=""
[[ -x "${LOCALBIN}/govulncheck" ]] && gv_ver="$(go version -m "${LOCALBIN}/govulncheck" 2>/dev/null | awk '$1=="mod" && $2=="golang.org/x/vuln"{print $3}')"
if [[ "${gv_ver}" != "${GOVULNCHECK_VERSION}" && "${INSTALL}" == 1 ]]; then
  install_tool govulncheck golang.org/x/vuln/cmd/govulncheck "${GOVULNCHECK_VERSION}"
  gv_ver="$(go version -m "${LOCALBIN}/govulncheck" 2>/dev/null | awk '$1=="mod" && $2=="golang.org/x/vuln"{print $3}')"
fi

go_ver="$(GOTOOLCHAIN="go${GO_PINNED}" go env GOVERSION 2>/dev/null | sed 's/^go//')"

echo "verify-tools: checking pinned versions"
report go              "${GO_PINNED}"                 "${go_ver}"
report controller-gen  "${CONTROLLER_TOOLS_VERSION}"  "${cg_ver}"
report kustomize       "${KUSTOMIZE_VERSION}"         "${kz_ver}"
report golangci-lint   "${GOLANGCI_LINT_VERSION}"     "${gl_ver}"
report govulncheck     "${GOVULNCHECK_VERSION}"       "${gv_ver}"

if [[ "${failed}" != 0 ]]; then
  echo "verify-tools: FAILED — run 'hack/verify-tools.sh --install' to install pinned versions" >&2
  exit 1
fi
echo "verify-tools: all tools match hack/tools.mk"
