#!/usr/bin/env bash
# hack/verify-drift.sh — fail if checked-in generated artifacts differ from what
# the current source generates (T009, constitution gate 6).
#
# CRDs, deepcopy functions, RBAC, and the install bundle are contract artifacts.
# A checked-in copy that disagrees with the generator is a lie that reviewers
# cannot see, so this runs on every pull request.
#
# The comparison snapshots the generated paths, regenerates, and diffs. It does
# not consult git status, so it behaves identically in a fresh clone, a dirty
# working tree, and a repository with no commits yet.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

# Paths whose contents are produced by `make manifests generate`.
GENERATED_PATHS=(
  "api"
  "config/crd"
  "config/rbac"
  "config/webhook"
)

snapshot="$(mktemp -d)"
trap 'rm -rf "${snapshot}"' EXIT

for path in "${GENERATED_PATHS[@]}"; do
  if [[ -e "${path}" ]]; then
    mkdir -p "${snapshot}/$(dirname "${path}")"
    cp -a "${path}" "${snapshot}/${path}"
  fi
done

echo "verify-drift: regenerating artifacts..."
make manifests generate >/dev/null

status=0
for path in "${GENERATED_PATHS[@]}"; do
  if [[ ! -e "${path}" && ! -e "${snapshot}/${path}" ]]; then
    continue
  fi
  if ! diff -ruN "${snapshot}/${path}" "${path}" >/dev/null 2>&1; then
    echo "verify-drift: DRIFT in ${path}" >&2
    diff -ruN "${snapshot}/${path}" "${path}" >&2 || true
    status=1
  fi
done

if [[ "${status}" != 0 ]]; then
  echo "" >&2
  echo "verify-drift: checked-in generated artifacts are stale." >&2
  echo "Run 'make manifests generate' and commit the result." >&2
  exit 1
fi

echo "verify-drift: no drift."
