#!/usr/bin/env bash
# hack/render-alloy-config.sh — write the Trawl Alloy pipelines into the
# gitops repository's Alloy HelmRelease.
#
# The chart runs Alloy against a single config file, so the only way the
# pipelines in config/alloy/ reach a cluster is inside that HelmRelease's
# inline content. Copying them there by hand would make the gitops repository a
# second source for the Loki label contract, and a contract with two sources
# drifts silently: nothing fails, queries just stop matching. So the files here
# stay authoritative and this script renders them, between markers, into the
# region of the HelmRelease that nobody is meant to edit.
#
#   hack/render-alloy-config.sh            # rewrite the HelmRelease
#   hack/render-alloy-config.sh --check    # fail if it is out of date
#
# The gitops repository is private and not a submodule, so this cannot run in
# CI. --check is what a person runs before deploying.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

CHECK=0
if [[ "${1:-}" == "--check" ]]; then
  CHECK=1
  shift
fi

GITOPS="${1:-${TRAWL_GITOPS:-${HOME}/git/shart-cloud-gh/containers/talos-gitops}}"
TARGET="${GITOPS}/infrastructure/controllers/alloy.yaml"

if [[ ! -f "${TARGET}" ]]; then
  echo "render-alloy-config: no HelmRelease at ${TARGET}" >&2
  echo "  pass the talos-gitops checkout as an argument, or set TRAWL_GITOPS" >&2
  exit 1
fi

# Ordered deliberately: observations first because that is the pipeline an
# investigation reads, audit second.
SOURCES=(
  config/alloy/trawl-observations.alloy
  config/alloy/trawl-audit.alloy
)

BEGIN="// >>> generated from trawl config/alloy - do not edit by hand"
END="// <<< end generated"

rendered="$(mktemp)"
trap 'rm -f "${rendered}"' EXIT

python3 - "${TARGET}" "${rendered}" "${BEGIN}" "${END}" "${SOURCES[@]}" <<'PY'
import sys

target, out, begin, end, *sources = sys.argv[1:]

with open(target, encoding="utf-8") as f:
    lines = f.read().split("\n")

starts = [i for i, l in enumerate(lines) if l.strip() == begin]
ends = [i for i, l in enumerate(lines) if l.strip() == end]
if len(starts) != 1 or len(ends) != 1 or ends[0] < starts[0]:
    sys.exit(f"{target}: expected exactly one generated region delimited by\n"
             f"  {begin}\n  {end}")

# The region sits inside a YAML block scalar, so every rendered line carries the
# marker's indentation. A blank line takes none: trailing whitespace in a block
# scalar is preserved, and yamllint rejects it.
indent = lines[starts[0]][: len(lines[starts[0]]) - len(lines[starts[0]].lstrip())]

body = []
for path in sources:
    with open(path, encoding="utf-8") as f:
        text = f.read().rstrip("\n")
    body.append(f"{indent}// Rendered from {path}. Edit it there.")
    for line in text.split("\n"):
        body.append(indent + line if line.strip() else "")
    body.append("")

rendered = lines[: starts[0] + 1] + body + lines[ends[0]:]
with open(out, "w", encoding="utf-8") as f:
    f.write("\n".join(rendered))
PY

if [[ "${CHECK}" == "1" ]]; then
  if ! diff -u "${TARGET}" "${rendered}"; then
    echo >&2
    echo "render-alloy-config: ${TARGET} is stale; run hack/render-alloy-config.sh" >&2
    exit 1
  fi
  echo "render-alloy-config: ${TARGET} matches config/alloy/"
  exit 0
fi

if cmp -s "${TARGET}" "${rendered}"; then
  echo "render-alloy-config: ${TARGET} already up to date"
  exit 0
fi

cp "${rendered}" "${TARGET}"
echo "render-alloy-config: wrote ${TARGET}"
