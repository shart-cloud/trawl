#!/usr/bin/env bash
# hack/build-custom-content.sh — validate, package, and push site-specific
# detection content as an OCI artifact (T047b, FR-043).
#
# Custom content is git-managed and reaches sensors as a digest-pinned artifact.
# Validation happens here, before publication, because a rule that fails to
# parse must never reach a sensor: Suricata refuses to start on a broken
# ruleset, which would turn a typo in a local rule into a monitoring outage
# across every tap that references it.
#
# Usage:
#   hack/build-custom-content.sh --analyzer Suricata --src content/suricata \
#       --repository registry.example.com/trawl/custom-suricata [--push]
#
# Prints the resulting digest reference, which is what goes into the
# NetworkTap's customContent.reference field.

set -euo pipefail

ANALYZER=""
SRC=""
REPOSITORY=""
TAG="$(date -u +%Y%m%d%H%M%S)"
PUSH=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --analyzer)   ANALYZER="$2"; shift 2 ;;
    --src)        SRC="$2"; shift 2 ;;
    --repository) REPOSITORY="$2"; shift 2 ;;
    --tag)        TAG="$2"; shift 2 ;;
    --push)       PUSH=1; shift ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

[[ -n "${ANALYZER}" && -n "${SRC}" && -n "${REPOSITORY}" ]] || {
  echo "usage: $0 --analyzer (Suricata|Zeek) --src DIR --repository REPO [--tag TAG] [--push]" >&2
  exit 2
}
[[ -d "${SRC}" ]] || { echo "source directory ${SRC} does not exist" >&2; exit 1; }

need() {
  command -v "$1" >/dev/null 2>&1 || { echo "$1 is required but not installed" >&2; exit 1; }
}

validate_suricata() {
  need suricata
  echo "validating Suricata rules in ${SRC}"
  # -T is Suricata's own config/rule test mode. Using the analyzer itself rather
  # than a bespoke parser means validation cannot drift from what will actually
  # load the rules at runtime.
  local tmp
  tmp="$(mktemp -d)"
  trap 'rm -rf "${tmp}"' RETURN
  cp -r "${SRC}"/. "${tmp}/"
  if ! suricata -T -S "${tmp}"/*.rules --set default-rule-path="${tmp}" >/dev/null; then
    echo "Suricata rule validation failed; the artifact was not built" >&2
    exit 1
  fi
}

validate_zeek() {
  need zeek
  echo "validating Zeek scripts in ${SRC}"
  # zeek --parse-only loads and type-checks without running, which catches the
  # syntax and identifier errors that would otherwise surface as a crash loop.
  local failed=0
  while IFS= read -r -d '' script; do
    if ! zeek --parse-only "${script}" >/dev/null 2>&1; then
      echo "  parse error: ${script}" >&2
      failed=1
    fi
  done < <(find "${SRC}" -name '*.zeek' -print0)
  if [[ "${failed}" != 0 ]]; then
    echo "Zeek script validation failed; the artifact was not built" >&2
    exit 1
  fi
}

case "${ANALYZER}" in
  Suricata) validate_suricata ;;
  Zeek)     validate_zeek ;;
  *) echo "unsupported analyzer ${ANALYZER}" >&2; exit 2 ;;
esac

need oras

echo "packaging ${SRC} as ${REPOSITORY}:${TAG}"
PUSH_ARGS=(--artifact-type "application/vnd.trawl.content.v1+tar")
if [[ "${PUSH}" != 1 ]]; then
  # Dry run by default. Publishing detection content is an outward action, and
  # the caller should have to ask for it.
  echo "(dry run; pass --push to publish)"
  exit 0
fi

DIGEST="$(cd "${SRC}" && oras push "${PUSH_ARGS[@]}" \
  --format go-template='{{.digest}}' \
  "${REPOSITORY}:${TAG}" . )"

echo ""
echo "published: ${REPOSITORY}@${DIGEST}"
echo ""
echo "Set this on the NetworkTap:"
echo "  spec.analyzers.$(echo "${ANALYZER}" | tr '[:upper:]' '[:lower:]').customContent.reference: ${REPOSITORY}@${DIGEST}"
