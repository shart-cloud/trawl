#!/usr/bin/env bash
# Generate the source and image SBOMs that the supply-chain manifest records.
#
# This is a script rather than an inline workflow loop because the important
# property is the correspondence between digests and SBOMs: every image the
# build records must be scanned by that immutable reference. Keeping the loop
# here lets a contract test exercise that property without pretending to run
# GitHub Actions locally.

set -euo pipefail

: "${SYFT:?set SYFT to the pinned syft executable}"
: "${DIGESTS_FILE:?set DIGESTS_FILE to the image digest record}"

OUT_DIR="${OUT_DIR:-dist/supply-chain}"
SOURCE_DIR="${SOURCE_DIR:-.}"

mkdir -p "${OUT_DIR}"

"${SYFT}" "dir:${SOURCE_DIR}" -o "spdx-json=${OUT_DIR}/source.spdx.json"

while IFS='=' read -r name reference; do
  if [[ -z "${name}" || -z "${reference}" || "${reference}" == \<* ]]; then
    continue
  fi
  if [[ ! "${name}" =~ ^[a-z0-9][a-z0-9-]*$ ]]; then
    echo "sbom: invalid image name in ${DIGESTS_FILE}: ${name}" >&2
    exit 1
  fi
  if [[ "${reference}" != *@sha256:* ]]; then
    echo "sbom: image is not pinned by digest: ${name}=${reference}" >&2
    exit 1
  fi
  "${SYFT}" "${reference}" -o "spdx-json=${OUT_DIR}/${name}.spdx.json"
done < "${DIGESTS_FILE}"
