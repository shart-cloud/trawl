#!/usr/bin/env bash
# hack/refresh-digests.sh — repoint every Trawl image reference at the build of
# one commit.
#
# Manifests pin digests rather than tags, so deploying a new commit means
# rewriting seven references across two files. Done by hand that is a step
# somebody forgets, and forgetting it is silent: the apply succeeds and the
# cluster keeps running the previous build. Doing it here also makes the
# refresh reproducible from the tree, which an editor session is not.
#
# A digest that does not resolve is a deployment that fails at pull time, so
# every reference is confirmed against the registry before any file is written.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

TAG="${1:?usage: hack/refresh-digests.sh <short-sha>}"
REGISTRY="${REGISTRY:-ghcr.io/shart-cloud/trawl}"

# image name -> "<file>:<yaml field>". The sensor's images are selected by the
# operator at runtime and so live in config; the manager and the event worker
# are pinned in their own Deployments.
declare -A TARGET=(
  [suricata]="config/dev/trawl-config.yaml:suricata"
  [zeek]="config/dev/trawl-config.yaml:zeek"
  [sensor-agent]="config/dev/trawl-config.yaml:sensorAgent"
  [content-init]="config/dev/trawl-config.yaml:contentInit"
  [capture-runner]="config/dev/trawl-config.yaml:captureRunner"
  [controller-manager]="config/manager/manager.yaml:image"
  [event-worker]="config/manager/event-worker.yaml:image"
)

# Resolve everything first. A partial rewrite leaves the tree describing a
# cluster state that was never deployed, which is worse than not starting.
declare -A DIGEST=()
for image in "${!TARGET[@]}"; do
  digest=$("${CONTAINER_TOOL:-docker}" buildx imagetools inspect \
    "${REGISTRY}/${image}:v0.0.0-dev.${TAG}" \
    --format '{{json .Manifest.Digest}}' 2>/dev/null | tr -d '"')
  if [[ ! ${digest} =~ ^sha256:[0-9a-f]{64}$ ]]; then
    echo "refresh-digests: ${image}:v0.0.0-dev.${TAG} did not resolve" >&2
    exit 1
  fi
  DIGEST[${image}]="${digest}"
done

for image in "${!TARGET[@]}"; do
  target="${TARGET[${image}]}"
  printf '%-20s %s\n' "${image}" "${DIGEST[${image}]}"
  python3 - "${target%%:*}" "${target##*:}" \
    "${REGISTRY}/${image}@${DIGEST[${image}]}" <<'PY'
import io, re, sys

path, field, ref = sys.argv[1], sys.argv[2], sys.argv[3]
text = io.open(path, encoding='utf-8').read()
pattern = re.compile(r'^(\s*%s:\s*).*$' % re.escape(field), re.M)
matches = pattern.findall(text)
if len(matches) != 1:
    sys.exit('refresh-digests: %s: expected one %s field, found %d'
             % (path, field, len(matches)))
io.open(path, 'w', encoding='utf-8').write(
    pattern.sub(lambda m: m.group(1) + ref, text, count=1))
PY
done

echo "refresh-digests: all references resolved and written for ${TAG}"
