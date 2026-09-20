#!/usr/bin/env bash
# Replace the install bundle's reviewed image pins with the digests produced by
# the tag build. The release workflow runs only after Images, so the binary's
# embedded version and commit are the tag being published rather than those of
# the earlier live-release candidate.

set -euo pipefail

INSTALL="${1:?usage: hack/pin-installer-images.sh <install.yaml> <digests.txt>}"
DIGESTS="${2:?usage: hack/pin-installer-images.sh <install.yaml> <digests.txt>}"

python3 - "${INSTALL}" "${DIGESTS}" <<'PY'
import io
import re
import sys

install_path, digests_path = sys.argv[1:]
digests = {}
with io.open(digests_path, encoding="utf-8") as handle:
    for raw in handle:
        line = raw.strip()
        if not line or "=" not in line:
            continue
        name, reference = line.split("=", 1)
        if reference.startswith("<"):
            continue
        if not re.fullmatch(r"ghcr\.io/shart-cloud/trawl/[a-z0-9-]+@sha256:[0-9a-f]{64}", reference):
            sys.exit(f"pin-installer: {name} has an invalid immutable reference: {reference}")
        digests[name] = reference

text = io.open(install_path, encoding="utf-8").read()
pattern = re.compile(
    r"^(?P<prefix>\s*image:\s*)"
    r"ghcr\.io/shart-cloud/trawl/(?P<name>[a-z0-9-]+)"
    r"(?:@sha256:[0-9a-f]{64}|:[^\s]+)\s*$",
    re.M,
)
seen = set()


def pin(match):
    name = match.group("name")
    reference = digests.get(name)
    if reference is None:
        sys.exit(f"pin-installer: the tag build recorded no digest for {name}")
    seen.add(name)
    return match.group("prefix") + reference


updated, count = pattern.subn(pin, text)
if count == 0:
    sys.exit("pin-installer: install bundle contains no Trawl image reference")

with io.open(install_path, "w", encoding="utf-8") as handle:
    handle.write(updated)

print("pin-installer: pinned " + ", ".join(sorted(seen)))
PY
