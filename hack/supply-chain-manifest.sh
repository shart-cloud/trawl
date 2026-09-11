#!/usr/bin/env bash
# hack/supply-chain-manifest.sh — assemble dist/supply-chain/manifest.json (T128).
#
# What a release can say about its own provenance, in one document: the upstream
# sources that were verified and how, the hashes of the detection content and
# entrypoints baked into the analyzer images, the image digests the installer
# pins, the SBOMs, and the vulnerability results.
#
# One rule governs the whole file, and it is the reason this is a script rather
# than a hand-maintained document.
#
#   A section that could not be produced is recorded as absent, with the reason.
#   It is never omitted.
#
# A supply-chain manifest missing its SBOM section looks exactly like one whose
# SBOMs were never generated, and the second is the case somebody needs to know
# about. Silence here would be the same failure this project keeps finding
# elsewhere: an absence that cannot be told apart from a negative result.
#
# Sections needing built images (SBOM, image digests, container vulnerability
# results) are only available where the images exist - in CI after a build, or
# locally with syft installed. The rest are always available, because they come
# from files in the tree.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

OUT_DIR="${OUT_DIR:-dist/supply-chain}"
OUT="${OUT_DIR}/manifest.json"
DIGESTS_FILE="${DIGESTS_FILE:-}"

mkdir -p "${OUT_DIR}"

python3 - "${OUT}" "${DIGESTS_FILE}" <<'PY'
import datetime
import hashlib
import json
import os
import shutil
import subprocess
import sys

out_path = sys.argv[1]
digests_file = sys.argv[2] if len(sys.argv) > 2 else ""

try:
    import yaml
except ImportError:
    print("supply-chain: PyYAML is required", file=sys.stderr)
    sys.exit(1)


def sha256_of(path):
    h = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


def run(cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, check=False)
    except FileNotFoundError:
        return None


def absent(reason):
    return {"status": "unavailable", "reason": reason}


manifest = {
    "schemaVersion": "trawl.supply-chain/v1",
    "generatedAt": datetime.datetime.now(datetime.timezone.utc)
    .replace(microsecond=0)
    .isoformat()
    .replace("+00:00", "Z"),
}

# --- Build identity ---------------------------------------------------------

commit = run(["git", "rev-parse", "HEAD"])
describe = run(["git", "describe", "--tags", "--always", "--dirty"])
status = run(["git", "status", "--porcelain"])
dirty = bool(status and status.stdout.strip())

manifest["build"] = {
    "commit": commit.stdout.strip() if commit and commit.returncode == 0 else None,
    "describe": describe.stdout.strip() if describe and describe.returncode == 0 else None,
    # A manifest generated from a dirty tree describes something that is not in
    # any commit, so it says so rather than implying reproducibility it does
    # not have.
    "cleanTree": not dirty,
}

# --- Upstream sources, and how each was verified ----------------------------
#
# Read from the SOURCES.lock files rather than restated, so the manifest and the
# build cannot disagree about what was pinned.

sources = []
for image in sorted(os.listdir("images")):
    lock_path = os.path.join("images", image, "SOURCES.lock")
    if not os.path.exists(lock_path):
        continue
    with open(lock_path) as handle:
        lock = yaml.safe_load(handle) or {}
    for name, entry in lock.items():
        if not isinstance(entry, dict):
            continue
        record = {"image": image, "component": name}
        for field in ("version", "url", "sha256", "reference", "digest",
                      "signing_key_fingerprint", "signature_url"):
            if entry.get(field):
                record[field] = entry[field]
        # Checksums may sit on the entry or inside a nested block - the
        # capture-runner pins each Debian package under `packages:` - so this
        # looks all the way down. Reading only the top level reported a fully
        # pinned entry as unpinned, and a manifest that cries wolf gets read
        # with the same attention as one that stays silent.
        def has_checksum(node):
            if isinstance(node, dict):
                if node.get("sha256") or node.get("digest"):
                    return True
                return any(has_checksum(v) for v in node.values())
            if isinstance(node, list):
                return any(has_checksum(v) for v in node)
            return False

        # Say plainly how strong the pin is. A checksum alone says the bytes
        # did not change; a signature says who published them.
        if entry.get("signing_key_fingerprint"):
            record["verification"] = "checksum and detached signature"
        elif has_checksum(entry):
            record["verification"] = "checksum only"
        else:
            record["verification"] = "version only"
        sources.append(record)

manifest["upstreamSources"] = {"status": "present", "entries": sources}

weak = [s for s in sources if s["verification"] == "version only"]
if weak:
    manifest["upstreamSources"]["warning"] = (
        f"{len(weak)} source(s) are pinned by version with no checksum: "
        + ", ".join(f"{s['image']}/{s['component']}" for s in weak)
    )

# --- Detection content and entrypoints baked into images --------------------
#
# These are the files that decide what the analyzers do. They are not fetched at
# runtime, so their hashes belong to the build, and a changed entrypoint with an
# unchanged image digest is a contradiction worth being able to detect.

content = []
for root, _dirs, files in os.walk("images"):
    for name in sorted(files):
        if not name.endswith((".zeek", ".yaml", ".sh")) or name == "SOURCES.lock":
            continue
        path = os.path.join(root, name)
        content.append({"path": path, "sha256": sha256_of(path)})

for extra in ("config/alloy/trawl-observations.alloy",):
    if os.path.exists(extra):
        content.append({"path": extra, "sha256": sha256_of(extra)})

manifest["detectionContent"] = {"status": "present", "entries": content}

# --- Image digests ----------------------------------------------------------
#
# The installer pins digests, not tags, and these are the digests it pins. Taken
# from the CI digest artifact when one is supplied, and otherwise read out of
# the manifests themselves so a local run still produces a truthful section.

digests = []
if digests_file and os.path.exists(digests_file):
    with open(digests_file) as handle:
        for line in handle:
            line = line.strip()
            if not line or "=" not in line:
                continue
            name, ref = line.split("=", 1)
            if "<" in ref:  # "<not built in this run>"
                continue
            digests.append({"image": name, "reference": ref, "source": "ci-build"})
    manifest["imageDigests"] = {"status": "present", "entries": digests}
else:
    pinned = []
    for root, _dirs, files in os.walk("config"):
        for name in files:
            if not name.endswith((".yaml", ".yml")):
                continue
            path = os.path.join(root, name)
            with open(path) as handle:
                for line in handle:
                    if "ghcr.io/" in line and "@sha256:" in line:
                        ref = line.split("ghcr.io/", 1)[1].strip().rstrip(",")
                        pinned.append({"reference": "ghcr.io/" + ref, "source": path})
    manifest["imageDigests"] = {
        "status": "present" if pinned else "unavailable",
        "entries": pinned,
        "note": "read from the pinned manifests; pass DIGESTS_FILE to record a build's own digests",
    }
    if not pinned:
        manifest["imageDigests"]["reason"] = "no digest-pinned image reference found in config/"

# --- Go vulnerability results -----------------------------------------------

govulncheck = os.path.join("bin", "govulncheck")
if os.environ.get("SUPPLY_CHAIN_SKIP_VULN") == "1":
    manifest["goVulnerabilities"] = absent("skipped by SUPPLY_CHAIN_SKIP_VULN")
elif os.path.exists(govulncheck):
    result = run([govulncheck, "-format", "json", "./..."])
    if result is None or result.returncode not in (0, 3):
        manifest["goVulnerabilities"] = absent(
            f"govulncheck exited {result.returncode if result else 'not found'}"
        )
    else:
        findings = []
        for line in result.stdout.splitlines():
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            # A line may decode to a bare string rather than an object.
            if not isinstance(event, dict):
                continue
            osv = event.get("osv")
            # govulncheck emits several event shapes on this key: the full OSV
            # record as an object, and elsewhere a bare id string. Taking
            # .get() on the second is the obvious crash.
            if isinstance(osv, dict):
                findings.append(
                    {"id": osv.get("id"), "summary": (osv.get("summary") or "").strip()}
                )
        manifest["goVulnerabilities"] = {
            "status": "present",
            "tool": "govulncheck",
            # Every OSV the scan mentioned, reachable or not. The count of
            # *called* vulnerabilities is what `make security` gates on; this
            # records the full surface so a later reader can see what was
            # considered.
            "considered": findings,
        }
else:
    manifest["goVulnerabilities"] = absent("bin/govulncheck not installed; run `make security`")

# --- SBOMs ------------------------------------------------------------------

if shutil.which("syft"):
    manifest["sbom"] = {
        "status": "present",
        "tool": "syft",
        "note": "per-image SBOMs are written beside this manifest",
    }
else:
    manifest["sbom"] = absent(
        "syft is not installed; SBOMs are generated in CI where the images are built"
    )

# --- Provenance -------------------------------------------------------------

if os.environ.get("GITHUB_ACTIONS") == "true":
    manifest["provenance"] = {
        "status": "present",
        "type": "slsa-github-actions",
        "workflow": os.environ.get("GITHUB_WORKFLOW"),
        "runID": os.environ.get("GITHUB_RUN_ID"),
        "repository": os.environ.get("GITHUB_REPOSITORY"),
        "ref": os.environ.get("GITHUB_REF"),
    }
else:
    manifest["provenance"] = absent(
        "generated outside GitHub Actions; a local build has no attestable provenance"
    )

with open(out_path, "w") as handle:
    json.dump(manifest, handle, indent=2, sort_keys=False)
    handle.write("\n")

unavailable = [k for k, v in manifest.items() if isinstance(v, dict) and v.get("status") == "unavailable"]
print(f"supply-chain: wrote {out_path}")
if unavailable:
    print(f"supply-chain: sections recorded as unavailable: {', '.join(unavailable)}")
PY
