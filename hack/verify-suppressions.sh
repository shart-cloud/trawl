#!/usr/bin/env bash
# hack/verify-suppressions.sh — fail on an expired or malformed security
# suppression (T129).
#
# A suppression file whose dates nothing enforces is not a review process, it is
# a list. This is the thing that makes `expires` mean something: an entry past
# its date breaks the build, so the choice becomes fixing the finding or
# re-reviewing it and writing a new date. Both are visible in a diff; neither is
# silent.
#
# Also rejects an entry missing any required field, because a suppression with
# no reason or no reviewer cannot be re-reviewed by anybody later — which is the
# only reason to record it rather than just deleting the alert.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EMIT=""
if [ "${1:-}" = "--emit-trivyignore" ]; then
  EMIT="trivy"
  shift
fi
FILE="${1:-${REPO_ROOT}/security/suppressions.yaml}"

if [ ! -f "${FILE}" ]; then
  echo "verify-suppressions: ${FILE} not found" >&2
  exit 1
fi

python3 - "${FILE}" "${EMIT}" <<'PY'
import datetime
import sys

try:
    import yaml
except ImportError:
    print("verify-suppressions: PyYAML is required", file=sys.stderr)
    sys.exit(1)

path = sys.argv[1]
emit = sys.argv[2] if len(sys.argv) > 2 else ""
with open(path) as handle:
    doc = yaml.safe_load(handle) or {}

entries = doc.get("suppressions")
if entries is None:
    print(f"verify-suppressions: {path} has no `suppressions` key", file=sys.stderr)
    sys.exit(1)
if not isinstance(entries, list):
    print(f"verify-suppressions: `suppressions` must be a list", file=sys.stderr)
    sys.exit(1)

required = ("id", "scanner", "reason", "expires", "reviewer", "added")
scanners = {"govulncheck", "trivy", "gitleaks", "manifest"}
today = datetime.date.today()
status = 0

for index, entry in enumerate(entries):
    where = entry.get("id") or f"entry {index}"

    if not isinstance(entry, dict):
        print(f"verify-suppressions: {where}: not a mapping", file=sys.stderr)
        status = 1
        continue

    for field in required:
        if not entry.get(field):
            print(f"verify-suppressions: {where}: missing `{field}`", file=sys.stderr)
            status = 1

    scanner = entry.get("scanner")
    if scanner and scanner not in scanners:
        print(
            f"verify-suppressions: {where}: unknown scanner {scanner!r} "
            f"(expected one of {sorted(scanners)})",
            file=sys.stderr,
        )
        status = 1

    # A reason that says nothing cannot be re-reviewed. This is a low bar on
    # purpose: it catches "n/a" and "not exploitable", not careless phrasing.
    reason = (entry.get("reason") or "").strip()
    if reason and len(reason) < 25:
        print(
            f"verify-suppressions: {where}: reason is too short to re-review "
            f"({reason!r}). Say which call path is absent or which control makes "
            f"it unreachable.",
            file=sys.stderr,
        )
        status = 1

    expires = entry.get("expires")
    if not expires:
        continue
    if isinstance(expires, datetime.datetime):
        expires = expires.date()
    if not isinstance(expires, datetime.date):
        print(
            f"verify-suppressions: {where}: `expires` is {expires!r}, want YYYY-MM-DD",
            file=sys.stderr,
        )
        status = 1
        continue

    if expires < today:
        print(
            f"verify-suppressions: {where}: suppression expired on {expires} "
            f"({(today - expires).days} days ago). Fix the finding, or re-review "
            f"it and write a new expiry with a new reason.",
            file=sys.stderr,
        )
        status = 1

# Trivy keeps its own ignore-file format, and a second place to suppress a
# finding is a second place for one to go stale. So the .trivyignore is derived
# from this file rather than maintained beside it: every Trivy suppression is
# therefore covered by the same expiry enforcement as everything else, and
# cannot outlive its review by being written somewhere the checker never reads.
if emit == "trivy":
    if status != 0:
        sys.exit(status)
    lines = []
    for entry in entries:
        if entry.get("scanner") != "trivy":
            continue
        lines.append(f"# {entry['reason']} (reviewed by {entry['reviewer']}, expires {entry['expires']})")
        lines.append(str(entry["id"]))
    sys.stdout.write("\n".join(lines) + ("\n" if lines else ""))
    sys.exit(0)

if status == 0:
    print(f"verify-suppressions: {len(entries)} suppression(s), none expired.")

sys.exit(status)
PY
