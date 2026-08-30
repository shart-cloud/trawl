# Object storage for a development cluster

Trawl requires two private buckets: one for capture artifacts and one for the
audit ledger. ADR-0003 requires them to be distinct buckets reached with
distinct credentials, so that the credential able to write evidence cannot
rewrite the record of how that evidence was handled.

This directory stands one MinIO up to satisfy that on a homelab cluster. **It
is not part of the release bundle** and `config/default` does not reference it.
A real installation points `artifacts` and `auditLedger` at storage whose
retention and access policy are managed outside Trawl - the whole point of the
audit ledger is that Trawl is not the only thing that can vouch for it.

The credentials here are generated per-install by the operator running
`hack/dev-storage.sh`, not committed. Nothing in this directory should ever
carry a key.
