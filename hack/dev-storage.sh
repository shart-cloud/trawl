#!/usr/bin/env bash
# Provisions the object storage a development installation needs.
#
# Trawl requires two private buckets reached with two distinct credentials: one
# for capture artifacts and one for the audit ledger. ADR-0003 requires them to
# be separate so the credential able to write evidence cannot rewrite the record
# of how that evidence was handled. Both are enforced by config.Validate, which
# rejects a configuration where the buckets or the credential paths match.
#
# Credentials are generated here rather than committed. A key in a repository is
# a key in every clone of it, and this script is run once per install.
set -euo pipefail

NAMESPACE="${NAMESPACE:-trawl-system}"
KUBECTL="${KUBECTL:-kubectl}"

ARTIFACT_BUCKET="${ARTIFACT_BUCKET:-trawl-artifacts}"
AUDIT_BUCKET="${AUDIT_BUCKET:-trawl-audit-ledger}"

log() { printf '%s\n' "$*" >&2; }

randkey() {
	# 32 bytes of urandom, base32'd to something MinIO accepts as a key.
	head -c 32 /dev/urandom | base32 | tr -d '=\n' | head -c "${1:-40}"
}

ensure_secret() {
	local name="$1" access="$2" secret="$3"
	if "$KUBECTL" -n "$NAMESPACE" get secret "$name" >/dev/null 2>&1; then
		log "secret/$name already exists; leaving it alone"
		return
	fi
	# The file names are what internal/storage/s3.go reads from the mounted
	# credentials directory.
	"$KUBECTL" -n "$NAMESPACE" create secret generic "$name" \
		--from-literal=accessKeyID="$access" \
		--from-literal=secretAccessKey="$secret"
	log "created secret/$name"
}

log "==> namespace"
"$KUBECTL" get namespace "$NAMESPACE" >/dev/null 2>&1 ||
	"$KUBECTL" create namespace "$NAMESPACE"

log "==> credentials"
ROOT_ACCESS="${ROOT_ACCESS:-trawl-root}"
ROOT_SECRET="$(randkey 40)"
ensure_secret minio-root "$ROOT_ACCESS" "$ROOT_SECRET"

# Read back whatever is actually in the cluster: on a re-run the generated
# values above are not the ones MinIO is using.
ROOT_ACCESS="$("$KUBECTL" -n "$NAMESPACE" get secret minio-root -o jsonpath='{.data.accessKeyID}' | base64 -d)"
ROOT_SECRET="$("$KUBECTL" -n "$NAMESPACE" get secret minio-root -o jsonpath='{.data.secretAccessKey}' | base64 -d)"

ARTIFACT_ACCESS="trawl-artifacts"
ARTIFACT_SECRET="$(randkey 40)"
ensure_secret trawl-artifact-storage "$ARTIFACT_ACCESS" "$ARTIFACT_SECRET"
ARTIFACT_ACCESS="$("$KUBECTL" -n "$NAMESPACE" get secret trawl-artifact-storage -o jsonpath='{.data.accessKeyID}' | base64 -d)"
ARTIFACT_SECRET="$("$KUBECTL" -n "$NAMESPACE" get secret trawl-artifact-storage -o jsonpath='{.data.secretAccessKey}' | base64 -d)"

AUDIT_ACCESS="trawl-audit"
AUDIT_SECRET="$(randkey 40)"
ensure_secret trawl-audit-ledger "$AUDIT_ACCESS" "$AUDIT_SECRET"
AUDIT_ACCESS="$("$KUBECTL" -n "$NAMESPACE" get secret trawl-audit-ledger -o jsonpath='{.data.accessKeyID}' | base64 -d)"
AUDIT_SECRET="$("$KUBECTL" -n "$NAMESPACE" get secret trawl-audit-ledger -o jsonpath='{.data.secretAccessKey}' | base64 -d)"

log "==> waiting for MinIO"
"$KUBECTL" -n "$NAMESPACE" rollout status deployment/minio --timeout=180s

# mc runs in the cluster rather than on the operator's workstation, so the
# credentials never leave the namespace and no port-forward is needed.
log "==> buckets and policies"
"$KUBECTL" -n "$NAMESPACE" delete job trawl-storage-init --ignore-not-found >/dev/null 2>&1 || true
cat <<EOF | "$KUBECTL" apply -f -
apiVersion: batch/v1
kind: Job
metadata:
  name: trawl-storage-init
  namespace: ${NAMESPACE}
spec:
  backoffLimit: 3
  ttlSecondsAfterFinished: 300
  template:
    spec:
      restartPolicy: OnFailure
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: mc
          image: quay.io/minio/mc:RELEASE.2025-04-16T18-13-26Z
          securityContext:
            allowPrivilegeEscalation: false
            capabilities:
              drop: ["ALL"]
          env:
            # mc writes its alias configuration to $HOME/.mc. The pod runs as
            # UID 1000 with no passwd entry, so HOME is / and the write is
            # denied - the job fails at the alias step before it touches MinIO.
            - name: MC_CONFIG_DIR
              value: /tmp/.mc
            - name: ROOT_ACCESS
              value: ${ROOT_ACCESS}
            - name: ROOT_SECRET
              value: ${ROOT_SECRET}
            - name: ARTIFACT_ACCESS
              value: ${ARTIFACT_ACCESS}
            - name: ARTIFACT_SECRET
              value: ${ARTIFACT_SECRET}
            - name: AUDIT_ACCESS
              value: ${AUDIT_ACCESS}
            - name: AUDIT_SECRET
              value: ${AUDIT_SECRET}
          command: ["/bin/sh", "-c"]
          args:
            - |
              set -eu
              mc alias set local http://minio:9000 "\$ROOT_ACCESS" "\$ROOT_SECRET"

              mc mb --ignore-existing local/${ARTIFACT_BUCKET}
              mc mb --ignore-existing local/${AUDIT_BUCKET}

              # Neither bucket is public. An artifact is evidence and reaches a
              # reader through the gateway's authorization, never through an
              # anonymous URL.
              mc anonymous set none local/${ARTIFACT_BUCKET}
              mc anonymous set none local/${AUDIT_BUCKET}

              # The audit ledger is write-once. Object locking cannot be added
              # to an existing bucket, so this is best-effort on a re-run and
              # the failure is reported rather than swallowed.
              mc version enable local/${AUDIT_BUCKET} || echo "WARNING: could not enable versioning on ${AUDIT_BUCKET}"

              cat >/tmp/artifact.json <<'POLICY'
              {"Version":"2012-10-17","Statement":[{"Effect":"Allow",
                "Action":["s3:GetObject","s3:PutObject","s3:DeleteObject","s3:ListBucket","s3:GetBucketLocation"],
                "Resource":["arn:aws:s3:::${ARTIFACT_BUCKET}","arn:aws:s3:::${ARTIFACT_BUCKET}/*"]}]}
              POLICY
              # No DeleteObject. The ledger records how evidence was handled; a
              # credential that could erase it would defeat the separation
              # ADR-0003 requires.
              cat >/tmp/audit.json <<'POLICY'
              {"Version":"2012-10-17","Statement":[{"Effect":"Allow",
                "Action":["s3:GetObject","s3:PutObject","s3:ListBucket","s3:GetBucketLocation"],
                "Resource":["arn:aws:s3:::${AUDIT_BUCKET}","arn:aws:s3:::${AUDIT_BUCKET}/*"]}]}
              POLICY

              mc admin user add local "\$ARTIFACT_ACCESS" "\$ARTIFACT_SECRET" || true
              mc admin user add local "\$AUDIT_ACCESS" "\$AUDIT_SECRET" || true
              mc admin policy create local trawl-artifacts /tmp/artifact.json || true
              mc admin policy create local trawl-audit /tmp/audit.json || true
              mc admin policy attach local trawl-artifacts --user "\$ARTIFACT_ACCESS" || true
              mc admin policy attach local trawl-audit --user "\$AUDIT_ACCESS" || true

              echo "storage ready"
EOF

"$KUBECTL" -n "$NAMESPACE" wait --for=condition=complete job/trawl-storage-init --timeout=180s
log "==> done"
"$KUBECTL" -n "$NAMESPACE" logs job/trawl-storage-init | tail -3
