---
title: "ADR-0003: Artifact storage and authorization gateway"
description: Captures land in a private bucket and are retrieved only through a Kubernetes-authorized gateway, with a separate write-once audit ledger.
---

**Status**: Accepted · **Date**: 2026-08-29 · **Requirements**: FR-017–FR-025, FR-035–FR-036

## Context

A pcap is the most sensitive artifact Trawl produces: credentials, session
tokens, personal data, and application payloads in the clear. Storage and
retrieval therefore need an explicit authorization boundary, not merely a
bucket that happens to be private.

The root architecture document put MinIO endpoint and bucket settings on each
CapturePolicy and offered no download path beyond direct object access.

## Decision

**One installation-level storage profile.** Endpoint, buckets, and credentials
are installation configuration referenced by all captures, not per-policy
fields. A policy author cannot redirect evidence to a bucket the operator has
not authorized.

**Two buckets, two credentials.** Artifacts and the audit ledger are separate,
with distinct credentials. The ledger bucket has backend-enforced versioning
and write-once retention, so a compromised artifact path cannot rewrite the
record of what happened.

**A gateway is the only download path.** `trawl-artifact-gateway` performs an
audience-bound TokenReview, then a SubjectAccessReview against the
`capturejobs/download` subresource, checks live execution and retention state,
durably commits the authorization decision to the audit ledger, and only then
issues a short presigned URL. Errors are enumeration-safe: an unauthorized
caller cannot distinguish "does not exist" from "not yours".

**Kubernetes RBAC is the authorization model.** Not a bespoke one. Operators
grant download rights the same way they grant everything else in the cluster.

**CLI-only retrieval in the MVP.** Grafana shows a copyable `trawlctl` command
and never a credential, bearer token, or presigned URL.

## Alternatives considered

- **Presigned URLs handed straight to Grafana.** Best UX. Rejected: it puts a
  bearer-equivalent secret into a dashboard and browser history, with no
  per-download authorization check or audit record.
- **Per-policy storage config, as sketched in the architecture doc.** Rejected:
  it makes every policy author a storage administrator and multiplies the
  credential surface.
- **A single bucket with prefix separation for audit.** Cheaper. Rejected:
  write-once retention is a bucket-level property, and shared credentials mean
  the audit trail is only as trustworthy as the artifact writer.
- **Browser SSO for downloads.** Rejected as MVP scope; it needs an identity
  integration the homelab does not have. Deferred, not refused.

## Consequences

- Every download costs a TokenReview, a SubjectAccessReview, and a durable
  audit commit before bytes move. That is the intended trade.
- The gateway is on the critical path for retrieval but not for monitoring or
  capture, so its failure never affects evidence collection.
- Retention changes are authorized separately and can shorten or extend only
  before expiry — expired evidence can never be resurrected.
- Audit ledger unavailability fails user-initiated actions closed. It must not
  affect monitored traffic.

## Rollback

Buckets and objects outlive any operator version. Rolling back the gateway
restores a previous authorization implementation but cannot un-audit a
download, by design. Uninstall does not delete artifacts; a documented purge
path enumerates objects and retention implications first.
