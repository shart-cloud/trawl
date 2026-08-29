# Reproducible build for every Trawl Go binary.
#
# One definition parameterized by BINARY rather than a Dockerfile per binary:
# the build flags that matter for reproducibility and for the supply-chain
# requirements (trimpath, stripped build ID, digest-pinned base) must be
# identical everywhere, and duplicating them is how they drift.
#
# Base images are digest-pinned. A tag can be repointed after the review that
# approved it, which the constitution's immutable-supply-chain rule forbids.

FROM golang:1.26.7@sha256:dc2521c2a906db43073b8b4d99f491b6341cf15610b6ebbab187c45153f9959e AS builder

ARG TARGETOS
ARG TARGETARCH

# BINARY selects which cmd/ package to build. Every Trawl image is produced from
# this stage so they share one toolchain and one set of flags.
ARG BINARY=controller-manager

# Build identification, stamped into the binary and reported by the process.
# These are required rather than defaulted: an unidentifiable build cannot be
# correlated with the source that produced it.
ARG VERSION
ARG COMMIT

WORKDIR /workspace

# Dependencies are resolved before the source is copied, so a source-only change
# does not re-download the module graph.
COPY go.mod go.mod
COPY go.sum go.sum
RUN go mod download

COPY . .

# CGO is disabled so the result is a static binary that runs on distroless.
# -trimpath removes local filesystem paths, and -buildid= clears the build ID,
# which together make the output byte-identical across machines for the same
# inputs. That is what lets the drift check and the SBOM mean anything.
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} \
    go build \
      -trimpath \
      -ldflags="-s -w -buildid= \
        -X main.version=${VERSION} \
        -X main.commit=${COMMIT}" \
      -o /workspace/trawl-binary \
      ./cmd/${BINARY}

# distroless static: no shell, no package manager, no libc. There is nothing in
# the image for a compromised process to execute, which matters most for the
# components that hold storage credentials.
FROM gcr.io/distroless/static:nonroot@sha256:1c2c046bc09ed40fad370b599a0b1ae7987f55b01e247cf27a7c27cd97e5bbc7

WORKDIR /

COPY --from=builder /workspace/trawl-binary /trawl

# Non-root, matching the restricted Pod Security profile the control-plane
# namespace enforces.
USER 65532:65532

ENTRYPOINT ["/trawl"]
