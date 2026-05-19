# fipscan — server image.
#
# Build stage: Go 1.26 toolchain producing a FIPS 140-3 binary.
# Runtime stage: distroless/static-debian12:nonroot — no shell, no
# package manager, runs as uid 65532, includes CA bundle for HTTPS to
# GitHub / OCI registries. Total image ~10 MB.
#
# Reproducibility flags match the Makefile's `release-fips` target:
#   GOFIPS140=v1.0.0   embed the Go Cryptographic Module
#   CGO_ENABLED=0      pure-Go static binary, no system libc dependency
#   -trimpath          strip local file paths from binary
#   -buildvcs=false    no VCS stamping
#   -ldflags="-s -w"   strip symbol table and DWARF
#
# Build:    docker build -t russell-del/fipscan:0.7.1 .
# Run:      docker run --rm -p 8080:8080 -v fipscan-data:/var/lib/fipscan russell-del/fipscan:0.7.1

# ---- build stage --------------------------------------------------------
# --platform=$BUILDPLATFORM keeps the toolchain on the build host's
# native architecture; we cross-compile to TARGETOS/TARGETARCH via Go.
# Avoids QEMU-emulated builds when buildx fans out for linux/amd64 +
# linux/arm64 in one go.
FROM --platform=$BUILDPLATFORM golang:1.26.3-alpine AS build
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src

# Copy module files first for layer caching. We have zero third-party deps
# so go mod download is a no-op, but the structure stays correct if deps
# are ever added.
COPY go.mod ./
COPY go.sum* ./
RUN go mod download

COPY . .

# An empty directory we COPY into the runtime image with the right owner
# so the data volume mount point exists with correct permissions.
RUN mkdir -p /out/data

RUN CGO_ENABLED=0 GOFIPS140=v1.0.0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -buildvcs=false -ldflags="-s -w" \
    -o /out/fipscan ./cmd/fipscan

# Self-test (only when the build host arch == target arch — otherwise the
# binary can't execute here under buildx without QEMU).
RUN if [ "${TARGETARCH}" = "$(go env GOHOSTARCH)" ] && [ "${TARGETOS}" = "$(go env GOHOSTOS)" ]; then \
      /out/fipscan -version | tee /dev/stderr | grep -q 'fips140-module: v1.0.0' \
        || (echo "FATAL: FIPS module not linked into binary" >&2; exit 1); \
    else \
      echo "skipping FIPS self-test for cross-built ${TARGETOS}/${TARGETARCH}"; \
    fi

# ---- runtime stage ------------------------------------------------------
FROM gcr.io/distroless/static-debian12:nonroot

LABEL org.opencontainers.image.title="fipscan"
LABEL org.opencontainers.image.description="FIPS 140-3 readiness scanner — code, dependency, and container image scanning. Server form factor with embedded UI."
LABEL org.opencontainers.image.source="https://github.com/russell-del/fipscan"
LABEL org.opencontainers.image.licenses="MIT"

COPY --from=build /out/fipscan /usr/local/bin/fipscan

# Pre-create the data directory with the nonroot user as owner so a
# bind-mounted host directory works without chown gymnastics.
COPY --from=build --chown=nonroot:nonroot /out/data /var/lib/fipscan

USER nonroot:nonroot
WORKDIR /var/lib/fipscan
VOLUME ["/var/lib/fipscan"]
EXPOSE 8080

# Audit log on by default in the image — lives inside the persisted
# volume so it survives container restarts. Operators can override by
# setting FIPSCAN_AUDIT_LOG to "" or another path.
ENV FIPSCAN_AUDIT_LOG=/var/lib/fipscan/audit.log

ENTRYPOINT ["/usr/local/bin/fipscan"]
CMD ["server", "-listen", "0.0.0.0:8080", "-data", "/var/lib/fipscan"]
