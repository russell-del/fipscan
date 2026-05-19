# fipscan build & release targets.
#
# Hardening posture for IL5+ deployment is built into `release-fips`:
#   - Go 1.26 native FIPS 140-3 cryptographic module (GOFIPS140=v1.0.0)
#   - No CGO (pure-Go binary; no system library coupling)
#   - Reproducible build flags (-trimpath, -buildvcs=false, GOFLAGS pinned)
#   - Symbols and debug info stripped (-s -w)
#   - Static binary, statically initialised, no telemetry, no auto-update
#
# Per-target binaries land in dist/.

SHELL := /bin/bash
GO    ?= go

GO_VERSION := $(shell $(GO) env GOVERSION)
GOOS       := $(shell $(GO) env GOOS)
GOARCH     := $(shell $(GO) env GOARCH)

# SOURCE_DATE_EPOCH lets the SBOM and any embedded timestamps reproduce.
# Set this to the timestamp of the release commit for byte-identical builds.
SOURCE_DATE_EPOCH ?= 0

# Common reproducible-build flags. -trimpath erases local paths; -buildvcs=false
# drops VCS stamping; -s -w strips symbol table and DWARF.
REPRO_FLAGS := -trimpath -buildvcs=false -ldflags="-s -w"

VERSION := $(shell awk -F\" '/const version =/ {print $$2}' cmd/fipscan/main.go)

.PHONY: build release release-fips clean verify dogfood reproducibility-check \
        fips-symbols-check sbom checksums release-all info \
        docker-build docker-run docker-stop \
        release-matrix docker-buildx homebrew-formula \
        update-catalog

# Multi-platform release matrix (FIPS-built for every platform).
PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64

info:
	@echo "fipscan $(VERSION)  (Go $(GO_VERSION), $(GOOS)/$(GOARCH))"
	@echo "SOURCE_DATE_EPOCH = $(SOURCE_DATE_EPOCH)"

# Dev build. FIPS-built even in dev so the runtime guard in main.go
# (requireFIPSMode) is satisfied — a non-FIPS dev build now refuses to
# scan, which would be confusing during development.
build:
	@mkdir -p bin
	CGO_ENABLED=0 GOFIPS140=v1.0.0 $(GO) build -o bin/fipscan ./cmd/fipscan

# Stripped, reproducible, FIPS-built release binary for the host platform.
# `release-fips` is kept as a synonym for backward compatibility — every
# fipscan build is now a FIPS build.
release release-fips:
	@mkdir -p dist
	CGO_ENABLED=0 GOFIPS140=v1.0.0 $(GO) build $(REPRO_FLAGS) \
		-o dist/fipscan-$(VERSION)-$(GOOS)-$(GOARCH) ./cmd/fipscan
	@$(MAKE) fips-symbols-check BIN=dist/fipscan-$(VERSION)-$(GOOS)-$(GOARCH)

# Runs the freshly-built binary and queries the embedded FIPS 140-3 module
# at runtime via crypto/fips140.Version(). Works on stripped binaries.
fips-symbols-check:
	@out=$$("$(BIN)" -version); \
	echo "$$out"; \
	echo "$$out" | grep -q 'fips140-module: v1.0.0' || { \
		echo "[FAIL] FIPS 140-3 module not reported by $(BIN)" >&2; exit 1; }
	@echo "[ok] FIPS 140-3 module v1.0.0 linked into $(BIN)"

# Run fipscan against its own source, excluding fixtures and catalog data
# files (where pattern strings appear as literals, not as crypto calls).
# A clean run is the credibility check: the tool itself does not use any
# non-FIPS-approved cryptography.
dogfood: build
	./bin/fipscan -path . \
		-exclude testdata,internal/scan/code/patterns.go,internal/deps/data.go,internal/container/catalog.go,internal/server/alerts.go,cmd/fipscan-osv-import,internal/deps/osv_entries.go,internal/osv/osv.go,internal/findings/waiver_test.go \
		-fail-on low

# Build twice and compare SHA-256. Reproducibility is the prerequisite for
# any meaningful supply-chain attestation. Both builds are FIPS-built so
# the test reflects what we actually ship.
reproducibility-check:
	@mkdir -p /tmp/reprocheck
	CGO_ENABLED=0 GOFIPS140=v1.0.0 $(GO) build $(REPRO_FLAGS) -o /tmp/reprocheck/a ./cmd/fipscan
	CGO_ENABLED=0 GOFIPS140=v1.0.0 $(GO) build $(REPRO_FLAGS) -o /tmp/reprocheck/b ./cmd/fipscan
	@A=$$(shasum -a 256 /tmp/reprocheck/a | awk '{print $$1}'); \
	 B=$$(shasum -a 256 /tmp/reprocheck/b | awk '{print $$1}'); \
	 if [ "$$A" = "$$B" ]; then \
	   echo "[ok] reproducible build — sha256 $$A"; \
	 else \
	   echo "[FAIL] non-reproducible: $$A vs $$B" >&2; exit 1; \
	 fi
	@rm -rf /tmp/reprocheck

# Generate a CycloneDX 1.5 SBOM. With zero third-party dependencies, the
# SBOM is a single primary component declaration plus the toolchain.
sbom:
	@mkdir -p dist
	@./scripts/gen-sbom.sh "$(VERSION)" "$(GO_VERSION)" > dist/fipscan-$(VERSION).cdx.json
	@echo "wrote dist/fipscan-$(VERSION).cdx.json"

# Produce SHA-256 checksums of every artifact in dist/.
checksums:
	@cd dist && shasum -a 256 fipscan-* > SHA256SUMS && \
	 echo "wrote dist/SHA256SUMS:" && cat SHA256SUMS

verify: dogfood reproducibility-check
	@echo "verify: PASS"

release-all: release release-fips sbom checksums
	@echo "release artifacts:" && ls -la dist/

clean:
	rm -rf bin dist

# Build the Docker image (FIPS-built binary on distroless runtime).
# The image's binary is verified at build time to carry the FIPS module.
docker-build:
	docker build -t rbuilta/fipscan:$(VERSION) -t rbuilta/fipscan:latest .

# Run the image bound to localhost (use `docker-run-network` to expose).
docker-run:
	docker run --rm --name fipscan -p 127.0.0.1:8080:8080 \
		-v fipscan-data:/var/lib/fipscan \
		rbuilta/fipscan:$(VERSION)

docker-stop:
	-docker stop fipscan 2>/dev/null
	-docker rm   fipscan 2>/dev/null

# Cross-compile FIPS binaries for every platform in $(PLATFORMS).
# Output names follow Homebrew + GitHub-Release conventions:
#   dist/fipscan-<version>-<os>-<arch>[.exe]
release-matrix:
	@mkdir -p dist
	@for plat in $(PLATFORMS); do \
	  os=$${plat%/*}; arch=$${plat#*/}; \
	  ext=""; [ "$$os" = "windows" ] && ext=".exe"; \
	  out="dist/fipscan-$(VERSION)-$$os-$$arch$$ext"; \
	  echo "→ $$out"; \
	  CGO_ENABLED=0 GOFIPS140=v1.0.0 GOOS=$$os GOARCH=$$arch \
	    $(GO) build $(REPRO_FLAGS) -o $$out ./cmd/fipscan || exit 1; \
	done

# Multi-arch image via buildx. Requires `docker buildx create --use` once.
# Pushes to GHCR; override IMAGE for a different registry.
IMAGE ?= ghcr.io/rbuilta/fipscan
docker-buildx:
	docker buildx build \
	  --platform linux/amd64,linux/arm64 \
	  -t $(IMAGE):$(VERSION) -t $(IMAGE):latest \
	  --push .

# Generate a Homebrew formula populated with the sha256 of each darwin /
# linux binary in dist/. Output to dist/fipscan.rb for tap distribution.
homebrew-formula:
	@./scripts/gen-homebrew-formula.sh "$(VERSION)" > dist/fipscan.rb
	@echo "wrote dist/fipscan.rb (publish to your homebrew-tap repo)"

# Refresh internal/deps/osv_entries.go from osv.dev's bulk dumps.
# Downloads each OSV ecosystem ZIP, filters to crypto-relevant CVEs,
# and writes a new generated Go source file. The output is committed —
# fipscan is single-binary so the catalog ships with the build.
update-catalog:
	$(GO) run ./cmd/fipscan-osv-import > internal/deps/osv_entries.go
	$(GO) fmt ./internal/deps/osv_entries.go
	@echo "regenerated internal/deps/osv_entries.go ($(shell wc -l < internal/deps/osv_entries.go) lines)"
