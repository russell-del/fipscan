#!/usr/bin/env bash
# Emit a Homebrew formula populated with the sha256 of every release
# binary in dist/. Output the formula to stdout.
#
# Usage: gen-homebrew-formula.sh <version>
#
# Publish the resulting file as Formula/fipscan.rb in your homebrew-tap
# repo (e.g. github.com/russell-del/homebrew-tap). Users then:
#   brew tap russell-del/tap
#   brew install fipscan

set -euo pipefail
VERSION="${1:?usage: gen-homebrew-formula.sh <version>}"
BASE_URL="https://github.com/russell-del/fipscan/releases/download/v${VERSION}"

sha() {
  shasum -a 256 "dist/$1" 2>/dev/null | awk '{print $1}'
}

DA64=$(sha "fipscan-${VERSION}-darwin-arm64")
DI64=$(sha "fipscan-${VERSION}-darwin-amd64")
LA64=$(sha "fipscan-${VERSION}-linux-arm64")
LI64=$(sha "fipscan-${VERSION}-linux-amd64")

cat <<RUBY
class Fipscan < Formula
  desc "FIPS 140-3 readiness scanner for source code, dependency manifests, and container images"
  homepage "https://github.com/russell-del/fipscan"
  version "${VERSION}"
  license "MIT"

  on_macos do
    on_arm do
      url "${BASE_URL}/fipscan-${VERSION}-darwin-arm64"
      sha256 "${DA64}"
    end
    on_intel do
      url "${BASE_URL}/fipscan-${VERSION}-darwin-amd64"
      sha256 "${DI64}"
    end
  end

  on_linux do
    on_arm do
      url "${BASE_URL}/fipscan-${VERSION}-linux-arm64"
      sha256 "${LA64}"
    end
    on_intel do
      url "${BASE_URL}/fipscan-${VERSION}-linux-amd64"
      sha256 "${LI64}"
    end
  end

  def install
    bin.install Dir["fipscan-*"].first => "fipscan"
  end

  test do
    output = shell_output("#{bin}/fipscan -version")
    assert_match "fipscan ${VERSION}", output
    assert_match "fips140-module: v1.0.0", output
  end
end
RUBY
