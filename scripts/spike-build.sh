#!/usr/bin/env bash
# Phase-1 spike build loop (D-02).
#
# The local machine has NO JDK and NO Clojure CLI (RESEARCH.md § Environment
# Availability), so the existing build runs INSIDE a container. This wraps the
# unchanged `clojure -T:build uber` task — build.clj already copies all of src/
# and resources/ wholesale, so any new .clj (incl. the spike harness) ships
# automatically. Output: target/starrocks.metabase-driver.jar
#
# Usage:
#   bash scripts/spike-build.sh
#
# Requires: a running Docker daemon. Nothing else on the host.
#
# TLS note: if the host routes container traffic through a TLS-intercepting
# proxy (e.g. Cloudflare WARP / Zero Trust Gateway, or a corporate MITM), the
# container's JDK truststore won't trust the re-signing CA and Maven downloads
# fail with "PKIX path building failed". On macOS this script auto-exports the
# host's trusted root CAs from the keychain and imports them into the container
# truststore before building, so the build works transparently behind such a
# proxy. Set SPIKE_SKIP_CA=1 to disable that.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="clojure:temurin-21-tools-deps"
# Persist the Maven cache across runs so deps are downloaded once, not every build.
M2_VOLUME="starrocks-spike-m2"

CA_MOUNT=()
CA_IMPORT=":"   # no-op by default
CA_BUNDLE=""
cleanup() { [ -n "${CA_BUNDLE}" ] && rm -f "${CA_BUNDLE}" 2>/dev/null || true; }
trap cleanup EXIT

if [ "${SPIKE_SKIP_CA:-0}" != "1" ] && [ "$(uname -s)" = "Darwin" ]; then
  CA_BUNDLE="$(mktemp -t spike-host-ca).pem"
  {
    security find-certificate -a -p /Library/Keychains/System.keychain 2>/dev/null || true
    security find-certificate -a -p ~/Library/Keychains/login.keychain-db 2>/dev/null || true
  } > "${CA_BUNDLE}"
  if [ -s "${CA_BUNDLE}" ]; then
    CA_MOUNT=(-v "${CA_BUNDLE}:/tmp/host-ca.pem:ro")
    # Import each cert; keytool needs unique aliases, so split and loop.
    CA_IMPORT='csplit -z -f /tmp/ca- -b %03d.pem /tmp/host-ca.pem "/-----BEGIN CERTIFICATE-----/" "{*}" >/dev/null 2>&1 || true; for c in /tmp/ca-*.pem; do keytool -importcert -noprompt -trustcacerts -alias "hostca-$(basename "$c" .pem)" -file "$c" -cacerts -storepass changeit >/dev/null 2>&1 || true; done'
    echo "==> Injecting host-trusted root CAs into the container truststore (proxy-safe)."
  fi
fi

echo "==> Building target/starrocks.metabase-driver.jar in ${IMAGE}"
docker run --rm \
  -v "${REPO_ROOT}:/work" \
  -v "${M2_VOLUME}:/root/.m2" \
  "${CA_MOUNT[@]}" \
  -w /work \
  "${IMAGE}" \
  sh -c "${CA_IMPORT}; clojure -T:build uber"

echo "==> Build complete:"
ls -la "${REPO_ROOT}/target/starrocks.metabase-driver.jar"
