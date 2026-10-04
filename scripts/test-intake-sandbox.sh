#!/usr/bin/env bash
set -euo pipefail

clam_image='clamav/clamav:1.5.4@sha256:ebec5bc138401b36ae987caa1a3fa3c3b2a21ed3d51f0bfa5852825e663e67b0'
tika_image='apache/tika:3.3.1.0-full@sha256:d8e6ed96260ad89307a93195a1b856102987a818ac648502f8efbaf313d32470'
runner_image='alpine:3.22.2@sha256:4b7ce07002c69e8f3d704a9c5d6fd3053be500b7f1c69fc0d80990c2ad8dd412'
suffix="$$"
network="keel-intake-contract-${suffix}"
clam_container="keel-intake-clamav-${suffix}"
tika_container="keel-intake-tika-${suffix}"
runner_container="keel-intake-runner-${suffix}"
test_bin="$(mktemp /tmp/keel-intake-contract.XXXXXX)"

cleanup() {
  docker rm -f "$clam_container" "$tika_container" "$runner_container" >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
  rm -f "$test_bin"
}
trap cleanup EXIT INT TERM

# Pull before creating the internal-only network. Parser/scanner/runner containers then have no egress.
docker pull "$clam_image"
docker pull "$tika_image"
docker pull "$runner_image"
docker network create --internal "$network" >/dev/null
docker run -d --name "$clam_container" --network "$network" --network-alias clamav \
  --cpus 1 --memory 1536m --memory-swap 1536m --pids-limit 128 \
  --security-opt no-new-privileges --tmpfs /tmp:rw,nosuid,nodev,size=128m "$clam_image" >/dev/null
docker run -d --name "$tika_container" --network "$network" --network-alias tika \
  --cpus 1.5 --memory 1g --memory-swap 1g --pids-limit 128 \
  --security-opt no-new-privileges --cap-drop ALL --read-only \
  --tmpfs /tmp:rw,nosuid,nodev,size=256m "$tika_image" >/dev/null

CGO_ENABLED=0 go test -c -o "$test_bin" ./internal/supplier/intake
docker create --name "$runner_container" --network "$network" --memory 512m --memory-swap 512m --pids-limit 64 \
  --env KEEL_TEST_CLAMD_ADDRESS=clamav:3310 \
  --env KEEL_TEST_TIKA_ENDPOINT=http://tika:9998 \
  "$runner_image" /tmp/intake.test -test.run '^TestPinnedSandboxServicesScanAndExtract$' -test.count=1 -test.timeout=3m >/dev/null
docker cp "$test_bin" "$runner_container:/tmp/intake.test"
docker start --attach "$runner_container"
