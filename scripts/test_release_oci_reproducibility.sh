#!/usr/bin/env bash
set -euo pipefail

: "${ANVA_BUILDKIT_IMAGE:?set the reviewed digest-pinned BuildKit image}"
test "$(uname -m)" = x86_64
test -n "${ANVA_REVISION:?set the exact source commit}"
test -n "${SOURCE_DATE_EPOCH:?set the exact source epoch}"
test -n "${ANVA_BUILD_INPUT_SHA256:?set the exact build-input hash}"
[[ "$ANVA_BUILD_INPUT_SHA256" =~ ^[a-f0-9]{64}$ ]]

test_root="$(mktemp -d /tmp/anva-oci-repro.XXXXXX)"
builders=()
cleanup() {
  docker buildx rm "${builders[@]}" >/dev/null 2>&1 || true
  find "$test_root" -mindepth 1 -delete
  rmdir "$test_root"
}
trap cleanup EXIT

build() {
  local name="$1" input="$2" output="$3"
  local builder="anva-oci-repro-${name}-$$"
  builders+=("$builder")
  docker buildx create --name "$builder" --driver docker-container \
    --driver-opt "image=$ANVA_BUILDKIT_IMAGE" --use >/dev/null
  docker buildx inspect --bootstrap >/dev/null
  ANVA_BUILD_INPUT_SHA256="$input" ANVA_OCI_OUTPUT="$output" \
    ANVA_OCI_BUILD_FLAGS=--no-cache make release-image-oci
  docker buildx rm "$builder" >/dev/null
}

changed="${ANVA_BUILD_INPUT_SHA256}"
replacement=0
test "${changed:0:1}" = 0 && replacement=1
changed="${replacement}${changed:1}"

build first "$ANVA_BUILD_INPUT_SHA256" "$test_root/first.tar"
build same "$ANVA_BUILD_INPUT_SHA256" "$test_root/same.tar"
build changed "$changed" "$test_root/changed.tar"
python3 scripts/verify_release_oci.py "$test_root/first.tar" \
  --compare "$test_root/same.tar" --output "$test_root/first.json"
python3 scripts/verify_release_oci.py "$test_root/changed.tar" \
  --output "$test_root/changed.json"
for field in archive_sha256 manifest_digest config_digest; do
  test "$(jq -r ".$field" "$test_root/first.json")" != \
    "$(jq -r ".$field" "$test_root/changed.json")"
done
