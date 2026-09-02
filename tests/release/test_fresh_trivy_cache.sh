#!/bin/sh
set -eu

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
project="anva-release-cache-test-$$"
cache_volume="${project}_release-trivy-cache"
trivy_image="aquasec/trivy:0.64.1@sha256:a8ca29078522f30393bdb34225e4c0994d38f37083be81a42da3a2a7e1488e9e"
ANVA_TRIVY_CACHE_DIR=/tmp
export ANVA_TRIVY_CACHE_DIR
runner_uid=$(id -u)
runner_gid=$(id -g)
docker_gid=$(stat -c '%g' /var/run/docker.sock)
ANVA_DOCKER_GID=$docker_gid
export ANVA_DOCKER_GID
compose="docker compose -f compose.yaml -f compose.release.yaml -f compose.release.cache.yaml -p $project"
foreign_project="${project}-foreign"
foreign_volume_label="foreign-cache"

validate_cache_volume() {
  test "$(docker volume inspect --format '{{ index .Labels "com.docker.compose.project" }}' "$cache_volume")" = "$project"
  test "$(docker volume inspect --format '{{ index .Labels "com.docker.compose.volume" }}' "$cache_volume")" = "release-trivy-cache"
}

cleanup() {
  if docker volume inspect "$cache_volume" >/dev/null 2>&1; then
    validate_cache_volume || return 1
  fi
  $compose --profile release down --volumes --remove-orphans >/dev/null 2>&1 || true
  if docker volume inspect "$cache_volume" >/dev/null 2>&1; then
    validate_cache_volume
    docker volume rm "$cache_volume" >/dev/null
  fi
}

final_cleanup() {
  if ! docker volume inspect "$cache_volume" >/dev/null 2>&1; then
    cleanup
    return
  fi
  if validate_cache_volume; then
    cleanup
    return
  fi
  project_label=$(docker volume inspect \
    --format '{{ index .Labels "com.docker.compose.project" }}' "$cache_volume")
  volume_label=$(docker volume inspect \
    --format '{{ index .Labels "com.docker.compose.volume" }}' "$cache_volume")
  test "$project_label" = "$foreign_project"
  test "$volume_label" = "$foreign_volume_label"
  docker volume rm "$cache_volume" >/dev/null
}
trap final_cleanup EXIT HUP INT TERM

prepare_cache_volume() {
  if docker volume inspect "$cache_volume" >/dev/null 2>&1; then
    return 1
  fi
  created_volume=$(docker volume create \
    --label "com.docker.compose.project=$project" \
    --label "com.docker.compose.volume=release-trivy-cache" \
    "$cache_volume")
  test "$created_volume" = "$cache_volume"
  docker run --rm \
    --user "$runner_uid:$runner_gid" \
    --env "EXPECTED_UID=$runner_uid" \
    --env "EXPECTED_GID=$runner_gid" \
    --env "TRIVY_CACHE_DIR=$ANVA_TRIVY_CACHE_DIR" \
    --read-only \
    --cap-drop ALL \
    --security-opt no-new-privileges \
    --network none \
    --mount "type=volume,src=${cache_volume},dst=${ANVA_TRIVY_CACHE_DIR}" \
    --entrypoint /bin/sh \
    "$trivy_image" -eu -c '
      test "$(id -u)" = "$EXPECTED_UID"
      test "$(id -g)" = "$EXPECTED_GID"
      umask 077
      mkdir "$TRIVY_CACHE_DIR/fanal"
      test -w "$TRIVY_CACHE_DIR/fanal"
      test "$(stat -c "%u:%g" "$TRIVY_CACHE_DIR/fanal")" = "$EXPECTED_UID:$EXPECTED_GID"
    '
}

run_tagged_scanner() {
  docker run --rm \
    --user "$runner_uid:$runner_gid" \
    --group-add "$docker_gid" \
    --env HOME=/tmp \
    --env "TRIVY_CACHE_DIR=$ANVA_TRIVY_CACHE_DIR" \
    --read-only \
    --cap-drop ALL \
    --security-opt no-new-privileges \
    --mount "type=volume,src=${cache_volume},dst=${ANVA_TRIVY_CACHE_DIR}" \
    --mount type=bind,src=/var/run/docker.sock,dst=/var/run/docker.sock,readonly \
    "$trivy_image" image --scanners vuln --skip-version-check \
      --skip-java-db-update --format json "$trivy_image"
}

cd "$repository_root"
$compose --profile release config --format json | python3 -c '
import json, sys
scanner = json.load(sys.stdin)["services"]["release-scanner"]
assert scanner["environment"]["TRIVY_CACHE_DIR"] == "/tmp"
mounts = [item for item in scanner["volumes"] if item["type"] == "volume"]
assert len(mounts) == 1
assert mounts[0]["target"] == scanner["environment"]["TRIVY_CACHE_DIR"]
'
test -z "$(docker ps -aq --filter "label=com.docker.compose.project=$project")"
test -z "$(docker volume ls -q --filter "label=com.docker.compose.project=$project")"
test -z "$(docker network ls -q --filter "label=com.docker.compose.project=$project")"

# Cleanup must refuse and preserve an exact-name collision with foreign labels.
docker volume create \
  --label "com.docker.compose.project=$foreign_project" \
  --label "com.docker.compose.volume=$foreign_volume_label" \
  "$cache_volume" >/dev/null
if cleanup; then
  echo "cleanup unexpectedly accepted a foreign cache volume" >&2
  exit 1
fi
test -n "$(docker volume inspect --format '{{.Name}}' "$cache_volume")"
test "$(docker volume inspect --format '{{ index .Labels "com.docker.compose.project" }}' "$cache_volume")" = "$foreign_project"
test "$(docker volume inspect --format '{{ index .Labels "com.docker.compose.volume" }}' "$cache_volume")" = "$foreign_volume_label"
docker volume rm "$cache_volume" >/dev/null

# The workflow-owned first mount at the canonical mode-1777 root prepares the volume.
prepare_cache_volume
test "$(docker volume inspect --format '{{ index .Labels "com.docker.compose.project" }}' "$cache_volume")" = "$project"
test "$(docker volume inspect --format '{{ index .Labels "com.docker.compose.volume" }}' "$cache_volume")" = "release-trivy-cache"
if prepare_cache_volume; then
  echo "cache preparation unexpectedly reused a pre-existing volume" >&2
  exit 1
fi

run_tagged_scanner >/dev/null
docker run --rm --user "$runner_uid:$runner_gid" --read-only --cap-drop ALL \
  --security-opt no-new-privileges --network none \
  --env "TRIVY_CACHE_DIR=$ANVA_TRIVY_CACHE_DIR" \
  --mount "type=volume,src=${cache_volume},dst=${ANVA_TRIVY_CACHE_DIR}" \
  --entrypoint /bin/sh "$trivy_image" -eu -c '
    test -s "$TRIVY_CACHE_DIR/db/metadata.json"
    cp "$TRIVY_CACHE_DIR/db/metadata.json" "$TRIVY_CACHE_DIR/copied-metadata.json"
    test -s "$TRIVY_CACHE_DIR/copied-metadata.json"
    test -s "$TRIVY_CACHE_DIR/fanal/fanal.db"
    printf "%s\n" cache-reuse-boundary > "$TRIVY_CACHE_DIR/fanal/anva-test"
  '
run_tagged_scanner >/dev/null
docker run --rm --user "$runner_uid:$runner_gid" --read-only --cap-drop ALL \
  --security-opt no-new-privileges --network none \
  --env "TRIVY_CACHE_DIR=$ANVA_TRIVY_CACHE_DIR" \
  --mount "type=volume,src=${cache_volume},dst=${ANVA_TRIVY_CACHE_DIR}" \
  --entrypoint /bin/sh "$trivy_image" -eu -c '
    test -s "$TRIVY_CACHE_DIR/db/metadata.json"
    test -s "$TRIVY_CACHE_DIR/copied-metadata.json"
    test "$(cat "$TRIVY_CACHE_DIR/fanal/anva-test")" = cache-reuse-boundary
    test -s "$TRIVY_CACHE_DIR/fanal/fanal.db"
  '

cleanup
trap - EXIT HUP INT TERM
test -z "$(docker ps -aq --filter "label=com.docker.compose.project=$project")"
test -z "$(docker volume ls -q --filter "label=com.docker.compose.project=$project")"
test -z "$(docker network ls -q --filter "label=com.docker.compose.project=$project")"
