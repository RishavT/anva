#!/bin/sh
set -eu

project="anva-local-digest-registry-test-$$"
registry_one="${project}-one"
registry_two="${project}-two"
owner_label="com.anva.release.owner"
registry_image="registry:2@sha256:a3d8aaa63ed8681a604f1dea0aa03f100d5895b6a58ace528858a7b332415373"
mismatch_image="aquasec/trivy:0.64.1@sha256:a8ca29078522f30393bdb34225e4c0994d38f37083be81a42da3a2a7e1488e9e"

validate_owner() {
  container=$1
  test "$(docker inspect --format "{{ index .Config.Labels \"$owner_label\" }}" "$container")" = "$project"
}

cleanup() {
  for container in "$registry_one" "$registry_two"; do
    if docker container inspect "$container" >/dev/null 2>&1; then
      validate_owner "$container" || return 1
      docker rm --force "$container" >/dev/null
    fi
  done
}
trap cleanup EXIT HUP INT TERM

start_registry() {
  container=$1
  if docker container inspect "$container" >/dev/null 2>&1; then
    return 1
  fi
  docker run --detach \
    --name "$container" \
    --label "$owner_label=$project" \
    --read-only \
    --cap-drop ALL \
    --security-opt no-new-privileges \
    --tmpfs /var/lib/registry:rw,nosuid,nodev,noexec,size=1g \
    --publish 127.0.0.1::5000 \
    "$registry_image" >/dev/null
  validate_owner "$container"
  test "$(docker inspect --format '{{.HostConfig.ReadonlyRootfs}}' "$container")" = true
  test "$(docker inspect --format '{{json .HostConfig.CapDrop}}' "$container")" = '["ALL"]'
  test "$(docker inspect --format '{{json .HostConfig.SecurityOpt}}' "$container")" = '["no-new-privileges"]'
  tmpfs_config=$(docker inspect --format '{{json .HostConfig.Tmpfs}}' "$container")
  printf '%s\n' "$tmpfs_config" | grep -q '"/var/lib/registry"'
  printf '%s\n' "$tmpfs_config" | grep -Eq 'size=(1g|1073741824)'

  address=$(docker port "$container" 5000/tcp)
  case "$address" in
    127.0.0.1:[0-9]*) ;;
    *) return 1 ;;
  esac
  ready=false
  attempt=0
  while [ "$attempt" -lt 20 ]; do
    if curl --fail --silent "http://${address}/v2/" >/dev/null; then
      ready=true
      break
    fi
    attempt=$((attempt + 1))
    sleep 1
  done
  test "$ready" = true
  printf '%s\n' "$address"
}

push_digest() {
  source_image=$1
  destination=$2
  log_file=$3
  docker tag "$source_image" "$destination"
  docker push "$destination" >"$log_file"
  digest=$(sed -n 's/^.*digest: \(sha256:[a-f0-9]\{64\}\).*$/\1/p' "$log_file" | tail -1)
  case "$digest" in
    sha256:????????????????????????????????????????????????????????????????) ;;
    *) return 1 ;;
  esac
  printf '%s\n' "$digest"
}

verify_published_digest() {
  expected=$1
  published=$2
  test "$published" = "$expected"
}

# Exact-name foreign resources must be refused and preserved.
docker run --detach \
  --name "$registry_one" \
  --label "$owner_label=${project}-foreign" \
  --read-only --cap-drop ALL --security-opt no-new-privileges \
  --tmpfs /var/lib/registry:rw,nosuid,nodev,noexec,size=1g \
  "$registry_image" >/dev/null
if start_registry "$registry_one"; then
  echo "registry startup unexpectedly reused a foreign exact-name container" >&2
  exit 1
fi
test "$(docker inspect --format "{{ index .Config.Labels \"$owner_label\" }}" "$registry_one")" = "${project}-foreign"
docker rm --force "$registry_one" >/dev/null

address_one=$(start_registry "$registry_one")
address_two=$(start_registry "$registry_two")

digest_one=$(push_digest "$registry_image" "${address_one}/anva:0.1.0" "/tmp/${project}-one.log")
digest_two=$(push_digest "$registry_image" "${address_two}/anva:0.1.0" "/tmp/${project}-two.log")
verify_published_digest "$digest_one" "$digest_two"

# A changed final candidate must fail the exact digest comparison.
mismatch_digest=$(push_digest "$mismatch_image" "${address_two}/anva:mismatch" "/tmp/${project}-mismatch.log")
test "$mismatch_digest" != "$digest_one"
if verify_published_digest "$digest_one" "$mismatch_digest"; then
  echo "digest mismatch unexpectedly passed the publication guard" >&2
  exit 1
fi

# Two 1 GiB registry tmpfs mounts plus both source images remain below 5 GiB.
registry_bytes=$(docker image inspect "$registry_image" --format '{{.Size}}')
mismatch_bytes=$(docker image inspect "$mismatch_image" --format '{{.Size}}')
test $((registry_bytes + mismatch_bytes + 2147483648)) -lt 5368709120

rm -f "/tmp/${project}-one.log" "/tmp/${project}-two.log" "/tmp/${project}-mismatch.log"
cleanup
trap - EXIT HUP INT TERM
test -z "$(docker ps -aq --filter "name=${project}")"
