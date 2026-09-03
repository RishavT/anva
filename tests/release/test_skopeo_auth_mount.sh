#!/bin/sh
set -eu

skopeo_image="quay.io/skopeo/stable@sha256:9c68e585103448f7e4abb835132ffe9759d7a962a0fa426035775956e7a1e021"
test_root=$(mktemp -d "${TMPDIR:-/tmp}/anva-skopeo-auth-test.XXXXXX")
auth_file="$test_root/auth.json"
image_was_present=false

if docker image inspect "$skopeo_image" >/dev/null 2>&1; then
  image_was_present=true
fi

cleanup() {
  rm -f "$auth_file"
  rmdir "$test_root" 2>/dev/null || true
  if test "$image_was_present" = false && docker image inspect "$skopeo_image" >/dev/null 2>&1; then
    docker image rm "$skopeo_image" >/dev/null
  fi
}
trap cleanup EXIT HUP INT TERM

docker pull "$skopeo_image" >/dev/null
printf '%s\n' '{"auths":{}}' >"$auth_file"
chmod 600 "$auth_file"
runner_uid=$(id -u)
runner_gid=$(id -g)

test "$(stat -c '%u:%g:%a' "$auth_file")" = "$runner_uid:$runner_gid:600"
test "$(docker image inspect "$skopeo_image" --format '{{json .Config.User}}')" = '""'

# The failed release shape must remain unreadable: image-default root has no
# DAC override after all capabilities are dropped, while the file belongs to
# the non-root runner and is intentionally mode 0600.
if test "$runner_uid" -ne 0; then
  if docker run --rm --entrypoint /bin/sh --network none --read-only \
    --cap-drop ALL --security-opt no-new-privileges \
    --mount "type=bind,src=$auth_file,dst=/run/containers/auth.json,readonly" \
    "$skopeo_image" -c 'test -r /run/containers/auth.json'; then
    echo "default container identity unexpectedly read the runner-owned auth file" >&2
    exit 1
  fi
fi

# The publication shape runs as the file owner, preserving mode 0600, a
# read-only bind, dropped capabilities, and no-new-privileges.
docker run --rm --entrypoint /bin/sh --user "$runner_uid:$runner_gid" \
  --network none --read-only --cap-drop ALL --security-opt no-new-privileges \
  --mount "type=bind,src=$auth_file,dst=/run/containers/auth.json,readonly" \
  "$skopeo_image" -c '
    test "$(id -u):$(id -g)" = "'"$runner_uid:$runner_gid"'"
    test -r /run/containers/auth.json
    test ! -w /run/containers/auth.json
    test "$(cat /run/containers/auth.json)" = "{\"auths\":{}}"
  '

cleanup
trap - EXIT HUP INT TERM
test ! -e "$test_root"
