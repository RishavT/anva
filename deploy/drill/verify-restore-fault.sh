#!/bin/sh
set -eu

status=${1:?restore exit status required}
log=${2:?restore log required}
writers=${3-}
project=${4:?exact drill project required}
image=${5:?exact drill image required}

test "$status" -eq 44 || {
  echo "restore fault must exit exactly 44 (received $status)" >&2
  exit 1
}
service_output="$(
  awk -v project="$project" -v image="$image" '
    {
      sub(/^[[:space:]]+/, "")
      sub(/[[:space:]]+$/, "")
    }
    /^$/ { next }
    $0 == "Image " image " Pulling" || $0 == "Image " image " Pulled" { next }
    index($0, "Container " project "-restore-objects-run-") == 1 {
      suffix = substr($0, length("Container " project "-restore-objects-run-") + 1)
      if (suffix ~ /^[[:xdigit:]]{12} (Creating|Created)$/) { next }
    }
    { print }
  ' "$log"
)"
test "$service_output" = DRILL_OBJECT_RESTORE_FAULT || {
  echo "restore fault marker missing or ambiguous" >&2
  exit 1
}
test -z "$writers" || {
  echo "writers resumed after failed restore" >&2
  exit 1
}
printf '%s\n' '{"check_code":"RESTORE_FAULT","exit_code":44,"marker_code":"DRILL_OBJECT_RESTORE_FAULT","outcome":"PASS","writers_running":0}'
