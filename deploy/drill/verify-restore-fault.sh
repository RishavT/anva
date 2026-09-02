#!/bin/sh
set -eu

status=${1:?restore exit status required}
log=${2:?restore log required}
writers=${3-}

test "$status" -eq 44 || {
  echo "restore fault must exit exactly 44 (received $status)" >&2
  exit 1
}
test "$(sed '/^$/d' "$log")" = DRILL_OBJECT_RESTORE_FAULT || {
  echo "restore fault marker missing or ambiguous" >&2
  exit 1
}
test -z "$writers" || {
  echo "writers resumed after failed restore" >&2
  exit 1
}
printf '%s\n' '{"check_code":"RESTORE_FAULT","exit_code":44,"marker_code":"DRILL_OBJECT_RESTORE_FAULT","outcome":"PASS","writers_running":0}'
