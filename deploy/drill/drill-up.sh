#!/bin/sh
set -eu

project=${DRILL_PROJECT:?DRILL_PROJECT is required}
test "$project" != anva || {
  echo "DRILL_PROJECT must be disposable" >&2
  exit 2
}

complete=false
cleanup() {
  status=$1
  trap - EXIT HUP INT TERM
  if test "$complete" != true; then
    docker compose -p "$project" -f compose.yaml -f compose.drill.yaml \
      --profile drill-tools --profile operations down --volumes --remove-orphans || true
  fi
  exit "$status"
}
trap 'cleanup $?' EXIT
trap 'cleanup 129' HUP
trap 'cleanup 130' INT
trap 'cleanup 143' TERM

docker compose -p "$project" -f compose.yaml -f compose.drill.yaml run --rm drill-certgen
docker compose -p "$project" -f compose.yaml -f compose.drill.yaml run --rm migrate
docker compose -p "$project" -f compose.yaml -f compose.drill.yaml \
  up -d --wait postgres minio api worker drill-tls
complete=true
trap - EXIT HUP INT TERM
