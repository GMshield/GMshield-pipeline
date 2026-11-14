#!/usr/bin/env bash
# GMshield on roberto-server: deploy the data stack from this repository (Story 1.6). Run as roberto.
#
#   bash deploy/stack.sh up       copies infra/ to ~/stack, starts or updates the stack, waits until it
#                                 is healthy, then creates the backend's role and database when absent
#   bash deploy/stack.sh status   the containers, their health and the networks
#
# Before the first `up`: bash deploy/certs.sh issue && bash deploy/data-credentials.sh
# ~/stack keeps .env and redis-users.acl (written by data-credentials.sh); everything else there is
# replaced by infra/ on each `up`, so never edit ~/stack by hand. Nothing secret is ever printed.
set -euo pipefail
umask 077

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
INFRA=${GMSHIELD_INFRA:-$HERE/infra}           # tests and the trial run point these elsewhere
CI_HOME=${GMSHIELD_HOME:-$HOME/gmshield-ci}
STACK=${GMSHIELD_STACK:-$HOME/stack}
export GMSHIELD_CERTS=${GMSHIELD_CERTS:-$CI_HOME/certs}
WAIT=${GMSHIELD_STACK_WAIT:-240}
OLD_NETWORK=rpg_default                        # the shared network before Story 1.6

usage() { echo "Usage: $0 {up|status}" >&2; exit 2; }
[ $# -eq 1 ] || usage
CMD=$1
case $CMD in up|status) ;; *) usage ;; esac

die() { echo "FAILED: $*" >&2; exit 1; }
value() { [ -f "$1" ] && sed -n "s/^$2=//p" "$1" | tail -n 1 || true; }
compose() { docker compose --project-directory "$STACK" -f "$STACK/compose.yaml" "$@"; }

preconditions() {
  local r=() svc f k
  command -v docker >/dev/null || r+=("docker is missing")
  docker compose version >/dev/null 2>&1 || r+=("docker compose is missing")
  [ -f "$INFRA/compose.yaml" ] || r+=("$INFRA/compose.yaml is missing")
  for svc in postgres redis qdrant; do
    for f in tls.crt tls.key ca.crt; do
      [ -s "$GMSHIELD_CERTS/$svc/$f" ] || r+=("$GMSHIELD_CERTS/$svc/$f is missing (run deploy/certs.sh issue)")
    done
  done
  for k in POSTGRES_PASSWORD REDIS_PROBE_PASSWORD QDRANT_API_KEY; do
    [ -n "$(value "$STACK/.env" "$k")" ] || r+=("$k is missing in $STACK/.env (run deploy/data-credentials.sh)")
  done
  [ -s "$STACK/redis-users.acl" ] || r+=("$STACK/redis-users.acl is missing (run deploy/data-credentials.sh)")
  [ -n "$(value "$CI_HOME/secrets/backend.env" GMSHIELD_DB_PASSWORD)" ] ||
    r+=("GMSHIELD_DB_PASSWORD is missing in $CI_HOME/secrets/backend.env (run deploy/data-credentials.sh)")
  if grep -q '^ *external: true' "$INFRA/compose.yaml" 2>/dev/null; then
    docker volume inspect qdrant_data >/dev/null 2>&1 || r+=("the external volume qdrant_data does not exist")
  fi
  if [ "${#r[@]}" -gt 0 ]; then
    for k in "${r[@]}"; do echo "    refused: $k" >&2; done
    exit 1
  fi
}

copy_infra() {   # infra/ -> ~/stack, keeping .env and redis-users.acl
  install -d -m 755 "$STACK" "$STACK/postgres" "$STACK/redis"
  if [ -f "$STACK/compose.yaml" ] && [ ! -e "$STACK/compose.yaml.before-1-6" ] &&
     ! grep -q 'Story 1.6' "$STACK/compose.yaml"; then
    cp -p "$STACK/compose.yaml" "$STACK/compose.yaml.before-1-6"
    echo "    the previous compose.yaml is kept as compose.yaml.before-1-6"
  fi
  install -m 644 "$INFRA/compose.yaml" "$STACK/compose.yaml"
  install -m 755 "$INFRA/postgres/start.sh" "$STACK/postgres/start.sh"
  install -m 644 "$INFRA/postgres/pg_hba.conf" "$INFRA/postgres/pg_ident.conf" "$STACK/postgres/"
  install -m 755 "$INFRA/redis/start.sh" "$STACK/redis/start.sh"
}

# The backend's role and database, created when absent; the password is set from backend.env each time
# (sent on stdin, never on a command line). The superuser logs in on the container's socket only.
init_postgres() {
  local pw sql
  pw=$(value "$CI_HOME/secrets/backend.env" GMSHIELD_DB_PASSWORD)
  case $pw in *[!A-Za-z0-9]*) die "GMSHIELD_DB_PASSWORD holds characters other than letters and digits" ;; esac
  sql=$(cat <<SQL
\\set ON_ERROR_STOP on
SELECT 'CREATE ROLE gmshield_backend LOGIN' WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'gmshield_backend') \\gexec
ALTER ROLE gmshield_backend WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '$pw';
SELECT 'CREATE DATABASE gmshield OWNER gmshield_backend' WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'gmshield') \\gexec
ALTER DATABASE gmshield OWNER TO gmshield_backend;
REVOKE ALL ON DATABASE gmshield FROM PUBLIC;
REVOKE ALL ON DATABASE rpg FROM PUBLIC;
SQL
)
  printf '%s\n' "$sql" | compose exec -T -u postgres postgres psql -X -q -U rpg -d rpg >/dev/null ||
    die "could not create the backend's role and database"
}

wait_healthy() {
  local i bad
  for i in $(seq 1 $((WAIT / 3))); do
    bad=""
    for c in postgres redis qdrant; do
      [ "$(compose ps --format '{{.Health}}' "$c" 2>/dev/null)" = healthy ] || bad="$bad $c"
    done
    [ -z "$bad" ] && return 0
    sleep 3
  done
  echo "    not healthy after ${WAIT}s:$bad" >&2
  for c in $bad; do compose logs --tail 20 "$c" >&2 || true; done
  return 1
}

cmd_up() {
  echo "==> 1/5 Preconditions"; preconditions; echo "    ok"
  echo "==> 2/5 Copy infra/ to $STACK"; copy_infra; echo "    done"
  echo "==> 3/5 Start or update the stack"
  compose up -d --quiet-pull 2>&1 | sed 's/^/    /'
  echo "==> 4/5 Wait until postgres, redis and qdrant are healthy"
  wait_healthy || die "the data stack is not healthy"
  echo "    healthy"
  echo "==> 5/5 The backend's role and database"
  init_postgres; echo "    gmshield_backend owns gmshield"
  if docker network inspect "$OLD_NETWORK" >/dev/null 2>&1 &&
     [ "$(docker network inspect -f '{{len .Containers}}' "$OLD_NETWORK")" = 0 ]; then
    docker network rm "$OLD_NETWORK" >/dev/null && echo "    removed the empty network $OLD_NETWORK"
  fi
  echo "DONE: check it with: bash tests/stack_check.sh"
}

cmd_status() {
  compose ps --format 'table {{.Name}}\t{{.Status}}\t{{.Ports}}' 2>/dev/null || echo "the stack is not deployed"
  docker network ls --filter name=gmshield- --format '{{.Name}} internal={{.Internal}}'
}

case $CMD in
  up) cmd_up ;;
  status) cmd_status ;;
esac
