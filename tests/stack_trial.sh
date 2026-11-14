#!/usr/bin/env bash
# Story 1.6: try the secured data stack on roberto-server without touching the live one. Run as roberto:
#   bash tests/stack_trial.sh [backend image]
# It issues a throwaway authority and throwaway credentials in a temporary folder, deploys a renamed copy
# of infra/compose.yaml (project gmshield-trial, containers trial-*, networks gmtrial-* on 172.29.0.0/16,
# no external volume, registry on 127.0.0.1:15999) with deploy/stack.sh, runs tests/stack_check.sh
# against it, and with a backend image also starts that image the way the pipeline deploys it and waits
# for its health. Everything it created is removed at the end, including the trial's own volumes.
set -euo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO=$(dirname "$HERE")
BACKEND_IMAGE=${1:-}
T=$(mktemp -d "${TMPDIR:-/tmp}/gmshield-trial.XXXXXX")
export GMSHIELD_HOME=$T/ci GMSHIELD_STACK=$T/stack GMSHIELD_INFRA=$T/infra
export STACK_CHECK_PREFIX=trial- STACK_CHECK_NETS=gmtrial-
compose() { docker compose --project-directory "$GMSHIELD_STACK" -f "$GMSHIELD_STACK/compose.yaml" "$@"; }
cleanup() {
  set +e
  docker rm -f trial-backend >/dev/null 2>&1
  [ -f "$GMSHIELD_STACK/compose.yaml" ] && compose down -v --remove-orphans >/dev/null 2>&1
  rm -rf "$T"
}
trap cleanup EXIT

cp -r "$REPO/infra" "$T/infra"
sed -i -e 's/^name: rpg$/name: gmshield-trial/' \
       -e 's/container_name: \(.*\)/container_name: trial-\1/' \
       -e 's/name: gmshield-/name: gmtrial-/' \
       -e 's/172\.30\./172.29./g' \
       -e 's/external: true.*/external: false/' \
       -e 's/127\.0\.0\.1:5000:5000/127.0.0.1:15999:5000/' "$T/infra/compose.yaml"
if grep -qE 'external: true|name: gmshield-|172\.30\.|^name: rpg' "$T/infra/compose.yaml"; then
  echo "the trial copy still names a live resource; stopping" >&2; exit 1
fi

bash "$REPO/deploy/certs.sh" issue >/dev/null
bash "$REPO/deploy/data-credentials.sh" >/dev/null
bash "$REPO/deploy/stack.sh" up
rc=0
bash "$HERE/stack_check.sh" || rc=1

if [ -n "$BACKEND_IMAGE" ]; then
  echo; echo "== The backend image $BACKEND_IMAGE, deployed as the pipeline does"
  docker create --name trial-backend --network gmtrial-app --env-file "$GMSHIELD_HOME/secrets/backend.env" \
    --read-only --user 10001:10001 --cap-drop ALL --security-opt no-new-privileges --tmpfs /tmp \
    -v "$GMSHIELD_HOME/certs/backend:/run/gmshield/certs:ro" "$BACKEND_IMAGE" >/dev/null
  for n in gmtrial-data gmtrial-work gmtrial-outbound; do docker network connect "$n" trial-backend; done
  docker start trial-backend >/dev/null
  zap=$(sed -n 's/^zap *= *"\(.*\)".*/\1/p' "$REPO/tools.toml")
  if docker run --rm --network gmtrial-app --entrypoint sh "$zap" -c \
       'for i in $(seq 1 60); do curl -fsS -m 5 http://trial-backend:8080/actuator/health && exit 0; sleep 3; done; exit 1'; then
    echo; echo "PASS  the backend is healthy: Postgres (verify-full) and Redis (TLS, account backend)"
  else
    echo "FAIL  the backend is not healthy; its log:"; docker logs --tail 40 trial-backend 2>&1; rc=1
  fi
  [ -z "$(docker port trial-backend)" ] && echo "PASS  the backend publishes no host port" || { echo "FAIL  host port"; rc=1; }
fi
exit "$rc"
