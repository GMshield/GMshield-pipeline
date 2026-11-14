#!/usr/bin/env bash
# Story 1.6: every row of the I/O matrix against the live data stack on roberto-server. Run as roberto:
#   bash tests/stack_check.sh
# Each check prints PASS, FAIL or SKIP; the exit status is 1 when any check fails. Nothing secret is
# printed or put on a command line: passwords reach the check containers through the environment.
# Side effects, all harmless: the backend's consumer group `workers` exists on both work streams
# afterwards (the backend creates it anyway), and certs.sh/data-credentials.sh rerun (they change nothing).
#
# tests/stack_trial.sh runs it against a throwaway copy of the stack with these overrides:
#   STACK_CHECK_PREFIX  container-name prefix (default none)    STACK_CHECK_NETS  network prefix (default gmshield-)
#   GMSHIELD_HOME, GMSHIELD_STACK  as in deploy/*.sh
set -uo pipefail
umask 077

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO=$(dirname "$HERE")
CI_HOME=${GMSHIELD_HOME:-$HOME/gmshield-ci}
STACK=${GMSHIELD_STACK:-$HOME/stack}
PFX=${STACK_CHECK_PREFIX:-}
NET=${STACK_CHECK_NETS:-gmshield-}
CERTS=$CI_HOME/certs
COMPOSE=$STACK/compose.yaml
OLLAMA=172.30.5.1:11434               # production addresses: the Ollama rows always use them
INTERNAL=(edge app data work model)

PASSES=0; FAILS=0; SKIPS=0
pass() { echo "PASS  $*"; PASSES=$((PASSES + 1)); }
fail() { echo "FAIL  $*"; FAILS=$((FAILS + 1)); }
skip() { echo "SKIP  $*"; SKIPS=$((SKIPS + 1)); }
expect() {   # expect <ok|refused> <description> <command...>: ok = exit 0, refused = non-zero exit
  local want=$1 what=$2; shift 2
  if "$@" >/dev/null 2>&1; then [ "$want" = ok ] && pass "$what" || fail "$what (it succeeded)"
  else [ "$want" = refused ] && pass "$what" || fail "$what (it was refused)"; fi
}
section() { echo; echo "== $*"; }
value() { [ -f "$1" ] && sed -n "s/^$2=//p" "$1" | tail -n 1 || true; }
image_of() { sed -n "s/^ *image: *\(.*$1.*@sha256:[0-9a-f]*\).*/\1/p" "$COMPOSE" | head -n 1; }

[ -f "$COMPOSE" ] || { echo "no $COMPOSE: deploy the stack first (bash deploy/stack.sh up)"; exit 1; }
PG_IMAGE=$(image_of postgres); REDIS_IMAGE=$(image_of redis)
CURL_IMAGE=$(sed -n 's/^zap *= *"\(.*\)".*/\1/p' "$REPO/tools.toml")
[ -n "$PG_IMAGE" ] && [ -n "$REDIS_IMAGE" ] && [ -n "$CURL_IMAGE" ] || { echo "cannot find the check images"; exit 1; }

export PGPASSWORD REDISCLI_AUTH QAPI
BACKEND_ENV=$CI_HOME/secrets/backend.env
WORKER_ENV=$CI_HOME/secrets/worker.env
CA=$CERTS/backend/ca.crt
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
# An authority nobody trusts, for the "unverified certificate" rows.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -noenc -keyout "$TMP/other.key" \
  -out "$TMP/other.crt" -days 2 -subj "/CN=another authority" >/dev/null 2>&1
chmod 644 "$TMP/other.crt"; chmod 755 "$TMP"

# psql <network> <ca file> <conninfo> <sql>, with $PGPASSWORD
psql_on() { docker run --rm --network "$NET$1" -e PGPASSWORD -v "$2:/ca.crt:ro" "$PG_IMAGE" \
              psql -X -q -t -A "$3 sslrootcert=/ca.crt connect_timeout=8" -c "$4"; }
# rcli <ca file> <redis-cli args...>, with $REDISCLI_AUTH; prints the reply
rcli() { local ca=$1; shift; docker run --rm --network "${NET}work" -e REDISCLI_AUTH -v "$ca:/ca.crt:ro" \
           "$REDIS_IMAGE" redis-cli --no-auth-warning -h redis "$@"; }
reply_has() { local want=$1; shift; "$@" 2>&1 | grep -q -- "$want"; }
# curl_on <network> <ca file> <url> [with-key]: HTTP status code; the key comes from $QAPI inside
curl_on() {
  local hdr=""; [ "${4:-}" = with-key ] && hdr='-H "api-key: $QAPI"'
  docker run --rm --network "$NET$1" -e QAPI -v "$2:/ca.crt:ro" --entrypoint sh "$CURL_IMAGE" \
    -c "curl -sS -o /dev/null -w '%{http_code}' -m 8 --cacert /ca.crt $hdr '$3'" 2>/dev/null
}
PGI="host=postgres port=5432 dbname=gmshield user=gmshield_backend sslmode=verify-full"
B_DB=$(value "$BACKEND_ENV" GMSHIELD_DB_PASSWORD)
B_REDIS=$(value "$BACKEND_ENV" GMSHIELD_REDIS_PASSWORD)
W_REDIS=$(value "$WORKER_ENV" GMSHIELD_REDIS_PASSWORD)
Q_KEY=$(value "$STACK/.env" QDRANT_API_KEY)
SUPER=$(value "$STACK/.env" POSTGRES_PASSWORD)

section "Right client: its own credential over verified TLS"
PGPASSWORD=$B_DB
out=$(psql_on data "$CA" "$PGI" "select current_user || ' ' || ssl || ' ' || version from pg_stat_ssl where pid = pg_backend_pid()" 2>&1)
case $out in "gmshield_backend t TLSv1.3"|"gmshield_backend true TLSv1.3") pass "postgres: gmshield_backend connects over TLS 1.3, verify-full" ;;
             *) fail "postgres: gmshield_backend over verify-full ($out)" ;; esac
REDISCLI_AUTH=$B_REDIS
reply_has OK rcli "$CA" --tls --cacert /ca.crt --user backend SET gmshield:stack-check ok &&
  pass "redis: backend writes gmshield:stack-check over verified TLS" || fail "redis: backend SET over TLS"
rcli "$CA" --tls --cacert /ca.crt --user backend DEL gmshield:stack-check >/dev/null 2>&1
for s in gmshield:work:interactive gmshield:work:ingestion; do      # the backend creates the group
  rcli "$CA" --tls --cacert /ca.crt --user backend XGROUP CREATE "$s" workers '$' MKSTREAM >/dev/null 2>&1
done
QAPI=$Q_KEY
[ "$(curl_on work "$CERTS/worker/ca.crt" https://qdrant:6333/collections with-key)" = 200 ] &&
  pass "qdrant: the worker's key over verified TLS" || fail "qdrant: the worker's key over verified TLS"
REDISCLI_AUTH=$W_REDIS
out=$(rcli "$CERTS/worker/ca.crt" --tls --cacert /ca.crt --user worker XREADGROUP GROUP workers stack-check COUNT 1 STREAMS gmshield:work:ingestion '>' 2>&1)
case $out in *ERR*|*NOPERM*|*NOAUTH*|*WRONGPASS*|*"Could not"*) fail "redis: worker XREADGROUP on gmshield:work:ingestion ($out)" ;;
             *) pass "redis: worker reads its group on gmshield:work:ingestion" ;; esac
out=$(rcli "$CERTS/worker/ca.crt" --tls --cacert /ca.crt --user worker XPENDING gmshield:work:interactive workers 2>&1)
case $out in *ERR*|*NOPERM*|*NOAUTH*|*WRONGPASS*|*NOGROUP*|*"Could not"*) fail "redis: worker XPENDING on gmshield:work:interactive ($out)" ;;
             *) pass "redis: worker XPENDING on gmshield:work:interactive" ;; esac
REDISCLI_AUTH=$B_REDIS
rcli "$CA" --tls --cacert /ca.crt --user backend XGROUP DELCONSUMER gmshield:work:ingestion workers stack-check >/dev/null 2>&1

section "Wrong credential: refused"
PGPASSWORD=wrong-$B_DB
expect refused "postgres: gmshield_backend with a wrong password" psql_on data "$CA" "$PGI" "select 1"
PGPASSWORD=
expect refused "postgres: gmshield_backend without a password" psql_on data "$CA" "$PGI" "select 1"
PGPASSWORD=$SUPER
expect refused "postgres: superuser rpg over TCP, even with its password" \
  psql_on data "$CA" "host=postgres port=5432 dbname=rpg user=rpg sslmode=verify-full" "select 1"
REDISCLI_AUTH=wrong-$B_REDIS
reply_has PONG rcli "$CA" --tls --cacert /ca.crt --user backend PING && fail "redis: backend with a wrong password answered" ||
  pass "redis: backend with a wrong password"
REDISCLI_AUTH=
reply_has PONG rcli "$CA" --tls --cacert /ca.crt PING && fail "redis: no account answered" ||
  pass "redis: no account (default user is off)"
REDISCLI_AUTH=$B_REDIS
reply_has PONG rcli "$CA" --tls --cacert /ca.crt --user default PING && fail "redis: the default user answered" ||
  pass "redis: the default user is off"
QAPI=""
[ "$(curl_on work "$CA" https://qdrant:6333/collections)" = 401 ] && pass "qdrant: no API key" || fail "qdrant: no API key"
QAPI=wrong-$Q_KEY
[ "$(curl_on work "$CA" https://qdrant:6333/collections with-key)" = 401 ] && pass "qdrant: a wrong API key" ||
  fail "qdrant: a wrong API key"

section "Unverified certificate or plain TCP: handshake fails"
PGPASSWORD=$B_DB
expect refused "postgres: a client trusting another authority" psql_on data "$TMP/other.crt" "$PGI" "select 1"
expect refused "postgres: plain TCP (sslmode=disable)" \
  psql_on data "$CA" "host=postgres port=5432 dbname=gmshield user=gmshield_backend sslmode=disable" "select 1"
PG_IP=$(docker inspect -f "{{(index .NetworkSettings.Networks \"${NET}data\").IPAddress}}" "${PFX}postgres" 2>/dev/null)
if [ -n "$PG_IP" ]; then
  expect refused "postgres: a host name the certificate does not name ($PG_IP)" \
    psql_on data "$CA" "host=$PG_IP port=5432 dbname=gmshield user=gmshield_backend sslmode=verify-full" "select 1"
else fail "postgres: cannot find its address on ${NET}data"; fi
# The server certificates name the service, not its address: a client verifying the host name
# refuses them by IP. curl does the TLS handshake (exit 60 = certificate rejected) before any protocol.
tls_by() {   # tls_by <container> <port>: curl's exit code connecting by IP with the right authority
  local ip; ip=$(docker inspect -f "{{(index .NetworkSettings.Networks \"${NET}work\").IPAddress}}" "$PFX$1" 2>/dev/null)
  [ -n "$ip" ] || { echo none; return; }
  docker run --rm --network "${NET}work" -v "$CA:/ca.crt:ro" --entrypoint curl "$CURL_IMAGE" \
    -sS -o /dev/null -m 8 --cacert /ca.crt "https://$ip:$2/" >/dev/null 2>&1; echo $?
}
for c in "redis 6379" "qdrant 6333"; do
  rc=$(tls_by $c)
  [ "$rc" = 60 ] && pass "${c% *}: a host name the certificate does not name (its IP)" ||
    fail "${c% *}: connecting by IP was not refused by the certificate check (curl exit $rc)"
done
REDISCLI_AUTH=$B_REDIS
reply_has PONG rcli "$CA" --user backend PING && fail "redis: plain TCP answered" || pass "redis: plain TCP"
reply_has PONG rcli "$TMP/other.crt" --tls --cacert /ca.crt --user backend PING && fail "redis: another authority accepted" ||
  pass "redis: a client trusting another authority"
QAPI=$Q_KEY
[ "$(curl_on work "$TMP/other.crt" https://qdrant:6333/collections with-key)" = 000 ] &&
  pass "qdrant: a client trusting another authority" || fail "qdrant: a client trusting another authority"
code=$(curl_on work "$CA" http://qdrant:6333/collections with-key)
[ "$code" != 200 ] && pass "qdrant: plain HTTP ($code)" || fail "qdrant: plain HTTP answered 200"

section "Worker oversteps: NOPERM"
REDISCLI_AUTH=$W_REDIS
wcli() { rcli "$CERTS/worker/ca.crt" --tls --cacert /ca.crt --user worker "$@"; }
reply_has NOPERM wcli GET gmshield:work:ingestion && pass "redis: worker GET" || fail "redis: worker GET"
reply_has NOPERM wcli XADD gmshield:work:ingestion '*' job x && pass "redis: worker XADD" || fail "redis: worker XADD"
reply_has NOPERM wcli KEYS '*' && pass "redis: worker KEYS" || fail "redis: worker KEYS"
reply_has NOPERM wcli XREADGROUP GROUP workers stack-check COUNT 1 STREAMS gmshield:sessions '>' &&
  pass "redis: worker on another key" || fail "redis: worker on another key"
REDISCLI_AUTH=$(value "$STACK/.env" REDIS_PROBE_PASSWORD)
reply_has NOPERM rcli "$CA" --tls --cacert /ca.crt --user probe GET gmshield:x && pass "redis: probe can only PING" ||
  fail "redis: probe can only PING"

section "Ollama from elsewhere"
if docker network inspect gmshield-model >/dev/null 2>&1; then
  addrs=$(ss -Hltn "sport = :11434" 2>/dev/null | awk '{ print $4 }' | sort -u | xargs)
  [ "$addrs" = "$OLLAMA" ] && pass "ollama listens on $OLLAMA alone" || fail "ollama listens on: ${addrs:-nothing} (expected $OLLAMA alone)"
  env=$(systemctl show -p Environment ollama.service 2>/dev/null | tr ' ' '\n')
  [ "$(sed -n 's/^\(Environment=\)\{0,1\}OLLAMA_MAX_LOADED_MODELS=//p' <<<"$env" | tail -n 1)" = 1 ] &&
    pass "ollama: OLLAMA_MAX_LOADED_MODELS=1" || fail "ollama: OLLAMA_MAX_LOADED_MODELS is not 1"
  systemctl show -p After ollama.service 2>/dev/null | grep -q docker.service &&
    pass "ollama starts after Docker" || fail "ollama does not start after Docker"
  tags=$(docker run --rm --network gmshield-model --entrypoint curl "$CURL_IMAGE" -sS -m 8 "http://$OLLAMA/api/tags" 2>/dev/null)
  case $tags in *embeddinggemma*) pass "ollama: reachable from gmshield-model" ;; *) fail "ollama: not reachable from gmshield-model" ;; esac
  case $tags in *qwen3.5*) fail "ollama: qwen3.5:4b is still installed" ;; *embeddinggemma*) pass "ollama: only embeddinggemma:300m" ;;
               *) fail "ollama: model list unreadable" ;; esac
  for n in work data app edge outbound registry; do
    expect refused "ollama: refused from gmshield-$n" docker run --rm --network "gmshield-$n" --entrypoint curl "$CURL_IMAGE" \
      -sS -m 8 "http://$OLLAMA/api/version"
  done
  lan=$(ip -4 -o route get 1.1.1.1 2>/dev/null | sed -n 's/.* src \([0-9.]*\).*/\1/p')
  if [ -n "$lan" ]; then expect refused "ollama: not on the LAN address $lan" curl -sS -m 5 "http://$lan:11434/api/version"
  else fail "ollama: cannot find the server's LAN address"; fi
else skip "ollama rows: the production network gmshield-model does not exist"; fi

section "Expiring certificate: check and deploy warn, exit 0"
H=$TMP/expiry
GMSHIELD_HOME=$H bash "$REPO/deploy/certs.sh" issue >/dev/null 2>&1
printf 'subjectAltName=DNS:redis\n' > "$TMP/ext"
openssl req -new -key "$H/certs/redis/tls.key" -subj /CN=redis -out "$TMP/csr" >/dev/null 2>&1 &&
  openssl x509 -req -in "$TMP/csr" -CA "$H/ca/ca.crt" -CAkey "$H/ca/ca.key" -set_serial 5 -days 20 \
    -extfile "$TMP/ext" -out "$H/certs/redis/tls.crt" >/dev/null 2>&1
out=$(GMSHIELD_HOME=$H bash "$REPO/deploy/certs.sh" check); rc=$?
[ "$rc" = 0 ] && grep -q "WARNING: .*redis/tls.crt expires" <<<"$out" && pass "certs.sh check warns about a leaf with 20 days left (exit 0)" ||
  fail "certs.sh check with a 20-day leaf (exit $rc)"
out=$(cd "$REPO" && python3 -c "
from types import SimpleNamespace as N; from pathlib import Path
from gmshield_ci import stages
print('\n'.join(stages.cert_warnings(N(home=Path('$H'), certs_dir=Path('$H/certs')))))" 2>&1)
grep -q "redis/tls.crt expires" <<<"$out" && pass "the deploy stage carries the same warning" || fail "the deploy stage warning ($out)"
out=$(GMSHIELD_HOME=$CI_HOME bash "$REPO/deploy/certs.sh" check 2>&1)
grep -q WARNING <<<"$out" && fail "the live certificates: $out" || pass "the live certificates: $out"

section "Rerun scripts: kept, reported already done"
sums() { find "$CI_HOME/ca" "$CI_HOME/certs" "$CI_HOME/secrets" "$STACK/.env" "$STACK/redis-users.acl" -type f -print0 2>/dev/null |
         sort -z | xargs -0 sha256sum; }
before=$(sums)
out=$(GMSHIELD_HOME=$CI_HOME bash "$REPO/deploy/certs.sh" issue 2>&1)
grep -q issued <<<"$out" && fail "certs.sh issue issued something on a rerun" || pass "certs.sh issue: already done"
out=$(GMSHIELD_HOME=$CI_HOME GMSHIELD_STACK=$STACK bash "$REPO/deploy/data-credentials.sh" 2>&1)
grep -qE "generated|written" <<<"$out" && fail "data-credentials.sh wrote something on a rerun" || pass "data-credentials.sh: already done"
[ "$before" = "$(sums)" ] && pass "no secret or certificate changed" || fail "a secret or certificate changed on a rerun"

section "No internet except on outbound"
for n in "${INTERNAL[@]}"; do
  if [ "$(docker network inspect -f '{{.Internal}}' "$NET$n" 2>/dev/null)" != true ]; then
    fail "$NET$n is missing or not internal"; continue
  fi
  pass "$NET$n is internal"
  expect refused "no internet on $NET$n" docker run --rm --network "$NET$n" --entrypoint curl "$CURL_IMAGE" -sS -m 8 -o /dev/null https://example.com
done
expect ok "internet on ${NET}outbound" docker run --rm --network "${NET}outbound" --entrypoint curl "$CURL_IMAGE" -sS -m 15 -o /dev/null https://example.com

section "Images, ports and membership"
bad=$(grep -E '^ *image:' "$COMPOSE" | grep -vE 'image: *[^ :@]+:[^ @]+@sha256:[0-9a-f]{64} *$' || true)
[ -z "$bad" ] && pass "every image is pinned version@sha256" || fail "unpinned: $bad"
for c in postgres redis qdrant; do
  [ -z "$(docker port "$PFX$c" 2>/dev/null)" ] && pass "$PFX$c publishes no host port" || fail "$PFX$c publishes a host port"
done
nets() { docker inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}' "$1" 2>/dev/null | xargs; }
[ "$(nets "${PFX}postgres")" = "${NET}data" ] && pass "postgres is on ${NET}data alone" || fail "postgres networks: $(nets "${PFX}postgres")"
[ "$(nets "${PFX}redis")" = "${NET}work" ] && pass "redis is on ${NET}work alone" || fail "redis networks: $(nets "${PFX}redis")"
[ "$(nets "${PFX}qdrant")" = "${NET}work" ] && pass "qdrant is on ${NET}work alone" || fail "qdrant networks: $(nets "${PFX}qdrant")"
for c in gmshield-backend gmshield-frontend gmshield-worker; do
  if docker inspect "$c" >/dev/null 2>&1; then
    [ -z "$(docker port "$c" 2>/dev/null)" ] && pass "$c publishes no host port" || fail "$c publishes a host port"
  fi
done

echo
echo "$PASSES passed, $FAILS failed, $SKIPS skipped"
[ "$FAILS" = 0 ]
