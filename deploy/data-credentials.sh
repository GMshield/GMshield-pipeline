#!/usr/bin/env bash
# GMshield on roberto-server: one credential per client of the data services (AD-23, Story 1.6).
# Run as roberto, no sudo: bash deploy/data-credentials.sh
#
# Writes, creating only what is missing (a rerun changes nothing and says "already done"):
#   ~/stack/.env                       the stack's own secrets: POSTGRES_PASSWORD (superuser rpg, local
#                                      socket only), REDIS_PROBE_PASSWORD (health check, PING only),
#                                      QDRANT_API_KEY (Qdrant's one key)
#   ~/gmshield-ci/secrets/backend.env  Postgres role gmshield_backend (TLS, verify-full), Redis account backend,
#                                      the vault's master and index keys (Story 1.7, AD-19), the frontend's
#                                      service credential (Story 1.10), the worker's credential (Story 1.12),
#                                      and empty placeholders for the Google OAuth client id and secret
#                                      (Story 1.9), which Dalton enters by hand and this script never overwrites
#   ~/gmshield-ci/secrets/worker.env   Redis account worker, the Qdrant key (Epic 2) and the same worker
#                                      credential as backend.env (Story 1.12: Authorization: Bearer on every
#                                      /internal/v1 call)
#   ~/gmshield-ci/secrets/frontend.env the backend's address on gmshield-app, and the same service credential
#                                      as backend.env (Story 1.10: Authorization: Bearer on every /api/v1 call)
#   ~/stack/redis-users.acl            Redis accounts with SHA-256 hashes of the passwords above
# Every secret is 32 random bytes (64 hex characters; the two vault keys in Base64, as the backend reads
# them), written once with mode 600, never printed. A value already present is kept, even if it differs
# from what this script would write: a vault key must never change, or what it protects is lost.
# The vault keys have no off-server copy yet (Epic 10): keep backend.env out of reach and intact.
set -euo pipefail
umask 077

CI_HOME=${GMSHIELD_HOME:-$HOME/gmshield-ci}
STACK=${GMSHIELD_STACK:-$HOME/stack}
SECRETS=$CI_HOME/secrets
STACK_ENV=$STACK/.env
ACL=$STACK/redis-users.acl
CA=/run/gmshield/certs/ca.crt
BACKEND_URL=http://gmshield-backend:8080
STREAMS=(gmshield:work:interactive gmshield:work:ingestion)

[ $# -eq 0 ] || { echo "Usage: $0   (no arguments)" >&2; exit 2; }
die() { echo "FAILED: $*" >&2; exit 1; }
command -v openssl >/dev/null || die "openssl is missing"
command -v sha256sum >/dev/null || die "sha256sum is missing"

# value <file> <key>: the value of KEY=..., empty when absent. Never printed by the callers.
value() { [ -f "$1" ] && sed -n "s/^$2=//p" "$1" | tail -n 1 || true; }
has() { [ -n "$(value "$1" "$2")" ]; }
put() {   # put <file> <key> <value>: append KEY=value (the file stays mode 600)
  local f=$1
  install -d -m 700 "$(dirname "$f")"
  [ -e "$f" ] || install -m 600 /dev/null "$f"
  chmod 600 "$f"
  if [ -s "$f" ] && [ -n "$(tail -c1 "$f")" ]; then echo >> "$f"; fi
  printf '%s=%s\n' "$2" "$3" >> "$f"
}
secret() {   # secret <file> <key>: a new random value, once
  if has "$1" "$2"; then echo "    $2: already done"; else put "$1" "$2" "$(openssl rand -hex 32)"; echo "    $2: generated"; fi
}
key_b64() {  # key_b64 <file> <key>: a new random 32-byte key in Base64, once
  if has "$1" "$2"; then echo "    $2: already done"; else put "$1" "$2" "$(openssl rand -base64 32)"; echo "    $2: generated"; fi
}
setting() {  # setting <file> <key> <value>: a plain setting, once
  local cur; cur=$(value "$1" "$2")
  if [ -z "$cur" ]; then put "$1" "$2" "$3"; echo "    $2: written"
  elif [ "$cur" = "$3" ]; then echo "    $2: already done"
  else echo "    $2: kept (differs from the default $3)"; fi
}
placeholder() {  # placeholder <file> <key>: a secret entered by hand; an empty KEY= once, a value never touched
  if has "$1" "$2"; then echo "    $2: already done (entered by hand)"
  elif [ -f "$1" ] && grep -q "^$2=" "$1"; then echo "    $2: still empty; enter it by hand (the backend refuses to start without it)"
  else put "$1" "$2" ""; echo "    $2: placeholder added; enter it by hand (the backend refuses to start without it)"; fi
}
copied() {   # copied <from file> <from key> <to file> <to key>: the same secret in two places
  local src dst; src=$(value "$1" "$2"); dst=$(value "$3" "$4")
  [ -n "$src" ] || die "$2 is missing in $1"
  if [ -z "$dst" ]; then put "$3" "$4" "$src"; echo "    $4: copied from $1"
  elif [ "$dst" = "$src" ]; then echo "    $4: already done"
  else die "$4 in $3 differs from $2 in $1; remove the wrong one and rerun"; fi
}
hash_of() { printf '%s' "$(value "$1" "$2")" | sha256sum | cut -d' ' -f1; }

echo "==> 1/5 The stack's own secrets ($STACK_ENV)"
secret "$STACK_ENV" POSTGRES_PASSWORD
secret "$STACK_ENV" REDIS_PROBE_PASSWORD
secret "$STACK_ENV" QDRANT_API_KEY

B=$SECRETS/backend.env
echo "==> 2/5 The backend ($B)"
setting "$B" GMSHIELD_DB_URL "jdbc:postgresql://postgres:5432/gmshield?sslmode=verify-full&sslrootcert=$CA"
setting "$B" GMSHIELD_DB_USER gmshield_backend
secret "$B" GMSHIELD_DB_PASSWORD
setting "$B" GMSHIELD_REDIS_HOST redis
setting "$B" GMSHIELD_REDIS_PORT 6379
setting "$B" GMSHIELD_REDIS_USERNAME backend
secret "$B" GMSHIELD_REDIS_PASSWORD
key_b64 "$B" GMSHIELD_VAULT_MASTER_KEY
key_b64 "$B" GMSHIELD_VAULT_INDEX_KEY
# Story 1.9: the Google OAuth client (redirect URI <GMSHIELD_PUBLIC_URL>/auth/google/callback, the public URL
# being set in the backend's .gmshield/pipeline.toml). Created by Dalton in the Google Cloud console.
placeholder "$B" GMSHIELD_GOOGLE_CLIENT_ID
placeholder "$B" GMSHIELD_GOOGLE_CLIENT_SECRET
# Story 1.10: the frontend's service credential. The backend refuses every /api/v1 call without it; the same
# value goes into frontend.env below (copied dies when the two differ).
secret "$B" GMSHIELD_FRONTEND_CREDENTIAL
# Story 1.12: the worker's credential. The backend refuses every /internal/v1 call without it; the same value
# goes into worker.env below (copied dies when the two differ).
secret "$B" GMSHIELD_WORKER_CREDENTIAL

W=$SECRETS/worker.env
echo "==> 3/5 The worker ($W)"
setting "$W" GMSHIELD_BACKEND_URL "$BACKEND_URL"
setting "$W" GMSHIELD_REDIS_HOST redis
setting "$W" GMSHIELD_REDIS_PORT 6379
setting "$W" GMSHIELD_REDIS_USERNAME worker
secret "$W" GMSHIELD_REDIS_PASSWORD
setting "$W" GMSHIELD_QDRANT_URL https://qdrant:6333
copied "$STACK_ENV" QDRANT_API_KEY "$W" GMSHIELD_QDRANT_API_KEY
copied "$B" GMSHIELD_WORKER_CREDENTIAL "$W" GMSHIELD_WORKER_CREDENTIAL
has "$W" GMSHIELD_ANTHROPIC_API_KEY || echo "    note: GMSHIELD_ANTHROPIC_API_KEY is not set; the worker refuses to start without it (add it by hand)"

F=$SECRETS/frontend.env
echo "==> 4/5 The frontend ($F)"
setting "$F" GMSHIELD_BACKEND_URL "$BACKEND_URL"
copied "$B" GMSHIELD_FRONTEND_CREDENTIAL "$F" GMSHIELD_FRONTEND_CREDENTIAL

echo "==> 5/5 The Redis accounts ($ACL)"
keys=""; for s in "${STREAMS[@]}"; do keys="$keys ~$s"; done
acl=$(printf '%s\n' \
  "user default off resetkeys resetchannels -@all" \
  "user backend on #$(hash_of "$B" GMSHIELD_REDIS_PASSWORD) resetkeys ~gmshield:* resetchannels &gmshield:* +@all -@admin -@dangerous +info" \
  "user worker on #$(hash_of "$W" GMSHIELD_REDIS_PASSWORD) resetkeys$keys resetchannels -@all +auth +hello +ping +xreadgroup +xack +xautoclaim +xclaim +xpending" \
  "user probe on #$(hash_of "$STACK_ENV" REDIS_PROBE_PASSWORD) resetkeys resetchannels -@all +ping")
if [ -f "$ACL" ] && [ "$(cat "$ACL")" = "$acl" ]; then echo "    already done"
else
  install -d -m 700 "$STACK"
  printf '%s\n' "$acl" > "$ACL.tmp"; chmod 600 "$ACL.tmp"; mv "$ACL.tmp" "$ACL"
  echo "    written (restart Redis to load it: bash deploy/stack.sh up)"
fi
chmod 700 "$SECRETS"
echo "DONE: nothing secret was printed"
