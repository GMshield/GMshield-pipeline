#!/usr/bin/env bash
# GMshield on roberto-server: narrow Ollama to the worker's model network (AD-14, AD-29; Story 1.6).
#
#   bash deploy/secure-ollama.sh plan          changes nothing: each step's state
#   sudo bash deploy/secure-ollama.sh apply    runs every step that is not done yet
#   sudo bash deploy/secure-ollama.sh status   the state of every step, the listening address, the rules
#
# Run it after `bash deploy/stack.sh up`: Ollama listens on the gateway of the gmshield-model network,
# which exists only once the data stack has created it. Every step checks first whether it is already
# done, so a rerun resumes where a failed run stopped.
#
# Afterwards Ollama answers on http://172.30.5.1:11434 only: from the host itself (the AI health check,
# an SSH tunnel to 172.30.5.1:11434) and from containers on gmshield-model. Nothing else reaches it.
set -euo pipefail
umask 022

# GMSHIELD_ROOT exists for the tests only: every file path below is taken relative to it.
R=${GMSHIELD_ROOT:-}
p() { printf '%s%s' "$R" "$1"; }

NETWORK=gmshield-model          # created by infra/compose.yaml with this bridge name
SUBNET=172.30.5.0/24
GATEWAY=172.30.5.1
PORT=11434
OLD_SOURCE=172.16.0.0/12        # the rule this replaces: every Docker network could reach Ollama
DROP_MODEL=qwen3.5:4b
KEEP_MODEL=embeddinggemma:300m
DROPIN_DIR=/etc/systemd/system/ollama.service.d
DROPIN=$DROPIN_DIR/zz-gmshield.conf   # sorts last: overrides network.conf and rag-tuning.conf
OLD_DROPIN=$DROPIN_DIR/network.conf   # OLLAMA_HOST=0.0.0.0:11434
HEALTHCHECK=/usr/local/bin/ai-healthcheck
STATE=/var/lib/gmshield/secure-ollama
UFW_COMMENT="GMshield worker network to Ollama"
TOOLS=(systemctl ufw ollama ss ip docker)

CMD=""
case ${1:-} in plan|apply|status) CMD=$1 ;; esac
[ -n "$CMD" ] && [ $# -eq 1 ] || { echo "Usage: $0 {plan|apply|status}" >&2; exit 2; }

CUR=""; CUR_NAME=""; TOTAL=0
die() { echo "    $*" >&2; exit 1; }
is_root() { [ "$(id -u)" -eq 0 ]; }
on_exit() {
  local rc=$?
  trap - EXIT
  if [ "$rc" -ne 0 ] && [ -n "$CUR" ]; then echo "FAILED at step $CUR: $CUR_NAME" >&2; fi
  exit "$rc"
}
trap on_exit EXIT

step() {   # step <n> <name> <check> <action>
  CUR=$1; CUR_NAME=$2
  echo "==> $1/$TOTAL $2"
  if $3; then echo "    already done"; return 0; fi
  $4
  $3 || die "the step ran but its check still fails"
}

# ---------- facts ----------
listening() {   # the local addresses Ollama listens on, one per line
  ss -Hltn "sport = :$PORT" 2>/dev/null | awk '{ print $4 }' | sort -u
}
on_gateway_only() { [ "$(listening)" = "$GATEWAY:$PORT" ]; }
api() { if on_gateway_only; then printf '%s:%s' "$GATEWAY" "$PORT"; else printf '127.0.0.1:%s' "$PORT"; fi; }
models() { OLLAMA_HOST=$(api) ollama list 2>/dev/null | awk 'NR > 1 { print $1 }'; }
network_ready() {
  [ "$(docker network inspect -f '{{.Internal}} {{range .IPAM.Config}}{{.Subnet}} {{.Gateway}}{{end}}' "$NETWORK" 2>/dev/null)" = \
    "true $SUBNET $GATEWAY" ] &&
    ip -4 -o addr show dev "$NETWORK" 2>/dev/null | grep -q " $GATEWAY/"
}
ufw_rules() { ufw status 2>/dev/null; }
unit_env() {     # unit_env <name>: the value systemd gives Ollama (the last assignment wins)
  systemctl show -p Environment ollama.service 2>/dev/null | tr ' ' '\n' | sed -n "s/^\(Environment=\)\{0,1\}$1=//p" | tail -n 1
}

# ---------- steps ----------
c_model() { local m; m=$(models) || return 1; [ -n "$m" ] && ! grep -qxF "$DROP_MODEL" <<<"$m"; }
a_model() { OLLAMA_HOST=$(api) ollama rm "$DROP_MODEL"; }

c_allow() { local r; r=$(ufw_rules) || return 1; grep -qE "^$GATEWAY $PORT/tcp on $NETWORK +ALLOW( IN)? +$SUBNET( |$)" <<<"$r"; }
a_allow() {   # first, so the existing "deny 11434/tcp" below it never wins
  ufw insert 1 allow in on "$NETWORK" proto tcp from "$SUBNET" to "$GATEWAY" port "$PORT" comment "$UFW_COMMENT"
}

c_noold() { local r; r=$(ufw_rules) || return 1; ! grep -qE "(^| )$PORT(/tcp)? .*ALLOW.* $OLD_SOURCE( |$)" <<<"$r"; }
a_noold() {
  local n
  # numbers of the old rules, highest first so that deleting one never renumbers the next
  for n in $(ufw status numbered | grep -E "(^| )$PORT(/tcp)? .*ALLOW.* $OLD_SOURCE( |$)" |
             sed -n 's/^\[ *\([0-9]*\)\].*/\1/p' | sort -rn); do
    ufw --force delete "$n"
  done
}

dropin_content() {
  printf '%s\n' "# Written by GMshield-pipeline deploy/secure-ollama.sh (Story 1.6)." \
    "# Ollama listens on the gmshield-model gateway only, after Docker has created that network." \
    "[Unit]" "After=docker.service" "Wants=docker.service" "" "[Service]" \
    "Environment=\"OLLAMA_HOST=$GATEWAY:$PORT\"" \
    "Environment=\"OLLAMA_MAX_LOADED_MODELS=1\"" \
    "ExecStartPre=/bin/sh -c 'for i in \$\$(seq 1 90); do ip -4 -o addr show dev $NETWORK 2>/dev/null | grep -q \" $GATEWAY/\" && exit 0; sleep 2; done; echo \"$NETWORK has no address $GATEWAY: run deploy/stack.sh up\" >&2; exit 1'"
}
c_dropin() { [ "$(cat "$(p "$DROPIN")" 2>/dev/null)" = "$(dropin_content)" ] && [ ! -e "$(p "$OLD_DROPIN")" ]; }
a_dropin() {
  local f; f=$(p "$DROPIN")
  mkdir -p "$(dirname "$f")" "$(p "$STATE")"
  dropin_content > "$f.tmp"; chmod 644 "$f.tmp"; mv "$f.tmp" "$f"
  if [ -e "$(p "$OLD_DROPIN")" ]; then   # kept beside the state, not deleted
    mv "$(p "$OLD_DROPIN")" "$(p "$STATE")/network.conf.before-gmshield"
  fi
  systemctl daemon-reload
}

healthcheck_content() {
  cat <<EOF
#!/usr/bin/env bash
# Written by GMshield-pipeline deploy/secure-ollama.sh (Story 1.6). Logs to the journal: journalctl -t ai-health
set -u
log() { logger -t ai-health "\$*"; }
API=http://$GATEWAY:$PORT     # Ollama listens on the gmshield-model gateway only
up() { curl -sf -m 15 "\$API/api/version" >/dev/null; }

if ! up; then
  sleep 20
  if ! up; then log "Ollama unresponsive twice; restarting"; systemctl restart ollama; sleep 15; fi
fi

if ! curl -sf -m 15 "\$API/api/ps" | grep -q '"name":"$KEEP_MODEL"'; then
  curl -sf -m 180 "\$API/api/embed" -d '{"model":"$KEEP_MODEL","input":"warm-up","keep_alive":-1}' >/dev/null \\
    && log "loaded $KEEP_MODEL" || log "failed to load $KEEP_MODEL"
fi

# Docker restarts crashed containers itself, but not hung ones: restart any marked unhealthy.
# Postgres, Redis and Qdrant have Docker health checks (Qdrant has no host port any more).
for c in \$(docker ps --filter health=unhealthy --format '{{.Names}}'); do
  log "container \$c unhealthy; restarting"; docker restart "\$c" >/dev/null
done

USE=\$(df --output=pcent / | tail -1 | tr -dc 0-9)
[ "\$USE" -ge 90 ] && log "WARNING: root disk \${USE}% full"
exit 0
EOF
}
c_health() { [ "$(cat "$(p "$HEALTHCHECK")" 2>/dev/null)" = "$(healthcheck_content)" ]; }
a_health() {
  local f; f=$(p "$HEALTHCHECK")
  mkdir -p "$(p "$STATE")"
  if [ -e "$f" ] && [ ! -e "$(p "$STATE")/ai-healthcheck.before-gmshield" ]; then
    cp -a "$f" "$(p "$STATE")/ai-healthcheck.before-gmshield"
  fi
  healthcheck_content > "$f.tmp"; chmod 755 "$f.tmp"; mv "$f.tmp" "$f"
}

c_listen() { on_gateway_only && [ "$(unit_env OLLAMA_MAX_LOADED_MODELS)" = 1 ] && [ "$(unit_env OLLAMA_HOST)" = "$GATEWAY:$PORT" ]; }
a_listen() {
  local i
  systemctl daemon-reload
  systemctl restart ollama.service
  for i in $(seq 1 30); do on_gateway_only && return 0; sleep 2; done
  die "Ollama does not listen on $GATEWAY:$PORT alone: $(listening | xargs)"
}

STEPS=(
  "Remove $DROP_MODEL from Ollama (only $KEEP_MODEL stays)|c_model|a_model"
  "Allow $SUBNET (gmshield-model) to reach Ollama at $GATEWAY:$PORT in ufw|c_allow|a_allow"
  "Remove the ufw rule that let every Docker network ($OLD_SOURCE) reach Ollama|c_noold|a_noold"
  "Systemd drop-in: listen on $GATEWAY:$PORT after Docker, one loaded model|c_dropin|a_dropin"
  "Point the AI health check at $GATEWAY:$PORT|c_health|a_health"
  "Restart Ollama and check it listens on $GATEWAY:$PORT alone|c_listen|a_listen"
)

preconditions() {   # fills REASONS
  local t
  REASONS=()
  for t in "${TOOLS[@]}"; do command -v "$t" >/dev/null 2>&1 || REASONS+=("missing tool: $t"); done
  network_ready || REASONS+=("the network $NETWORK ($SUBNET, gateway $GATEWAY on the host) does not exist yet: run bash deploy/stack.sh up first")
}

report_steps() {
  local i=0 e name check mark
  for e in "${STEPS[@]}"; do
    i=$((i + 1)); name=${e%%|*}; check=${e#*|}; check=${check%%|*}
    if $check 2>/dev/null; then mark="done"; else mark="  --"; fi
    printf '  [%s] %d %s\n' "$mark" "$i" "$name"
  done
}

cmd_plan() {
  local r
  echo "Plan: narrow Ollama to the worker's model network (nothing is changed by this command)"
  is_root || echo "  (not root: the ufw checks read as not done)"
  preconditions
  for r in "${REASONS[@]}"; do echo "  apply would refuse: $r"; done
  report_steps
}

cmd_status() {
  is_root || echo "(not root: the ufw checks read as not done)"
  report_steps
  echo "Ollama listens on: $(listening | xargs)"
  echo "OLLAMA_HOST=$(unit_env OLLAMA_HOST) OLLAMA_MAX_LOADED_MODELS=$(unit_env OLLAMA_MAX_LOADED_MODELS)"
  echo "Models: $(models | xargs)"
  if is_root; then echo "ufw rules for $PORT:"; ufw_rules | grep -E "(^| )$PORT(/tcp)? " | sed 's/^/  /' || true; fi
}

cmd_apply() {
  local e i=0 name rest r
  TOTAL=${#STEPS[@]}
  CUR=0; CUR_NAME="Preconditions"
  echo "==> 0/$TOTAL Preconditions"
  is_root || die "not root: run it with sudo"
  preconditions
  if [ "${#REASONS[@]}" -gt 0 ]; then for r in "${REASONS[@]}"; do echo "    refused: $r" >&2; done; exit 1; fi
  echo "    ok"
  for e in "${STEPS[@]}"; do
    i=$((i + 1)); name=${e%%|*}; rest=${e#*|}
    step "$i" "$name" "${rest%%|*}" "${rest#*|}"
  done
  CUR=""
  echo "DONE: Ollama answers on http://$GATEWAY:$PORT only. Point an SSH tunnel at $GATEWAY:$PORT, not 127.0.0.1."
}

case $CMD in
  plan) cmd_plan ;;
  status) cmd_status ;;
  apply) cmd_apply ;;
esac
