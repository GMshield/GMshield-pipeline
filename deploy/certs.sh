#!/usr/bin/env bash
# GMshield on roberto-server: the private certificate authority of the data services (AD-23, Story 1.6).
# Run as roberto, no sudo.
#
#   bash deploy/certs.sh issue            creates whatever is missing: the authority, then each leaf
#   bash deploy/certs.sh issue --renew    replaces every leaf (new key and certificate); the authority stays
#   bash deploy/certs.sh check            warns about any certificate that expires within 30 days (exit 0)
#
# Layout (GMSHIELD_HOME, default ~/gmshield-ci):
#   ca/ca.key, ca/ca.crt                  the authority (folder 700, key 600); mounted into no container
#   certs/<service>/tls.crt, tls.key      the leaf of postgres, redis and qdrant (365 days, key 600)
#   certs/<service>/ca.crt                the authority's certificate, in every service's folder,
#                                         including the clients' (backend, worker), which get no leaf
# Each folder is mounted read-only into its own container only. Nothing secret is ever printed.
set -euo pipefail
umask 077

CI_HOME=${GMSHIELD_HOME:-$HOME/gmshield-ci}
CA_DIR=$CI_HOME/ca
CERTS=$CI_HOME/certs
CA_DAYS=3650
LEAF_DAYS=365
WARN_DAYS=30
SERVERS=(postgres redis qdrant)      # a leaf each; host names: the service, localhost, 127.0.0.1
CLIENTS=(backend worker)             # the authority's certificate only

usage() { echo "Usage: $0 {issue [--renew]|check}" >&2; exit 2; }
CMD=${1:-}; RENEW=0
case $CMD in
  issue) [ $# -le 2 ] || usage; [ "${2:-}" = "" ] || [ "${2:-}" = --renew ] || usage; [ "${2:-}" = --renew ] && RENEW=1 ;;
  check) [ $# -eq 1 ] || usage ;;
  *) usage ;;
esac

die() { echo "FAILED: $*" >&2; exit 1; }
EC=(-newkey ec -pkeyopt ec_paramgen_curve:P-256 -noenc)

ca_ok() { [ -s "$CA_DIR/ca.key" ] && [ -s "$CA_DIR/ca.crt" ]; }
make_ca() {
  install -d -m 700 "$CA_DIR"
  openssl req -x509 "${EC[@]}" -keyout "$CA_DIR/ca.key.tmp" -out "$CA_DIR/ca.crt.tmp" -days "$CA_DAYS" \
    -subj "/CN=GMshield private authority" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -addext "subjectKeyIdentifier=hash" 2>/dev/null || die "openssl could not create the authority"
  chmod 600 "$CA_DIR/ca.key.tmp"; chmod 644 "$CA_DIR/ca.crt.tmp"
  mv "$CA_DIR/ca.key.tmp" "$CA_DIR/ca.key"; mv "$CA_DIR/ca.crt.tmp" "$CA_DIR/ca.crt"
}

# A leaf is valid when its key matches it and it chains to the current authority.
leaf_ok() {
  local d=$CERTS/$1
  [ -s "$d/tls.crt" ] && [ -s "$d/tls.key" ] || return 1
  openssl verify -CAfile "$CA_DIR/ca.crt" "$d/tls.crt" >/dev/null 2>&1 || return 1
  [ "$(openssl x509 -in "$d/tls.crt" -noout -pubkey 2>/dev/null)" = "$(openssl pkey -in "$d/tls.key" -pubout 2>/dev/null)" ]
}
make_leaf() {
  local svc=$1 d=$CERTS/$1 tmp
  tmp=$(mktemp -d "$CERTS/.issue-$svc.XXXXXX")
  printf '%s\n' "subjectAltName=DNS:$svc,DNS:localhost,IP:127.0.0.1" "basicConstraints=critical,CA:FALSE" \
    "keyUsage=critical,digitalSignature" "extendedKeyUsage=serverAuth" \
    "subjectKeyIdentifier=hash" "authorityKeyIdentifier=keyid" > "$tmp/leaf.ext"
  openssl req "${EC[@]}" -keyout "$tmp/tls.key" -out "$tmp/tls.csr" -subj "/CN=$svc" 2>/dev/null &&
    openssl x509 -req -in "$tmp/tls.csr" -CA "$CA_DIR/ca.crt" -CAkey "$CA_DIR/ca.key" -set_serial "0x$(openssl rand -hex 16)" \
      -days "$LEAF_DAYS" -extfile "$tmp/leaf.ext" -out "$tmp/tls.crt" 2>/dev/null ||
    { rm -rf "$tmp"; die "openssl could not issue the $svc certificate"; }
  chmod 600 "$tmp/tls.key"; chmod 644 "$tmp/tls.crt"
  mv "$tmp/tls.key" "$d/tls.key"; mv "$tmp/tls.crt" "$d/tls.crt"
  rm -rf "$tmp"
}
# The folder, readable by the container user of a client (the files decide what is secret).
service_dir() { install -d -m 700 "$CERTS"; install -d -m 755 "$CERTS/$1"; }
copy_ca() {   # prints whether the folder's ca.crt changed
  local d=$CERTS/$1
  if cmp -s "$CA_DIR/ca.crt" "$d/ca.crt"; then return 1; fi
  install -m 644 "$CA_DIR/ca.crt" "$d/ca.crt.tmp"; mv "$d/ca.crt.tmp" "$d/ca.crt"
}

cmd_issue() {
  local svc n=0 total=$((1 + ${#SERVERS[@]} + ${#CLIENTS[@]}))
  command -v openssl >/dev/null || die "openssl is missing"
  n=$((n + 1)); echo "==> $n/$total The authority ($CA_DIR, $CA_DAYS days)"
  if ca_ok; then echo "    already done"
  elif [ -e "$CA_DIR/ca.key" ] || [ -e "$CA_DIR/ca.crt" ]; then die "$CA_DIR holds half an authority; move it aside and rerun"
  else make_ca; echo "    created"; fi
  chmod 700 "$CA_DIR"
  for svc in "${SERVERS[@]}"; do
    n=$((n + 1)); echo "==> $n/$total The $svc certificate ($CERTS/$svc, $LEAF_DAYS days)"
    service_dir "$svc"
    if [ "$RENEW" = 0 ] && leaf_ok "$svc"; then echo "    already done"
    else make_leaf "$svc"; echo "    issued, valid until $(openssl x509 -in "$CERTS/$svc/tls.crt" -noout -enddate | cut -d= -f2)"; fi
    if copy_ca "$svc"; then echo "    ca.crt updated"; fi
  done
  for svc in "${CLIENTS[@]}"; do
    n=$((n + 1)); echo "==> $n/$total The $svc folder (ca.crt only)"
    service_dir "$svc"
    if copy_ca "$svc"; then echo "    ca.crt written"; else echo "    already done"; fi
  done
  [ "$RENEW" = 0 ] || echo "Restart the data services so they load the new leaves: bash deploy/stack.sh up"
}

cmd_check() {
  local f end warned=0 count=0
  if ! command -v openssl >/dev/null; then echo "WARNING: openssl is missing; certificates not checked"; return 0; fi
  for f in "$CA_DIR/ca.crt" "$CERTS"/*/tls.crt; do
    [ -f "$f" ] || continue
    count=$((count + 1))
    end=$(openssl x509 -in "$f" -noout -enddate 2>/dev/null | cut -d= -f2) || end=""
    if [ -z "$end" ]; then echo "WARNING: $f is not a readable certificate"; warned=1; continue; fi
    if ! openssl x509 -in "$f" -noout -checkend $((WARN_DAYS * 86400)) >/dev/null 2>&1; then
      if [ "$f" = "$CA_DIR/ca.crt" ]; then
        echo "WARNING: the authority $f expires on $end (within $WARN_DAYS days): a new authority is needed"
      else
        echo "WARNING: $f expires on $end (within $WARN_DAYS days): run deploy/certs.sh issue --renew, then deploy/stack.sh up"
      fi
      warned=1
    fi
  done
  if [ "$count" = 0 ]; then echo "WARNING: no certificates under $CI_HOME (run deploy/certs.sh issue)"; return 0; fi
  [ "$warned" = 1 ] || echo "ok: $count certificates valid for more than $WARN_DAYS days"
  return 0
}

case $CMD in
  issue) cmd_issue ;;
  check) cmd_check ;;
esac
