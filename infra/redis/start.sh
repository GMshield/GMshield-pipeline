#!/bin/sh
# Runs as root before the image's own entrypoint (which then drops to the redis user).
# The read-only folders belong to roberto on the host and hold mode-600 files: the key and the
# account list are copied into a tmpfs, owned by redis, readable by redis alone.
set -eu
dir=/run/gmshield-redis
install -d -o redis -m 700 "$dir"
install -o redis -m 600 /certs/tls.key "$dir/tls.key"
install -o redis -m 600 /gmshield/users.acl "$dir/users.acl"
# TLS only (--port 0); clients authenticate with their account, not with a certificate.
exec docker-entrypoint.sh redis-server \
  --port 0 \
  --tls-port 6379 \
  --tls-cert-file /certs/tls.crt \
  --tls-key-file "$dir/tls.key" \
  --tls-ca-cert-file /certs/ca.crt \
  --tls-auth-clients no \
  --tls-protocols TLSv1.3 \
  --aclfile "$dir/users.acl" \
  --appendonly yes \
  --maxmemory 200mb \
  --maxmemory-policy noeviction
