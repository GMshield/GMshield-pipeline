#!/bin/sh
# Runs as root before the image's own entrypoint (which then drops to the postgres user).
# PostgreSQL refuses a key it does not own, or one others can read: the read-only certificate
# folder belongs to roberto on the host, so its key is copied into a tmpfs, owned by postgres, 600.
set -eu
dir=/run/gmshield-postgres
install -d -o postgres -g postgres -m 700 "$dir"
install -o postgres -g postgres -m 600 /certs/tls.key "$dir/tls.key"
install -o postgres -g postgres -m 644 /certs/tls.crt "$dir/tls.crt"
install -o postgres -g postgres -m 644 /certs/ca.crt "$dir/ca.crt"
install -o postgres -g postgres -m 600 /gmshield/pg_hba.conf "$dir/pg_hba.conf"
install -o postgres -g postgres -m 600 /gmshield/pg_ident.conf "$dir/pg_ident.conf"
exec docker-entrypoint.sh postgres \
  -c listen_addresses='*' \
  -c ssl=on \
  -c ssl_cert_file="$dir/tls.crt" \
  -c ssl_key_file="$dir/tls.key" \
  -c ssl_ca_file="$dir/ca.crt" \
  -c ssl_min_protocol_version=TLSv1.3 \
  -c password_encryption=scram-sha-256 \
  -c hba_file="$dir/pg_hba.conf" \
  -c ident_file="$dir/pg_ident.conf" \
  -c shared_buffers=128MB \
  -c max_connections=50
