#!/bin/sh
set -eu
cd "$(dirname "$0")"
mkdir -p .runtime/certs .runtime/logs
if [ ! -f .runtime/elastic.env ]; then
    umask 077
    printf 'ELASTIC_PASSWORD=%s\n' "$(openssl rand -hex 24)" > .runtime/elastic.env
fi
if [ ! -f .runtime/certs/server.crt ]; then
    cat > .runtime/certs/openssl.cnf <<'EOF'
[req]
distinguished_name = dn
x509_extensions = extensions
prompt = no
[dn]
CN = localhost
[extensions]
subjectAltName = DNS:localhost,DNS:elasticsearch,IP:127.0.0.1
basicConstraints = critical,CA:TRUE
keyUsage = critical,digitalSignature,keyEncipherment,keyCertSign
EOF
    openssl req -x509 -newkey rsa:2048 -nodes -days 7 -config .runtime/certs/openssl.cnf -keyout .runtime/certs/server.key -out .runtime/certs/server.crt 2>/dev/null
    # Synthetic local test certificate, readable by the container's non-root user.
    chmod 755 .runtime .runtime/certs .runtime/logs
    chmod 644 .runtime/certs/server.key .runtime/certs/server.crt
fi
docker compose up -d --wait elasticsearch
