#!/bin/sh
# Runs from /docker-entrypoint.d/ before nginx starts.
# Generates a self-signed cert if /etc/nginx/certs is empty so the HTTPS
# server block can boot without manual setup. Mount your own certs to
# /etc/nginx/certs/{cert.pem,key.pem} to override.
set -e

CERT_DIR=/etc/nginx/certs
CERT=$CERT_DIR/cert.pem
KEY=$CERT_DIR/key.pem

mkdir -p "$CERT_DIR"

if [ ! -s "$CERT" ] || [ ! -s "$KEY" ]; then
    echo "[sechub-tls] No cert found — generating self-signed (CN=sechub.local, 365d valid)."
    openssl req -x509 -nodes -newkey rsa:2048 -days 365 \
        -subj "/CN=sechub.local" \
        -addext "subjectAltName=DNS:localhost,DNS:sechub.local,IP:127.0.0.1" \
        -keyout "$KEY" -out "$CERT" 2>/dev/null
    chmod 644 "$CERT" && chmod 600 "$KEY"
    echo "[sechub-tls] Self-signed cert ready. Replace $CERT / $KEY for production."
else
    echo "[sechub-tls] Using existing cert at $CERT."
fi
