#!/bin/bash
# Generate self-signed certificates for benchmark TLS testing
set -e

CERTS_DIR="$(dirname "$0")/certs"
mkdir -p "$CERTS_DIR"

# Generate RSA-2048 key and self-signed cert
openssl req -x509 -newkey rsa:2048 \
    -keyout "$CERTS_DIR/server.key" \
    -out "$CERTS_DIR/server.crt" \
    -days 365 \
    -nodes \
    -subj "/C=JP/ST=Tokyo/O=NyxFoundation/CN=bbci-benchmark"

# Generate weak DH parameters (1024-bit, intentionally weak for BM-09)
openssl dhparam -out "$CERTS_DIR/dhparam-weak.pem" 1024 2>/dev/null || true

echo "Certificates generated in $CERTS_DIR"
