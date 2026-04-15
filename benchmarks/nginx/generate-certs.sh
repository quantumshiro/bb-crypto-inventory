#!/bin/bash
# Generate self-signed certificates for benchmark TLS testing
set -e

CERTS_DIR="$(dirname "$0")/certs"
mkdir -p "$CERTS_DIR"

# Weak benchmark certificate: RSA-1024 + SHA-1
openssl req -x509 -newkey rsa:1024 \
    -keyout "$CERTS_DIR/weak-server.key" \
    -out "$CERTS_DIR/weak-server.crt" \
    -days 365 \
    -nodes \
    -sha1 \
    -subj "/C=JP/ST=Tokyo/O=NyxFoundation/CN=bbci-weak-benchmark"

# Strong benchmark certificate: RSA-2048 + SHA-256
openssl req -x509 -newkey rsa:2048 \
    -keyout "$CERTS_DIR/strong-server.key" \
    -out "$CERTS_DIR/strong-server.crt" \
    -days 365 \
    -nodes \
    -sha256 \
    -subj "/C=JP/ST=Tokyo/O=NyxFoundation/CN=bbci-strong-benchmark"

# Generate weak DH parameters (1024-bit, intentionally weak for BM-09)
openssl dhparam -out "$CERTS_DIR/dhparam-weak.pem" 1024 2>/dev/null || true

echo "Certificates generated in $CERTS_DIR"
