#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# Generate a local CA + server TLS certificate for SecureChat
#
# Usage:  bash scripts/generate-certs.sh
#
# Outputs (in certs/):
#   ca.key      — CA private key       (KEEP SECRET / not committed)
#   ca.crt      — CA certificate       (import into browser to trust)
#   server.key  — Server private key   (KEEP SECRET / not committed)
#   server.crt  — Server certificate   (signed by ca.crt)
#
# To trust the cert in your browser (no warning on https://localhost:8443):
#   Chrome/Edge:  Settings → Privacy → Security → Manage certificates
#                 → Authorities → Import → select certs/ca.crt
#   Firefox:      about:preferences#privacy → View Certificates
#                 → Authorities → Import → select certs/ca.crt
#   Linux (system): sudo cp certs/ca.crt /usr/local/share/ca-certificates/
#                   sudo update-ca-certificates
# ─────────────────────────────────────────────────────────────
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERTS_DIR="$SCRIPT_DIR/../certs"
mkdir -p "$CERTS_DIR"
cd "$CERTS_DIR"

echo "── Generating Local CA ──────────────────────────────────"
openssl genrsa -out ca.key 4096
openssl req -new -x509 -days 3650 \
  -key ca.key \
  -out ca.crt \
  -config ca.cnf
echo "✓ CA certificate generated (valid 10 years)"

echo ""
echo "── Generating Server Certificate ────────────────────────"
openssl genrsa -out server.key 2048
openssl req -new \
  -key server.key \
  -out server.csr \
  -config server.cnf
openssl x509 -req -days 730 \
  -in server.csr \
  -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out server.crt \
  -extensions v3_req \
  -extfile server.cnf
rm -f server.csr ca.srl
echo "✓ Server certificate signed by local CA (valid 2 years)"

echo ""
echo "── Verification ─────────────────────────────────────────"
openssl verify -CAfile ca.crt server.crt
openssl x509 -in server.crt -noout -subject -issuer -dates -ext subjectAltName

echo ""
echo "✅  Done.  Restart Docker Compose: docker compose up --build"
echo ""
echo "📌  To avoid browser security warnings, import certs/ca.crt"
echo "    into your browser's Certificate Authorities trust store."
