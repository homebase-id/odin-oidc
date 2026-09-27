#!/usr/bin/env bash
# Copies a dev certificate for the login app's host from the sibling odin-core checkout, which
# keeps Let's Encrypt certificates for the *.dotyou.cloud dev names (see its
# src/apps/Odin.Hosting/https/get-certificates.sh). Default host: collab.dotyou.cloud. Once
# oidc.dotyou.cloud is issued there, pass it as the argument and switch Broker:PublicHost.
# Usage: scripts/dev-cert.sh [host]
set -euo pipefail
host="${1:-collab.dotyou.cloud}"
core="$(dirname "$0")/../${ODIN_CORE_DIR:-../odin-core}"
src="$core/src/apps/Odin.Hosting/https/$host"
dst="$(dirname "$0")/../certs/$host"
[ -f "$src/certificate.crt" ] || { echo "no certificate for $host at $src" >&2; exit 1; }
mkdir -p "$dst"
cp "$src/certificate.crt" "$src/private.key" "$dst/"
openssl x509 -in "$dst/certificate.crt" -noout -subject -enddate
echo "copied to $dst"
