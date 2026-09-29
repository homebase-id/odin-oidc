#!/usr/bin/env bash
# Registers the demo relying party used by run-demo-rp.sh and prints its id and secret.
# The `hydra perform authorization-code` demo does not do PKCE, so this client is confidential;
# real relying parties get a public PKCE client (M2).
set -euo pipefail
cd "$(dirname "$0")/../docker"
docker compose exec hydra hydra create client \
  --endpoint http://127.0.0.1:4445 \
  --format json \
  --metadata '{"managed":"operator"}' \
  --name "Demo relying party" \
  --grant-type authorization_code,refresh_token \
  --response-type code \
  --scope openid,offline,profile \
  --redirect-uri http://127.0.0.1:5555/callback \
  --token-endpoint-auth-method client_secret_basic
