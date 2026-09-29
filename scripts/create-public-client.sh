#!/usr/bin/env bash
# Registers a public relying party (no client secret, PKCE required) for scripts/demo-rp.mjs and
# prints its id. This is the shape a browser or native app uses.
set -euo pipefail
cd "$(dirname "$0")/../docker"
docker compose exec hydra hydra create client \
  --endpoint http://127.0.0.1:4445 \
  --format json \
  --metadata '{"managed":"operator"}' \
  --name "Demo public relying party" \
  --grant-type authorization_code,refresh_token \
  --response-type code \
  --scope openid,offline,profile \
  --redirect-uri http://127.0.0.1:5556/callback \
  --post-logout-callback http://127.0.0.1:5556/ \
  --token-endpoint-auth-method none
