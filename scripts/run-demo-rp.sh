#!/usr/bin/env bash
# Runs Hydra's built-in demo relying party on http://127.0.0.1:5555 against the local Hydra.
# Host networking, so the links it renders point at Hydra's host port and its callback listens on
# the host directly (the same binary inside the compose network would link to a port the browser
# cannot reach).
# Usage: scripts/run-demo-rp.sh <client_id> <client_secret>   (from create-test-client.sh)
set -euo pipefail
docker run --rm --network host oryd/hydra:v26.2.0 perform authorization-code \
  --endpoint http://127.0.0.1:14444/ \
  --client-id "$1" \
  --client-secret "$2" \
  --scope openid,offline \
  --port 5555 \
  --redirect http://127.0.0.1:5555/callback \
  --no-open
