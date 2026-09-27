#!/usr/bin/env bash
# Points odin-core.ref at the sibling checkout's current commit (or the one given), after checking
# the solution still builds against it.
set -euo pipefail
cd "$(dirname "$0")/.."
core="${ODIN_CORE_DIR:-../odin-core}"
sha="${1:-$(git -C "$core" rev-parse HEAD)}"
dotnet build odin-oidc.sln --warnaserror -p:OdinCoreDir="$(realpath "$core")/" >/dev/null
echo "$sha" > odin-core.ref
echo "odin-core.ref -> $sha"
