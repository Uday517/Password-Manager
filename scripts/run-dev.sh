#!/usr/bin/env bash
#
# Run Vault from source.
#
#   ./scripts/run-dev.sh              # uses your real vault in ~/Library/... (or OS equivalent)
#   ./scripts/run-dev.sh --sandbox    # uses a throwaway vault under ./.sandbox-home
#
# --sandbox overrides user.home, so the app creates its database inside the repo
# instead of touching your real one. Use it to try things out safely.
set -euo pipefail
cd "$(dirname "$0")/.."

SANDBOX=""
if [[ "${1:-}" == "--sandbox" ]]; then
  SANDBOX="$PWD/.sandbox-home"
  mkdir -p "$SANDBOX"
  echo "Sandbox mode — vault lives under $SANDBOX"
fi

mvn -q -B compile
mvn -q -B dependency:build-classpath -Dmdep.outputFile=target/cp.txt

ARGS=(-cp "target/classes:$(cat target/cp.txt)")
[[ -n "$SANDBOX" ]] && ARGS+=("-Duser.home=$SANDBOX")

exec java "${ARGS[@]}" com.passwordmanager.Launcher
