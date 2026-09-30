#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")" || exit 1

if [ $# -lt 1 ] || [ -z "$1" ]; then
    echo "ERROR: Explicit authorization reference is required." >&2
    echo "Usage: ./wifi-live.sh <AUTHORIZATION_REF>" >&2
    exit 2
fi

echo "===== LIVE WIFI INVENTORY ====="
echo

python3 -m assessment.live_inventory \
    --authorization-ref "$1"

echo
echo "===== TESTS ====="
python3 -m pytest -q

echo
echo "===== STATUS ====="
git status --short
