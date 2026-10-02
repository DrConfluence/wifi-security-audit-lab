#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "========================================"
echo " Wi-Fi Passive Audit"
echo "========================================"
echo "Directory: $SCRIPT_DIR"
echo

python3 "$SCRIPT_DIR/wifi_scan.py" "$@"

if [ -f "$SCRIPT_DIR/networks_log.csv" ]; then
    echo
    echo "Latest observations:"
    tail -n 5 "$SCRIPT_DIR/networks_log.csv"
fi

