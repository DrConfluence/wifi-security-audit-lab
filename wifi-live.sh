#!/data/data/com.termux/files/usr/bin/bash
set -u

cd "$HOME/wifi-audit" || exit 1

echo "===== LIVE WIFI INVENTORY ====="
echo

python -m assessment.live_inventory \
    --authorization-ref "${1:-AUTHORIZED-LAB}" 

echo
echo "===== TESTS ====="
python -m pytest -q

echo
echo "===== STATUS ====="
git status --short
