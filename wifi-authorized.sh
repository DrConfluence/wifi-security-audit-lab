#!/data/data/com.termux/files/usr/bin/bash
set -e
cd "$HOME/wifi-audit"

if [ "$#" -ne 1 ]; then
    echo "Usage: ./wifi-authorized.sh AUTHORIZATION_REF"
    exit 2
fi

exec python -m assessment.authorized_inventory "$1"
