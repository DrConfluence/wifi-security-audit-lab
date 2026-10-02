#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")" || exit 1

if [ "$#" -ne 1 ] || [ -z "$1" ]; then
    echo "Usage: ./wifi-authorized.sh AUTHORIZATION_REF" >&2
    exit 2
fi

exec python3 -m assessment.authorized_inventory "$1"
