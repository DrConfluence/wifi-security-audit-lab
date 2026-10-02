#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")" || exit 1

if [ "$#" -lt 3 ]; then
    echo "Usage:" >&2
    echo "  ./wifi-assess.sh --ssid '<SSID>' --authorization-ref '<REF>'" >&2
    exit 2
fi

exec python3 -m assessment.live_assessment "$@"
