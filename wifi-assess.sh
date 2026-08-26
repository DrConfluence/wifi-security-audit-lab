#!/data/data/com.termux/files/usr/bin/bash
set -u

cd "$(dirname "$0")"

if [ "$#" -lt 3 ]; then
    echo "Usage:"
    echo "  ./wifi-assess.sh --ssid '<SSID>' --authorization-ref '<REF>'"
    exit 2
fi

python -m assessment.live_assessment "$@"
