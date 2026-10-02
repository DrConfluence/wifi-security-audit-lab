#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")" || exit 1

if [ $# -lt 1 ] || [ -z "$1" ]; then
    echo "ERROR: Explicit authorization reference is required." >&2
    echo "Usage: ./wifi-authorized-lan.sh <AUTHORIZATION_REF>" >&2
    exit 2
fi

AUTH_REF="$1"

if ! command -v termux-wifi-connectioninfo >/dev/null 2>&1; then
    echo "ERROR: termux-wifi-connectioninfo is not installed on this system." >&2
    exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
    echo "ERROR: jq is required but not installed." >&2
    exit 1
fi

CONN_JSON="$(termux-wifi-connectioninfo)"
IP="$(printf '%s' "$CONN_JSON" | jq -r '.ip')"
SSID="$(printf '%s' "$CONN_JSON" | jq -r '.ssid')"
BSSID="$(printf '%s' "$CONN_JSON" | jq -r '.bssid')"

if [ -z "$IP" ] || [ "$IP" = "null" ] || [ "$IP" = "0.0.0.0" ]; then
    echo "ERROR: Wi-Fi is not connected." >&2
    exit 1
fi

# Fail closed before any network probe if authorization is missing or invalid
python3 -c "
import sys
from assessment.session import validate_scope
ref, ssid, bssid = sys.argv[1], sys.argv[2], sys.argv[3]
valid, reason = validate_scope(ssid=ssid, bssid=bssid, authorization_ref=ref)
if not valid:
    print(f'ERROR: Scope validation failed: {reason}', file=sys.stderr)
    sys.exit(1)
" "$AUTH_REF" "$SSID" "$BSSID" || exit 1

if ! command -v nmap >/dev/null 2>&1; then
    echo "ERROR: nmap is required for LAN host discovery but not installed." >&2
    exit 1
fi

PREFIX="${IP%.*}"
TARGET="${PREFIX}.0/24"

mkdir -p evidence

echo "============================================================"
echo "AUTHORIZED LAN INVENTORY"
echo "============================================================"
echo "Authorization : $AUTH_REF"
echo "SSID          : $SSID"
echo "BSSID         : $BSSID"
echo "Device IP     : $IP"
echo "Target        : $TARGET"
echo "============================================================"
echo

echo "[1] HOST DISCOVERY"
nmap -n -sn \
    --send-ip \
    --max-retries 1 \
    --host-timeout 5s \
    "$TARGET" \
    -oX evidence/lan_hosts.xml

echo
echo "[2] HOSTS FOUND"

python - "$IP" "$TARGET" <<'PY'
import json
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

ip = sys.argv[1]
target = sys.argv[2]

hosts = []

try:
    root = ET.parse("evidence/lan_hosts.xml").getroot()

    for host in root.findall("host"):
        status = host.find("status")

        if status is None or status.get("state") != "up":
            continue

        addresses = [
            {
                "address": a.get("addr"),
                "type": a.get("addrtype"),
            }
            for a in host.findall("address")
        ]

        names = [
            x.get("name")
            for x in host.findall("./hostnames/hostname")
            if x.get("name")
        ]

        hosts.append({
            "addresses": addresses,
            "hostnames": names,
        })

except Exception as exc:
    print("Could not parse Nmap XML:", exc)

result = {
    "timestamp": datetime.now(timezone.utc).isoformat(),
    "device_ip": ip,
    "target": target,
    "hosts_observed": len(hosts),
    "hosts": hosts,
}

stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
target_path = Path(f"evidence/lan_hosts_{stamp}.json")
counter = 1
while target_path.exists():
    target_path = Path(f"evidence/lan_hosts_{stamp}_{counter}.json")
    counter += 1
target_path.write_text(
    json.dumps(result, indent=2),
    encoding="utf-8",
)
Path("evidence/lan_hosts.json").write_text(
    json.dumps(result, indent=2),
    encoding="utf-8",
)

print(json.dumps(result, indent=2))
PY

echo
echo "[3] SERVICE DISCOVERY"

nmap -n -sT \
    --open \
    --max-retries 1 \
    --host-timeout 10s \
    -p 22,53,80,443,445,3389,8080,8443 \
    "$TARGET" \
    -oX evidence/lan_services.xml

echo
echo "============================================================"
echo "RESULT FILES"
echo "============================================================"

ls -lh \
    evidence/lan_hosts.xml \
    evidence/lan_hosts.json \
    evidence/lan_services.xml

echo
echo "============================================================"
echo "OPEN SERVICES"
echo "============================================================"

grep -E '<address|<port |<service ' \
    evidence/lan_services.xml |
    head -200
