#!/data/data/com.termux/files/usr/bin/bash
set -u

IP="$(termux-wifi-connectioninfo | jq -r '.ip')"

if [ -z "$IP" ] || [ "$IP" = "null" ] || [ "$IP" = "0.0.0.0" ]; then
    echo "ERROR: Wi-Fi is not connected."
    exit 1
fi

PREFIX="${IP%.*}"
TARGET="${PREFIX}.0/24"

echo "============================================================"
echo "AUTHORIZED LAN INVENTORY"
echo "============================================================"
echo "SSID      : $(termux-wifi-connectioninfo | jq -r '.ssid')"
echo "BSSID     : $(termux-wifi-connectioninfo | jq -r '.bssid')"
echo "Device IP : $IP"
echo "Target    : $TARGET"
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
