#!/usr/bin/env python3

import json
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
EVIDENCE_DIR = BASE_DIR / "evidence"


def run(command):
    try:
        p = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
        )
        return {
            "returncode": p.returncode,
            "stdout": p.stdout.strip(),
            "stderr": p.stderr.strip(),
        }
    except FileNotFoundError as exc:
        return {
            "returncode": 127,
            "stdout": "",
            "stderr": str(exc),
        }


def security_class(capabilities):
    value = (capabilities or "").upper()

    if not value:
        return "UNKNOWN"

    if "OWE" in value:
        return "OWE"

    if "WPA3" in value or "SAE" in value:
        if "WPA2" in value:
            return "WPA2/WPA3"
        return "WPA3"

    if "WPA2" in value:
        return "WPA2"

    if "WPA" in value:
        return "WPA"

    if "WEP" in value:
        return "WEP"

    if "[ESS]" in value:
        return "OPEN/UNSPECIFIED"

    return "UNKNOWN"


def band_from_frequency(frequency):
    try:
        frequency = int(frequency)
    except (TypeError, ValueError):
        return "UNKNOWN"

    if 2400 <= frequency < 2500:
        return "2.4 GHz"

    if 4900 <= frequency < 5900:
        return "5 GHz"

    if 5925 <= frequency <= 7125:
        return "6 GHz"

    return "UNKNOWN"


def normalize_network(item):
    if not isinstance(item, dict):
        return None

    frequency = item.get("frequency_mhz")
    capabilities = item.get("capabilities", "")

    return {
        "ssid": item.get("ssid") or "<hidden>",
        "bssid": item.get("bssid"),
        "rssi": item.get("rssi"),
        "frequency_mhz": frequency,
        "band": band_from_frequency(frequency),
        "channel_bandwidth_mhz": item.get(
            "channel_bandwidth_mhz"
        ),
        "center_frequency_mhz": item.get(
            "center_frequency_mhz"
        ),
        "capabilities": capabilities,
        "security": security_class(capabilities),
        "wps_advertised": "[WPS]" in capabilities.upper(),
        "timestamp": item.get("timestamp"),
    }


def scan():
    if not shutil.which("termux-wifi-scaninfo"):
        return {
            "available": False,
            "reason": "termux-wifi-scaninfo unavailable",
            "networks": [],
        }

    result = run(["termux-wifi-scaninfo"])

    if result["returncode"] != 0:
        return {
            "available": False,
            "reason": result["stderr"],
            "networks": [],
        }

    try:
        raw = json.loads(result["stdout"])
    except json.JSONDecodeError:
        return {
            "available": False,
            "reason": "invalid JSON",
            "networks": [],
            "raw": result["stdout"],
        }

    if isinstance(raw, dict) and "API_ERROR" in raw:
        return {
            "available": False,
            "reason": raw["API_ERROR"],
            "networks": [],
        }

    if not isinstance(raw, list):
        return {
            "available": False,
            "reason": "unexpected API response",
            "networks": [],
        }

    networks = []

    for item in raw:
        normalized = normalize_network(item)
        if normalized:
            networks.append(normalized)

    return {
        "available": True,
        "timestamp": datetime.now(
            timezone.utc
        ).isoformat(),
        "count": len(networks),
        "networks": networks,
    }


def write_evidence(result):
    EVIDENCE_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    path = EVIDENCE_DIR / "wifi_discovery.json"

    path.write_text(
        json.dumps(
            result,
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    return path


def print_table(result):
    print()
    print("=" * 108)
    print(
        "SSID".ljust(24),
        "BAND".ljust(9),
        "RSSI".ljust(7),
        "SECURITY".ljust(14),
        "WPS".ljust(5),
        "BSSID",
    )
    print("-" * 108)

    for network in result.get("networks", []):
        print(
            str(network["ssid"])[:23].ljust(24),
            str(network["band"]).ljust(9),
            str(network["rssi"]).ljust(7),
            str(network["security"]).ljust(14),
            ("YES" if network["wps_advertised"] else "NO").ljust(5),
            str(network["bssid"] or "-"),
        )

    print("=" * 108)


def main():
    print("=" * 108)
    print("             LIVE WI-FI DISCOVERY")
    print("=" * 108)

    result = scan()

    if not result["available"]:
        print("Discovery unavailable:", result["reason"])
        return 1

    print("Networks observed:", result["count"])

    print_table(result)

    path = write_evidence(result)

    print()
    print("Evidence:", path)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
