#!/usr/bin/env python3

import csv
import json
import secrets
import subprocess
from datetime import datetime
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

AUTH_FILE = BASE_DIR / "authorized_networks.csv"
CSV_LOG = BASE_DIR / "networks_log.csv"
JSON_LOG = BASE_DIR / "networks_log.json"

CSV_FIELDS = [
    "scan_id",
    "timestamp",
    "ssid",
    "bssid",
    "security",
    "capabilities",
    "signal_dbm",
    "frequency_mhz",
    "band",
    "channel",
    "authorized",
    "authorization_ref",
    "scope",
    "authorization_match",
]


def generate_scan_id():
    timestamp = datetime.now().astimezone().strftime("%Y%m%d-%H%M%S")
    return f"{timestamp}-{secrets.token_hex(2)}"


def scan_wifi():
    result = subprocess.run(
        ["termux-wifi-scaninfo"],
        capture_output=True,
        text=True,
        check=False,
    )

    if result.returncode != 0:
        raise RuntimeError(
            result.stderr.strip() or "Wi-Fi scan command failed"
        )

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            "Termux:API did not return valid JSON"
        ) from exc

    if isinstance(data, dict) and "error" in data:
        raise RuntimeError(data["error"])

    if not isinstance(data, list):
        raise RuntimeError("Unexpected Wi-Fi scan response")

    return data


def load_authorizations():
    """
    Returns:
        {
            "bssid": {
                "ssid": ...,
                "authorization_ref": ...,
                "scope": ...
            },
            ...
        }

    BSSID is the strongest authorization identifier.
    """

    authorizations = {}

    if not AUTH_FILE.exists():
        return authorizations

    with AUTH_FILE.open(
        newline="",
        encoding="utf-8",
    ) as handle:

        reader = csv.DictReader(handle)

        required = {
            "ssid",
            "bssid",
            "authorization_ref",
            "scope",
        }

        if not required.issubset(reader.fieldnames or set()):
            raise RuntimeError(
                "authorized_networks.csv must contain: "
                "ssid,bssid,authorization_ref,scope"
            )

        for row in reader:
            bssid = row["bssid"].strip().lower()

            if not bssid:
                continue

            authorizations[bssid] = {
                "ssid": row["ssid"].strip(),
                "authorization_ref": row["authorization_ref"].strip(),
                "scope": row["scope"].strip(),
            }

    return authorizations


def classify_security(capabilities):
    caps = (capabilities or "").upper()

    if "WEP" in caps:
        return "WEP"

    if "WPA3" in caps or "SAE" in caps:
        return "WPA3"

    if "WPA2" in caps or "RSN" in caps:
        return "WPA2"

    if "WPA" in caps:
        return "WPA"

    if "[ESS]" in caps:
        return "OPEN"

    return "UNKNOWN"


def frequency_to_band(frequency):
    if 2400 <= frequency <= 2500:
        return "2.4GHz"

    if 4900 <= frequency <= 5900:
        return "5GHz"

    return "OTHER"


def frequency_to_channel(frequency):
    if 2412 <= frequency <= 2472:
        return (frequency - 2407) // 5

    if frequency == 2484:
        return 14

    if 5000 <= frequency <= 5900:
        return (frequency - 5000) // 5

    return ""


def normalize_bssid(value):
    return (value or "").strip().lower()


def build_record(
    network,
    scan_id,
    timestamp,
    authorizations,
):
    ssid = network.get("ssid", "")
    bssid = network.get("bssid", "")
    capabilities = network.get("capabilities", "")

    frequency = network.get(
        "frequency_mhz",
        network.get("frequency", ""),
    )

    try:
        frequency = int(frequency)
    except (TypeError, ValueError):
        frequency = 0

    signal = network.get(
        "rssi",
        network.get("level", ""),
    )

    bssid_key = normalize_bssid(bssid)

    authorization = authorizations.get(bssid_key)

    if authorization:
        authorized = True
        authorization_ref = authorization["authorization_ref"]
        scope = authorization["scope"]
        authorization_match = "BSSID"
    else:
        authorized = False
        authorization_ref = ""
        scope = ""
        authorization_match = "NONE"

    return {
        "scan_id": scan_id,
        "timestamp": timestamp,
        "ssid": ssid,
        "bssid": bssid,
        "security": classify_security(capabilities),
        "capabilities": capabilities,
        "signal_dbm": signal,
        "frequency_mhz": frequency,
        "band": frequency_to_band(frequency),
        "channel": (
            frequency_to_channel(frequency)
            if frequency
            else ""
        ),
        "authorized": authorized,
        "authorization_ref": authorization_ref,
        "scope": scope,
        "authorization_match": authorization_match,
    }


def write_csv(records):
    with CSV_LOG.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as handle:

        writer = csv.DictWriter(
            handle,
            fieldnames=CSV_FIELDS,
        )

        writer.writeheader()
        writer.writerows(records)


def write_json(records):
    JSON_LOG.write_text(
        json.dumps(
            records,
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )


def main():
    scan_id = generate_scan_id()
    timestamp = datetime.now().astimezone().isoformat()

    authorizations = load_authorizations()
    networks = scan_wifi()

    records = [
        build_record(
            network,
            scan_id,
            timestamp,
            authorizations,
        )
        for network in networks
    ]

    write_csv(records)
    write_json(records)

    authorized = sum(
        bool(record["authorized"])
        for record in records
    )

    total = len(records)
    not_authorized = total - authorized

    percentage = (
        (authorized / total) * 100
        if total
        else 0
    )

    print("========================================")
    print(" Wi-Fi Passive Audit")
    print("========================================")
    print(f"Scan ID:          {scan_id}")
    print(f"Networks:         {total}")
    print(f"Authorized:       {authorized}")
    print(f"Not authorized:   {not_authorized}")
    print(f"Authorization:    {percentage:.1f}%")
    print(f"Scope records:    {len(authorizations)}")
    print(f"CSV:              {CSV_LOG}")
    print(f"JSON:             {JSON_LOG}")


if __name__ == "__main__":
    main()
