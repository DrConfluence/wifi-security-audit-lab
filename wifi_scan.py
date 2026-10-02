#!/usr/bin/env python3

import argparse
import csv
import json
import secrets
import subprocess
import sys
from datetime import datetime
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

try:
    from assessment.session import DISALLOWED_REFS
except ImportError:
    DISALLOWED_REFS = {
        "",
        "none",
        "null",
        "undefined",
        "default",
        "test",
        "authorized-lab",
    }

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
    try:
        result = subprocess.run(
            ["termux-wifi-scaninfo"],
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError as exc:
        raise RuntimeError(
            "Missing optional platform tool: 'termux-wifi-scaninfo' was not found on this system. "
            "This command requires Termux with Termux:API installed on Android."
        ) from exc

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


def load_authorizations(auth_file=None):
    """
    Load scope records from an authorization file.
    Validates required headers: ssid, bssid, authorization_ref, scope.
    Rejects disallowed authorization references (e.g. 'none', 'default', 'test', 'authorized-lab').
    Indexes records by both normalized BSSID and SSID for established scope matching.
    Fails closed on missing or malformed headers.
    """
    path = Path(auth_file) if auth_file else AUTH_FILE
    if not path.exists():
        return {}

    if not path.is_file():
        raise ValueError(f"Authorization path '{path}' is not a regular file")

    authorizations = {}

    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        required = {
            "ssid",
            "bssid",
            "authorization_ref",
            "scope",
        }

        if not reader.fieldnames or not required.issubset(set(reader.fieldnames)):
            raise ValueError(
                "authorized_networks.csv must contain: "
                "ssid,bssid,authorization_ref,scope"
            )

        for row in reader:
            if not row:
                continue

            ref = (row.get("authorization_ref") or "").strip()
            if not ref or ref.lower() in DISALLOWED_REFS:
                continue

            bssid = normalize_bssid(row.get("bssid"))
            ssid = (row.get("ssid") or "").strip()

            if not bssid and not ssid:
                continue

            rec = {
                "ssid": ssid,
                "bssid": bssid,
                "authorization_ref": ref,
                "scope": (row.get("scope") or "").strip(),
            }

            if bssid:
                authorizations.setdefault(bssid, []).append(rec)
            if ssid:
                authorizations.setdefault(ssid.lower(), []).append(rec)

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
    ssid_key = (ssid or "").strip().lower()

    # Scope validation: An SSID match alone does NOT grant authorization to an AP.
    # Authorization requires matching the specific authorized BSSID hardware identity.
    # An SSID match without a matching BSSID is retained purely as a non-authorizing discovery hint.
    authorized = False
    authorization_ref = ""
    scope = ""
    authorization_match = "NONE"

    if bssid_key and bssid_key in authorizations:
        entry = authorizations[bssid_key]
        match_entry = entry[0] if isinstance(entry, list) else entry
        auth_ssid = (match_entry.get("ssid") or "").strip().lower()
        if not auth_ssid or auth_ssid == ssid_key:
            authorized = True
            authorization_match = "BSSID"
            authorization_ref = match_entry.get("authorization_ref", "")
            scope = match_entry.get("scope", "")
        else:
            authorized = False
            authorization_match = "BSSID_SSID_MISMATCH"
            authorization_ref = ""
            scope = ""
    elif ssid_key and ssid_key in authorizations:
        # SSID matches an authorized network profile, but the scanned BSSID is different or unverified.
        # Retained as a non-authorizing hint for discovery without granting authorization.
        authorized = False
        authorization_match = "SSID_HINT"
        authorization_ref = ""
        scope = ""

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


def write_csv(records, path=None):
    """
    Append scan records to the cumulative CSV log without destroying prior evidence.
    Writes the header only if the file does not exist or is empty.
    Handles empty record sets gracefully without corrupting existing files.
    Note: Log writes are sequential and append-only. Multiple concurrent processes
    should not write simultaneously without external file locking.
    """
    target = Path(path) if path else CSV_LOG
    target.parent.mkdir(parents=True, exist_ok=True)

    file_exists_with_content = target.exists() and target.stat().st_size > 0

    if not file_exists_with_content:
        with target.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=CSV_FIELDS)
            writer.writeheader()
            if records:
                writer.writerows(records)
    else:
        if records:
            with target.open("a+", newline="", encoding="utf-8") as handle:
                handle.seek(0, 2)
                pos = handle.tell()
                if pos > 0:
                    handle.seek(pos - 1)
                    last_char = handle.read(1)
                    if last_char != "\n":
                        handle.write("\n")

                writer = csv.DictWriter(handle, fieldnames=CSV_FIELDS)
                writer.writerows(records)

    return target


def write_json(records, path=None):
    """
    Append scan records to the cumulative JSON log without destroying prior evidence.
    Maintains parity with the cumulative CSV log.
    Handles empty record sets gracefully without corrupting existing files.
    Safely preserves malformed existing files via backup to prevent evidence loss.
    Uses atomic temporary-file replacement for crash resilience.
    """
    target = Path(path) if path else JSON_LOG
    target.parent.mkdir(parents=True, exist_ok=True)

    if not records and target.exists() and target.stat().st_size > 0:
        return target

    existing_records = []
    if target.exists() and target.stat().st_size > 0:
        try:
            content = target.read_text(encoding="utf-8").strip()
            if content:
                loaded = json.loads(content)
                if isinstance(loaded, list):
                    existing_records = loaded
                else:
                    raise ValueError("JSON log root is not a list")
        except Exception:
            # Preserve malformed evidence safely by creating a timestamped backup copy
            backup_path = target.with_name(
                f"{target.stem}.corrupt.{datetime.now().astimezone().strftime('%Y%m%d_%H%M%S')}{target.suffix}"
            )
            try:
                backup_path.write_text(target.read_text(encoding="utf-8"), encoding="utf-8")
            except OSError:
                pass
            existing_records = []

    combined = existing_records + list(records)
    payload = json.dumps(combined, indent=2, ensure_ascii=False) + "\n"

    # Write atomically via temp file to prevent partial/truncated writes on interrupt
    temp_target = target.with_name(f"{target.name}.tmp.{secrets.token_hex(4)}")
    try:
        temp_target.write_text(payload, encoding="utf-8")
        temp_target.replace(target)
    except OSError:
        target.write_text(payload, encoding="utf-8")
        if temp_target.exists():
            try:
                temp_target.unlink()
            except OSError:
                pass

    return target


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Passive Wi-Fi assessment scan via Termux:API against authorized network scope."
    )
    return parser.parse_args(argv)


def main(argv=None):
    parse_args(argv)

    scan_id = generate_scan_id()
    timestamp = datetime.now().astimezone().isoformat()

    try:
        authorizations = load_authorizations()
    except (RuntimeError, ValueError) as exc:
        print(f"[-] Authorization configuration error: {exc}", file=sys.stderr)
        return 1

    try:
        networks = scan_wifi()
    except RuntimeError as exc:
        print(f"[-] Scan error: {exc}", file=sys.stderr)
        return 1

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

    unique_scope_count = len({
        (e.get("ssid"), e.get("bssid"), e.get("authorization_ref"))
        for entries in authorizations.values()
        for e in (entries if isinstance(entries, list) else [entries])
    })

    print("========================================")
    print(" Wi-Fi Passive Audit")
    print("========================================")
    print(f"Scan ID:          {scan_id}")
    print(f"Networks:         {total}")
    print(f"Authorized:       {authorized}")
    print(f"Not authorized:   {not_authorized}")
    print(f"Authorization:    {percentage:.1f}%")
    print(f"Scope records:    {unique_scope_count}")
    print(f"CSV:              {CSV_LOG}")
    print(f"JSON:             {JSON_LOG}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
