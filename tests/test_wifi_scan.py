import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from wifi_scan import (
    classify_security,
    frequency_to_band,
    frequency_to_channel,
)


def test_wpa2_classification():
    capabilities = "[WPA2-PSK-CCMP-128][RSN-PSK-CCMP-128][ESS]"
    assert classify_security(capabilities) == "WPA2"


def test_wpa3_classification():
    capabilities = "[WPA3-SAE-CCMP-128][ESS]"
    assert classify_security(capabilities) == "WPA3"


def test_wep_classification():
    capabilities = "[WEP][ESS]"
    assert classify_security(capabilities) == "WEP"


def test_open_network_classification():
    assert classify_security("[ESS]") == "OPEN"


def test_unknown_security():
    assert classify_security("") == "UNKNOWN"


def test_24ghz_band():
    assert frequency_to_band(2412) == "2.4GHz"


def test_5ghz_band():
    assert frequency_to_band(5180) == "5GHz"


def test_channel_1():
    assert frequency_to_channel(2412) == 1


def test_channel_6():
    assert frequency_to_channel(2437) == 6


def test_channel_11():
    assert frequency_to_channel(2462) == 11


def test_channel_36():
    assert frequency_to_channel(5180) == 36


def test_channel_149():
    assert frequency_to_channel(5745) == 149


def test_help_does_not_require_hardware():
    from wifi_scan import parse_args
    import pytest

    with pytest.raises(SystemExit) as exc:
        parse_args(["--help"])
    assert exc.value.code == 0


def test_scan_wifi_missing_tool_actionable_error(monkeypatch):
    import subprocess
    import pytest
    from wifi_scan import scan_wifi

    def fake_run(*args, **kwargs):
        raise FileNotFoundError("termux-wifi-scaninfo")

    monkeypatch.setattr(subprocess, "run", fake_run)

    with pytest.raises(RuntimeError) as exc_info:
        scan_wifi()

    msg = str(exc_info.value)
    assert "Missing optional platform tool" in msg
    assert "termux-wifi-scaninfo" in msg


def test_main_missing_tool_fails_gracefully(monkeypatch):
    import subprocess
    from wifi_scan import main

    def fake_run(*args, **kwargs):
        raise FileNotFoundError("termux-wifi-scaninfo")

    monkeypatch.setattr(subprocess, "run", fake_run)

    code = main([])
    assert code == 1


def make_mock_record(scan_id="scan-001", ssid="TestNet", bssid="aa:bb:cc:dd:ee:01", authorized=True):
    return {
        "scan_id": scan_id,
        "timestamp": "2026-10-02T10:00:00+00:00",
        "ssid": ssid,
        "bssid": bssid,
        "security": "WPA2",
        "capabilities": "[WPA2-PSK-CCMP-128][ESS]",
        "signal_dbm": -65,
        "frequency_mhz": 2412,
        "band": "2.4GHz",
        "channel": 1,
        "authorized": authorized,
        "authorization_ref": "AUTH-2026-A1" if authorized else "",
        "scope": "LAB-INTERNAL" if authorized else "",
        "authorization_match": "BSSID" if authorized else "NONE",
    }


def test_first_scan_creates_valid_evidence(tmp_path):
    from wifi_scan import write_csv, write_json, CSV_FIELDS
    import csv
    import json

    csv_file = tmp_path / "networks_log.csv"
    json_file = tmp_path / "networks_log.json"

    rec1 = make_mock_record(scan_id="scan-1", ssid="Net1", bssid="11:22:33:44:55:66")
    rec2 = make_mock_record(scan_id="scan-1", ssid="Net2", bssid="aa:bb:cc:dd:ee:ff", authorized=False)
    records = [rec1, rec2]

    write_csv(records, path=csv_file)
    write_json(records, path=json_file)

    assert csv_file.exists()
    assert json_file.exists()

    with csv_file.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        assert reader.fieldnames == CSV_FIELDS
        csv_rows = list(reader)
        assert len(csv_rows) == 2
        assert csv_rows[0]["scan_id"] == "scan-1"
        assert csv_rows[0]["ssid"] == "Net1"
        assert csv_rows[0]["authorized"] == "True"
        assert csv_rows[1]["authorized"] == "False"

    with json_file.open(encoding="utf-8") as f:
        json_data = json.load(f)
        assert isinstance(json_data, list)
        assert len(json_data) == 2
        assert json_data[0]["scan_id"] == "scan-1"
        assert json_data[0]["ssid"] == "Net1"
        assert json_data[0]["authorized"] is True


def test_second_scan_preserves_first_scan_evidence(tmp_path):
    from wifi_scan import write_csv, write_json
    import csv
    import json

    csv_file = tmp_path / "networks_log.csv"
    json_file = tmp_path / "networks_log.json"

    scan1 = [make_mock_record(scan_id="scan-1", ssid="Net1")]
    scan2 = [make_mock_record(scan_id="scan-2", ssid="Net2")]

    write_csv(scan1, path=csv_file)
    write_json(scan1, path=json_file)

    # Second run appends without overwriting or truncating
    write_csv(scan2, path=csv_file)
    write_json(scan2, path=json_file)

    raw_lines = csv_file.read_text(encoding="utf-8").splitlines()
    header_count = sum(1 for line in raw_lines if line.startswith("scan_id,"))
    assert header_count == 1
    assert len(raw_lines) == 3  # 1 header + 2 data rows

    with csv_file.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
        assert len(rows) == 2
        assert rows[0]["scan_id"] == "scan-1"
        assert rows[1]["scan_id"] == "scan-2"

    with json_file.open(encoding="utf-8") as f:
        json_data = json.load(f)
        assert len(json_data) == 2
        assert json_data[0]["scan_id"] == "scan-1"
        assert json_data[1]["scan_id"] == "scan-2"


def test_repeated_runs_cannot_overwrite_prior_evidence(tmp_path):
    from wifi_scan import write_csv, write_json
    import csv
    import json

    csv_file = tmp_path / "networks_log.csv"
    json_file = tmp_path / "networks_log.json"

    total_runs = 5
    for i in range(1, total_runs + 1):
        rec = [make_mock_record(scan_id=f"run-{i}", ssid=f"Net-{i}")]
        write_csv(rec, path=csv_file)
        write_json(rec, path=json_file)

    with csv_file.open(newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
        assert len(rows) == total_runs
        for i, row in enumerate(rows, 1):
            assert row["scan_id"] == f"run-{i}"
            assert row["ssid"] == f"Net-{i}"

    with json_file.open(encoding="utf-8") as f:
        json_data = json.load(f)
        assert len(json_data) == total_runs
        for i, item in enumerate(json_data, 1):
            assert item["scan_id"] == f"run-{i}"
            assert item["ssid"] == f"Net-{i}"


def test_csv_and_json_represent_same_scan_data(tmp_path):
    from wifi_scan import write_csv, write_json, CSV_FIELDS
    import csv
    import json

    csv_file = tmp_path / "networks_log.csv"
    json_file = tmp_path / "networks_log.json"

    records = [
        make_mock_record(scan_id="scan-a", ssid="SSID-A", bssid="11:22:33:44:55:01", authorized=True),
        make_mock_record(scan_id="scan-a", ssid="SSID-B", bssid="11:22:33:44:55:02", authorized=False),
        make_mock_record(scan_id="scan-b", ssid="SSID-C", bssid="11:22:33:44:55:03", authorized=True),
    ]

    write_csv(records, path=csv_file)
    write_json(records, path=json_file)

    with csv_file.open(newline="", encoding="utf-8") as f:
        csv_rows = list(csv.DictReader(f))

    with json_file.open(encoding="utf-8") as f:
        json_rows = json.load(f)

    assert len(csv_rows) == len(json_rows) == 3

    for csv_rec, json_rec in zip(csv_rows, json_rows):
        for field in CSV_FIELDS:
            assert csv_rec[field] == str(json_rec[field])


def test_empty_scan_results_do_not_corrupt_prior_evidence(tmp_path):
    from wifi_scan import write_csv, write_json
    import csv
    import json

    csv_file = tmp_path / "networks_log.csv"
    json_file = tmp_path / "networks_log.json"

    # Case 1: Empty scan on fresh files creates valid empty structures
    write_csv([], path=csv_file)
    write_json([], path=json_file)
    assert csv_file.exists()
    assert json_file.exists()
    with csv_file.open(newline="", encoding="utf-8") as f:
        assert len(list(csv.DictReader(f))) == 0
    with json_file.open(encoding="utf-8") as f:
        assert json.load(f) == []

    # Populate with actual scan records
    records = [make_mock_record(scan_id="scan-live", ssid="TargetAP")]
    write_csv(records, path=csv_file)
    write_json(records, path=json_file)

    content_csv_before = csv_file.read_text(encoding="utf-8")
    content_json_before = json_file.read_text(encoding="utf-8")

    # Case 2: Subsequent empty scan must NOT truncate or alter prior records
    write_csv([], path=csv_file)
    write_json([], path=json_file)

    assert csv_file.read_text(encoding="utf-8") == content_csv_before
    assert json_file.read_text(encoding="utf-8") == content_json_before


def test_missing_or_malformed_authorization_headers_fail_gracefully(tmp_path):
    from wifi_scan import load_authorizations
    import pytest

    # Missing 'scope' column
    bad_header_file = tmp_path / "bad_headers.csv"
    bad_header_file.write_text("ssid,bssid,authorization_ref\nLabNet,aa:bb:cc:dd:ee:ff,AUTH-01\n", encoding="utf-8")

    with pytest.raises(ValueError) as exc:
        load_authorizations(auth_file=bad_header_file)
    assert "authorized_networks.csv must contain: ssid,bssid,authorization_ref,scope" in str(exc.value)

    # Empty file
    empty_file = tmp_path / "empty.csv"
    empty_file.write_text("", encoding="utf-8")
    with pytest.raises(ValueError) as exc_empty:
        load_authorizations(auth_file=empty_file)
    assert "authorized_networks.csv must contain: ssid,bssid,authorization_ref,scope" in str(exc_empty.value)

    # Non-file path (directory)
    dir_path = tmp_path / "some_dir"
    dir_path.mkdir()
    with pytest.raises(ValueError) as exc_dir:
        load_authorizations(auth_file=dir_path)
    assert "not a regular file" in str(exc_dir.value)


def test_disallowed_references_are_rejected(tmp_path):
    from wifi_scan import load_authorizations

    auth_file = tmp_path / "authorized_networks.csv"
    auth_file.write_text(
        "ssid,bssid,authorization_ref,scope\n"
        "Net1,aa:bb:cc:dd:ee:01,default,LAB-SCOPE\n"
        "Net2,aa:bb:cc:dd:ee:02,test,LAB-SCOPE\n"
        "Net3,aa:bb:cc:dd:ee:03,none,LAB-SCOPE\n"
        "Net4,aa:bb:cc:dd:ee:04,null,LAB-SCOPE\n"
        "Net5,aa:bb:cc:dd:ee:05,undefined,LAB-SCOPE\n"
        "Net6,aa:bb:cc:dd:ee:06,authorized-lab,LAB-SCOPE\n"
        "Net7,aa:bb:cc:dd:ee:07,,LAB-SCOPE\n"
        "ValidNet,aa:bb:cc:dd:ee:08,AUTH-LEGIT-2026,LAB-SCOPE\n",
        encoding="utf-8",
    )

    auth = load_authorizations(auth_file=auth_file)
    assert "aa:bb:cc:dd:ee:01" not in auth
    assert "aa:bb:cc:dd:ee:02" not in auth
    assert "aa:bb:cc:dd:ee:03" not in auth
    assert "aa:bb:cc:dd:ee:04" not in auth
    assert "aa:bb:cc:dd:ee:05" not in auth
    assert "aa:bb:cc:dd:ee:06" not in auth
    assert "aa:bb:cc:dd:ee:07" not in auth

    assert "aa:bb:cc:dd:ee:08" in auth
    assert "validnet" in auth
    assert auth["aa:bb:cc:dd:ee:08"][0]["authorization_ref"] == "AUTH-LEGIT-2026"


def test_authorization_matching_bssid_and_ssid_rules():
    from wifi_scan import build_record

    authorizations = {
        "aa:bb:cc:dd:ee:01": [{
            "ssid": "AuthByBSSID",
            "bssid": "aa:bb:cc:dd:ee:01",
            "authorization_ref": "REF-BSSID",
            "scope": "SCOPE-BSSID",
        }],
        "authbyssid": [{
            "ssid": "AuthBySSID",
            "bssid": "",
            "authorization_ref": "REF-SSID",
            "scope": "SCOPE-SSID",
        }],
    }

    # 1. Matches BSSID directly
    rec1 = build_record(
        {"ssid": "AuthByBSSID", "bssid": "AA:BB:CC:DD:EE:01", "capabilities": "[WPA2-PSK]"},
        "scan-1",
        "2026-10-02T12:00:00Z",
        authorizations,
    )
    assert rec1["authorized"] is True
    assert rec1["authorization_match"] == "BSSID"
    assert rec1["authorization_ref"] == "REF-BSSID"

    # 1b. Mismatched SSID on known BSSID is not authorized
    rec1_mismatch = build_record(
        {"ssid": "ImposterSSID", "bssid": "AA:BB:CC:DD:EE:01", "capabilities": "[WPA2-PSK]"},
        "scan-1",
        "2026-10-02T12:00:00Z",
        authorizations,
    )
    assert rec1_mismatch["authorized"] is False
    assert rec1_mismatch["authorization_match"] == "BSSID_SSID_MISMATCH"

    # 2. Matches SSID when BSSID does not match (non-authorizing discovery hint)
    rec2 = build_record(
        {"ssid": "AuthBySSID", "bssid": "11:22:33:44:55:66", "capabilities": "[WPA2-PSK]"},
        "scan-1",
        "2026-10-02T12:00:00Z",
        authorizations,
    )
    assert rec2["authorized"] is False
    assert rec2["authorization_match"] == "SSID_HINT"
    assert rec2["authorization_ref"] == ""

    # 3. BSSID takes priority over SSID if both match
    authorizations_both = {
        "aa:bb:cc:dd:ee:99": [{
            "ssid": "DualMatch",
            "bssid": "aa:bb:cc:dd:ee:99",
            "authorization_ref": "REF-PRIORITY-BSSID",
            "scope": "SCOPE-PRIORITY",
        }],
        "dualmatch": [{
            "ssid": "DualMatch",
            "bssid": "",
            "authorization_ref": "REF-FALLBACK-SSID",
            "scope": "SCOPE-FALLBACK",
        }],
    }
    rec3 = build_record(
        {"ssid": "DualMatch", "bssid": "AA:BB:CC:DD:EE:99", "capabilities": "[WPA2-PSK]"},
        "scan-1",
        "2026-10-02T12:00:00Z",
        authorizations_both,
    )
    assert rec3["authorized"] is True
    assert rec3["authorization_match"] == "BSSID"
    assert rec3["authorization_ref"] == "REF-PRIORITY-BSSID"

    # 4. Neither matches
    rec4 = build_record(
        {"ssid": "RogueNet", "bssid": "fe:dc:ba:98:76:54", "capabilities": "[OPEN]"},
        "scan-1",
        "2026-10-02T12:00:00Z",
        authorizations,
    )
    assert rec4["authorized"] is False
    assert rec4["authorization_match"] == "NONE"
    assert rec4["authorization_ref"] == ""
    assert rec4["scope"] == ""


def test_spoofed_ssid_with_mismatched_bssid_is_not_authorized():
    from wifi_scan import build_record

    authorizations = {
        "02:00:00:00:00:01": [{
            "ssid": "CorpWiFi",
            "bssid": "02:00:00:00:00:01",
            "authorization_ref": "AUTH-CORP",
            "scope": "CORP-SCOPE",
        }],
        "corpwifi": [{
            "ssid": "CorpWiFi",
            "bssid": "02:00:00:00:00:01",
            "authorization_ref": "AUTH-CORP",
            "scope": "CORP-SCOPE",
        }],
    }

    # Rogue AP broadcasting CorpWiFi with rogue BSSID
    rogue_network = {
        "ssid": "CorpWiFi",
        "bssid": "de:ad:be:ef:00:99",
        "capabilities": "[WPA2-PSK]",
    }
    rec = build_record(rogue_network, "scan-99", "2026-10-02T12:00:00Z", authorizations)
    assert rec["authorized"] is False
    assert rec["authorization_match"] == "SSID_HINT"
    assert rec["authorization_ref"] == ""


def test_write_json_malformed_existing_file_preserves_backup(tmp_path):
    from wifi_scan import write_json
    import json

    json_file = tmp_path / "networks_log.json"
    # Create malformed existing JSON
    json_file.write_text("corrupted json content { not valid", encoding="utf-8")

    rec = [make_mock_record(scan_id="scan-fresh", ssid="FreshNet")]
    write_json(rec, path=json_file)

    # Valid fresh JSON is written
    loaded = json.loads(json_file.read_text(encoding="utf-8"))
    assert len(loaded) == 1
    assert loaded[0]["ssid"] == "FreshNet"

    # Backup file must exist and contain original corrupted content
    backups = list(tmp_path.glob("networks_log.corrupt.*.json"))
    assert len(backups) == 1
    assert "corrupted json content" in backups[0].read_text(encoding="utf-8")


def test_invalid_authorization_configuration_exits_code_1(tmp_path, monkeypatch, capsys):
    import wifi_scan
    from wifi_scan import main

    bad_csv = tmp_path / "bad_auth.csv"
    bad_csv.write_text("invalid,header\nfoo,bar\n", encoding="utf-8")

    monkeypatch.setattr(wifi_scan, "AUTH_FILE", bad_csv)
    monkeypatch.setattr(wifi_scan, "scan_wifi", lambda: [])

    code = main([])
    assert code == 1

    captured = capsys.readouterr()
    assert "[-] Authorization configuration error:" in captured.err
    assert "authorized_networks.csv must contain: ssid,bssid,authorization_ref,scope" in captured.err
