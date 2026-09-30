import csv
import json
from pathlib import Path
import pytest

from assessment.session import validate_scope, create_session, is_in_scope, DISALLOWED_REFS, load_authorizations
from assessment.findings import generate_findings
from assessment.executive import build_executive_summary
from assessment.evidence import (
    record_observation,
    write_collision_safe,
    get_collision_safe_path,
    write_evidence,
)
import assessment.session as session_mod
import assessment.connectivity as conn_mod
import assessment.engine as engine_mod
import assessment.discovery as disc_mod
import assessment.live as live_mod
import assessment.live_inventory as live_inv_mod
import assessment.live_assessment as live_assess_mod


BASE_DIR = Path(__file__).resolve().parent.parent


# ==============================================================================
# 1. Authorization Fail-Closed & Target Validation Tests
# ==============================================================================

def test_scope_validation_empty_ref():
    valid, reason = validate_scope("LAB-NET", authorization_ref="")
    assert valid is False
    assert "Missing explicit authorization reference" in reason


def test_scope_validation_generic_disallowed_refs():
    for ref in DISALLOWED_REFS:
        valid, reason = validate_scope("LAB-NET", authorization_ref=ref)
        assert valid is False
        assert "Invalid or generic" in reason or "Missing" in reason


def test_scope_validation_unknown_target():
    valid, reason = validate_scope("UNKNOWN-WIFI-123", authorization_ref="VALID-REF-999")
    assert valid is False
    assert "not in recorded authorization scope" in reason


def test_scope_validation_missing_target():
    valid, reason = validate_scope("", None, authorization_ref="LAB-001")
    assert valid is False
    assert "Target SSID or BSSID must be specified" in reason


def test_scope_validation_mismatched_reference():
    valid, reason = validate_scope("LAB-NET", authorization_ref="WRONG-REF-002")
    assert valid is False
    assert "does not match record" in reason


def test_scope_validation_authorized_match():
    valid, reason = validate_scope("LAB-NET", authorization_ref="LAB-001")
    assert valid is True
    assert "Authorized by" in reason


def test_scope_validation_missing_auth_file_fails_closed(tmp_path):
    missing_file = tmp_path / "nonexistent_auth.csv"
    valid, reason = validate_scope("LAB-NET", authorization_ref="LAB-001", auth_file=missing_file)
    assert valid is False
    assert "Authorization scope file not found" in reason


def test_scope_validation_empty_auth_file_fails_closed(tmp_path):
    empty_file = tmp_path / "empty_auth.csv"
    empty_file.write_text("", encoding="utf-8")
    valid, reason = validate_scope("LAB-NET", authorization_ref="LAB-001", auth_file=empty_file)
    assert valid is False
    assert "Authorization scope file not found or contains no records" in reason


def test_scope_validation_malformed_csv_fails_closed(tmp_path):
    malformed_file = tmp_path / "corrupt.csv"
    malformed_file.write_bytes(b"\x00\xff\xfe\xfa\x00")
    valid, reason = validate_scope("LAB-NET", authorization_ref="LAB-001", auth_file=malformed_file)
    assert valid is False
    assert "Authorization scope file not found or contains no records" in reason


def test_scope_validation_missing_headers_fails_closed(tmp_path):
    bad_header_file = tmp_path / "bad_headers.csv"
    bad_header_file.write_text("network_name,mac_address\nLAB-NET,02:00:00:00:00:01\n", encoding="utf-8")
    valid, reason = validate_scope("LAB-NET", authorization_ref="LAB-001", auth_file=bad_header_file)
    assert valid is False
    assert "Authorization scope file not found or contains no records" in reason


def test_no_runtime_fallback_to_example_file(monkeypatch, tmp_path):
    # Ensure load_authorizations does NOT fall back to authorized_networks.example.csv
    # when AUTH_FILE does not exist
    non_existent = tmp_path / "no_authorized_networks.csv"
    monkeypatch.setattr(session_mod, "AUTH_FILE", non_existent)

    auths = load_authorizations()
    assert auths == {}

    valid, reason = validate_scope("LAB-NETWORK", authorization_ref="EXAMPLE-001")
    assert valid is False
    assert "Authorization scope file not found" in reason


# ==============================================================================
# 2. Probe Execution Prevention Tests
# ==============================================================================

def test_probe_fail_closed_live_inventory(monkeypatch):
    module = live_inv_mod

    monkeypatch.setattr(module, "wifi_connection", lambda: {
        "available": True,
        "data": {
            "ssid": "UNAUTHORIZED-SSID",
            "bssid": "00:11:22:33:44:55",
            "ip": "192.168.1.100",
            "rssi": -60,
            "frequency_mhz": 2412,
            "link_speed_mbps": 72,
        },
    })
    monkeypatch.setattr(module, "wifi_scan", lambda: {"available": False, "data": []})

    probes_executed = []
    monkeypatch.setattr(module, "discover_lan", lambda ip: probes_executed.append("discover_lan"))
    monkeypatch.setattr(module, "ping_host", lambda host, timeout=1: probes_executed.append("ping_host"))

    result = module.run_live(authorization_ref="INVALID-REF")

    assert result["overall_state"] == "BLOCKED_UNAUTHORIZED"
    assert result["authorized"] is False
    assert "Authorization validation failed" in result["reason"]
    assert len(probes_executed) == 0
    assert "lan" not in result


def test_probe_fail_closed_authorized_inventory(monkeypatch):
    import assessment.authorized_inventory as module

    monkeypatch.setattr(module, "wifi_connection", lambda: {
        "supplicant_state": "COMPLETED",
        "ssid": "UNAUTHORIZED-NET",
        "bssid": "00:11:22:33:44:55",
        "ip": "192.168.1.50",
    })
    monkeypatch.setattr(module.argparse.ArgumentParser, "parse_args", lambda self: module.argparse.Namespace(authorization_ref="INVALID-REF"))

    discover_called = []
    monkeypatch.setattr(module, "discover", lambda net: discover_called.append(net))

    with pytest.raises(SystemExit) as exc_info:
        module.main()

    assert "Authorization verification failed" in str(exc_info.value)
    assert len(discover_called) == 0


def test_probe_fail_closed_authorized_scan(monkeypatch):
    import assessment.authorized_scan as module

    monkeypatch.setattr(module, "wifi", lambda: {
        "supplicant_state": "COMPLETED",
        "ssid": "UNAUTHORIZED-NET",
        "bssid": "00:11:22:33:44:55",
        "ip": "192.168.1.50",
    })
    monkeypatch.setattr(module.argparse.ArgumentParser, "parse_args", lambda self: module.argparse.Namespace(
        authorization_ref="INVALID-REF",
        target=None,
    ))

    probes_run = []
    monkeypatch.setattr(module, "run", lambda cmd, timeout=90: probes_run.append(cmd))

    with pytest.raises(SystemExit) as exc_info:
        module.main()

    assert "Authorization verification failed" in str(exc_info.value)
    assert len(probes_run) == 0


def test_probe_fail_closed_connectivity_evidence(monkeypatch, tmp_path):
    monkeypatch.setattr(conn_mod, "EVIDENCE_DIR", tmp_path)
    probes_run = []
    monkeypatch.setattr(conn_mod, "run_command", lambda cmd: probes_run.append(cmd))
    monkeypatch.setattr(conn_mod, "get_termux_connection_info", lambda: {
        "available": True,
        "data": {"ssid": "UNAUTHORIZED-NET", "bssid": "00:11:22:33:44:55", "ip": "10.0.0.5"},
    })
    monkeypatch.setattr(conn_mod, "get_routes", lambda: {"stdout": "default via 10.0.0.1 dev wlan0"})

    evidence = conn_mod.collect_connectivity_evidence(
        assessment_id="WA-PROBE-TEST",
        ssid="UNAUTHORIZED-NET",
        bssid="00:11:22:33:44:55",
        authorization_ref="INVALID-REF",
    )

    assert evidence["gateway_test"]["status"] == "NOT_TESTED"
    assert "Authorization verification failed" in evidence["gateway_test"]["reason"]
    assert len(probes_run) == 0


def test_probe_fail_closed_engine_phase1():
    unauthorized_session = {
        "assessment_id": "WA-UNAUTH-P1",
        "ssid": "UNAUTHORIZED-SSID",
        "authorization_ref": "INVALID-REF",
        "scope_status": "UNAUTHORIZED",
    }
    with pytest.raises(PermissionError) as exc_info:
        engine_mod.run_phase1(unauthorized_session)
    assert "outside the recorded authorization scope" in str(exc_info.value)


def test_probe_fail_closed_engine_phase2():
    unauthorized_session = {
        "assessment_id": "WA-UNAUTH-P2",
        "ssid": "UNAUTHORIZED-SSID",
        "authorization_ref": "INVALID-REF",
        "scope_status": "UNAUTHORIZED",
    }
    with pytest.raises(PermissionError) as exc_info:
        engine_mod.run_phase2(unauthorized_session, host="192.168.1.1")
    assert "outside the recorded authorization scope" in str(exc_info.value)


def test_probe_fail_closed_live_not_connected(monkeypatch, tmp_path):
    monkeypatch.setattr(live_mod, "EVIDENCE", tmp_path)
    monkeypatch.setattr(live_mod, "wifi_scan", lambda: {"available": False, "reason": "No scan"})
    monkeypatch.setattr(live_mod, "wifi_connection", lambda: {
        "available": True,
        "data": {"ssid": "<unknown ssid>", "bssid": None, "ip": "0.0.0.0"},
    })
    monkeypatch.setattr(live_mod, "routes", lambda: {"default_gateway": "192.168.1.1"})

    pings_run = []
    monkeypatch.setattr(live_mod, "ping", lambda host: pings_run.append(host))

    live_mod.main()
    assert len(pings_run) == 0


# ==============================================================================
# 3. Evidence Collisions & Collision-Safe Writing Tests
# ==============================================================================

def test_evidence_collision_same_second(tmp_path):
    # Simulate multiple writes occurring in the same second with identical base path
    base_target = tmp_path / "wifi_discovery_20261001-045000.json"

    p1 = write_collision_safe(base_target, '{"write": 1}')
    p2 = write_collision_safe(base_target, '{"write": 2}')
    p3 = write_collision_safe(base_target, '{"write": 3}')

    assert p1 == base_target
    assert p2 == tmp_path / "wifi_discovery_20261001-045000_1.json"
    assert p3 == tmp_path / "wifi_discovery_20261001-045000_2.json"

    assert p1.exists() and p2.exists() and p3.exists()
    assert json.loads(p1.read_text())["write"] == 1
    assert json.loads(p2.read_text())["write"] == 2
    assert json.loads(p3.read_text())["write"] == 3


def test_write_collision_safe_preserves_original_content(tmp_path):
    target = tmp_path / "evidence_record.json"
    target.write_text('{"original": true, "payload": "immutable"}', encoding="utf-8")

    colliding_write = write_collision_safe(target, '{"original": false, "payload": "new"}')

    assert colliding_write != target
    assert colliding_write.name == "evidence_record_1.json"

    # Original file is completely intact
    assert json.loads(target.read_text())["original"] is True
    assert json.loads(colliding_write.read_text())["original"] is False


def test_discovery_evidence_collision_same_second(tmp_path, monkeypatch):
    monkeypatch.setattr(disc_mod, "EVIDENCE_DIR", tmp_path)

    # Freeze datetime stamp in discovery module
    fixed_stamp = "20261001-120000"
    class FakeDatetime:
        @classmethod
        def now(cls, tz=None):
            class FakeNow:
                def strftime(self, fmt):
                    return fixed_stamp
            return FakeNow()

    monkeypatch.setattr(disc_mod, "datetime", FakeDatetime)

    res1 = {"scan_run": 1, "networks": []}
    res2 = {"scan_run": 2, "networks": []}

    path1 = disc_mod.write_evidence(res1)
    path2 = disc_mod.write_evidence(res2)

    assert path1 != path2
    assert path1.name == f"wifi_discovery_{fixed_stamp}.json"
    assert path2.name == f"wifi_discovery_{fixed_stamp}_1.json"

    assert json.loads(path1.read_text())["scan_run"] == 1
    assert json.loads(path2.read_text())["scan_run"] == 2


def test_live_inventory_evidence_collision_same_second(tmp_path, monkeypatch):
    monkeypatch.setattr(live_inv_mod, "EVIDENCE", tmp_path)

    fixed_stamp = "20261001-120000"
    class FakeDatetime:
        @classmethod
        def now(cls, tz=None):
            class FakeNow:
                def strftime(self, fmt):
                    return fixed_stamp
            return FakeNow()

    monkeypatch.setattr(live_inv_mod, "datetime", FakeDatetime)

    inv1 = {"inventory_id": 1, "devices": []}
    inv2 = {"inventory_id": 2, "devices": []}

    path1 = live_inv_mod.save(inv1)
    path2 = live_inv_mod.save(inv2)

    assert path1 != path2
    assert path1.name == f"live_inventory_{fixed_stamp}.json"
    assert path2.name == f"live_inventory_{fixed_stamp}_1.json"

    assert json.loads(path1.read_text())["inventory_id"] == 1
    assert json.loads(path2.read_text())["inventory_id"] == 2


def test_live_assessment_evidence_collision_same_second(tmp_path, monkeypatch):
    monkeypatch.setattr(live_assess_mod, "EVIDENCE", tmp_path)

    fixed_stamp = "20261001-120000"
    class FakeDatetime:
        @classmethod
        def now(cls, tz=None):
            class FakeNow:
                def strftime(self, fmt):
                    return fixed_stamp
            return FakeNow()

    monkeypatch.setattr(live_assess_mod, "datetime", FakeDatetime)

    data1 = {"run": 1, "assessment": "alpha"}
    data2 = {"run": 2, "assessment": "beta"}

    path1 = live_assess_mod.save_evidence(data1)
    path2 = live_assess_mod.save_evidence(data2)

    assert path1 != path2
    assert path1.name == f"live_authorized_assessment_{fixed_stamp}.json"
    assert path2.name == f"live_authorized_assessment_{fixed_stamp}_1.json"

    assert json.loads(path1.read_text())["run"] == 1
    assert json.loads(path2.read_text())["run"] == 2


# ==============================================================================
# 4. Preservation of Existing Evidence
# ==============================================================================

def test_sequential_evidence_preservation(tmp_path, monkeypatch):
    import assessment.evidence as module
    monkeypatch.setattr(module, "EVIDENCE_DIR", tmp_path)

    session = {
        "assessment_id": "WA-SECURITY-PRESERVE-01",
        "ssid": "LAB-NET",
        "authorization_ref": "LAB-001",
        "scope_status": "AUTHORIZED",
    }

    # Step 1: Record initial observation
    path1 = record_observation(session, "connectivity", "PASS", {"rtt": 5})
    assert path1.exists()
    data1 = json.loads(path1.read_text(encoding="utf-8"))
    assert "connectivity" in data1["observations"]
    assert "services" not in data1["observations"]

    # Step 2: Record subsequent observation under same assessment ID
    path2 = record_observation(session, "services", "PASS", {"ports": [80]})
    assert path1 == path2
    data2 = json.loads(path2.read_text(encoding="utf-8"))

    # Both initial and subsequent observations must be intact
    assert "connectivity" in data2["observations"]
    assert data2["observations"]["connectivity"]["status"] == "PASS"
    assert "services" in data2["observations"]
    assert data2["observations"]["services"]["status"] == "PASS"


# ==============================================================================
# 5. Dashboard Safety, Findings, & Gateway Checks
# ==============================================================================

def test_dashboard_report_no_unsafe_innerhtml_injection():
    report_html_path = BASE_DIR / "assessment-report" / "index.html"
    assert report_html_path.exists()
    content = report_html_path.read_text(encoding="utf-8")

    assert "innerHTML +=" not in content
    assert ".textContent =" in content


def test_live_dashboard_report_no_unsafe_innerhtml_injection():
    live_html_path = BASE_DIR / "assessment-report" / "live.html"
    assert live_html_path.exists()
    content = live_html_path.read_text(encoding="utf-8")

    assert "innerHTML +=" not in content
    assert ".textContent =" in content


def test_gateway_failure_finding_net003():
    connectivity = {
        "connection_state": "DHCP_ACQUIRED",
        "gateway_test": {
            "status": "FAIL",
            "reason": "Ping timeout",
        },
    }
    findings = generate_findings(connectivity, [])
    net003 = next((f for f in findings if f["id"] == "NET-003"), None)
    assert net003 is not None
    assert net003["status"] == "FAIL"
    assert net003["severity"] == "WARNING"


def test_connectivity_check_gateway_ping_args_darwin(monkeypatch):
    captured_commands = []
    def fake_run(command):
        captured_commands.append(command)
        return {"returncode": 0, "stdout": "", "stderr": ""}

    monkeypatch.setattr(conn_mod, "run_command", fake_run)
    monkeypatch.setattr(conn_mod.sys, "platform", "darwin")

    conn_mod.check_gateway("192.168.1.1", count=2)
    assert len(captured_commands) == 1
    assert captured_commands[0] == ["ping", "-c", "2", "-W", "2000", "192.168.1.1"]


def test_connectivity_check_gateway_ping_args_linux(monkeypatch):
    captured_commands = []
    def fake_run(command):
        captured_commands.append(command)
        return {"returncode": 0, "stdout": "", "stderr": ""}

    monkeypatch.setattr(conn_mod, "run_command", fake_run)
    monkeypatch.setattr(conn_mod.sys, "platform", "linux")

    conn_mod.check_gateway("192.168.1.1", count=2)
    assert len(captured_commands) == 1
    assert captured_commands[0] == ["ping", "-c", "2", "-W", "2", "192.168.1.1"]
