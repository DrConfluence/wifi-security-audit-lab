# Wi-Fi Security Assessment Lab

A defensive, authorization-aware Wi-Fi assessment and audit framework designed for controlled security testing, passive discovery, and evidence-backed reporting.

Built for defensive security engineers, auditors, and students operating in controlled laboratory environments and mobile assessment scenarios (including Termux on Android).

---

## Purpose & Scope

The Wi-Fi Security Assessment Lab demonstrates an evidence-based security auditing workflow:

$$\text{Discover} \longrightarrow \text{Classify} \longrightarrow \text{Verify Authorization} \longrightarrow \text{Preserve Evidence} \longrightarrow \text{Report}$$

### Defensive Boundaries & Authorization Principle
- **Passive Observation vs. Active Testing:** Observing an SSID or BSSID over the air is passive radio observation only. Passive discovery does not prove vulnerability and **never** constitutes authorization to probe, associate, authenticate, or transmit packets to a network.
- **Fail-Closed Authorization:** Active network operations (LAN host scanning, gateway reachability, TCP service verification) require explicit, documented authorization. If authorization configuration is missing, malformed, empty, or mismatched, all active operations fail closed immediately.
- **BSSID-Specific Scope Binding:** Authorization is strictly bound to the specific hardware BSSID (MAC address) of the access point. An SSID match alone is treated solely as a non-authorizing discovery hint (`SSID_HINT`) and **never** grants permission to probe a network. Mismatched or spoofed BSSIDs are rejected.
- **Privacy & Responsible Disclosure:** No credential theft, password cracking, denial-of-service, or deauthentication attacks are implemented. Real private credentials and captured evidence are excluded from version control.

---

## Features & Capabilities

- **Passive Wi-Fi Discovery:** Queries broadcast beacons via `termux-wifi-scaninfo` (Termux:API) without associating or transmitting active probes.
- **Security Capability Classification:** Automatically classifies network security protocols (WPA3-SAE, WPA2-PSK, WPA, WEP, OPEN) and band/channel frequencies (2.4 GHz, 5 GHz).
- **Append-Only Evidence Preservation:** Historical scan logs (`networks_log.csv` and `networks_log.json`) are cumulative and never truncated on repeated runs. Scans are indexed by unique `scan_id` tokens and timestamps. JSON writing uses atomic file replacement and automatic backup for corrupt logs.
- **Strict Scope Verification:** Validates target scope against `authorized_networks.csv` (`ssid,bssid,authorization_ref,scope`). Disallowed/placeholder references (`none`, `default`, `test`, `authorized-lab`, `null`) are rejected.
- **Authorized LAN Inventory:** Performs bounded, authorized ARP/ping host discovery and TCP port enumeration when explicitly connected to an authorized network.
- **Interactive Security Dashboards:** Standalone web consoles (`index.html`, `assessment-report/index.html`, `assessment-report/live.html`) for reviewing findings, telemetry snapshots, and audit metrics.
- **Automated Regression Testing:** Comprehensive unit and integration test suite (110 passing tests) with zero external hardware or network dependencies.

---

## Architecture & Repository Structure

```text
├── .github/workflows/ci.yml       # GitHub Actions CI matrix workflow (Python 3.9 - 3.12)
├── assessment/                    # Core Python assessment package
│   ├── authorized_inventory.py   # Authorized network discovery & inventory
│   ├── authorized_scan.py        # Host & service discovery runner
│   ├── connectivity.py           # Association state & gateway ping checks
│   ├── discovery.py              # Wireless frequency, band, and capability parsing
│   ├── engine.py                 # Multi-phase assessment session runner
│   ├── evidence.py               # Collision-safe evidence writing & JSON/TXT artifact storage
│   ├── executive.py              # Summary generators for assessment reports
│   ├── findings.py               # Security finding rules (e.g. NET-001, NET-002, NET-003)
│   ├── live.py                   # Termux live telemetry parsers
│   ├── live_assessment.py        # Live network validation and service assessment
│   ├── live_inventory.py         # Live LAN discovery orchestration
│   ├── phase6.py                 # Telemetry normalization for dashboard presentation
│   ├── services.py               # TCP port & banner enumeration
│   └── session.py                # Authorization scope validation & session lifecycle
├── assessment-report/             # Static HTML assessment report dashboards
│   ├── index.html                # Executive assessment report
│   └── live.html                 # Live connection dashboard
├── authorized_networks.example.csv# Example template for authorization configuration
├── index.html                     # Primary interactive Termux-style web console
├── public-data/                   # Sanitized benchmark evidence data
│   └── phase6_snapshot.json      # Sample telemetry snapshot for demonstration
├── requirements.txt               # Declared Python test dependencies (pytest)
├── tests/                         # Automated test suite (110 tests)
│   ├── conftest.py               # Pytest fixtures and isolated scope configuration
│   ├── test_connectivity.py      # Connectivity & gateway validation tests
│   ├── test_discovery.py         # Wireless band & security classification tests
│   ├── test_engine.py            # Assessment engine session tests
│   ├── test_evidence.py          # Evidence preservation & collision safety tests
│   ├── test_findings.py          # Finding generation tests
│   ├── test_security_fixes.py    # Fail-closed scope, mismatched BSSID, & injection tests
│   ├── test_services.py          # Service target parsing & TCP probing tests
│   ├── test_session.py           # Scope validation lifecycle tests
│   └── test_wifi_scan.py         # Scanner append logging, CSV/JSON parity, & scope tests
├── wifi_scan.py                   # CLI tool for passive Wi-Fi scanning & audit logging
├── wifi_scan.sh                   # Wrapper script for passive scanning
├── wifi-assess.sh                 # Wrapper script for live target assessment
├── wifi-authorized-lan.sh         # Shell runner for authorized LAN discovery
├── wifi-authorized.sh             # Shell runner for authorized inventory
├── wifi-live.sh                   # Shell runner for live inventory
└── wiki/                          # Documentation wiki (methodology, limitations, architecture)
```

---

## Supported Platforms & Prerequisites

| Environment | Supported Features | Prerequisites |
| :--- | :--- | :--- |
| **Android (Termux)** | Live passive Wi-Fi scans, LAN inventory, Nmap host discovery | Termux, Termux:API package & Android app, Location enabled, `nmap`, `jq`, `python` |
| **Linux / macOS / Windows** | Development, offline assessment engine, test suite, dashboard, data parsing | Python 3.9+, standard POSIX tools (`bash`, `git`) |

---

## Installation & Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/Rohit30Confluence/wifi-security-audit-lab.git
   cd wifi-security-audit-lab
   ```

2. **Create and activate an isolated virtual environment:**
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```

3. **Install declared dependencies:**
   ```bash
   pip install --upgrade pip
   pip install -r requirements.txt
   ```

---

## Authorization Configuration

Before running any scans or assessments against a target network, create `authorized_networks.csv` in the project root:

```bash
cp authorized_networks.example.csv authorized_networks.csv
```

### File Format (`authorized_networks.csv`)
The authorization file **must** contain four columns with exact headers:
```csv
ssid,bssid,authorization_ref,scope
LAB-NET,02:00:00:00:00:01,AUTH-2026-LAB01,Controlled laboratory assessment
CORP-WIFI,02:00:00:00:00:02,AUTH-2026-CORP02,Authorized internal audit
```

### Scope Rules
- **Specific BSSID Required:** `bssid` must match the MAC address of the target radio.
- **SSID-Only Non-Authorizing Hint:** If an AP broadcasts a matching SSID but an unauthorized or different BSSID, it is classified as `SSID_HINT` and marked `authorized=False`.
- **Disallowed Reference Protection:** Values like `default`, `test`, `none`, `null`, `undefined`, and `authorized-lab` are rejected.
- **Fail Closed:** If `authorized_networks.csv` is missing or empty, all active operations fail closed. The tool **never** falls back to `authorized_networks.example.csv`.

---

## Usage

### 1. Passive Wi-Fi Scan (Observation Only)
Runs a passive scan via Termux:API, classifies observable networks, matches against recorded scope, and appends records to cumulative audit logs:

```bash
python3 wifi_scan.py
# or
./wifi_scan.sh
```

**Output files generated:**
- `networks_log.csv` (append-only cumulative CSV log)
- `networks_log.json` (append-only cumulative JSON array with atomic replace)

### 2. Live Target Assessment
Evaluates association, gateway connectivity, and service reachability for an explicitly authorized target:

```bash
./wifi-assess.sh --ssid 'LAB-NET' --authorization-ref 'AUTH-2026-LAB01'
```

### 3. Authorized LAN Discovery
Conducts bounded LAN host discovery on the currently connected subnet:

```bash
./wifi-authorized-lan.sh AUTH-2026-LAB01
```

### 4. Interactive Dashboards
Open `index.html` or `assessment-report/index.html` in any modern web browser or serve locally:

```bash
python3 -m http.server 8000
# Open http://localhost:8000 in your browser
```

---

## Automated Testing & Quality Gates

The repository includes a complete automated test suite that executes locally without requiring live network interfaces, Termux APIs, or physical radios:

```bash
# Run full pytest suite (110 tests)
python3 -m pytest -v

# Byte-compile all Python modules
python3 -m compileall -q .

# Validate shell script syntax
for f in *.sh; do bash -n "$f"; done

# Verify git diff formatting and whitespace
git diff --check
```

---

## CI/CD Pipeline

Continuous integration is managed via GitHub Actions in [`.github/workflows/ci.yml`](.github/workflows/ci.yml):
- **Triggers:** Pushes and pull requests to `main`.
- **Matrix:** Python 3.9, 3.10, 3.11, and 3.12 on `ubuntu-latest`.
- **Checks:** Dependency installation, full pytest suite (110 tests), bytecode compilation, shell syntax validation (`bash -n`), and git diff checks.
- **Security:** Least-privilege `contents: read` permissions; no external secrets required.

---

## Troubleshooting

- **`Missing optional platform tool: 'termux-wifi-scaninfo'`**:
  Occurs when running `wifi_scan.py` on non-Android or desktop systems. The CLI exits gracefully with code 1 and explanatory diagnostics. For testing on desktop, use the pytest test suite which mocks platform subprocess calls.
- **`API_ERROR: Location needs to be enabled on the device`**:
  Android requires Location services to be turned ON for apps to receive Wi-Fi scan results via Termux:API. Enable Location in Android Settings.
- **`Authorization configuration error: authorized_networks.csv must contain: ...`**:
  Ensure `authorized_networks.csv` has the exact header `ssid,bssid,authorization_ref,scope` with valid comma-separated values.
- **`Permission denied on ip route / proc/net`**:
  Modern Android restricts direct access to Linux routing tables from unprivileged app sandboxes. The assessment scripts detect this and record the condition honestly rather than reporting misleading data.

---

## Responsible Security & Contributing

- **Security Vulnerabilities:** If you discover a security issue or unexpected privilege escalation in this repository, please report it via private GitHub security advisory.
- **Contributions:** Contributions that improve test coverage, documentation clarity, defensive telemetry parsing, or platform resilience are welcome. Please ensure all 110 tests pass and code compiles cleanly before submitting a pull request.

---

## Documentation Wiki

Detailed architectural documentation, platform boundary analysis, and testing guides are available in the [`wiki/`](wiki/Home.md) directory:
- [Wiki Home](wiki/Home.md)
- [Architecture](wiki/Architecture.md)
- [Assessment Methodology](wiki/Methodology.md)
- [Testing Guide](wiki/Testing.md)
- [Android & Termux Limitations](wiki/Android-Termux-Limitations.md)
- [LAN Inventory](wiki/LAN-Inventory.md)
- [Evidence Handling](wiki/Evidence.md)
- [Status & Validation](wiki/Status.md)
