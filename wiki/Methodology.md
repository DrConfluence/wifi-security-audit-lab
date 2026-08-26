# Assessment Methodology

## Phase 1 — Wireless discovery

Use Android/Termux Wi-Fi telemetry to collect observable access-point metadata:

- SSID
- BSSID
- RSSI
- Frequency
- Channel bandwidth
- Security capabilities
- WPS advertisement when exposed

This phase identifies radio-visible networks only.

## Phase 2 — Authorized association

The device must be connected to an explicitly authorized network before IP-layer inventory is attempted.

Connection telemetry is collected through Termux:API.

## Phase 3 — LAN discovery

The authorized IPv4 network is derived from the connected device address where available.

Nmap host discovery is then used to identify reachable hosts inside the authorized scope.

## Phase 4 — Service inventory

Reachable hosts may be assessed for selected TCP services.

The project records:

- Host address
- Port
- State
- Service
- Product/version when identification succeeds

## Phase 5 — Evidence

Assessment artifacts are retained as machine-readable JSON/XML/TXT evidence.

## Phase 6 — Reporting

The collected evidence is converted into an assessment state suitable for technical review and portfolio presentation.

## Important distinction

Wireless visibility, network membership and authorization are separate concepts.

Seeing an SSID or BSSID does not authorize connection, credential recovery, exploitation or access to devices on that network.
