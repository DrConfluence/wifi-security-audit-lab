# LAB-001 Status

## Real-device validation

| Capability | Status |
|---|---|
| Android / Termux environment | Validated |
| Termux:API Wi-Fi discovery | Validated |
| Real AP observation | Validated |
| SSID / BSSID collection | Validated |
| RSSI / frequency collection | Validated |
| Security capability collection | Validated |
| Authorized LAN discovery | Validated |
| Host inventory | Validated |
| TCP service inventory | Validated |
| Service/version identification | Validated |
| Evidence generation | Validated |
| Automated tests | 61 passing |
| Python compilation | Passing |
| Shell syntax checks | Passing |

## Captured LAB-001 result

The real assessment previously observed 13 Wi-Fi networks.

During an authorized LAN assessment, the device was observed as:

- SSID: `Shubh`
- BSSID: `32:93:58:39:45:b7`
- IPv4: `172.22.25.69`
- LAN target: `172.22.25.0/24`

An additional host was observed:

- Host: `172.22.25.133`
- TCP/53: open
- Service: DNS/domain
- Identified product/version: `dnsmasq 2.51`

TCP connectivity to port 53 was independently verified with Ncat.

## Current runtime condition

The latest Android runtime check reports the device as disconnected:

`ssid: <unknown ssid>`

and:

`ip: 0.0.0.0`

The latest Wi-Fi scan also reports:

`API_ERROR: Location needs to be enabled on the device`

This is a runtime/platform condition. The project does not substitute synthetic results for unavailable live telemetry.

## Boundary

SSID discovery does not constitute authorization to access a network.

LAN discovery and service inventory are intended for networks explicitly placed in the assessment scope.
