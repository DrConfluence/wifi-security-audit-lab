# Wi-Fi Security Audit Lab

## LAB-001 — Real Device Assessment

This project has progressed from test/demo reporting to real Android/Termux
Wi-Fi discovery and authorized LAN inventory.

### Real evidence demonstrated

- 13 Wi-Fi access points observed in a real scan
- SSID, BSSID, RSSI and frequency collection
- Security capability and WPS advertisement reporting
- Real authorized Wi-Fi association telemetry
- Authorized LAN target: `172.22.25.0/24`
- Device IP observed: `172.22.25.69`
- Additional live host observed: `172.22.25.133`
- TCP/53 reachable
- `dnsmasq 2.51` identified on TCP/53
- JSON/XML/TXT evidence artifacts
- 61 automated tests passing

### Current Android state

The latest check reports the device as disconnected and Termux:API currently
returns `API_ERROR: Location needs to be enabled on the device` for Wi-Fi
scanning. This is recorded as an Android platform condition, not replaced by
synthetic data.

### Documentation

- [Architecture](Architecture.md)
- [Wi-Fi Discovery](WiFi-Discovery.md)
- [LAN Inventory](LAN-Inventory.md)
- [Service Assessment](Service-Assessment.md)
- [Evidence](Evidence.md)
- [Android / Termux Limitations](Android-Termux-Limitations.md)
- [Roadmap](Roadmap.md)
