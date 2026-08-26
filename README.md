# Wi-Fi Security Assessment Lab

A reduced, defensive, authorization-aware Wi-Fi passive assessment tool for controlled security assessments using Termux on Android.

## Purpose

This project demonstrates:

discover -> classify -> verify authorization -> collect evidence -> report

## Authorization Boundary

Network visibility does not constitute authorization. Only networks owned by the assessor or explicitly authorized for assessment should be marked authorized.

## Usage

```bash
cd ~/wifi-audit
python wifi_scan.py
```

Or use:

```bash
./wifi_scan.sh
```

## Testing

Run:
````bash
python -m pytest -q
bash -n wifi_scan.sh
python -m py_compile wifi_scan.py
```

Current test status: 12 passed

## Real-Environment Workflow

1. Obtain documented authorization.
2. Define the exact wireless scope.
3. Record the authorization reference.
4. Run passive discovery.
5. Verify authorization matching.
6. Preserve the scan ID and evidence.
7. Perform only explicitly permitted testing.
8. Produce a findings report.

## Evidence Protection

Real scan outputs and authorization records are excluded from the public repository. This prevents unrelated network data from being published.

## Limitations

Passive discovery does not prove that a network or device is vulnerable. Active testing must remain within the explicit scope of an authorization.

## Security Principle

The goal is not to maximize the number of networks marked authorized. The goal is to demonstrate that the assessor can operate in a real environment while maintaining a defensible authorization boundary and producing reliable evidence.

## LAB-001 — Real Device Progress

LAB-001 has progressed beyond synthetic demonstration data into a real Android/Termux assessment workflow.

### Validated on Android / Termux

- Real Wi-Fi discovery through Termux:API
- SSID, BSSID, RSSI, frequency and security capability collection
- Real AP observation: 13 networks in one captured scan
- Authorized LAN host discovery using Nmap
- Authorized target network: `172.22.25.0/24`
- Device IP observed during the assessment: `172.22.25.69`
- Additional live host observed: `172.22.25.133`
- TCP/53 reachable on the observed host
- Service identification: `dnsmasq 2.51`
- JSON, XML and TXT evidence generation
- Live assessment and authorized inventory modules
- 61 automated tests passing
- Python compilation passing
- Shell syntax validation passing

### Platform limitations discovered

Android/Termux does not expose unrestricted Linux networking to the application environment. Direct `ip route`, `ip neigh` and `/proc/net/*` access can return permission errors.

Termux:API Wi-Fi scanning also requires Android Location to be enabled. The project records these conditions instead of fabricating network information.

### Assessment boundary

Wireless visibility is observation only. LAN inventory is performed only inside an explicitly authorized assessment scope. The project does not treat discovery of an SSID as authorization to access it.

See [`wiki/`](wiki/Home.md) for the technical documentation and assessment methodology.


## Web Dashboard

The interactive project dashboard is available through `index.html` and the GitHub Pages deployment. The repository wiki documentation is under [`wiki/`](wiki/Home.md).
