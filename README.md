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
/wiki-scan.sh
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