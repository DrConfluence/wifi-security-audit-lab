# Testing

## Automated tests

Run: python -m pytest -q

Current validated result: 61 passed

## Python compilation

Run: python -m py_compile assessment/*.py

Current result: PYTHON COMPILE: PASS

## Shell validation

Run: bash -n wifi-assess.sh; bash -n wifi-authorized.sh; bash -n wifi-authorized-lan.sh

All three scripts passed syntax validation.

## Real-device validation

The project has been exercised against real Android/Termux telemetry, Nmap LAN discovery, Nmap service identification, and Ncat TCP connectivity verification.

Automated tests and real-device evidence are kept separate.
