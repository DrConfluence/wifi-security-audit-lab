# Testing

## Automated tests

Run: `python -m pytest -v`

Current validated result: 110 passed

## Python compilation

Run: `python -m compileall -q .`

Current result: PYTHON COMPILE: PASS

## Shell validation

Run: `for f in *.sh; do bash -n "$f"; done`

All repository shell scripts pass syntax validation.

## Real-device validation

The project has been exercised against real Android/Termux telemetry, Nmap LAN discovery, Nmap service identification, and Ncat TCP connectivity verification.

Automated tests and real-device evidence are kept separate.
