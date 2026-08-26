# Android / Termux Limitations

Real testing identified platform restrictions.

## Observed

- termux-wifi-scaninfo provides Wi-Fi scan telemetry when Android permits it.
- termux-wifi-connectioninfo provides current association information.
- Direct ip route and ip neigh access can return Permission denied.
- /proc/net/dev and /proc/net/route can be inaccessible.
- Nmap can report no interfaces/routes when Android does not expose them.

The assessment therefore uses Termux:API where appropriate instead of assuming unrestricted Linux networking.

A current test also returned:

API_ERROR: Location needs to be enabled on the device

This is an Android permission/state condition and should not be represented as a failed Wi-Fi scanner implementation.
