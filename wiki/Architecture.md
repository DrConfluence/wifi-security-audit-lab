# Architecture

```text
Android Wi-Fi subsystem
        |
        v
    Termux:API
        |
        +--> Wi-Fi discovery
        +--> Connection telemetry
        |
        v
Authorized assessment scope
        |
        +--> LAN host discovery
        +--> TCP service inventory
        |
        v
Evidence
        |
        +--> JSON
        +--> XML
        +--> TXT
        |
        v
Assessment reporting
```

The implementation separates wireless discovery from IP-layer inventory because Android exposes different capabilities to Termux at each layer.
