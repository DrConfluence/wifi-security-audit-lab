#!/usr/bin/env python3

from assessment.runner import run_end_to_end


def print_result(result):
    print()
    print("=" * 64)
    print("        WI-FI SECURITY ASSESSMENT")
    print("=" * 64)

    print(f"Assessment ID : {result['assessment_id']}")
    print(f"SSID          : {result['ssid']}")
    print(f"Authorization : {result['authorization_ref']}")

    print()
    print("PHASE 1 — CONNECTIVITY")
    print("-" * 64)

    print(f"Connection     : {result['connection_state']}")
    print(f"Gateway        : {result['gateway']}")
    print(f"Gateway status : {result['gateway_status']}")

    print()
    print("PHASE 2 — SERVICES")
    print("-" * 64)

    print(f"Services tested    : {result['services_tested']}")
    print(f"Services reachable : {result['services_reachable']}")

    print()
    print("EVIDENCE")
    print("-" * 64)
    print(result["report"])

    print("=" * 64)
    print()


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Authorized Wi-Fi assessment runner"
    )

    parser.add_argument("--ssid", required=True)
    parser.add_argument("--bssid")
    parser.add_argument("--authorization-ref", required=True)
    parser.add_argument("--phase2-host")

    args = parser.parse_args()

    result = run_end_to_end(
        ssid=args.ssid,
        bssid=args.bssid,
        authorization_ref=args.authorization_ref,
        phase2_host=args.phase2_host,
    )

    print_result(result)


if __name__ == "__main__":
    main()
