#!/usr/bin/env python3

import argparse
import json

from assessment.engine import run_assessment


def main():
    parser = argparse.ArgumentParser(
        description="Authorized Wi-Fi security assessment"
    )

    parser.add_argument(
        "--ssid",
        required=True,
    )

    parser.add_argument(
        "--bssid",
    )

    parser.add_argument(
        "--authorization-ref",
        required=True,
    )

    parser.add_argument(
        "--phase2-host",
        help="Authorized host/IP for Phase 2 validation",
    )

    args = parser.parse_args()

    result = run_assessment(
        ssid=args.ssid,
        bssid=args.bssid,
        authorization_ref=args.authorization_ref,
        phase2_host=args.phase2_host,
    )

    print("=" * 60)
    print("AUTHORIZED WI-FI SECURITY ASSESSMENT")
    print("=" * 60)

    session = result["session"]
    connectivity = result["connectivity"]

    print(f"Assessment : {session['assessment_id']}")
    print(f"SSID       : {session['ssid']}")
    print(f"BSSID      : {session.get('bssid')}")
    print(f"Authorization: {session['authorization_ref']}")
    print(f"Connection : {connectivity['connection_state']}")
    print(f"Gateway    : {connectivity['gateway']}")
    print(
        f"Gateway status: "
        f"{connectivity['gateway_test']['status']}"
    )

    if result["services"]:
        print()
        print("PHASE 2 SERVICES")

        for item in result["services"]:
            print(
                f"{item['service']:8} "
                f"{item['port']:5} "
                f"{item['status']}"
            )

    print()
    print(f"Report: {result['report']}")
    print("=" * 60)

    print(
        json.dumps(
            {
                "assessment_id": session["assessment_id"],
                "connection_state": connectivity[
                    "connection_state"
                ],
                "gateway_status": connectivity[
                    "gateway_test"
                ]["status"],
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
