#!/usr/bin/env python3
"""Compare fastscan vs tshark IP/port catalog extraction on PCAP files."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from models.scan_options import FastScanUserOptions
from services.endpoint_compare import compare_endpoints_sync


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pcaps", nargs="+", help="PCAP file paths")
    parser.add_argument(
        "--endpoint-max-packets",
        type=int,
        default=10000,
        help="Max packets for both fastscan endpoints and tshark (default: 10000)",
    )
    parser.add_argument("--sample-every", type=int, default=None)
    parser.add_argument("--max-packets", type=int, default=None)
    parser.add_argument("--json", action="store_true", help="Emit JSON report")
    args = parser.parse_args()

    fast_options = FastScanUserOptions(
        output="summary",
        sample_every=args.sample_every,
        max_packets=args.max_packets,
    )

    reports = []
    exit_code = 0
    for pcap in args.pcaps:
        path = Path(pcap)
        if not path.is_file():
            print(f"SKIP missing: {pcap}", file=sys.stderr)
            exit_code = 1
            continue
        result = compare_endpoints_sync(
            str(path),
            endpoint_max_packets=args.endpoint_max_packets,
            fast_options=fast_options,
        )
        reports.append(result)
        if not args.json:
            print(f"\n=== {result.pcap_file} ===")
            print(
                f"IPs: fast={len(result.fast_ips)} tshark={len(result.tshark_ips)} "
                f"recall={result.ip_recall:.2%} precision={result.ip_precision:.2%}"
            )
            print(
                f"Ports: fast={len(result.fast_ports)} tshark={len(result.tshark_ports)} "
                f"recall={result.port_recall:.2%} precision={result.port_precision:.2%}"
            )
            if result.ips_only_in_tshark:
                sample = sorted(result.ips_only_in_tshark)[:10]
                print(f"  IPs only in tshark (sample): {sample}")
            if result.ips_only_in_fast:
                sample = sorted(result.ips_only_in_fast)[:10]
                print(f"  IPs only in fastscan (sample): {sample}")
            if result.ports_only_in_tshark:
                sample = sorted(result.ports_only_in_tshark)[:10]
                print(f"  Ports only in tshark (sample): {sample}")
            if result.ports_only_in_fast:
                sample = sorted(result.ports_only_in_fast)[:10]
                print(f"  Ports only in fastscan (sample): {sample}")

    if args.json:
        payload = [
            {
                "pcap_file": r.pcap_file,
                "fast_ips": sorted(r.fast_ips),
                "tshark_ips": sorted(r.tshark_ips),
                "fast_ports": sorted(r.fast_ports),
                "tshark_ports": sorted(r.tshark_ports),
                "ip_recall": r.ip_recall,
                "ip_precision": r.ip_precision,
                "port_recall": r.port_recall,
                "port_precision": r.port_precision,
            }
            for r in reports
        ]
        print(json.dumps(payload, indent=2))

    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
