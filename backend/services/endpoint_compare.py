"""Compare catalog endpoints from fastscan vs tshark."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from typing import Optional, Set

from models.scan_options import FastScanUserOptions

from .endpoint_extract import extract_endpoints_sync
from .fastscan_options import build_fastscan_command, parse_fastscan_output


@dataclass
class EndpointCompareResult:
    pcap_file: str
    fast_ips: Set[str]
    fast_ports: Set[str]
    tshark_ips: Set[str]
    tshark_ports: Set[str]
    ip_recall: float
    ip_precision: float
    port_recall: float
    port_precision: float
    ips_only_in_fast: Set[str]
    ips_only_in_tshark: Set[str]
    ports_only_in_fast: Set[str]
    ports_only_in_tshark: Set[str]


def _ratio(numerator: int, denominator: int) -> float:
    if denominator == 0:
        return 1.0 if numerator == 0 else 0.0
    return round(numerator / denominator, 4)


def _compare_sets(reference: Set[str], candidate: Set[str]) -> tuple[float, float, Set[str], Set[str]]:
    if not reference and not candidate:
        return 1.0, 1.0, set(), set()
    recall = _ratio(len(reference & candidate), len(reference))
    precision = _ratio(len(reference & candidate), len(candidate))
    only_candidate = candidate - reference
    only_reference = reference - candidate
    return recall, precision, only_candidate, only_reference


def run_fastscan_endpoints_sync(
    pcap_file: str,
    *,
    endpoint_max_packets: int = 10000,
    fast_options: Optional[FastScanUserOptions] = None,
) -> tuple[Set[str], Set[str]]:
    options = fast_options or FastScanUserOptions(output="summary")
    command = build_fastscan_command(
        pcap_file,
        options,
        endpoint_max_packets=endpoint_max_packets,
    )
    result = subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=600,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"fastscan failed for {pcap_file}: {result.stderr.strip()[:500]}"
        )
    parsed = parse_fastscan_output(result.stdout)
    if parsed is None:
        return set(), set()
    return set(parsed.indexed_ips), set(parsed.indexed_ports)


def compare_endpoints_sync(
    pcap_file: str,
    *,
    endpoint_max_packets: int = 10000,
    fast_options: Optional[FastScanUserOptions] = None,
) -> EndpointCompareResult:
    fast_ips, fast_ports = run_fastscan_endpoints_sync(
        pcap_file,
        endpoint_max_packets=endpoint_max_packets,
        fast_options=fast_options,
    )
    tshark = extract_endpoints_sync(pcap_file, max_packets=endpoint_max_packets)
    tshark_ips = tshark.get("ips", set())
    tshark_ports = tshark.get("ports", set())

    ip_recall, ip_precision, ips_only_fast, ips_only_tshark = _compare_sets(
        tshark_ips, fast_ips
    )
    port_recall, port_precision, ports_only_fast, ports_only_tshark = _compare_sets(
        tshark_ports, fast_ports
    )

    return EndpointCompareResult(
        pcap_file=pcap_file,
        fast_ips=fast_ips,
        fast_ports=fast_ports,
        tshark_ips=tshark_ips,
        tshark_ports=tshark_ports,
        ip_recall=ip_recall,
        ip_precision=ip_precision,
        port_recall=port_recall,
        port_precision=port_precision,
        ips_only_in_fast=ips_only_fast,
        ips_only_in_tshark=ips_only_tshark,
        ports_only_in_fast=ports_only_fast,
        ports_only_in_tshark=ports_only_tshark,
    )
