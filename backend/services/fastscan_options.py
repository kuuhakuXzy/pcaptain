"""Build fastscan CLI args and parse output for user-selected scan options."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, Optional, Set, Tuple

from models.scan_options import FastScanUserOptions

_SUMMARY_PREFIX = "PCAPTAIN_SUMMARY"
_FP_PREFIX = "PCAPTAIN_FP"
_ENDPOINTS_PREFIX = "PCAPTAIN_ENDPOINTS"


@dataclass
class ProtocolScanResult:
    """Unified result from protocol scan (fast, full, or quick)."""

    protocol_counts: Dict[str, int]
    packets_scanned: int
    indexed_ips: Optional[Set[str]] = None
    indexed_ports: Optional[Set[str]] = None
    protocol_fingerprint: Optional[str] = None


@dataclass
class FastScanParseResult:
    protocol_counts: Dict[str, int]
    packets_scanned: int
    packets_seen: Optional[int] = None
    protocol_fingerprint: Optional[str] = None
    sampled: bool = False
    indexed_ips: Set[str] = field(default_factory=set)
    indexed_ports: Set[str] = field(default_factory=set)


@dataclass
class FastScanDefaults:
    output: str = "summary"
    sample_every: Optional[int] = None
    max_packets: Optional[int] = None
    bpf_filter: Optional[str] = None
    emit_fingerprint: bool = False
    ports_file: Optional[str] = None


def merge_fast_options(
    defaults: FastScanDefaults,
    user: Optional[FastScanUserOptions],
) -> FastScanUserOptions:
    """Merge config.yaml defaults with optional per-scan user overrides."""
    base = FastScanUserOptions(
        output=defaults.output,  # type: ignore[arg-type]
        sample_every=defaults.sample_every,
        max_packets=defaults.max_packets,
        bpf_filter=defaults.bpf_filter,
        emit_fingerprint=defaults.emit_fingerprint,
        ports_file=defaults.ports_file,
    )
    if user is None:
        return base
    merged = {**base.model_dump(), **user.model_dump(exclude_unset=True)}
    return FastScanUserOptions(**merged)


def build_fastscan_command(
    pcap_file: str,
    options: FastScanUserOptions,
    *,
    endpoint_max_packets: Optional[int] = None,
) -> list[str]:
    cmd = ["fastscan"]
    if options.output == "lines":
        cmd.append("--lines")
    else:
        cmd.append("--summary")
    if options.sample_every:
        cmd.extend(["--sample-every", str(options.sample_every)])
    if options.max_packets:
        cmd.extend(["--max-packets", str(options.max_packets)])
    if endpoint_max_packets and endpoint_max_packets > 0:
        cmd.extend(["--endpoint-max-packets", str(endpoint_max_packets)])
    if options.bpf_filter:
        cmd.extend(["--bpf", options.bpf_filter])
    if options.emit_fingerprint:
        cmd.append("--fingerprint")
    if options.ports_file:
        cmd.extend(["--ports-file", options.ports_file])
    cmd.append(pcap_file)
    return cmd


def _parse_summary_line(line: str) -> Tuple[Dict[str, int], int, Optional[int], bool]:
    counts: Dict[str, int] = {}
    packets_scanned = 0
    packets_seen: Optional[int] = None
    sampled = "sample_every=" in line

    seen_m = re.search(r"packets_seen=(\d+)", line)
    if seen_m:
        packets_seen = int(seen_m.group(1))
    scanned_m = re.search(r"packets_scanned=(\d+)", line)
    if scanned_m:
        packets_scanned = int(scanned_m.group(1))

    proto_m = re.search(r"protocols=([^\s]+)", line)
    if proto_m:
        for part in proto_m.group(1).split(","):
            if ":" not in part:
                continue
            name, _, val = part.partition(":")
            if name:
                counts[name] = int(val)

    return counts, packets_scanned, packets_seen, sampled


def _parse_endpoints_line(line: str) -> Tuple[Set[str], Set[str]]:
    ips: Set[str] = set()
    ports: Set[str] = set()
    ips_m = re.search(r"\bips=([^\s]+)", line)
    if ips_m and ips_m.group(1):
        for part in ips_m.group(1).split(","):
            part = part.strip()
            if part:
                ips.add(part)
    ports_m = re.search(r"\bports=([^\s]+)", line)
    if ports_m and ports_m.group(1):
        for part in ports_m.group(1).split(","):
            part = part.strip()
            if part:
                ports.add(part)
    return ips, ports


def _parse_lines(stdout: str, excluded: Optional[Set[str]]) -> Tuple[Dict[str, int], int]:
    protocol_counts: Dict[str, int] = {}
    packets_scanned = 0
    for line in stdout.splitlines():
        if not line or line.startswith("PCAPTAIN_"):
            continue
        packets_scanned += 1
        protocols = line.split(":")
        unique_protocols = set(protocols) - (excluded or set())
        for proto in unique_protocols:
            if proto:
                protocol_counts[proto] = protocol_counts.get(proto, 0) + 1
    return protocol_counts, packets_scanned


def parse_fastscan_output(
    stdout: str,
    *,
    excluded_protocols: Optional[Set[str]] = None,
) -> Optional[FastScanParseResult]:
    if not stdout.strip():
        return FastScanParseResult({}, 0)

    fingerprint: Optional[str] = None
    summary_line: Optional[str] = None
    endpoints_line: Optional[str] = None

    for line in stdout.splitlines():
        if line.startswith(_FP_PREFIX):
            fingerprint = line.strip()
        elif line.startswith(_SUMMARY_PREFIX):
            summary_line = line.strip()
        elif line.startswith(_ENDPOINTS_PREFIX):
            endpoints_line = line.strip()

    indexed_ips: Set[str] = set()
    indexed_ports: Set[str] = set()
    if endpoints_line:
        indexed_ips, indexed_ports = _parse_endpoints_line(endpoints_line)

    if summary_line:
        counts, scanned, seen, sampled = _parse_summary_line(summary_line)
        return FastScanParseResult(
            protocol_counts=counts,
            packets_scanned=scanned,
            packets_seen=seen,
            protocol_fingerprint=fingerprint,
            sampled=sampled,
            indexed_ips=indexed_ips,
            indexed_ports=indexed_ports,
        )

    counts, scanned = _parse_lines(stdout, excluded_protocols)
    return FastScanParseResult(
        protocol_counts=counts,
        packets_scanned=scanned,
        protocol_fingerprint=fingerprint,
        sampled=False,
        indexed_ips=indexed_ips,
        indexed_ports=indexed_ports,
    )
