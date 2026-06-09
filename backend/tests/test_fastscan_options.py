from services.fastscan_options import (
    FastScanDefaults,
    build_fastscan_command,
    merge_fast_options,
    parse_fastscan_output,
)
from models.scan_options import FastScanUserOptions


def test_build_fastscan_command_summary_and_bpf():
    opts = FastScanUserOptions(
        output="summary",
        sample_every=10,
        bpf_filter="tcp port 443",
        emit_fingerprint=True,
    )
    cmd = build_fastscan_command("/data/a.pcap", opts)
    assert cmd[0] == "fastscan"
    assert "--summary" in cmd
    assert "--sample-every" in cmd
    assert "--bpf" in cmd
    assert cmd[-1] == "/data/a.pcap"


def test_merge_fast_options_user_overrides_defaults():
    defaults = FastScanDefaults(output="summary", emit_fingerprint=True)
    user = FastScanUserOptions(bpf_filter="tcp port 443")
    merged = merge_fast_options(defaults, user)
    assert merged.output == "summary"
    assert merged.emit_fingerprint is True
    assert merged.bpf_filter == "tcp port 443"


def test_parse_summary_packets_seen():
    stdout = "PCAPTAIN_SUMMARY packets_seen=9999 packets_scanned=9999 protocols=tcp:1\n"
    parsed = parse_fastscan_output(stdout)
    assert parsed is not None
    assert parsed.packets_seen == 9999


def test_parse_summary_line():
    stdout = (
        "PCAPTAIN_SUMMARY packets_seen=1000 packets_scanned=100 sample_every=10 "
        "protocols=eth:100,ip:100,tcp:80,http:50\n"
        "PCAPTAIN_ENDPOINTS ips=10.0.0.1,192.168.1.2 ports=80,443\n"
        "PCAPTAIN_FP v1|eth=100|http=50\n"
    )
    parsed = parse_fastscan_output(stdout)
    assert parsed is not None
    assert parsed.packets_scanned == 100
    assert parsed.protocol_counts.get("http") == 50
    assert parsed.protocol_fingerprint is not None
    assert parsed.sampled is True
    assert parsed.indexed_ips == {"10.0.0.1", "192.168.1.2"}
    assert parsed.indexed_ports == {"80", "443"}


def test_build_fastscan_command_endpoint_max_packets():
    cmd = build_fastscan_command(
        "/data/a.pcap",
        FastScanUserOptions(output="summary"),
        endpoint_max_packets=10000,
    )
    assert "--endpoint-max-packets" in cmd
    assert "10000" in cmd
