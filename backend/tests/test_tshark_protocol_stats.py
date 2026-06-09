from services.tshark_protocol_stats import (
    build_protocol_fingerprint,
    parse_io_phs_output,
)


_SAMPLE_PHS = """
===================================================================
Protocol Hierarchy Statistics
Filter:

frame                                    frames:1253100 bytes:999
eth                                      frames:1253100 bytes:999
ip                                       frames:1253100 bytes:999
tcp                                      frames:1200000 bytes:888
s7comm                                   frames:500000 bytes:444
udp                                      frames:53100 bytes:111
dns                                      frames:40000 bytes:100
===================================================================
"""


def test_parse_io_phs_output_extracts_protocol_counts():
    counts = parse_io_phs_output(_SAMPLE_PHS)
    assert counts["frame"] == 1253100
    assert counts["eth"] == 1253100
    assert counts["s7comm"] == 500000
    assert counts["dns"] == 40000
    assert "afp" not in counts


def test_parse_io_phs_output_ignores_bytes_column():
    text = """
===================================================================
Protocol Hierarchy Statistics
Filter:

tcp                                      frames:10 bytes:1234
===================================================================
"""
    assert parse_io_phs_output(text)["tcp"] == 10


def test_build_protocol_fingerprint_sorted():
    fp = build_protocol_fingerprint({"tcp": 10, "eth": 100, "dns": 5})
    assert fp == "PCAPTAIN_FP v1|dns=5|eth=100|tcp=10"
