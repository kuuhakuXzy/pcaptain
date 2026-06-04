"""Unit tests for Network Catalog helpers (no Redis/Docker required)."""

import sys
from pathlib import Path

# backend/ on path when run from repo root or backend/
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from services.catalog_query import _row_matches_filters
from services.search_parse import parse_shorthand_query, resolve_protocols
from services.endpoint_index import endpoints_summary_json, _split_csv_field


def test_parse_shorthand_include_exclude():
    inc, exc = parse_shorthand_query("http !json sip")
    assert inc == ["http", "sip"]
    assert exc == ["json"]


def test_parse_shorthand_empty():
    assert parse_shorthand_query("") == ([], [])
    assert parse_shorthand_query("   ") == ([], [])


def test_resolve_protocols_exact_and_prefix():
    candidates = ["HTTP", "JSON", "SIP", "TCP"]
    assert resolve_protocols("http", candidates) == ["HTTP"]
    assert "SIP" in resolve_protocols("si", candidates)


def test_row_matches_filters_size_and_path():
    row = {
        "filename": "capture.pcap",
        "path": "/data/pcaps/foo/capture.pcap",
        "size_bytes": "5000",
        "last_modified": "1700000000",
        "capture_start": "1699999000",
        "capture_end": "1700001000",
    }
    assert _row_matches_filters(row, {"size_min": 1000, "size_max": 10000}) is True
    assert _row_matches_filters(row, {"size_min": 10000}) is False
    assert _row_matches_filters(row, {"path_prefix": "/data/pcaps"}) is True
    assert _row_matches_filters(row, {"path_prefix": "/other"}) is False


def test_row_matches_capture_window():
    row = {
        "filename": "x.pcap",
        "path": "/x",
        "size_bytes": "1",
        "capture_start": "100",
        "capture_end": "200",
    }
    # capture must overlap [150, 250]: end >= 150 and start <= 250
    assert _row_matches_filters(row, {"capture_after": 150}) is True
    assert _row_matches_filters(row, {"capture_before": 50}) is False


def test_endpoints_summary_json():
    raw = endpoints_summary_json({"10.0.0.1", "10.0.0.2"}, {"443", "80"})
    assert "10.0.0.1" in raw
    assert "443" in raw


def test_split_csv_field():
    assert _split_csv_field("a, b ,c") == ["a", "b", "c"]
    assert _split_csv_field(None) == []


def test_subnet_cidr_parsing():
    import ipaddress

    net = ipaddress.ip_network("10.0.0.0/24", strict=False)
    assert ipaddress.ip_address("10.0.0.55") in net
    assert ipaddress.ip_address("10.0.1.1") not in net


def test_subnet_invalid_raises():
    import ipaddress

    try:
        ipaddress.ip_network("not-a-cidr", strict=False)
        assert False, "expected ValueError"
    except ValueError:
        pass
