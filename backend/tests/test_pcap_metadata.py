from unittest.mock import patch

from services.fastscan_options import fastscan_reports_full_packet_count
from services.pcap_metadata import (
    PcapMetadata,
    PcapMetadataCache,
    resolve_pcap_metadata,
    reset_metadata_cache,
)
from models.scan_options import FastScanUserOptions


def test_fastscan_reports_full_packet_count():
    assert fastscan_reports_full_packet_count(FastScanUserOptions()) is True
    assert (
        fastscan_reports_full_packet_count(
            FastScanUserOptions(max_packets=1000)
        )
        is False
    )


def test_metadata_cache_hit_by_mtime():
    cache = PcapMetadataCache(ttl_seconds=60)
    meta = PcapMetadata(42, 1.0, 2.0)
    with patch("services.pcap_metadata.os.stat") as mock_stat:
        mock_stat.return_value.st_size = 100
        mock_stat.return_value.st_mtime_ns = 999
        cache.set("/tmp/a.pcap", meta)
        assert cache.get("/tmp/a.pcap") == meta
        mock_stat.return_value.st_mtime_ns = 1000
        assert cache.get("/tmp/a.pcap") is None


def test_resolve_uses_packets_seen_hint():
    reset_metadata_cache(ttl_seconds=60)
    with patch("services.pcap_metadata.get_pcap_metadata_sync") as mock_meta:
        mock_meta.return_value = PcapMetadata(None, 10.0, 20.0)
        total, start, end = resolve_pcap_metadata(
            "/tmp/a.pcap",
            packets_seen_hint=5000,
            cache_ttl_seconds=60,
        )
        mock_meta.assert_called_once_with(
            "/tmp/a.pcap",
            include_packet_count=False,
            include_time_range=True,
        )
        assert total == 5000
        assert start == 10.0
        assert end == 20.0
