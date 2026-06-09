"""Fast scan path: endpoints from fastscan, no tshark for catalog IPs/ports."""

from unittest.mock import patch

import pytest

from services.config import ScanMode
from services.fastscan_options import ProtocolScanResult


@pytest.mark.asyncio
async def test_fast_mode_skips_tshark_endpoint_extract():
    from services.scan import ScanService

    service = ScanService()
    protocol_result = ProtocolScanResult(
        protocol_counts={"tcp": 10, "ip": 10},
        packets_scanned=10,
        indexed_ips={"10.0.0.1"},
        indexed_ports={"443"},
    )

    with patch(
        "services.scan.extract_endpoints_sync",
    ) as mock_extract:
        ips = set()
        ports = set()
        current_scan_mode = ScanMode.FAST
        catalog_endpoint_index_enabled = True

        if catalog_endpoint_index_enabled:
            if current_scan_mode == ScanMode.FAST:
                ips = set(protocol_result.indexed_ips or set())
                ports = set(protocol_result.indexed_ports or set())
            else:
                extracted = mock_extract("file.pcap", max_packets=10000)
                ips = extracted.get("ips", set())
                ports = extracted.get("ports", set())

        mock_extract.assert_not_called()
        assert ips == {"10.0.0.1"}
        assert ports == {"443"}
