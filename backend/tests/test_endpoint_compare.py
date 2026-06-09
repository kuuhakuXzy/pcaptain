from unittest.mock import patch

from services.endpoint_compare import compare_endpoints_sync


def test_compare_endpoints_perfect_match():
    with patch(
        "services.endpoint_compare.run_fastscan_endpoints_sync",
        return_value=({"10.0.0.1"}, {"443"}),
    ), patch(
        "services.endpoint_compare.extract_endpoints_sync",
        return_value={"ips": {"10.0.0.1"}, "ports": {"443"}},
    ):
        result = compare_endpoints_sync("/tmp/a.pcap", endpoint_max_packets=100)
        assert result.ip_recall == 1.0
        assert result.ip_precision == 1.0
        assert result.port_recall == 1.0
        assert result.port_precision == 1.0


def test_compare_endpoints_partial_recall():
    with patch(
        "services.endpoint_compare.run_fastscan_endpoints_sync",
        return_value=({"10.0.0.1"}, {"80"}),
    ), patch(
        "services.endpoint_compare.extract_endpoints_sync",
        return_value={"ips": {"10.0.0.1", "10.0.0.2"}, "ports": {"80", "443"}},
    ):
        result = compare_endpoints_sync("/tmp/a.pcap")
        assert result.ip_recall == 0.5
        assert result.port_recall == 0.5
        assert result.ips_only_in_tshark == {"10.0.0.2"}
        assert result.ports_only_in_tshark == {"443"}
