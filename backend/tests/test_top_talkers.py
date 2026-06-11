"""Tests for catalog top-talkers aggregation."""

import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from services.catalog_constants import IP_INDEX_PREFIX, PORT_INDEX_PREFIX
from services.catalog_stats import _index_key_label, get_top_talkers


def test_index_key_label_strips_prefix():
    key = f"{IP_INDEX_PREFIX}:10.0.0.1"
    assert _index_key_label(key, IP_INDEX_PREFIX) == "10.0.0.1"


@pytest.mark.asyncio
async def test_get_top_talkers_ranks_by_file_count():
    redis = MagicMock()

    all_keys = [
        f"{IP_INDEX_PREFIX}:10.0.0.1".encode(),
        f"{IP_INDEX_PREFIX}:10.0.0.2".encode(),
        f"{PORT_INDEX_PREFIX}:443".encode(),
        f"{PORT_INDEX_PREFIX}:80".encode(),
    ]

    def fake_scan(cursor, match, count):
        if cursor != 0:
            return (0, [])
        prefix = match.rstrip("*")
        return (0, [k for k in all_keys if k.decode().startswith(prefix)])

    def fake_scard(key):
        labels = {
            f"{IP_INDEX_PREFIX}:10.0.0.1".encode(): 5,
            f"{IP_INDEX_PREFIX}:10.0.0.2".encode(): 12,
            f"{PORT_INDEX_PREFIX}:443".encode(): 9,
            f"{PORT_INDEX_PREFIX}:80".encode(): 3,
        }
        return labels.get(key, 0)

    redis.scan.side_effect = fake_scan
    redis.scard.side_effect = fake_scard

    result = await get_top_talkers(redis, top=2)

    assert result["top_ips"] == {"10.0.0.2": 12, "10.0.0.1": 5}
    assert result["top_ports"] == {"443": 9, "80": 3}
