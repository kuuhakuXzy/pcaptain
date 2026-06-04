"""Redis index maintenance for IP/port endpoint catalog."""

import json
from typing import Iterable, Optional

from redis import Redis

from .catalog_constants import IP_INDEX_PREFIX, PORT_INDEX_PREFIX
from .logger import get_logger

logger = get_logger(__name__)


def _split_csv_field(value: Optional[str]) -> list[str]:
    if not value:
        return []
    return [part.strip() for part in value.split(",") if part.strip()]


def remove_endpoint_indexes(
    redis: Redis,
    file_hash: str,
    stored: Optional[dict],
) -> None:
    if not stored:
        return
    pipe = redis.pipeline()
    for ip in _split_csv_field(stored.get("indexed_ips")):
        pipe.srem(f"{IP_INDEX_PREFIX}:{ip}", file_hash)
    for port in _split_csv_field(stored.get("indexed_ports")):
        pipe.srem(f"{PORT_INDEX_PREFIX}:{port}", file_hash)
    pipe.execute()


def add_endpoint_indexes(
    redis: Redis,
    pipe,
    file_hash: str,
    ips: Iterable[str],
    ports: Iterable[str],
) -> None:
    for ip in ips:
        pipe.sadd(f"{IP_INDEX_PREFIX}:{ip}", file_hash)
    for port in ports:
        pipe.sadd(f"{PORT_INDEX_PREFIX}:{port}", file_hash)


def endpoints_summary_json(ips: Iterable[str], ports: Iterable[str], limit: int = 50) -> str:
    """Compact JSON for API responses stored on file records."""
    ip_list = sorted(set(ips))[:limit]
    port_list = sorted(set(ports), key=lambda x: int(x))[:limit]
    return json.dumps({"ips": ip_list, "ports": port_list})
