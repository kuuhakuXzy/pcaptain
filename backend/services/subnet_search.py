"""CIDR / subnet search against IP endpoint index."""

import asyncio
import ipaddress
from typing import Any

from redis import Redis

from services.catalog_constants import IP_INDEX_PREFIX, PCAP_FILE_KEY_PREFIX


async def search_by_subnet(
    redis: Redis,
    cidr: str,
    *,
    page: int = 1,
    limit: int = 20,
    prefix_str: str | None = None,
    internal_root: str = "",
) -> dict[str, Any]:
    try:
        network = ipaddress.ip_network(cidr.strip(), strict=False)
    except ValueError as exc:
        raise ValueError(f"Invalid CIDR: {exc}") from exc

    matching_ips: list[str] = []
    cursor = 0
    while True:
        cursor, keys = await asyncio.to_thread(
            redis.scan,
            cursor=cursor,
            match=f"{IP_INDEX_PREFIX}:*",
            count=500,
        )
        for key in keys:
            ip = key.split(":")[-1]
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                continue
            if addr in network:
                matching_ips.append(ip)
        if cursor == 0:
            break

    file_hashes: set[bytes] = set()
    for ip in matching_ips:
        members = await asyncio.to_thread(redis.smembers, f"{IP_INDEX_PREFIX}:{ip}")
        file_hashes.update(members)

    ids = list(file_hashes)
    total = len(ids)
    start = (page - 1) * limit
    page_ids = ids[start : start + limit]

    pipe = redis.pipeline()
    for h in page_ids:
        hid = h.decode() if isinstance(h, bytes) else h
        pipe.hgetall(f"{PCAP_FILE_KEY_PREFIX}:{hid}")
    rows = await asyncio.to_thread(pipe.execute)

    data = []
    for row in rows:
        if not row:
            continue
        if prefix_str and row.get("path"):
            row["path"] = row["path"].replace(internal_root, prefix_str, 1)
        data.append(row)

    return {
        "cidr": str(network),
        "matching_ips": sorted(matching_ips)[:100],
        "matching_ip_count": len(matching_ips),
        "total": total,
        "page": page,
        "limit": limit,
        "data": data,
    }
