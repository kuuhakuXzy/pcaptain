"""Track known IPs and surface newly seen addresses after scans."""

import asyncio
import json
import time
from typing import Any

from redis import Redis

from services.catalog_constants import (
    IP_INDEX_PREFIX,
    KNOWN_IPS_KEY,
    NEW_IPS_SNAPSHOT_KEY,
)


async def _all_indexed_ips(redis: Redis) -> set[str]:
    ips: set[str] = set()
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
            if ip:
                ips.add(ip)
        if cursor == 0:
            break
    return ips


async def snapshot_new_ips(redis: Redis) -> dict[str, Any]:
    """Compare current IP index to known set; update known; return new IPs."""
    current = await _all_indexed_ips(redis)
    known_raw = await asyncio.to_thread(redis.smembers, KNOWN_IPS_KEY)
    known = {
        (m.decode() if isinstance(m, bytes) else m) for m in (known_raw or set())
    }

    if not known:
        new_ips = sorted(current)
        is_first_baseline = True
    else:
        new_ips = sorted(current - known)
        is_first_baseline = False

    if current:
        await asyncio.to_thread(redis.sadd, KNOWN_IPS_KEY, *list(current))

    payload = {
        "new_ips": new_ips,
        "new_ip_count": len(new_ips),
        "total_indexed_ips": len(current),
        "is_first_baseline": is_first_baseline,
        "checked_at": time.time(),
    }
    await asyncio.to_thread(
        redis.set,
        NEW_IPS_SNAPSHOT_KEY,
        json.dumps(
            {
                "new_ips": new_ips,
                "new_ip_count": len(new_ips),
                "total_indexed_ips": len(current),
                "is_first_baseline": is_first_baseline,
            }
        ),
    )
    return payload


async def get_last_new_ips(redis: Redis) -> dict[str, Any]:
    raw = await asyncio.to_thread(redis.get, NEW_IPS_SNAPSHOT_KEY)
    if not raw:
        return {"new_ips": [], "new_ip_count": 0, "total_indexed_ips": 0}
    return json.loads(raw)


async def reset_known_ips(redis: Redis) -> int:
    await asyncio.to_thread(redis.delete, KNOWN_IPS_KEY)
    await asyncio.to_thread(redis.delete, NEW_IPS_SNAPSHOT_KEY)
    current = await _all_indexed_ips(redis)
    if current:
        await asyncio.to_thread(redis.sadd, KNOWN_IPS_KEY, *list(current))
    return len(current)
