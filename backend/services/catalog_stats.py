"""Aggregate catalog statistics from Redis."""

import asyncio
import json
import os
import time
from collections import defaultdict

from redis import Redis

from services.catalog_constants import (
    IP_INDEX_PREFIX,
    PCAP_FILE_KEY_PREFIX,
    PORT_INDEX_PREFIX,
    PROTOCOL_INDEX_PREFIX,
    STATS_SUMMARY_KEY,
)
from services.logger import get_logger

logger = get_logger(__name__)


async def build_stats_summary(redis: Redis, root_directory: str, ttl_seconds: int = 300) -> dict:
    now = time.time()
    total_files = 0
    total_bytes = 0
    protocol_presence: dict[str, int] = defaultdict(int)
    directory_dist: dict[str, int] = defaultdict(int)
    co_occurrence: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))

    cursor = 0
    root_dir = root_directory.rstrip(os.sep)

    while True:
        cursor, keys = await asyncio.to_thread(
            redis.scan,
            cursor=cursor,
            match=f"{PCAP_FILE_KEY_PREFIX}:*",
            count=500,
        )
        for key in keys:
            data = await asyncio.to_thread(redis.hgetall, key)
            if not data:
                continue
            total_files += 1
            total_bytes += int(data.get("size_bytes") or 0)
            protocols = [
                p.strip().lower()
                for p in data.get("protocols", "").split(",")
                if p.strip()
            ]
            for proto in protocols:
                protocol_presence[proto] += 1
            for i, a in enumerate(protocols):
                for b in protocols[i + 1 :]:
                    co_occurrence[a][b] += 1
                    co_occurrence[b][a] += 1

            file_path = data.get("path", "")
            if file_path.startswith(root_dir):
                rel = file_path[len(root_dir) :].lstrip(os.sep)
                top = rel.split(os.sep)[0] if rel else "(root)"
                directory_dist[top or "(root)"] += 1

        if cursor == 0:
            break

    top_protocols = sorted(
        protocol_presence.items(), key=lambda x: x[1], reverse=True
    )[:50]
    top_directories = sorted(
        directory_dist.items(), key=lambda x: x[1], reverse=True
    )[:30]

    summary = {
        "generated_at": now,
        "total_files": total_files,
        "total_bytes": total_bytes,
        "protocol_count": len(protocol_presence),
        "top_protocols": dict(top_protocols),
        "directory_distribution": dict(top_directories),
    }
    await asyncio.to_thread(
        redis.setex, STATS_SUMMARY_KEY, ttl_seconds, json.dumps(summary)
    )
    return summary


async def get_co_occurrence_for_protocol(
    redis: Redis, protocol: str, limit: int = 20
) -> dict:
    proto = protocol.lower().strip()
    index_key = f"{PROTOCOL_INDEX_PREFIX}:{proto}"
    file_hashes = await asyncio.to_thread(redis.smembers, index_key)
    if not file_hashes:
        return {"protocol": proto, "co_occurring": {}}

    counts: dict[str, int] = defaultdict(int)
    pipe = redis.pipeline()
    for h in file_hashes:
        pipe.hgetall(f"{PCAP_FILE_KEY_PREFIX}:{h}")
    rows = await asyncio.to_thread(pipe.execute)

    for row in rows:
        if not row:
            continue
        for other in row.get("protocols", "").split(","):
            other = other.strip().lower()
            if other and other != proto:
                counts[other] += 1

    ranked = sorted(counts.items(), key=lambda x: x[1], reverse=True)[:limit]
    return {"protocol": proto, "co_occurring": dict(ranked)}


def _index_key_label(key: str | bytes, prefix: str) -> str:
    text = key.decode() if isinstance(key, bytes) else key
    needle = f"{prefix}:"
    if text.startswith(needle):
        return text[len(needle) :]
    return text.rsplit(":", 1)[-1]


async def _top_index_by_cardinality(
    redis: Redis, prefix: str, top: int
) -> dict[str, int]:
    """Rank IP or port index keys by how many PCAP files reference them."""
    counts: list[tuple[str, int]] = []
    cursor = 0
    while True:
        cursor, keys = await asyncio.to_thread(
            redis.scan,
            cursor=cursor,
            match=f"{prefix}:*",
            count=500,
        )
        for key in keys:
            card = await asyncio.to_thread(redis.scard, key)
            if card <= 0:
                continue
            label = _index_key_label(key, prefix)
            if label:
                counts.append((label, card))
        if cursor == 0:
            break
    ranked = sorted(counts, key=lambda x: x[1], reverse=True)[:top]
    return dict(ranked)


async def get_top_talkers(redis: Redis, top: int = 15) -> dict:
    ips, ports = await asyncio.gather(
        _top_index_by_cardinality(redis, IP_INDEX_PREFIX, top),
        _top_index_by_cardinality(redis, PORT_INDEX_PREFIX, top),
    )
    return {"top_ips": ips, "top_ports": ports}
