"""Find exact and near-duplicate PCAP groups from catalog metadata."""

import asyncio
from collections import defaultdict
from typing import Any

from redis import Redis

from services.catalog_constants import PCAP_FILE_KEY_PREFIX


def _parse_int(value) -> int:
    try:
        return int(float(value or 0))
    except (TypeError, ValueError):
        return 0


async def find_duplicate_groups(
    redis: Redis,
    *,
    min_group_size: int = 2,
    max_groups: int = 100,
) -> dict[str, Any]:
    """Group files by near-duplicate fingerprint (size + packet count)."""
    same_name_size: dict[tuple[str, int], list[dict]] = defaultdict(list)
    near_by_fp: dict[tuple[int, int], list[dict]] = defaultdict(list)
    by_protocol_fp: dict[str, list[dict]] = defaultdict(list)

    cursor = 0
    total_indexed = 0

    while True:
        cursor, keys = await asyncio.to_thread(
            redis.scan,
            cursor=cursor,
            match=f"{PCAP_FILE_KEY_PREFIX}:*",
            count=300,
        )
        if not keys:
            if cursor == 0:
                break
        pipe = redis.pipeline()
        for key in keys:
            pipe.hgetall(key)
        rows = await asyncio.to_thread(pipe.execute)

        for key, row in zip(keys, rows):
            if not row:
                continue
            total_indexed += 1
            file_hash = key.split(":")[-1]
            size_b = _parse_int(row.get("size_bytes"))
            packets = _parse_int(row.get("total_packets"))
            entry = {
                "file_hash": file_hash,
                "filename": row.get("filename", ""),
                "path": row.get("path", ""),
                "size_bytes": size_b,
                "total_packets": packets,
                "capture_start": row.get("capture_start"),
                "capture_end": row.get("capture_end"),
            }
            name_key = (entry["filename"].lower(), size_b)
            same_name_size[name_key].append(entry)
            near_by_fp[(size_b, packets)].append(entry)
            proto_fp = (row.get("protocol_fingerprint") or "").strip()
            if proto_fp:
                by_protocol_fp[proto_fp].append(entry)

        if cursor == 0:
            break

    exact_groups = [
        {
            "type": "same_name_size",
            "fingerprint": {"filename": name, "size_bytes": size},
            "files": files,
            "count": len(files),
        }
        for (name, size), files in same_name_size.items()
        if len(files) >= min_group_size
    ]
    exact_groups.sort(key=lambda g: g["count"], reverse=True)

    near_groups = []
    for (_size, _packets), files in near_by_fp.items():
        if len(files) < min_group_size:
            continue
        hashes = {f["file_hash"] for f in files}
        if len(hashes) < 2:
            continue
        near_groups.append(
            {
                "type": "near",
                "fingerprint": {"size_bytes": _size, "total_packets": _packets},
                "files": files,
                "count": len(files),
            }
        )
    near_groups.sort(key=lambda g: g["count"], reverse=True)

    protocol_fp_groups = [
        {
            "type": "protocol_fingerprint",
            "fingerprint": {"protocol_fingerprint": fp},
            "files": files,
            "count": len(files),
        }
        for fp, files in by_protocol_fp.items()
        if len(files) >= min_group_size
    ]
    protocol_fp_groups.sort(key=lambda g: g["count"], reverse=True)

    return {
        "total_indexed": total_indexed,
        "exact_duplicate_groups": exact_groups[:max_groups],
        "near_duplicate_groups": near_groups[:max_groups],
        "protocol_fingerprint_groups": protocol_fp_groups[:max_groups],
        "exact_group_count": len(exact_groups),
        "near_group_count": len(near_groups),
        "protocol_fingerprint_group_count": len(protocol_fp_groups),
    }
