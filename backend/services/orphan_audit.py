"""Compare on-disk PCAP files with Redis catalog index."""

import asyncio
import os
from typing import Any

from redis import Redis


async def audit_catalog_vs_disk(
    redis: Redis,
    root_directory: str,
    allowed_extensions: tuple[str, ...],
    *,
    prefix_str: str | None = None,
) -> dict[str, Any]:
    indexed_paths: set[str] = set()
    indexed_by_hash: dict[str, dict] = {}
    stale_indexed: list[dict] = []

    cursor = 0
    from services.catalog_constants import PCAP_FILE_KEY_PREFIX

    while True:
        cursor, keys = await asyncio.to_thread(
            redis.scan,
            cursor=cursor,
            match=f"{PCAP_FILE_KEY_PREFIX}:*",
            count=300,
        )
        pipe = redis.pipeline()
        for key in keys:
            pipe.hgetall(key)
        rows = await asyncio.to_thread(pipe.execute)
        for key, row in zip(keys, rows):
            if not row:
                continue
            path = row.get("path") or ""
            indexed_paths.add(os.path.normpath(path))
            fh = key.split(":")[-1]
            indexed_by_hash[fh] = row
            if path and not await asyncio.to_thread(os.path.isfile, path):
                display_path = path
                if prefix_str:
                    display_path = path.replace(root_directory, prefix_str, 1)
                stale_indexed.append(
                    {
                        "file_hash": fh,
                        "path": display_path,
                        "filename": row.get("filename", ""),
                        "reason": "indexed_but_missing_on_disk",
                    }
                )
        if cursor == 0:
            break

    disk_files: list[str] = []
    for root, _dirs, files in await asyncio.to_thread(
        os.walk, root_directory
    ):
        for name in files:
            if name.endswith(allowed_extensions):
                disk_files.append(os.path.normpath(os.path.join(root, name)))

    not_indexed: list[dict] = []
    for path in disk_files:
        if path not in indexed_paths:
            display_path = path
            if prefix_str:
                display_path = path.replace(root_directory, prefix_str, 1)
            try:
                size_b = await asyncio.to_thread(os.path.getsize, path)
            except OSError:
                size_b = 0
            not_indexed.append(
                {
                    "path": display_path,
                    "filename": os.path.basename(path),
                    "size_bytes": size_b,
                    "reason": "on_disk_not_indexed",
                }
            )

    from services.catalog_constants import SCAN_FAILURES_KEY

    failures_raw = await asyncio.to_thread(redis.lrange, SCAN_FAILURES_KEY, 0, 199)
    scan_failures = []
    import json

    for item in failures_raw or []:
        try:
            scan_failures.append(json.loads(item))
        except json.JSONDecodeError:
            continue

    return {
        "disk_file_count": len(disk_files),
        "indexed_file_count": len(indexed_by_hash),
        "not_indexed": not_indexed[:500],
        "not_indexed_count": len(not_indexed),
        "stale_indexed": stale_indexed[:500],
        "stale_indexed_count": len(stale_indexed),
        "scan_failures": scan_failures,
        "scan_failure_count": len(scan_failures),
    }
