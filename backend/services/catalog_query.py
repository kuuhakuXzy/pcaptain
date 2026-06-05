"""Advanced catalog query execution against Redis indexes."""

import asyncio
import json
from typing import Optional
from uuid import uuid4

from redis import Redis

from services.context import AppContext
from services.catalog_constants import (
    PCAP_FILE_KEY_PREFIX,
    PROTOCOL_INDEX_PREFIX,
    SORT_INDEX_CAPTURE_START,
    SORT_INDEX_FILENAME,
    SORT_INDEX_PACKET_COUNT,
    SORT_INDEX_PATH,
    SORT_INDEX_SIZE,
    TMP_KEY_TTL_SECONDS,
    TMP_RESULT_PREFIX,
    IP_INDEX_PREFIX,
    PORT_INDEX_PREFIX,
)
from services.search_parse import parse_shorthand_query, resolve_protocols
from services.scan import get_all_protocols
from services.logger import get_logger

logger = get_logger(__name__)

SORT_FIELD_TO_INDEX = {
    "filename": SORT_INDEX_FILENAME,
    "path": SORT_INDEX_PATH,
    "size_bytes": SORT_INDEX_SIZE,
    "protocol_packet_count": SORT_INDEX_PACKET_COUNT,
    "capture_start": SORT_INDEX_CAPTURE_START,
}


async def search_by_filename(query: str, redis, sort_index: str) -> set[str]:
    q = query.lower().strip()
    all_ids = await asyncio.to_thread(redis.zrange, sort_index, 0, -1)
    if not all_ids:
        return set()

    pipe = redis.pipeline()
    for h in all_ids:
        pipe.hgetall(f"{PCAP_FILE_KEY_PREFIX}:{h}")
    rows = await asyncio.to_thread(pipe.execute)

    return {
        h
        for h, row in zip(all_ids, rows)
        if row and q in row.get("filename", "").lower()
    }


def _parse_float_field(value) -> Optional[float]:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _parse_int_field(value) -> Optional[int]:
    if value is None or value == "":
        return None
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return None


def _row_matches_filters(row: dict, filters: dict) -> bool:
    filename = row.get("filename", "")
    path = row.get("path", "")
    size_bytes = _parse_int_field(row.get("size_bytes")) or 0
    last_modified = _parse_float_field(row.get("last_modified"))
    capture_start = _parse_float_field(row.get("capture_start"))
    capture_end = _parse_float_field(row.get("capture_end"))

    fn_contains = filters.get("filename_contains")
    if fn_contains and fn_contains.lower() not in filename.lower():
        return False

    path_prefix = filters.get("path_prefix")
    if path_prefix and not path.lower().startswith(path_prefix.lower()):
        return False

    size_min = filters.get("size_min")
    if size_min is not None and size_bytes < size_min:
        return False

    size_max = filters.get("size_max")
    if size_max is not None and size_bytes > size_max:
        return False

    modified_after = filters.get("modified_after")
    if modified_after is not None and (
        last_modified is None or last_modified < modified_after
    ):
        return False

    modified_before = filters.get("modified_before")
    if modified_before is not None and (
        last_modified is None or last_modified > modified_before
    ):
        return False

    capture_after = filters.get("capture_after")
    if capture_after is not None and (
        capture_end is None or capture_end < capture_after
    ):
        return False

    capture_before = filters.get("capture_before")
    if capture_before is not None and (
        capture_start is None or capture_start > capture_before
    ):
        return False

    return True


async def _seed_all_files(redis: Redis, tmp_set: str, sort_index: str) -> bool:
    all_ids = await asyncio.to_thread(redis.zrange, sort_index, 0, -1)
    if not all_ids:
        return False
    pipe = redis.pipeline()
    for h in all_ids:
        pipe.sadd(tmp_set, h)
    await asyncio.to_thread(pipe.execute)
    return True


async def _intersect_with_set(redis: Redis, tmp_set: str, other_key: str) -> None:
    tmp_other = f"{tmp_set}:intersect"
    await asyncio.to_thread(redis.rename, tmp_set, tmp_other)
    await asyncio.to_thread(redis.sinterstore, tmp_set, tmp_other, other_key)
    await asyncio.to_thread(redis.delete, tmp_other)


async def execute_catalog_query(
    redis: Redis,
    context: AppContext,
    *,
    protocol_query: str = "",
    protocols_include: Optional[list[str]] = None,
    protocols_exclude: Optional[list[str]] = None,
    filename_contains: Optional[str] = None,
    path_prefix: Optional[str] = None,
    size_min: Optional[int] = None,
    size_max: Optional[int] = None,
    modified_after: Optional[float] = None,
    modified_before: Optional[float] = None,
    capture_after: Optional[float] = None,
    capture_before: Optional[float] = None,
    ip: Optional[str] = None,
    port: Optional[int] = None,
    page: int = 1,
    limit: int = 10,
    sort_by: str = "filename",
    descending: bool = False,
) -> dict:
    sort_index = SORT_FIELD_TO_INDEX.get(sort_by, SORT_INDEX_FILENAME)
    protocol_resolved_set: set[str] = set()

    base_tmp = f"{TMP_RESULT_PREFIX}:{uuid4().hex}"
    tmp_set = f"{base_tmp}:set"
    tmp_z = f"{base_tmp}:z"
    tmp_sorted = f"{base_tmp}:sorted"

    include = list(protocols_include or [])
    exclude = list(protocols_exclude or [])
    if protocol_query.strip():
        parsed_inc, parsed_exc = parse_shorthand_query(protocol_query)
        include.extend(parsed_inc)
        exclude.extend(parsed_exc)

    has_protocol = bool(include or exclude)
    has_filename = bool(filename_contains)

    if not has_protocol and not has_filename and not ip and port is None:
        if not await _seed_all_files(redis, tmp_set, sort_index):
            return {"total": 0, "page": page, "limit": limit, "data": []}
    elif include:
        all_protocols = await get_all_protocols(redis)
        resolved = resolve_protocols(" ".join(include), list(all_protocols))
        if not resolved:
            return {"total": 0, "page": page, "limit": limit, "data": []}
        protocol_resolved_set = {p.lower() for p in resolved}
        keys = [f"{PROTOCOL_INDEX_PREFIX}:{p.lower()}" for p in resolved]
        await asyncio.to_thread(redis.sunionstore, tmp_set, *keys)
    else:
        if not await _seed_all_files(redis, tmp_set, sort_index):
            return {"total": 0, "page": page, "limit": limit, "data": []}

    if exclude:
        exclude_keys = [
            f"{PROTOCOL_INDEX_PREFIX}:{p.lower()}" for p in exclude if p.strip()
        ]
        if exclude_keys:
            await asyncio.to_thread(
                redis.sdiffstore, tmp_set, tmp_set, *exclude_keys
            )

    if has_filename:
        fn_hashes = await search_by_filename(filename_contains, redis, sort_index)
        if not fn_hashes:
            return {"total": 0, "page": page, "limit": limit, "data": []}
        tmp_fn = f"{base_tmp}:fn"
        pipe = redis.pipeline()
        for h in fn_hashes:
            pipe.sadd(tmp_fn, h)
        await asyncio.to_thread(pipe.execute)
        await _intersect_with_set(redis, tmp_set, tmp_fn)
        await asyncio.to_thread(redis.delete, tmp_fn)

    if ip:
        ip_key = f"{IP_INDEX_PREFIX}:{ip}"
        if not await asyncio.to_thread(redis.exists, ip_key):
            return {"total": 0, "page": page, "limit": limit, "data": []}
        await _intersect_with_set(redis, tmp_set, ip_key)

    if port is not None:
        port_key = f"{PORT_INDEX_PREFIX}:{port}"
        if not await asyncio.to_thread(redis.exists, port_key):
            return {"total": 0, "page": page, "limit": limit, "data": []}
        await _intersect_with_set(redis, tmp_set, port_key)

    metadata_filters = {
        "filename_contains": filename_contains,
        "path_prefix": path_prefix,
        "size_min": size_min,
        "size_max": size_max,
        "modified_after": modified_after,
        "modified_before": modified_before,
        "capture_after": capture_after,
        "capture_before": capture_before,
    }
    needs_row_filter = any(
        metadata_filters[k] is not None for k in metadata_filters
    )

    if needs_row_filter:
        members = list(await asyncio.to_thread(redis.smembers, tmp_set))
        if not members:
            return {"total": 0, "page": page, "limit": limit, "data": []}
        pipe = redis.pipeline()
        for h in members:
            pipe.hgetall(f"{PCAP_FILE_KEY_PREFIX}:{h}")
        rows = await asyncio.to_thread(pipe.execute)
        await asyncio.to_thread(redis.delete, tmp_set)
        matched_ids = [
            h
            for h, row in zip(members, rows)
            if row and _row_matches_filters(row, metadata_filters)
        ]
        if not matched_ids:
            return {"total": 0, "page": page, "limit": limit, "data": []}
        pipe = redis.pipeline()
        for h in matched_ids:
            pipe.sadd(tmp_set, h)
        await asyncio.to_thread(pipe.execute)

    total = await asyncio.to_thread(redis.scard, tmp_set)
    if total == 0:
        return {"total": 0, "page": page, "limit": limit, "data": []}

    await asyncio.to_thread(redis.zinterstore, tmp_z, {tmp_set: 1})
    await asyncio.to_thread(
        redis.zinterstore,
        tmp_sorted,
        {sort_index: 1, tmp_z: 0},
    )
    for key in (tmp_set, tmp_z, tmp_sorted):
        await asyncio.to_thread(redis.expire, key, TMP_KEY_TTL_SECONDS)

    start = (page - 1) * limit
    end = start + limit - 1
    ids = await asyncio.to_thread(
        redis.zrevrange if descending else redis.zrange,
        tmp_sorted,
        start,
        end,
    )

    pipe = redis.pipeline()
    for h in ids:
        pipe.hgetall(f"{PCAP_FILE_KEY_PREFIX}:{h}")
    rows = await asyncio.to_thread(pipe.execute)

    internal_root = context.config.pcap.root_directory
    prefix_str = context.config.pcap.prefix_str
    results = []
    for row in rows:
        if not row:
            continue
        counts = json.loads(row.get("protocol_counts", "{}"))
        if protocol_resolved_set:
            matched = [p for p in counts if p.lower() in protocol_resolved_set]
        else:
            matched = list(counts.keys())
        row["matched_protocols"] = matched
        if prefix_str and row.get("path"):
            row["path"] = row["path"].replace(internal_root, prefix_str, 1)
        results.append(row)

    return {"total": total, "page": page, "limit": limit, "data": results}
