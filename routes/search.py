from enum import Enum

from fastapi import APIRouter, HTTPException, Query, Depends
import asyncio
import json

from services.context import get_app_context, AppContext
from services.logger import get_logger
from services.scan import (
    PCAP_FILE_KEY_PREFIX,
    PROTOCOCOL_INDEX_PREFIX,
    SORT_INDEX_FILENAME,
    SORT_INDEX_PATH,
    SORT_INDEX_SIZE,
    SORT_INDEX_PACKET_COUNT,
    TMP_KEY_TTL_SECONDS,
    TMP_RESULT_PREFIX,
    get_all_protocols
)
from utils.protocols_utils import rank_protocols
from uuid import uuid4


router = APIRouter(tags=["Search"])
logger = get_logger(__name__)


class SortField(str, Enum):
    filename = "filename"
    size = "size_bytes"
    count = "protocol_packet_count"
    path = "path"


SORT_FIELD_TO_INDEX = {
    SortField.filename: SORT_INDEX_FILENAME,
    SortField.path: SORT_INDEX_PATH,
    SortField.size: SORT_INDEX_SIZE,
    SortField.count: SORT_INDEX_PACKET_COUNT,
}

def resolve_protocols(
    query: str,
    candidates: list[str],
    *,
    min_prefix_len: int = 3,
    max_contains_matches: int = 5,
    max_prefix_matches: int = 3,
    max_fuzzy: int = 10,
) -> list[str]:
    q = query.lower()

    exact = []
    contains = []
    prefix = []

    for p in candidates:
        pl = p.lower()

        if pl == q:
            exact.append(p)
            continue

        if q in pl:
            contains.append(p)
            continue

        if pl.startswith(q):
            prefix.append(p)

    if exact:
        return exact

    if (
        len(q) >= min_prefix_len
        and contains
        and len(contains) <= max_contains_matches
    ):
        return contains

    if (
        len(q) >= min_prefix_len
        and prefix
        and len(prefix) <= max_prefix_matches
    ):
        return prefix

    fuzzy = rank_protocols(q, candidates, max_dist=0.5)
    return fuzzy[:max_fuzzy]


@router.get("/search", summary="Search for pcaps containing a specific protocol")
async def fuzzy_search_pcaps(
    protocol: str = Query(
        ..., description="The protocol name to search for, e.g., sip"
    ),
    page: int = Query(1, ge=1),
    limit: int = Query(10, ge=1, le=100),
    sort_by: SortField = Query(SortField.filename),
    descending: bool = Query(False),
    context: AppContext = Depends(get_app_context),
):
    redis = context.redis_client
    if not redis:
        raise HTTPException(503, "Redis unavailable")

    excluded = context.get_excluded_protocols()

    all_protocols = await get_all_protocols(redis)
    candidates = [
        p for p in all_protocols
        if p.lower() not in excluded
    ]

    protocols = resolve_protocols(protocol, candidates)
    if not protocols:
        return {"total": 0, "page": page, "limit": limit, "data": []}

    resolved_set = {p.lower() for p in protocols}

    protocol_keys = [f"{PROTOCOCOL_INDEX_PREFIX}:{p.lower()}" for p in protocols]

    base_tmp = f"{TMP_RESULT_PREFIX}:{uuid4().hex}"
    tmp_set = f"{base_tmp}:set"
    tmp_z = f"{base_tmp}:z"
    tmp_sorted = f"{base_tmp}:sorted"

    await asyncio.to_thread(redis.sunionstore, tmp_set, *protocol_keys)

    if excluded:
        exclude_keys = [f"{PROTOCOCOL_INDEX_PREFIX}:{p.lower()}" for p in excluded]
        await asyncio.to_thread(redis.sdiffstore, tmp_set, tmp_set, *exclude_keys)

    total = await asyncio.to_thread(redis.scard, tmp_set)
    logger.info(f"Search for protocol '{protocol}' yielded {total} results")

    if total == 0:
        return {"total": 0, "page": page, "limit": limit, "data": []}

    await asyncio.to_thread(redis.zinterstore, tmp_z, {tmp_set: 1})

    sort_index = SORT_FIELD_TO_INDEX.get(sort_by)
    await asyncio.to_thread(
        redis.zinterstore,
        tmp_sorted,
        {sort_index: 1, tmp_z: 0},
    )

    # TTLs
    await asyncio.to_thread(redis.expire, tmp_set, TMP_KEY_TTL_SECONDS)
    await asyncio.to_thread(redis.expire, tmp_z, TMP_KEY_TTL_SECONDS)
    await asyncio.to_thread(redis.expire, tmp_sorted, TMP_KEY_TTL_SECONDS)

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

    results = []
    for row in rows:
        if not row:
            continue

        counts = json.loads(row.get("protocol_counts", "{}"))
        matched = [
            p for p in counts.keys()
            if p.lower() in resolved_set
        ]

        row["matched_protocols"] = matched
        row["searched_protocol"] = protocol

        if context.PCAP_FILE_PREFIX:
            row["path"] = row["path"].replace(
                context.PCAP_DIRECTORIES_STR,
                context.PCAP_FILE_PREFIX,
                1,
            )

        results.append(row)

    return {
        "total": total,
        "page": page,
        "limit": limit,
        "data": results,
    }
