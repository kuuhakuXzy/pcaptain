from enum import Enum

from fastapi import APIRouter, HTTPException, Query, Depends
import asyncio
import json
import re

from services.context import get_app_context, AppContext
from services.config import map_path_to_display
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
    get_all_protocols,
)
from services.risk import RISK_INDEX_KEY, risk_level_meets
from uuid import uuid4


router = APIRouter(tags=["Search"])
logger = get_logger(__name__)

BATCH_SIZE = 500
RISK_FILTER_EAGER_THRESHOLD = 2000
RISK_META_FIELDS = ("risk_score", "risk_level", "alert_count")


class SortField(str, Enum):
    filename = "filename"
    size = "size_bytes"
    count = "protocol_packet_count"
    path = "path"
    risk = "risk_score"


SORT_FIELD_TO_INDEX = {
    SortField.filename: SORT_INDEX_FILENAME,
    SortField.path: SORT_INDEX_PATH,
    SortField.size: SORT_INDEX_SIZE,
    SortField.count: SORT_INDEX_PACKET_COUNT,
    SortField.risk: RISK_INDEX_KEY,
}


def resolve_protocols(
    query: str,
    protocol_candidates: list[str],
    *,
    min_prefix_len: int = 3,
    max_contains_matches: int = 5,
    max_prefix_matches: int = 3,
    max_fuzzy: int = 10,
) -> list[str]:
    q_low = query.lower().strip()
    words = q_low.split()

    p_exact, p_contains, p_prefix = [], [], []

    for proto in protocol_candidates:
        c_low = proto.lower()

        for word in words:
            if c_low == word:
                if proto not in p_exact:
                    p_exact.append(proto)
                break

            if c_low.startswith(word) and len(word) >= min_prefix_len:
                if proto not in p_prefix and len(p_prefix) < max_prefix_matches:
                    p_prefix.append(proto)
                break

            if word in c_low:
                if proto not in p_contains and len(p_contains) < max_contains_matches:
                    p_contains.append(proto)
                break

    results = p_exact + p_prefix + p_contains
    return results[:max_fuzzy]


def parse_shorthand_query(raw: str):
    """Supports both \"!\" and \"not\" exclude tokens."""
    s = (raw or "").strip().lower()
    if not s:
        return [], []

    tokens = [t for t in re.compile(r"[,\s]+").split(s) if t]
    include, exclude = [], []

    for t in tokens:
        if t.startswith("!"):
            v = t[1:].strip()
            if v:
                exclude.append(v)
        else:
            include.append(t)

    def dedup(xs):
        out, seen = [], set()
        for x in xs:
            if not x or x in seen:
                continue
            seen.add(x)
            out.append(x)
        return out

    return dedup(include), dedup(exclude)


def is_pure_protocol_query(include_tokens: list[str], protocols: list[str]) -> bool:
    """Skip filename scan when query is an exact single-protocol lookup."""
    if len(include_tokens) != 1 or len(protocols) != 1:
        return False
    return include_tokens[0] == protocols[0].lower()


def _passes_risk_filter(
    meta: dict,
    *,
    min_risk: int,
    risk_level: str,
    has_alerts: bool,
) -> bool:
    score = int(meta.get("risk_score") or 0)
    level = meta.get("risk_level", "none")
    ac = int(meta.get("alert_count") or 0)
    if score < min_risk:
        return False
    if risk_level and not risk_level_meets(risk_level, level):
        return False
    if has_alerts and ac == 0:
        return False
    return True


async def paginate_with_risk_filter(
    redis,
    source_set: str,
    sort_index: str,
    tmp_filter_z: str,
    tmp_sorted: str,
    page: int,
    limit: int,
    descending: bool,
    *,
    min_risk: int,
    risk_level: str,
    has_alerts: bool,
) -> tuple[list[str], int]:
    """Walk sorted candidates and apply risk filters without full HGETALL per file."""
    count = await materialize_set_as_zset(redis, source_set, tmp_filter_z)
    if count == 0:
        return [], 0

    await asyncio.to_thread(
        redis.zinterstore,
        tmp_sorted,
        {sort_index: 1, tmp_filter_z: 0},
    )

    total_passing = 0
    page_ids: list[str] = []
    target_start = (page - 1) * limit
    target_end = target_start + limit
    offset = 0
    scan_batch = max(limit * 4, 40)

    zrange_fn = redis.zrevrange if descending else redis.zrange
    while True:
        chunk = await asyncio.to_thread(zrange_fn, tmp_sorted, offset, offset + scan_batch - 1)
        if not chunk:
            break
        offset += len(chunk)

        pipe = redis.pipeline()
        for h in chunk:
            pipe.hmget(f"{PCAP_FILE_KEY_PREFIX}:{h}", *RISK_META_FIELDS)
        rows = await asyncio.to_thread(pipe.execute)

        for h, values in zip(chunk, rows):
            score_raw, level_raw, alert_raw = values
            meta = {
                "risk_score": score_raw or 0,
                "risk_level": level_raw or "none",
                "alert_count": alert_raw or 0,
            }
            if not _passes_risk_filter(
                meta,
                min_risk=min_risk,
                risk_level=risk_level,
                has_alerts=has_alerts,
            ):
                continue
            if target_start <= total_passing < target_end:
                page_ids.append(h)
            total_passing += 1

    return page_ids, total_passing


async def search_by_filename(
    query: str,
    redis,
    *,
    scope_hashes: set[str] | None = None,
    exclude_hashes: set[str] | None = None,
) -> set[str]:
    """
    Find file hashes whose filename contains query (case-insensitive).

    scope_hashes: only scan these hashes (None = full corpus via sort index).
    exclude_hashes: skip hashes already matched via protocol index (OR semantics).
    """
    q = query.lower().strip()
    if not q:
        return set()

    if scope_hashes is not None:
        candidates = list(scope_hashes)
    else:
        candidates = await asyncio.to_thread(redis.zrange, SORT_INDEX_FILENAME, 0, -1)

    if exclude_hashes:
        candidates = [h for h in candidates if h not in exclude_hashes]

    if not candidates:
        return set()

    result: set[str] = set()
    for i in range(0, len(candidates), BATCH_SIZE):
        batch = candidates[i : i + BATCH_SIZE]
        pipe = redis.pipeline()
        for h in batch:
            pipe.hget(f"{PCAP_FILE_KEY_PREFIX}:{h}", "filename")
        filenames = await asyncio.to_thread(pipe.execute)
        for h, fname in zip(batch, filenames):
            if fname and q in fname.lower():
                result.add(h)
    return result


async def materialize_set_as_zset(redis, source_set: str, dest_zset: str) -> int:
    members = await asyncio.to_thread(redis.smembers, source_set)
    if not members:
        await asyncio.to_thread(redis.delete, dest_zset)
        return 0

    member_list = list(members)
    pipe = redis.pipeline()
    pipe.delete(dest_zset)
    for i in range(0, len(member_list), BATCH_SIZE):
        batch = member_list[i : i + BATCH_SIZE]
        pipe.zadd(dest_zset, {m: 0 for m in batch})
    await asyncio.to_thread(pipe.execute)
    return len(member_list)


async def filter_set_by_risk(
    redis,
    source_set: str,
    *,
    min_risk: int,
    risk_level: str,
    has_alerts: bool,
) -> set[str]:
    members = await asyncio.to_thread(redis.smembers, source_set)
    if not members:
        return set()

    member_list = list(members)
    filtered: set[str] = set()
    for i in range(0, len(member_list), BATCH_SIZE):
        batch = member_list[i : i + BATCH_SIZE]
        pipe = redis.pipeline()
        for h in batch:
            pipe.hmget(f"{PCAP_FILE_KEY_PREFIX}:{h}", *RISK_META_FIELDS)
        rows = await asyncio.to_thread(pipe.execute)
        for h, values in zip(batch, rows):
            score_raw, level_raw, alert_raw = values
            meta = {
                "risk_score": score_raw or 0,
                "risk_level": level_raw or "none",
                "alert_count": alert_raw or 0,
            }
            if _passes_risk_filter(
                meta,
                min_risk=min_risk,
                risk_level=risk_level,
                has_alerts=has_alerts,
            ):
                filtered.add(h)
    return filtered


async def paginate_sorted_ids(
    redis,
    source_set: str,
    sort_index: str,
    tmp_filter_z: str,
    tmp_sorted: str,
    page: int,
    limit: int,
    descending: bool,
) -> tuple[list[str], int]:
    count = await materialize_set_as_zset(redis, source_set, tmp_filter_z)
    if count == 0:
        return [], 0

    await asyncio.to_thread(
        redis.zinterstore,
        tmp_sorted,
        {sort_index: 1, tmp_filter_z: 0},
    )

    start = (page - 1) * limit
    end = start + limit - 1
    zrange_fn = redis.zrevrange if descending else redis.zrange
    ids = await asyncio.to_thread(zrange_fn, tmp_sorted, start, end)
    return list(ids), count


async def _expire_tmp_keys(redis, *keys: str) -> None:
    pipe = redis.pipeline()
    for key in keys:
        pipe.expire(key, TMP_KEY_TTL_SECONDS)
    await asyncio.to_thread(pipe.execute)


@router.get("/search", summary="Search for pcaps by protocol or filename")
async def fuzzy_search_pcaps(
    protocol: str = Query(
        "", description="The search query - matches protocol name AND filename"
    ),
    page: int = Query(1, ge=1),
    limit: int = Query(10, ge=1, le=100),
    sort_by: SortField = Query(SortField.filename),
    descending: bool = Query(False),
    min_risk: int = Query(0, ge=0, le=100, description="Minimum risk score (0-100)"),
    risk_level: str = Query("", description="Filter by risk level: low, medium, high, critical"),
    has_alerts: bool = Query(False, description="Only files with triggered alerts"),
    context: AppContext = Depends(get_app_context),
):
    redis = context.redis_client
    if not redis:
        raise HTTPException(503, "Redis unavailable")

    sort_index = SORT_FIELD_TO_INDEX.get(sort_by)
    protocol_resolved_set: set[str] = set()
    has_risk_filter = min_risk > 0 or bool(risk_level) or has_alerts

    base_tmp = f"{TMP_RESULT_PREFIX}:{uuid4().hex}"
    tmp_set = f"{base_tmp}:set"
    tmp_filter_z = f"{base_tmp}:filter_z"
    tmp_sorted = f"{base_tmp}:sorted"

    if not protocol.strip():
        all_ids = await asyncio.to_thread(redis.zrange, sort_index, 0, -1)
        if not all_ids:
            return {"total": 0, "page": page, "limit": limit, "data": []}

        pipe = redis.pipeline()
        for h in all_ids:
            pipe.sadd(tmp_set, h)
        await asyncio.to_thread(pipe.execute)
    else:
        all_protocols = await get_all_protocols(redis)
        protocol_candidates = list(all_protocols)

        include_tokens, exclude_tokens = parse_shorthand_query(protocol)
        protocol_for_resolve = " ".join(include_tokens).strip()
        if not protocol_for_resolve:
            protocol_for_resolve = " ".join(exclude_tokens).strip()

        protocols = resolve_protocols(protocol_for_resolve, protocol_candidates)
        protocol_resolved_set = {p.lower() for p in protocols}
        protocol_keys = [f"{PROTOCOCOL_INDEX_PREFIX}:{p.lower()}" for p in protocols]

        protocol_member_count = 0
        if protocol_keys:
            await asyncio.to_thread(redis.sunionstore, tmp_set, *protocol_keys)
            protocol_member_count = await asyncio.to_thread(redis.scard, tmp_set)

        skip_filename_scan = bool(protocol_keys) and is_pure_protocol_query(
            include_tokens, protocols
        )

        if not skip_filename_scan:
            exclude: set[str] | None = None
            if protocol_member_count > 0:
                exclude = await asyncio.to_thread(redis.smembers, tmp_set)

            filename_hashes = await search_by_filename(
                protocol,
                redis,
                exclude_hashes=exclude,
            )
            if filename_hashes:
                pipe = redis.pipeline()
                for h in filename_hashes:
                    pipe.sadd(tmp_set, h)
                await asyncio.to_thread(pipe.execute)

    total = await asyncio.to_thread(redis.scard, tmp_set)
    logger.info("Search for '%s' yielded %s results", protocol, total)

    if total == 0:
        return {"total": 0, "page": page, "limit": limit, "data": []}

    if has_risk_filter:
        if total <= RISK_FILTER_EAGER_THRESHOLD:
            filtered = await filter_set_by_risk(
                redis,
                tmp_set,
                min_risk=min_risk,
                risk_level=risk_level,
                has_alerts=has_alerts,
            )
            filter_tmp = f"{base_tmp}:filtered"
            if not filtered:
                await asyncio.to_thread(redis.delete, tmp_set, tmp_filter_z, tmp_sorted)
                return {"total": 0, "page": page, "limit": limit, "data": []}

            pipe = redis.pipeline()
            pipe.delete(filter_tmp)
            for h in filtered:
                pipe.sadd(filter_tmp, h)
            await asyncio.to_thread(pipe.execute)
            await asyncio.to_thread(redis.delete, tmp_set)
            await asyncio.to_thread(redis.rename, filter_tmp, tmp_set)
            total = len(filtered)

            ids, _ = await paginate_sorted_ids(
                redis,
                tmp_set,
                sort_index,
                tmp_filter_z,
                tmp_sorted,
                page,
                limit,
                descending,
            )
        else:
            ids, total = await paginate_with_risk_filter(
                redis,
                tmp_set,
                sort_index,
                tmp_filter_z,
                tmp_sorted,
                page,
                limit,
                descending,
                min_risk=min_risk,
                risk_level=risk_level,
                has_alerts=has_alerts,
            )
    else:
        ids, total = await paginate_sorted_ids(
            redis,
            tmp_set,
            sort_index,
            tmp_filter_z,
            tmp_sorted,
            page,
            limit,
            descending,
        )

    await _expire_tmp_keys(redis, tmp_set, tmp_filter_z, tmp_sorted)

    if not ids:
        return {"total": total, "page": page, "limit": limit, "data": []}

    pipe = redis.pipeline()
    for h in ids:
        pipe.hgetall(f"{PCAP_FILE_KEY_PREFIX}:{h}")
    rows = await asyncio.to_thread(pipe.execute)

    results = []
    pcap_config = context.config.pcap
    for row in rows:
        if not row:
            continue

        counts = json.loads(row.get("protocol_counts", "{}"))
        if protocol_resolved_set:
            matched = [p for p in counts.keys() if p.lower() in protocol_resolved_set]
        else:
            matched = list(counts.keys())

        row["matched_protocols"] = matched
        row["searched_protocol"] = protocol

        if pcap_config.prefix_str or pcap_config.root_directories:
            row["path"] = map_path_to_display(row.get("path", ""), pcap_config)

        results.append(row)

    return {
        "total": total,
        "page": page,
        "limit": limit,
        "data": results,
    }
