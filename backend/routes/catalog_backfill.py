import asyncio

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse

from services.capture_info import get_capture_time_range_sync
from services.catalog_constants import PCAP_FILE_KEY_PREFIX, SORT_INDEX_CAPTURE_START
from services.context import AppContext, get_app_context
from services.endpoint_extract import extract_endpoints_sync
from services.endpoint_index import add_endpoint_indexes, remove_endpoint_indexes
from services.logger import get_logger

router = APIRouter(tags=["Catalog Backfill"])
logger = get_logger(__name__)


@router.post(
    "/backfill/endpoints",
    summary="Backfill IP/port indexes and capture times for indexed files",
)
async def backfill_endpoints(
    context: AppContext = Depends(get_app_context),
):
    redis = context.redis_client
    if not redis:
        raise HTTPException(503, "Redis unavailable")

    catalog = context.config.catalog
    keys = await asyncio.to_thread(redis.keys, f"{PCAP_FILE_KEY_PREFIX}:*")
    updated = 0
    skipped = 0

    for key in keys:
        data = await asyncio.to_thread(redis.hgetall, key)
        if not data:
            continue
        file_path = data.get("path")
        if not file_path:
            skipped += 1
            continue

        file_hash = key.split(":")[-1]
        remove_endpoint_indexes(redis, file_hash, data)

        ips: set[str] = set()
        ports: set[str] = set()
        if catalog.endpoint_index_enabled:
            extracted = await asyncio.to_thread(
                extract_endpoints_sync,
                file_path,
                max_packets=catalog.endpoint_max_packets,
            )
            ips = extracted.get("ips", set())
            ports = extracted.get("ports", set())

        capture_start, capture_end = await asyncio.to_thread(
            get_capture_time_range_sync, file_path
        )

        from services.endpoint_index import endpoints_summary_json

        mapping = {
            "indexed_ips": ",".join(sorted(ips)),
            "indexed_ports": ",".join(sorted(ports)),
            "endpoints_summary": endpoints_summary_json(ips, ports),
        }
        if capture_start is not None:
            mapping["capture_start"] = capture_start
        if capture_end is not None:
            mapping["capture_end"] = capture_end

        pipe = redis.pipeline()
        pipe.hset(key, mapping=mapping)
        add_endpoint_indexes(redis, pipe, file_hash, ips, ports)
        if capture_start is not None:
            pipe.zadd(SORT_INDEX_CAPTURE_START, {file_hash: capture_start})
        await asyncio.to_thread(pipe.execute)
        updated += 1

    return JSONResponse(
        content={
            "status": "completed",
            "updated": updated,
            "skipped": skipped,
            "total": len(keys),
        }
    )
