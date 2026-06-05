import asyncio
import json

from fastapi import APIRouter, Depends, HTTPException, Query

from services.catalog_constants import IP_INDEX_PREFIX, PCAP_FILE_KEY_PREFIX, PORT_INDEX_PREFIX
from services.context import AppContext, get_app_context

router = APIRouter(tags=["Catalog Endpoints"])


@router.get(
    "/search/endpoints",
    summary="Search pcaps by IP address and/or port",
)
async def search_by_endpoints(
    ip: str | None = Query(None),
    port: int | None = Query(None, ge=1, le=65535),
    page: int = Query(1, ge=1),
    limit: int = Query(10, ge=1, le=100),
    context: AppContext = Depends(get_app_context),
):
    if not ip and port is None:
        raise HTTPException(400, "Provide at least one of: ip, port")

    redis = context.redis_client
    if not redis:
        raise HTTPException(503, "Redis unavailable")

    if ip and port is not None:
        ip_hashes = await asyncio.to_thread(redis.smembers, f"{IP_INDEX_PREFIX}:{ip}")
        port_hashes = await asyncio.to_thread(
            redis.smembers, f"{PORT_INDEX_PREFIX}:{port}"
        )
        ids = list(ip_hashes & port_hashes)
    elif ip:
        ids = list(await asyncio.to_thread(redis.smembers, f"{IP_INDEX_PREFIX}:{ip}"))
    else:
        ids = list(
            await asyncio.to_thread(
                redis.smembers, f"{PORT_INDEX_PREFIX}:{port}"
            )
        )

    total = len(ids)
    start = (page - 1) * limit
    page_ids = ids[start : start + limit]

    pipe = redis.pipeline()
    for h in page_ids:
        pipe.hgetall(f"{PCAP_FILE_KEY_PREFIX}:{h}")
    rows = await asyncio.to_thread(pipe.execute)

    prefix_str = context.config.pcap.prefix_str
    internal_root = context.config.pcap.root_directory
    data = []
    for row in rows:
        if not row:
            continue
        if prefix_str and row.get("path"):
            row["path"] = row["path"].replace(internal_root, prefix_str, 1)
        if row.get("endpoints_summary"):
            try:
                row["endpoints"] = json.loads(row["endpoints_summary"])
            except json.JSONDecodeError:
                row["endpoints"] = {}
        data.append(row)

    return {"total": total, "page": page, "limit": limit, "data": data}
