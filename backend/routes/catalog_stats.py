import asyncio
import json

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import JSONResponse

from services.catalog_constants import STATS_SUMMARY_KEY
from services.catalog_stats import build_stats_summary, get_co_occurrence_for_protocol
from services.context import AppContext, get_app_context

router = APIRouter(tags=["Catalog Stats"])


@router.get("/stats/overview", summary="Catalog overview statistics")
async def stats_overview(
    refresh: bool = Query(False),
    context: AppContext = Depends(get_app_context),
):
    redis = context.redis_client
    if not redis:
        raise HTTPException(503, "Redis unavailable")

    if not refresh:
        cached = await asyncio.to_thread(redis.get, STATS_SUMMARY_KEY)
        if cached:
            return JSONResponse(content=json.loads(cached))

    summary = await build_stats_summary(
        redis,
        context.config.pcap.root_directory,
        ttl_seconds=context.config.catalog.stats_cache_ttl_seconds,
    )
    return JSONResponse(content=summary)


@router.get("/stats/protocols", summary="Top protocols by file count")
async def stats_protocols(
    top: int = Query(20, ge=1, le=100),
    refresh: bool = Query(False),
    context: AppContext = Depends(get_app_context),
):
    redis = context.redis_client
    if not redis:
        raise HTTPException(503, "Redis unavailable")

    if refresh:
        summary = await build_stats_summary(
            redis,
            context.config.pcap.root_directory,
            ttl_seconds=context.config.catalog.stats_cache_ttl_seconds,
        )
    else:
        cached = await asyncio.to_thread(redis.get, STATS_SUMMARY_KEY)
        if cached:
            summary = json.loads(cached)
        else:
            summary = await build_stats_summary(
                redis,
                context.config.pcap.root_directory,
                ttl_seconds=context.config.catalog.stats_cache_ttl_seconds,
            )

    top_protocols = summary.get("top_protocols", {})
    items = sorted(top_protocols.items(), key=lambda x: x[1], reverse=True)[:top]
    return {"protocols": dict(items), "total_protocols": summary.get("protocol_count", 0)}


@router.get("/stats/directories", summary="File count by top-level directory")
async def stats_directories(
    context: AppContext = Depends(get_app_context),
):
    redis = context.redis_client
    if not redis:
        raise HTTPException(503, "Redis unavailable")

    cached = await asyncio.to_thread(redis.get, STATS_SUMMARY_KEY)
    if not cached:
        summary = await build_stats_summary(
            redis,
            context.config.pcap.root_directory,
            ttl_seconds=context.config.catalog.stats_cache_ttl_seconds,
        )
    else:
        summary = json.loads(cached)

    return {"directories": summary.get("directory_distribution", {})}


@router.get(
    "/stats/co-occurrence",
    summary="Protocols that often appear with a given protocol",
)
async def stats_co_occurrence(
    protocol: str = Query(..., min_length=1),
    limit: int = Query(20, ge=1, le=50),
    context: AppContext = Depends(get_app_context),
):
    redis = context.redis_client
    if not redis:
        raise HTTPException(503, "Redis unavailable")

    return await get_co_occurrence_for_protocol(redis, protocol, limit=limit)
