import asyncio
import json
import os

# Tyler code
from fastapi import APIRouter, Depends, HTTPException, Query

from services.context import get_app_context, AppContext
from services.config import get_pcap_root_directories
from services.logger import get_logger
from services.scan import PCAP_FILE_KEY_PREFIX
from services.analysis import (
    DEFAULT_BUCKET_SECONDS,
    _parse_pct,
    cluster_files,
    extract_ioc_sync,
    extract_timeline_sync,
    find_similar_files,
)

router = APIRouter(tags=["Analysis"])
logger = get_logger(__name__)

CLUSTERS_CACHE_KEY = "pcap:analysis:clusters"
CLUSTERS_CACHE_TTL = 300


async def _get_file_meta(context: AppContext, file_hash: str) -> dict:
    if not context.redis_client:
        raise HTTPException(status_code=503, detail="Redis unavailable")
    meta = await asyncio.to_thread(
        context.redis_client.hgetall,
        f"{PCAP_FILE_KEY_PREFIX}:{file_hash}",
    )
    if not meta:
        raise HTTPException(status_code=404, detail="File not found")
    return meta


async def _resolve_abs_path(context: AppContext, meta: dict) -> str:
    file_path = meta.get("path")
    if not file_path:
        raise HTTPException(status_code=404, detail="File path missing")
    abs_path = await asyncio.to_thread(os.path.abspath, file_path)
    allowed_abs_dirs = [
        await asyncio.to_thread(os.path.abspath, root)
        for root in get_pcap_root_directories(context.config.pcap)
    ]
    if not any(abs_path.startswith(d) for d in allowed_abs_dirs):
        raise HTTPException(status_code=403, detail="Access denied")
    if not await asyncio.to_thread(os.path.isfile, abs_path):
        raise HTTPException(status_code=404, detail="File not on disk")
    return abs_path


def _load_all_indexed_files(context: AppContext) -> list:
    redis = context.redis_client
    files = []
    for key in redis.scan_iter(f"{PCAP_FILE_KEY_PREFIX}:*"):
        meta = redis.hgetall(key)
        if not meta or not meta.get("protocol_percentages"):
            continue
        file_hash = key.split(":")[-1]
        protocols = [
            p.strip() for p in meta.get("protocols", "").split(",") if p.strip()
        ]
        files.append({
            "file_hash": file_hash,
            "filename": meta.get("filename"),
            "path": meta.get("path"),
            "protocols": protocols,
            "protocol_percentages": _parse_pct(meta.get("protocol_percentages")),
        })
    return files


@router.get("/pcaps/{file_hash}/ioc", summary="Extract IOCs (IP, port, domain) from a pcap")
async def get_file_ioc(
    file_hash: str,
    refresh: bool = Query(False),
    context: AppContext = Depends(get_app_context),
):
    meta = await _get_file_meta(context, file_hash)

    if not refresh and meta.get("ioc_data"):
        try:
            cached = json.loads(meta["ioc_data"])
            cached["cached"] = True
            return cached
        except json.JSONDecodeError:
            pass

    abs_path = await _resolve_abs_path(context, meta)
    total_packets = int(meta.get("total_packets") or 0)

    ioc = await asyncio.to_thread(
        extract_ioc_sync, abs_path, total_packets=total_packets or None
    )
    ioc["filename"] = meta.get("filename")
    ioc["file_hash"] = file_hash
    ioc["cached"] = False

    await asyncio.to_thread(
        context.redis_client.hset,
        f"{PCAP_FILE_KEY_PREFIX}:{file_hash}",
        mapping={"ioc_data": json.dumps(ioc)},
    )
    return ioc


@router.get("/pcaps/{file_hash}/timeline", summary="Packet timeline / flow visualization data")
async def get_file_timeline(
    file_hash: str,
    refresh: bool = Query(False),
    bucket_seconds: int = Query(DEFAULT_BUCKET_SECONDS, ge=1, le=60),
    context: AppContext = Depends(get_app_context),
):
    meta = await _get_file_meta(context, file_hash)

    cache_key = f"timeline_{bucket_seconds}"
    if not refresh and meta.get("timeline_data"):
        try:
            all_timelines = json.loads(meta["timeline_data"])
            if str(bucket_seconds) in all_timelines:
                cached = all_timelines[str(bucket_seconds)]
                cached["cached"] = True
                return cached
        except json.JSONDecodeError:
            pass

    abs_path = await _resolve_abs_path(context, meta)
    total_packets = int(meta.get("total_packets") or 0)

    timeline = await asyncio.to_thread(
        extract_timeline_sync,
        abs_path,
        bucket_seconds,
        total_packets=total_packets or None,
    )
    timeline["filename"] = meta.get("filename")
    timeline["file_hash"] = file_hash
    timeline["cached"] = False

    existing = {}
    if meta.get("timeline_data"):
        try:
            existing = json.loads(meta["timeline_data"])
        except json.JSONDecodeError:
            existing = {}
    existing[str(bucket_seconds)] = timeline

    await asyncio.to_thread(
        context.redis_client.hset,
        f"{PCAP_FILE_KEY_PREFIX}:{file_hash}",
        mapping={"timeline_data": json.dumps(existing)},
    )
    return timeline


@router.get("/pcaps/{file_hash}/similar", summary="Find files with similar protocol profiles")
async def get_similar_files(
    file_hash: str,
    limit: int = Query(10, ge=1, le=50),
    min_similarity: float = Query(50.0, ge=0, le=100),
    context: AppContext = Depends(get_app_context),
):
    meta = await _get_file_meta(context, file_hash)
    target_pct = _parse_pct(meta.get("protocol_percentages"))
    if not target_pct:
        return {"file_hash": file_hash, "filename": meta.get("filename"), "similar": []}

    all_files = await asyncio.to_thread(_load_all_indexed_files, context)
    similar = find_similar_files(
        file_hash, target_pct, all_files, limit=limit, min_similarity=min_similarity
    )
    return {
        "file_hash": file_hash,
        "filename": meta.get("filename"),
        "similar": similar,
    }


@router.get("/pcaps/clusters", summary="Cluster indexed files by protocol similarity")
async def get_clusters(
    threshold: float = Query(70.0, ge=0, le=100),
    refresh: bool = Query(False),
    context: AppContext = Depends(get_app_context),
):
    if not context.redis_client:
        raise HTTPException(status_code=503, detail="Redis unavailable")

    redis = context.redis_client
    cache_field = f"{threshold}"

    if not refresh:
        cached_raw = redis.hget(CLUSTERS_CACHE_KEY, cache_field)
        if cached_raw:
            try:
                return json.loads(cached_raw)
            except json.JSONDecodeError:
                pass

    all_files = await asyncio.to_thread(_load_all_indexed_files, context)
    clusters = cluster_files(all_files, threshold=threshold)

    result = {
        "threshold": threshold,
        "total_files": len(all_files),
        "cluster_count": len(clusters),
        "clusters": clusters,
    }

    pipe = redis.pipeline()
    pipe.hset(CLUSTERS_CACHE_KEY, cache_field, json.dumps(result))
    pipe.expire(CLUSTERS_CACHE_KEY, CLUSTERS_CACHE_TTL)
    await asyncio.to_thread(pipe.execute)

    return result


@router.post("/analysis/extract-all", summary="Extract IOC and timeline for all indexed files")
async def extract_all_analysis(context: AppContext = Depends(get_app_context)):
    if not context.redis_client:
        raise HTTPException(status_code=503, detail="Redis unavailable")

    redis = context.redis_client
    keys = list(redis.scan_iter(f"{PCAP_FILE_KEY_PREFIX}:*"))
    processed = 0
    errors = 0

    for key in keys:
        meta = redis.hgetall(key)
        if not meta:
            continue
        file_hash = key.split(":")[-1]
        file_path = meta.get("path")
        if not file_path:
            continue
        abs_path = os.path.abspath(file_path)
        if not os.path.isfile(abs_path):
            errors += 1
            continue

        total_packets = int(meta.get("total_packets") or 0)
        try:
            ioc = extract_ioc_sync(abs_path, total_packets=total_packets or None)
            timeline = extract_timeline_sync(abs_path, total_packets=total_packets or None)
            redis.hset(
                key,
                mapping={
                    "ioc_data": json.dumps(ioc),
                    "timeline_data": json.dumps({"1": timeline}),
                },
            )
            processed += 1
        except Exception as e:
            logger.error("Analysis failed for %s: %s", file_path, e)
            errors += 1

    redis.delete(CLUSTERS_CACHE_KEY)
    return {"processed": processed, "errors": errors, "total": len(keys)}
