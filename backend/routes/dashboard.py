from collections import defaultdict
import json
import time
from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from fastapi.params import Query
from enum import Enum
import asyncio
import os

from services.scan import PCAP_FILE_KEY_PREFIX, PATH_INDEX_PREFIX, get_scan_service
from services.logger import get_logger
from services.config import get_pcap_root_directories, get_pcap_display_paths, get_upload_directory
from services.context import get_app_context, AppContext
from services.alerts import ALERT_INDEX_KEY, get_all_rules, seed_default_rules
from services.dashboard_cache import (
    DASHBOARD_STATUS_KEY,
    DASHBOARD_SUMMARY_KEY,
    DASHBOARD_TTL_SECONDS,
    invalidate_dashboard_summary,
)

router = APIRouter(tags=["Dashboard"])
logger = get_logger(__name__)


def schedule_dashboard_rebuild(context: AppContext) -> None:
    """Invalidate stale analytics cache and rebuild in the background."""
    if not context.redis_client:
        return
    invalidate_dashboard_summary(context.redis_client)
    asyncio.create_task(build_dashboard_summary(context))


async def refresh_dashboard_summary(context: AppContext) -> None:
    """Invalidate and rebuild analytics cache before returning to the client."""
    if not context.redis_client:
        return
    invalidate_dashboard_summary(context.redis_client)
    await build_dashboard_summary(context)


class DASHBOARD_STATUS(Enum):
    IDLE = "idle"
    PROCESSING = "processing"
    ERROR = "error"

@router.get("/dashboard-summary", summary="Get dashboard summary statistics")
async def dashboard_summary(refresh: bool = Query(False), context: AppContext = Depends(get_app_context)):
    redis = context.redis_client
    if redis is None:
        logger.error("Redis client not initialized. Cannot fetch dashboard summary.")
        return JSONResponse(
            status_code=503,
            content={"error": "Service unavailable"},
        )

    summary = redis.get(DASHBOARD_SUMMARY_KEY)
    if summary and not refresh:
        return JSONResponse(
            status_code=200,
            content={
                "status": DASHBOARD_STATUS.IDLE.value,
                "data": json.loads(summary),
            },
        )

    status = redis.get(DASHBOARD_STATUS_KEY)

    if status == DASHBOARD_STATUS.PROCESSING.value:
        return JSONResponse(
            status_code=202,
            content={"status": DASHBOARD_STATUS.PROCESSING.value},
        )

    if status == DASHBOARD_STATUS.ERROR.value:
        return JSONResponse(
            status_code=500,
            content={"status": DASHBOARD_STATUS.ERROR.value},
        )

    asyncio.create_task(build_dashboard_summary(context))

    return JSONResponse(
        status_code=202,
        content={"status": DASHBOARD_STATUS.PROCESSING.value},
    )


SIZE_BUCKETS = [
    (0, 10 * 1024 * 1024, "<10MB"),
    (10 * 1024 * 1024, 100 * 1024 * 1024, "10-100MB"),
    (100 * 1024 * 1024, 1024 * 1024 * 1024, "100MB-1GB"),
    (1024 * 1024 * 1024, float("inf"), ">1GB"),
]

AGE_BUCKETS = [
    (0, 86400, "<24h"),
    (86400, 7 * 86400, "1-7d"),
    (7 * 86400, 30 * 86400, "7-30d"),
    (30 * 86400, float("inf"), ">30d"),
]

RATE_BUCKETS = [
    (0, 64, "<64B"),
    (64, 128, "64-128B"),
    (128, 256, "128-256B"),
    (256, 512, "256-512B"),
    (512, 1024, "512B-1KB"),
    (1024, 1500, "1KB-MTU"),
    (1500, float("inf"), ">MTU"),
]


def _bucketize(value: float, buckets):
    for low, high, label in buckets:
        if low <= value < high:
            return label
    return "unknown"


async def build_dashboard_summary(context: AppContext):
    redis = context.redis_client
    config = context.config
    now = time.time()
    root_dirs = get_pcap_root_directories(config.pcap)

    redis.set(DASHBOARD_STATUS_KEY, DASHBOARD_STATUS.PROCESSING.value)

    try:
        size_dist = defaultdict(int)
        packet_dist = defaultdict(int)
        protocol_presence = defaultdict(int)
        diversity_dist = defaultdict(int)
        age_dist = defaultdict(int)
        directory_dist = defaultdict(int)
        extension_dist = defaultdict(int)
        rate_dist = defaultdict(int)
        scan_mode_dist = defaultdict(int)
        capture_year_dist = defaultdict(int)
        total_files = 0
        combo_dist = defaultdict(int)
        diversity_combo_dist: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))

        cursor = 0

        while True:
            cursor, keys = redis.scan(
                cursor=cursor,
                match=f"{PCAP_FILE_KEY_PREFIX}:*",
                count=500,
            )

            for key in keys:
                data = redis.hgetall(key)
                if not data:
                    continue

                size_bytes = int(data.get("size_bytes", 0))
                packet_count = int(data.get("total_packets", 0))
                protocols_raw = data.get("protocols", "")
                clean_protocols = sorted(
                    [p.strip().lower() for p in protocols_raw.split(",") if p.strip()]
                )
                last_modified = float(data.get("last_modified", now))
                file_path = data.get("path", "")
                scan_mode = data.get("scan_mode", "full").lower()

                total_files += 1

                # Scan mode distribution
                scan_mode_dist[scan_mode] += 1

                # Size distribution
                size_bucket = _bucketize(size_bytes, SIZE_BUCKETS)
                size_dist[size_bucket] += 1

                # Packet count distribution
                if packet_count == 0:
                    packet_dist["0"] += 1
                elif packet_count < 1_000:
                    packet_dist["<1k"] += 1
                elif packet_count < 100_000:
                    packet_dist["1k-100k"] += 1
                else:
                    packet_dist[">100k"] += 1

                # Protocol presence
                for proto in clean_protocols:
                    protocol_presence[proto] += 1

                # Protocol diversity (count distinct protocols per file)
                diversity_key = str(len(clean_protocols))
                diversity_dist[diversity_key] += 1

                # Protocol combination distribution
                if clean_protocols:
                    combo_key = " + ".join(clean_protocols)
                    combo_dist[combo_key] += 1
                    diversity_combo_dist[diversity_key][combo_key] += 1

                # Capture year (from earliest packet time in PCAP, not file mtime)
                capture_year_raw = data.get("capture_year", "")
                if capture_year_raw not in (None, ""):
                    capture_year_dist[str(int(float(capture_year_raw)))] += 1
                else:
                    capture_year_dist["Unknown"] += 1

                # File age (filesystem modified — kept for reference)
                age_seconds = now - last_modified
                age_bucket = _bucketize(age_seconds, AGE_BUCKETS)
                age_dist[age_bucket] += 1

                # Size per packet distribution
                if packet_count >= 10:
                    rate = size_bytes / packet_count
                    rate_bucket = _bucketize(rate, RATE_BUCKETS)
                    rate_dist[rate_bucket] += 1
                elif packet_count > 0:
                    rate_dist["(small sample)"] += 1
                else:
                    rate_dist["(no packets)"] += 1

                # Directory distribution - strip matching PCAP root
                if file_path:
                    relative_path = file_path
                    matched_root = None
                    for root_dir in root_dirs:
                        root_norm = root_dir.rstrip(os.sep)
                        if file_path.startswith(root_norm):
                            matched_root = root_norm
                            relative_path = file_path[len(root_norm):].lstrip(os.sep)
                            break
                    if matched_root is None:
                        relative_path = file_path
                    dir_name = os.path.dirname(relative_path)
                    if not dir_name:
                        directory_dist["(root)"] += 1
                    else:
                        parts = dir_name.split(os.sep)
                        for i in range(len(parts)):
                            path_segment = os.sep.join(parts[:i+1])
                            directory_dist[path_segment] += 1

                    # File extension distribution
                    _, ext = os.path.splitext(file_path)
                    if ext:
                        extension_dist[ext.lower()] += 1
                    else:
                        extension_dist["(no extension)"] += 1

            if cursor == 0:
                break

        diversity_details = {}
        for div_key, combos in diversity_combo_dist.items():
            diversity_details[div_key] = [
                {"protocols": combo, "count": count}
                for combo, count in sorted(combos.items(), key=lambda x: x[1], reverse=True)
            ]

        capture_year_sorted = sorted(
            capture_year_dist.items(),
            key=lambda item: (item[0] == "Unknown", item[0]),
        )
        capture_year_table = [
            {
                "year": year,
                "count": count,
                "percentage": round((count / total_files) * 100, 1) if total_files else 0,
            }
            for year, count in capture_year_sorted
        ]

        summary = {
            "generated_at": now,
            "total_files": total_files,
            "scan_mode_distribution": dict(scan_mode_dist),
            "pcap_size_distribution": dict(size_dist),
            "packet_count_distribution": dict(packet_dist),
            "protocol_presence_distribution": dict(protocol_presence),
            "protocol_diversity_distribution": dict(
                sorted(diversity_dist.items(), key=lambda x: x[1], reverse=True)
            ),
            "protocol_diversity_details": diversity_details,
            "file_age_distribution": dict(age_dist),
            "capture_year_distribution": dict(capture_year_dist),
            "capture_year_table": capture_year_table,
            "directory_distribution": dict(directory_dist),
            "extension_distribution": dict(extension_dist),
            "size_per_packet_distribution": dict(rate_dist),
            "protocol_combination_distribution": dict(
                sorted(combo_dist.items(), key=lambda x: x[1], reverse=True)
            ),
        }

        redis.setex(
            DASHBOARD_SUMMARY_KEY,
            DASHBOARD_TTL_SECONDS,
            json.dumps(summary),
        )

        redis.set(DASHBOARD_STATUS_KEY, "idle")

    except Exception as e:
        logger.error(f"Error building dashboard summary: {e}")
        redis.set(DASHBOARD_STATUS_KEY, DASHBOARD_STATUS.ERROR.value, ex=30)
        raise


def _list_files_by_capture_year(redis, year: str) -> list[dict]:
    results = []
    cursor = 0

    while True:
        cursor, keys = redis.scan(
            cursor=cursor,
            match=f"{PCAP_FILE_KEY_PREFIX}:*",
            count=500,
        )

        for key in keys:
            data = redis.hgetall(key)
            if not data:
                continue

            capture_year_raw = data.get("capture_year", "")
            if capture_year_raw not in (None, ""):
                file_year = str(int(float(capture_year_raw)))
            else:
                file_year = "Unknown"

            if file_year != year:
                continue

            file_hash = key[len(f"{PCAP_FILE_KEY_PREFIX}:"):]
            results.append(
                {
                    "hash": file_hash,
                    "filename": data.get("filename", ""),
                    "path": data.get("path", ""),
                    "capture_start": data.get("capture_start", ""),
                    "size_bytes": int(data.get("size_bytes", 0) or 0),
                }
            )

        if cursor == 0:
            break

    results.sort(key=lambda item: item["filename"].lower())
    return results


@router.get("/dashboard/capture-year-files", summary="List PCAP files for a capture year")
async def capture_year_files(
    year: str = Query(..., description="Capture year (e.g. 2011) or Unknown"),
    context: AppContext = Depends(get_app_context),
):
    redis = context.redis_client
    if redis is None:
        logger.error("Redis client not initialized. Cannot list capture-year files.")
        return JSONResponse(
            status_code=503,
            content={"error": "Service unavailable"},
        )

    files = await asyncio.to_thread(_list_files_by_capture_year, redis, year)
    return {
        "year": year,
        "count": len(files),
        "files": files,
    }


def _collect_index_stats(redis) -> dict:
    total_files = 0
    total_size = 0
    cursor = 0

    while True:
        cursor, keys = redis.scan(
            cursor=cursor,
            match=f"{PCAP_FILE_KEY_PREFIX}:*",
            count=500,
        )
        for key in keys:
            data = redis.hgetall(key)
            if not data:
                continue
            total_files += 1
            total_size += int(data.get("size_bytes", 0) or 0)
        if cursor == 0:
            break

    path_entries = 0
    cursor = 0
    while True:
        cursor, keys = redis.scan(
            cursor=cursor,
            match=f"{PATH_INDEX_PREFIX}:*",
            count=500,
        )
        path_entries += len(keys)
        if cursor == 0:
            break

    return {
        "total_files": total_files,
        "total_size_bytes": total_size,
        "path_index_entries": path_entries,
    }


def _collect_alert_stats(redis) -> dict:
    seed_default_rules(redis)
    rules = get_all_rules(redis)
    enabled_rules = sum(1 for rule in rules if rule.get("enabled", True))

    hashes = list(redis.smembers(ALERT_INDEX_KEY))
    by_severity: dict[str, int] = defaultdict(int)
    recent = []

    for file_hash in hashes:
        meta = redis.hgetall(f"{PCAP_FILE_KEY_PREFIX}:{file_hash}")
        if not meta:
            continue
        alerts_raw = meta.get("alerts", "[]")
        try:
            alerts = json.loads(alerts_raw)
        except json.JSONDecodeError:
            alerts = []

        for alert in alerts:
            severity = alert.get("severity", "medium")
            by_severity[severity] += 1

        recent.append(
            {
                "file_hash": file_hash,
                "filename": meta.get("filename", ""),
                "path": meta.get("path", ""),
                "alert_count": len(alerts),
                "top_severity": _highest_severity(alerts),
            }
        )

    recent.sort(key=lambda item: (-item["alert_count"], item["filename"].lower()))

    return {
        "files_with_alerts": len(hashes),
        "alert_events": sum(by_severity.values()),
        "by_severity": dict(by_severity),
        "enabled_rules": enabled_rules,
        "total_rules": len(rules),
        "recent": recent[:12],
    }


def _highest_severity(alerts: list) -> str:
    order = {"high": 3, "medium": 2, "low": 1}
    best = "low"
    best_rank = 0
    for alert in alerts:
        severity = alert.get("severity", "medium")
        rank = order.get(severity, 0)
        if rank > best_rank:
            best_rank = rank
            best = severity
    return best


def _build_operations_snapshot(context: AppContext) -> dict:
    redis = context.redis_client
    config = context.config
    scan_service = get_scan_service()
    now = time.time()

    redis_ok = False
    if redis is not None:
        try:
            redis.ping()
            redis_ok = True
        except Exception:
            redis_ok = False

    index_stats = _collect_index_stats(redis) if redis_ok else {}
    alert_stats = _collect_alert_stats(redis) if redis_ok else {}

    pcap_config = config.pcap
    scan_cfg = {
        "scan_mode": pcap_config.scan_mode.value,
        "max_parallel_scans": pcap_config.max_parallel_scans,
        "config_version": pcap_config.quick_scan.config_version,
        "pebc": pcap_config.quick_scan.pebc if pcap_config.scan_mode.value == "quick" else None,
        "min_file_size": pcap_config.quick_scan.min_file_size if pcap_config.scan_mode.value == "quick" else None,
        "sample_segments": pcap_config.quick_scan.sample_segments,
    }

    dashboard_status = redis.get(DASHBOARD_STATUS_KEY) if redis_ok else None
    summary_raw = redis.get(DASHBOARD_SUMMARY_KEY) if redis_ok else None
    dashboard_generated_at = None
    if summary_raw:
        try:
            dashboard_generated_at = json.loads(summary_raw).get("generated_at")
        except json.JSONDecodeError:
            pass

    return {
        "generated_at": now,
        "health": {
            "api": "ok",
            "redis": "ok" if redis_ok else "error",
        },
        "scan": dict(scan_service.scan_status),
        "backfill": dict(scan_service.backfill_status),
        "rebuild_searchindex": dict(scan_service.rebuild_searchindex_status),
        "index": index_stats,
        "alerts": alert_stats,
        "scan_config": scan_cfg,
        "pcap_paths": {
            "root_directories": get_pcap_root_directories(pcap_config),
            "display_paths": get_pcap_display_paths(pcap_config),
            "upload_directory": get_upload_directory(pcap_config),
            "allowed_extensions": sorted(pcap_config.allowed_file_extensions),
        },
        "dashboard_cache": {
            "status": dashboard_status or "missing",
            "generated_at": dashboard_generated_at,
            "ttl_seconds": DASHBOARD_TTL_SECONDS,
        },
    }


@router.get("/dashboard/operations", summary="Operations dashboard snapshot")
async def operations_dashboard(context: AppContext = Depends(get_app_context)):
    if context.redis_client is None:
        return JSONResponse(
            status_code=503,
            content={"error": "Redis unavailable"},
        )

    snapshot = await asyncio.to_thread(_build_operations_snapshot, context)
    return snapshot
