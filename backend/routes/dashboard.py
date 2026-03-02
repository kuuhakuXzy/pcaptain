from collections import defaultdict
import json
import time
from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from fastapi.params import Query
from enum import Enum
import asyncio
import os

from services.scan import PCAP_FILE_KEY_PREFIX
from services.logger import get_logger
from services.context import get_app_context, AppContext

router = APIRouter(tags=["Dashboard"])
logger = get_logger(__name__)

DASHBOARD_STATUS_KEY = "dashboard:status"
DASHBOARD_SUMMARY_KEY = "dashboard:summary"
DASHBOARD_TTL_SECONDS = 300  # 5 minutes

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
    root_dir = config.pcap.root_directory.rstrip(os.sep)

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
        total_files = 0

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
                protocols = data.get("protocols", "").split(',')
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
                for proto in protocols:
                    protocol_presence[proto] += 1

                # Protocol diversity
                diversity_dist[str(len(protocols))] += 1

                # File age
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

                # Directory distribution - strip root directory
                if file_path:
                    relative_path = file_path
                    if file_path.startswith(root_dir):
                        relative_path = file_path[len(root_dir):].lstrip(os.sep)
                    
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

        summary = {
            "generated_at": now,
            "total_files": total_files,
            "scan_mode_distribution": dict(scan_mode_dist),
            "pcap_size_distribution": dict(size_dist),
            "packet_count_distribution": dict(packet_dist),
            "protocol_presence_distribution": dict(protocol_presence),
            "protocol_diversity_distribution": dict(diversity_dist),
            "file_age_distribution": dict(age_dist),
            "directory_distribution": dict(directory_dist),
            "extension_distribution": dict(extension_dist),
            "size_per_packet_distribution": dict(rate_dist),
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
