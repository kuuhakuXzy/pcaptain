from fastapi import APIRouter, HTTPException, Query
from typing import List
import asyncio
import json
import logging
from enum import Enum

from container import container
from services.redis_service import RedisService
from config.config_service import ConfigService

router = APIRouter()
redis_service = container.get(RedisService)
config_service = container.get(ConfigService)
logger = logging.getLogger(__name__)
AUTOCOMPLETE_KEY = "pcap:protocols:autocomplete"


class SortField(str, Enum):
    filename = "filename"
    size = "size_bytes"
    count = "protocol_packet_count"
    path = "path"


@router.get("/search")
async def search_pcaps(
    protocol: str = Query(
        ..., description="The protocol name to search for, e.g., sip"
    ),
    page: int = Query(1, ge=1, description="Page number"),
    limit: int = Query(10, ge=1, le=100, description="Items per page"),
    sort_by: SortField = Query(SortField.filename, description="Field to sort by"),
    descending: bool = Query(False, description="Sort in descending order"),
):
    redis_client = redis_service.client
    if not redis_client:
        raise HTTPException(
            status_code=503, detail="Service unavailable: Redis connection failed."
        )

    index_key = f"pcap:index:protocol:{protocol.lower()}"

    try:
        matching_hashes = await asyncio.to_thread(redis_client.smembers, index_key)
        if not matching_hashes:
            return {
                "results": [],
                "total_items": 0,
                "page": page,
                "limit": limit,
                "total_pages": 0,
            }

        pipe = redis_client.pipeline()
        for file_hash in matching_hashes:
            pipe.hgetall(f"pcap:file:{file_hash}")
        raw_results = await asyncio.to_thread(pipe.execute)

        results = []
        settings = config_service.init()

        for pcap_data in raw_results:
            if pcap_data:
                counts_str = pcap_data.pop("protocol_counts", None)
                packet_count = 0
                if counts_str:
                    try:
                        counts_dict = json.loads(counts_str)
                        packet_count = counts_dict.get(protocol, 0)
                    except json.JSONDecodeError:
                        logger.warning(f"Could not parse protocol_counts for pcap hash")

                # Replace internal path with host path
                internal_path = pcap_data.get("path", "")
                if (
                    internal_path
                    and settings.PCAP_DIRECTORY
                    and settings.HOST_PCAP_DIRECTORY
                ):
                    host_path = internal_path.replace(
                        settings.PCAP_DIRECTORY, settings.HOST_PCAP_DIRECTORY
                    )
                    pcap_data["path"] = host_path

                pcap_data["searched_protocol"] = protocol
                pcap_data["protocol_packet_count"] = packet_count
                results.append(pcap_data)

        # SORTING LOGIC
        def get_sort_key(item):
            value = item.get(sort_by.value, "")
            if sort_by in [SortField.size, SortField.count]:
                return int(value) if str(value).isdigit() else 0
            return str(value).lower()

        results.sort(key=get_sort_key, reverse=descending)

        # PAGINATION LOGIC
        total_items = len(results)
        start_index = (page - 1) * limit
        end_index = start_index + limit
        paginated_results = results[start_index:end_index]

        return {
            "results": paginated_results,
            "total_items": total_items,
            "page": page,
            "limit": limit,
            "total_pages": (total_items + limit - 1) // limit,
        }
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"An error occurred while querying Redis: {e}"
        )


@router.get(
    "/protocols/suggest", summary="Get protocol name suggestions for autocomplete"
)
async def suggest_protocols(
    q: str = Query(
        ...,
        min_length=1,
        description="The prefix text to search for (e.g., 'ht' or 'tc')",
    )
):
    redis_client = redis_service.client
    if not redis_client:
        raise HTTPException(
            status_code=503, detail="Service unavailable: Redis connection failed."
        )

    try:
        start_range = f"[{q}"
        end_range = f"[{q}\xff"

        suggestions = await asyncio.to_thread(
            redis_client.zrangebylex,
            AUTOCOMPLETE_KEY,
            start_range,
            end_range,
            start=0,
            num=10,
        )
        return suggestions
    except Exception as e:
        logger.error(f"Error during protocol suggestion: {e}")
        raise HTTPException(
            status_code=500, detail="An error occurred while fetching suggestions."
        )
