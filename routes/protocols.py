from fastapi import APIRouter, Depends
from typing import List

from services.context import get_app_context, AppContext
import asyncio
from services.scan import AUTOCOMPLETE_KEY, get_all_protocols
from services.logger import get_logger
from fastapi import Query, HTTPException
from utils.protocols_utils import rank_protocols

router = APIRouter(tags=["Protocols"])
logger = get_logger(__name__)


@router.get("/excluded-protocols", summary="Get list of excluded protocols")
async def excluded_protocols(context: AppContext = Depends(get_app_context)):
    excluded = context.get_dynamic_excluded_protocols()
    return list(excluded)


@router.post("/excluded-protocols", summary="Set excluded protocols")
async def set_excluded_protocols(
    protocols: List[str], context: AppContext = Depends(get_app_context)
):
    cleaned = " ".join(p.strip().lower() for p in protocols if p.strip())
    await asyncio.to_thread(
        context.redis_client.set, "pcap:config:excluded_protocols", cleaned
    )
    context.dynamic_excluded_protocols = set(protocols)
    return {"status": "success", "excluded_protocols": protocols}


@router.get("/protocols/suggest", summary="Get protocol name suggestions for autocomplete")
async def suggest_protocols(
    q: str = Query(..., min_length=1, description="The prefix text to search for (e.g., 'ht' or 'tc')"),
    limit: int = Query(10, ge=1, le=50, description="Maximum number of suggestions to return"),
    context: AppContext = Depends(get_app_context),
):
    if not context.redis_client:
        raise HTTPException(status_code=503, detail="Service unavailable: Redis connection failed.")

    try:
        excluded = context.get_excluded_protocols()

        # Prefix matching
        start_range = f"[{q}"
        end_range = f"[{q}\xff"

        prefix_matches = await asyncio.to_thread(
            context.redis_client.zrangebylex,
            AUTOCOMPLETE_KEY,
            start_range,
            end_range,
            start=0,
            num=limit,
        )
        prefix_matches = [s for s in prefix_matches if s.lower() not in excluded]

        # Fuzzy matching
        all_protocols = await get_all_protocols(context.redis_client)
        candidates = [p for p in all_protocols if p.lower() not in excluded]

        fuzzy_matches = rank_protocols(q, candidates, max_dist=0.5)
        
        prefix_set = {p.lower() for p in prefix_matches}
        unique_fuzzy = [p for p in fuzzy_matches if p.lower() not in prefix_set]
        
        all_matches = prefix_matches + unique_fuzzy
        
        return all_matches[:limit]
    except Exception as e:
        logger.error(f"Error during protocol suggestion: {e}")
        raise HTTPException(status_code=500, detail="An error occurred while fetching suggestions.")