from fastapi import APIRouter, Depends
from typing import List

from services.context import get_app_context, AppContext
import asyncio
from services.scan import AUTOCOMPLETE_KEY
from services.logger import get_logger
from fastapi import Query, HTTPException

router = APIRouter(tags=["Protocols"])
logger = get_logger(__name__)


@router.get("/excluded-protocols", summary="Get list of excluded protocols")
async def excluded_protocols(context: AppContext = Depends(get_app_context)):
    excluded = context.get_dynamic_excluded_protocols()
    return list(excluded)

@router.post("/excluded-protocols", summary="Set excluded protocols")
async def set_excluded_protocols(protocols: List[str], context: AppContext = Depends(get_app_context)):
    cleaned = " ".join(p.strip().lower() for p in protocols if p.strip())
    await asyncio.to_thread(
        context.redis_client.set,
        "pcap:config:excluded_protocols",
        cleaned
    )
    context.dynamic_excluded_protocols = set(protocols)
    return {"status": "success", "excluded_protocols": protocols}


@router.get("/protocols/suggest", summary="Get protocol name suggestions for autocomplete")
async def suggest_protocols(
    q: str = Query(..., min_length=1, description="The prefix text to search for (e.g., 'ht' or 'tc')"),
    context: AppContext = Depends(get_app_context),
):
    if not context.redis_client:
        raise HTTPException(status_code=503, detail="Service unavailable: Redis connection failed.")

    try:
        excluded = context.get_excluded_protocols()
        start_range = f"[{q}"
        end_range = f"[{q}\xff"

        suggestions = await asyncio.to_thread(
            context.redis_client.zrangebylex, AUTOCOMPLETE_KEY, start_range, end_range, start=0, num=10
        )
        return [s for s in suggestions if s.lower() not in excluded]
    except Exception as e:
        logger.error(f"Error during protocol suggestion: {e}")
        raise HTTPException(status_code=500, detail="An error occurred while fetching suggestions.")