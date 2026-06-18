from fastapi import APIRouter, Depends

from services.context import get_app_context, AppContext
import asyncio
from services.scan import (
    AUTOCOMPLETE_KEY,
    LEX_INDEX_FILENAME,
    SORT_INDEX_FILENAME,
    PCAP_FILE_KEY_PREFIX,
    get_all_protocols,
)
from services.logger import get_logger
from fastapi import Query, HTTPException
from utils.protocols_utils import rank_protocols

router = APIRouter(tags=["Protocols"])
logger = get_logger(__name__)


@router.get("/protocols/suggest", summary="Get protocol name suggestions for autocomplete")
async def suggest_protocols(
    q: str = Query(..., min_length=1, description="The prefix text to search for (e.g., 'ht' or 'tc')"),
    limit: int = Query(10, ge=1, le=50, description="Maximum number of suggestions to return"),
    context: AppContext = Depends(get_app_context),
):
    if not context.redis_client:
        raise HTTPException(status_code=503, detail="Service unavailable: Redis connection failed.")

    redis = context.redis_client

    try:
        q_low = q.lower()
        start_range = f"[{q_low}"
        end_range = f"[{q_low}\xff"

        prefix_matches = await asyncio.to_thread(
            redis.zrangebylex,
            AUTOCOMPLETE_KEY,
            start_range,
            end_range,
            start=0,
            num=limit,
        )
        prefix_matches = [s for s in prefix_matches]

        all_protocols = await get_all_protocols(redis)
        fuzzy_matches = rank_protocols(q, list(all_protocols), max_dist=0.5)

        prefix_set = {p.lower() for p in prefix_matches}
        unique_fuzzy = [p for p in fuzzy_matches if p.lower() not in prefix_set]
        protocol_suggestions = (prefix_matches + unique_fuzzy)[:limit]

        lex_filenames = await asyncio.to_thread(
            redis.zrangebylex,
            LEX_INDEX_FILENAME,
            start_range,
            end_range,
            start=0,
            num=limit,
        )

        filename_suggestions: list[str] = []
        seen_filenames: set[str] = set()
        for norm_name in lex_filenames:
            if not norm_name or norm_name in seen_filenames:
                continue
            seen_filenames.add(norm_name)
            filename_suggestions.append(norm_name)

        if len(filename_suggestions) < limit and q_low:
            sample_ids = await asyncio.to_thread(redis.zrange, SORT_INDEX_FILENAME, 0, 49)
            if sample_ids:
                pipe = redis.pipeline()
                for h in sample_ids:
                    pipe.hget(f"{PCAP_FILE_KEY_PREFIX}:{h}", "filename")
                names = await asyncio.to_thread(pipe.execute)
                for fname in names:
                    if not fname or fname in seen_filenames:
                        continue
                    if q_low in fname.lower():
                        seen_filenames.add(fname)
                        filename_suggestions.append(fname)
                        if len(filename_suggestions) >= limit:
                            break

        seen_all: set[str] = set()
        merged: list[str] = []
        for item in protocol_suggestions + filename_suggestions:
            if item not in seen_all:
                seen_all.add(item)
                merged.append(item)

        return merged[:limit]

    except Exception as e:
        logger.error(f"Error during protocol suggestion: {e}")
        raise HTTPException(status_code=500, detail="An error occurred while fetching suggestions.")
