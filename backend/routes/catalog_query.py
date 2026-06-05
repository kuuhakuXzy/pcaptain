from fastapi import APIRouter, Depends, HTTPException

from models.catalog import CatalogQueryRequest
from services.catalog_query import execute_catalog_query
from services.context import AppContext, get_app_context

router = APIRouter(tags=["Catalog Query"])


@router.post("/query", summary="Advanced catalog search with filters")
async def catalog_query(
    body: CatalogQueryRequest,
    context: AppContext = Depends(get_app_context),
):
    redis = context.redis_client
    if not redis:
        raise HTTPException(503, "Redis unavailable")

    size_min = size_max = None
    if body.size_bytes:
        size_min = body.size_bytes.get("min")
        size_max = body.size_bytes.get("max")

    modified_after = modified_before = None
    if body.modified:
        modified_after = body.modified.get("after")
        modified_before = body.modified.get("before")

    capture_after = capture_before = None
    if body.capture:
        capture_after = body.capture.get("after")
        capture_before = body.capture.get("before")

    include = body.protocols.include if body.protocols else []
    exclude = body.protocols.exclude if body.protocols else []

    return await execute_catalog_query(
        redis,
        context,
        protocol_query=body.protocol_query,
        protocols_include=include,
        protocols_exclude=exclude,
        filename_contains=body.filename_contains,
        path_prefix=body.path_prefix,
        size_min=size_min,
        size_max=size_max,
        modified_after=modified_after,
        modified_before=modified_before,
        capture_after=capture_after,
        capture_before=capture_before,
        ip=body.ip,
        port=body.port,
        page=body.page,
        limit=body.limit,
        sort_by=body.sort_by,
        descending=body.descending,
    )
