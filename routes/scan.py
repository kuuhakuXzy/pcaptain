from fastapi import APIRouter
from services.context import get_app_context, AppContext
from typing import Optional, List
from fastapi import Depends, Query, Request, HTTPException
from fastapi.responses import JSONResponse
import asyncio

from services.scan import ScanState, get_scan_service
from services.logger import get_logger

router = APIRouter(tags=["Scan"])

logger = get_logger(__name__)


@router.post("/reindex", summary="Rescan pcap directories and rebuild the index")
async def reindex_pcaps(
    request: Request,
    exclude: Optional[List[str]] = Query(None),
    context: AppContext = Depends(get_app_context),
):

    scan_service = get_scan_service()
    if scan_service.scan_status["state"] == ScanState.RUNNING:
        return JSONResponse(
            content={"status": "busy", "message": "A scan is already running."},
            status_code=409,
        )
    scan_service.scan_cancel_event.clear()

    base_url = context.FULL_BASE_URL or str(request.base_url).rstrip("/")
    loop = asyncio.get_event_loop()
    loop.run_in_executor(
        context.thread_executor,
        lambda: scan_service.scan_wrapper(
            exclude_files=exclude, base_url=base_url
        ),
    )
    return JSONResponse(content={"status": "started"})


@router.get("/scan-status")
async def scan_status_endpoint():
    scan_service = get_scan_service()
    return scan_service.scan_status

@router.post("/scan-cancel", summary="Cancel the currently running scan")
async def cancel_scan():
    scan_service = get_scan_service()
    if scan_service.scan_status["state"] != ScanState.RUNNING:
        return JSONResponse(
            content={"status": "no_scan", "message": "No scan is currently running."},
            status_code=400,
        )

    scan_service.scan_cancel_event.set()
    logger.info("Scan cancellation requested by user")
    return JSONResponse(
        content={
            "status": "cancelling",
            "message": "Scan cancellation has been triggered.",
        }
    )


@router.post(
    "/reindex/{folder_name}", summary="Reindex a specific folder under PCAP directories"
)
async def reindex_specific_folder(
    folder_name: str,
    request: Request,
    exclude: Optional[List[str]] = Query(None),
):
    scan_service = get_scan_service()
    base_url = str(request.base_url).rstrip("/")
    result = await scan_service.scan_and_index(
        exclude_files=exclude,
        base_url=base_url,
        target_folder=folder_name,
    )
    if "error" in result:
        raise HTTPException(status_code=500, detail=result["error"])
    return JSONResponse(content=result)
