from fastapi import APIRouter
from pydantic import BaseModel, Field
from services.config import (
    ScanMode,
    get_pcap_display_paths,
    get_pcap_root_directories,
    get_upload_directory,
    list_pcap_scan_folders,
    update_scan_mode,
)
from services.context import get_app_context, AppContext
from typing import Optional, List
from fastapi import Depends, Query, Request, HTTPException
from fastapi.responses import JSONResponse
import asyncio

from services.scan import BackfillState, RebuildSearchIndexState, ScanState, get_scan_service
from services.logger import get_logger

router = APIRouter(tags=["Scan"])

logger = get_logger(__name__)


class ScanConfigUpdate(BaseModel):
    scan_mode: ScanMode = Field(..., description="Global scan mode: full, quick, or fast")


def _scan_config_payload(pcap_config) -> dict:
    return {
        "scan_mode": pcap_config.scan_mode.value,
        "max_parallel_scans": pcap_config.max_parallel_scans,
        "pebc": pcap_config.quick_scan.pebc if pcap_config.scan_mode == ScanMode.QUICK else None,
        "min_file_size": pcap_config.quick_scan.min_file_size if pcap_config.scan_mode == ScanMode.QUICK else None,
        "config_version": pcap_config.quick_scan.config_version,
        "sample_segments": pcap_config.quick_scan.sample_segments,
    }


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

    loop = asyncio.get_event_loop()
    loop.run_in_executor(
        context.thread_executor,
        lambda: scan_service.scan_wrapper(
            exclude_files=exclude
        ),
    )
    return JSONResponse(content={"status": "started"})


@router.get("/scan-status")
async def scan_status_endpoint():
    scan_service = get_scan_service()
    return scan_service.scan_status


@router.post("/backfill/total-packets", summary="Backfill total packet counts for existing pcaps")
async def backfill_total_packets_endpoint(
    context: AppContext = Depends(get_app_context),
):
    scan_service = get_scan_service()
    if scan_service.backfill_status.get("state") == BackfillState.RUNNING:
        return JSONResponse(
            content={"status": "busy", "message": "A backfill is already running."},
            status_code=409,
        )

    loop = asyncio.get_event_loop()
    loop.run_in_executor(
        context.thread_executor,
        lambda: scan_service.backfill_wrapper(),
    )
    return JSONResponse(content={"status": "started"})


@router.get("/backfill-status")
async def backfill_status_endpoint():
    scan_service = get_scan_service()
    return scan_service.backfill_status


@router.post(
    "/backfill/rebuild-searchindex",
    summary="Rebuild all sort indexes from existing Redis data",
)
async def rebuild_searchindex_endpoint(
    context: AppContext = Depends(get_app_context),
):
    scan_service = get_scan_service()
    if scan_service.rebuild_searchindex_status.get("state") == RebuildSearchIndexState.RUNNING:
        return JSONResponse(
            content={
                "status": "busy",
                "message": "A rebuild-searchindex job is already running.",
            },
            status_code=409,
        )

    loop = asyncio.get_event_loop()
    loop.run_in_executor(
        context.thread_executor,
        lambda: scan_service.rebuild_searchindex_wrapper(),
    )
    return JSONResponse(content={"status": "started"})


@router.get("/backfill/rebuild-searchindex-status")
async def rebuild_searchindex_status_endpoint():
    scan_service = get_scan_service()
    return scan_service.rebuild_searchindex_status

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

@router.get("/pcap-config", summary="Get PCAP mount directory configuration")
async def pcap_config(*, context: AppContext = Depends(get_app_context)):
    pcap_config = context.config.pcap
    return {
        "root_directory": pcap_config.root_directory,
        "root_directories": get_pcap_root_directories(pcap_config),
        "display_paths": get_pcap_display_paths(pcap_config),
        "prefix_str": pcap_config.prefix_str,
        "allowed_extensions": sorted(pcap_config.allowed_file_extensions),
        "upload_directory": get_upload_directory(pcap_config),
        "note": "Change mount paths via .env and docker compose, then restart containers.",
    }


@router.get("/pcap-folders", summary="List scannable subfolders under PCAP roots")
async def pcap_folders(*, context: AppContext = Depends(get_app_context)):
    return {
        "folders": list_pcap_scan_folders(context.config.pcap),
    }


@router.get("/scan-config", summary="Get current scan configuration")
async def scan_config(*, context: AppContext = Depends(get_app_context)):
    """Expose current runtime scan configuration."""
    return _scan_config_payload(context.config.pcap)


@router.patch("/scan-config", summary="Update global scan mode")
async def update_scan_config(
    body: ScanConfigUpdate,
    reindex: bool = Query(False, description="Start reindex after updating scan mode"),
    context: AppContext = Depends(get_app_context),
):
    scan_service = get_scan_service()
    if scan_service.scan_status["state"] == ScanState.RUNNING:
        raise HTTPException(status_code=409, detail="A scan is already running.")

    previous = context.config.pcap.scan_mode
    update_scan_mode(body.scan_mode, context=context)

    started_reindex = False
    if reindex:
        scan_service.scan_cancel_event.clear()
        loop = asyncio.get_event_loop()
        loop.run_in_executor(
            context.thread_executor,
            lambda: scan_service.scan_wrapper(),
        )
        started_reindex = True

    return {
        "status": "updated",
        "previous_scan_mode": previous.value,
        "scan_config": _scan_config_payload(context.config.pcap),
        "reindex_started": started_reindex,
        "message": (
            f"Scan mode changed from {previous.value} to {body.scan_mode.value}."
            + (" Reindex started." if started_reindex else " Run Scan/Reindex to apply to existing files.")
        ),
    }


@router.post(
    "/reindex/{folder_path:path}", summary="Reindex a specific folder under PCAP directories"
)
async def reindex_specific_folder(
    folder_path: str,
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

    loop = asyncio.get_event_loop()
    loop.run_in_executor(
        context.thread_executor,
        lambda: scan_service.scan_wrapper(
            exclude_files=exclude,
            target_folder=folder_path,
        ),
    )
    return JSONResponse(
        content={"status": "started", "target_folder": folder_path or "(root)"}
    )
