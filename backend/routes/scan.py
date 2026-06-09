from fastapi import APIRouter
from services.config import ScanMode
from services.context import get_app_context, AppContext
from typing import Optional, List
from fastapi import Depends, Query, Request, HTTPException
from fastapi.responses import JSONResponse
import asyncio

from models.scan_options import ReindexRequest
from services.scan import BackfillState, RebuildSearchIndexState, ScanState, get_scan_service
from services.logger import get_logger

router = APIRouter(tags=["Scan"])

logger = get_logger(__name__)


@router.post("/reindex", summary="Rescan pcap directories and rebuild the index")
async def reindex_pcaps(
    request: Request,
    body: Optional[ReindexRequest] = None,
    exclude: Optional[List[str]] = Query(None),
    folder: Optional[str] = Query(
        None, description="Scan only this immediate subfolder under PCAP root"
    ),
    context: AppContext = Depends(get_app_context),
):

    scan_service = get_scan_service()
    if scan_service.scan_status["state"] == ScanState.RUNNING:
        return JSONResponse(
            content={"status": "busy", "message": "A scan is already running."},
            status_code=409,
        )
    scan_service.scan_cancel_event.clear()

    target = None
    fast_options = None
    exclude_files = exclude or []

    if body:
        target = (body.folder or "").strip() or None
        fast_options = body.fast_options
        if body.exclude:
            exclude_files = body.exclude
    if folder and not target:
        target = folder.strip() or None

    loop = asyncio.get_event_loop()
    loop.run_in_executor(
        context.thread_executor,
        lambda: scan_service.scan_wrapper(
            exclude_files=exclude_files,
            target_folder=target,
            fast_options=fast_options,
            context=context,
        ),
    )
    payload = {"status": "started", "folder": target}
    if fast_options is not None:
        payload["fast_options"] = fast_options.model_dump(exclude_none=True)
    return JSONResponse(content=payload)


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
        lambda: scan_service.backfill_wrapper(context=context),
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
        lambda: scan_service.rebuild_searchindex_wrapper(context=context),
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

@router.get("/scan-config", summary="Get current scan configuration")
async def scan_config(*, context: AppContext = Depends(get_app_context)):
    """Expose current runtime scan configuration."""
    pcap_config = context.config.pcap
    fs = pcap_config.fast_scan
    return {
        "scan_mode": pcap_config.scan_mode.value,
        "pebc": pcap_config.quick_scan.pebc if pcap_config.scan_mode == ScanMode.QUICK else None,
        "min_file_size": pcap_config.quick_scan.min_file_size if pcap_config.scan_mode == ScanMode.QUICK else None,
        "config_version": pcap_config.quick_scan.config_version,
        "fast_scan_defaults": {
            "output": fs.output,
            "sample_every": fs.sample_every,
            "max_packets": fs.max_packets,
            "bpf_filter": fs.bpf_filter,
            "emit_fingerprint": fs.emit_fingerprint,
            "ports_file": fs.ports_file,
        },
        "fast_scan_option_help": {
            "output": "summary (fast, one line) or lines (legacy, per packet)",
            "sample_every": "Process every Nth packet only",
            "max_packets": "Stop after N packets",
            "bpf_filter": "libpcap filter, e.g. host 10.0.0.1 and tcp",
            "emit_fingerprint": "Store PCAPTAIN_FP for duplicate detection",
            "ports_file": "Extra port→app mappings file",
        },
    }

@router.post(
    "/reindex/{folder_name}", summary="Reindex a specific folder under PCAP directories"
)
async def reindex_specific_folder(
    folder_name: str,
    request: Request,
    exclude: Optional[List[str]] = Query(None),
):
    scan_service = get_scan_service()
    result = await scan_service.scan_and_index(
        exclude_files=exclude,
        target_folder=folder_name,
    )
    if "error" in result:
        raise HTTPException(status_code=500, detail=result["error"])
    return JSONResponse(content=result)
