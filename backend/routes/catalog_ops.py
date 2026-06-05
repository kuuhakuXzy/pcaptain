import asyncio
import os

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from fastapi.responses import FileResponse, JSONResponse

from models.catalog import MergePcapsRequest, ReindexFolderRequest
from services.catalog_ops_folders import list_pcap_subfolders
from services.context import AppContext, get_app_context
from services.duplicate_detect import find_duplicate_groups
from services.health_dashboard import build_health_dashboard
from services.new_ip_tracker import get_last_new_ips, reset_known_ips, snapshot_new_ips
from services.orphan_audit import audit_catalog_vs_disk
from services.pcap_merge import merge_pcaps_to_file, resolve_pcap_paths
from services.scan import ScanState, get_scan_service
from services.subnet_search import search_by_subnet

router = APIRouter(tags=["Catalog Operations"])


@router.get("/catalog/duplicates", summary="Find duplicate and near-duplicate PCAP groups")
async def catalog_duplicates(
    max_groups: int = Query(50, ge=1, le=200),
    context: AppContext = Depends(get_app_context),
):
    redis = context.redis_client
    if not redis:
        raise HTTPException(503, "Redis unavailable")
    return await find_duplicate_groups(redis, max_groups=max_groups)


@router.get("/catalog/orphans", summary="Files on disk vs Redis index audit")
async def catalog_orphans(context: AppContext = Depends(get_app_context)):
    redis = context.redis_client
    if not redis:
        raise HTTPException(503, "Redis unavailable")
    pcap = context.config.pcap
    return await audit_catalog_vs_disk(
        redis,
        pcap.root_directory,
        tuple(pcap.allowed_file_extensions),
        prefix_str=pcap.prefix_str,
    )


@router.get("/health/dashboard", summary="Ops health dashboard payload")
async def health_dashboard(context: AppContext = Depends(get_app_context)):
    return await build_health_dashboard(context.redis_client, context)


@router.get("/search/subnet", summary="Search PCAPs by CIDR subnet")
async def search_subnet(
    cidr: str = Query(..., min_length=3, description="e.g. 10.0.0.0/24"),
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    context: AppContext = Depends(get_app_context),
):
    redis = context.redis_client
    if not redis:
        raise HTTPException(503, "Redis unavailable")
    try:
        return await search_by_subnet(
            redis,
            cidr,
            page=page,
            limit=limit,
            prefix_str=context.config.pcap.prefix_str,
            internal_root=context.config.pcap.root_directory,
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc


@router.get("/catalog/ips/new", summary="IPs newly seen after last scan")
async def new_ips_snapshot(context: AppContext = Depends(get_app_context)):
    redis = context.redis_client
    if not redis:
        raise HTTPException(503, "Redis unavailable")
    return await get_last_new_ips(redis)


@router.post("/catalog/ips/reset-baseline", summary="Reset known-IP baseline to current index")
async def reset_ips_baseline(context: AppContext = Depends(get_app_context)):
    redis = context.redis_client
    if not redis:
        raise HTTPException(503, "Redis unavailable")
    count = await reset_known_ips(redis)
    return {"status": "ok", "known_ips": count}


@router.post("/catalog/ips/snapshot", summary="Manually run new-IP detection")
async def trigger_ips_snapshot(context: AppContext = Depends(get_app_context)):
    redis = context.redis_client
    if not redis:
        raise HTTPException(503, "Redis unavailable")
    return await snapshot_new_ips(redis)


@router.get("/scan/folders", summary="List subfolders under PCAP root for targeted scan")
async def scan_folders(context: AppContext = Depends(get_app_context)):
    root = context.config.pcap.root_directory
    if not os.path.isdir(root):
        return {"folders": [], "root": root}
    folders = await list_pcap_subfolders(root, tuple(context.config.pcap.allowed_file_extensions))
    return {"folders": folders, "root": root}


@router.post("/reindex/folder", summary="Start background scan of one subfolder")
async def reindex_folder(
    body: ReindexFolderRequest,
    context: AppContext = Depends(get_app_context),
):
    folder = (body.folder or "").strip()
    if not folder:
        raise HTTPException(400, "folder is required")

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
            exclude_files=None,
            target_folder=folder,
        ),
    )
    return JSONResponse(content={"status": "started", "folder": folder})


@router.post("/pcaps/merge", summary="Merge multiple indexed PCAPs into one file")
async def merge_pcaps(
    body: MergePcapsRequest,
    background_tasks: BackgroundTasks,
    context: AppContext = Depends(get_app_context),
):
    redis = context.redis_client
    if not redis:
        raise HTTPException(503, "Redis unavailable")

    resolved = await resolve_pcap_paths(
        redis,
        body.file_hashes,
        context.config.pcap.root_directory,
    )
    if len(resolved) < 2:
        raise HTTPException(400, "Need at least 2 valid indexed file hashes")

    paths = [p for _h, p in resolved]
    try:
        out_path = await merge_pcaps_to_file(paths, max_files=20)
    except (ValueError, RuntimeError) as exc:
        raise HTTPException(400, str(exc)) from exc

    background_tasks.add_task(os.remove, out_path)
    return FileResponse(
        out_path,
        media_type="application/vnd.tcpdump.pcap",
        filename="merged.pcap",
    )
