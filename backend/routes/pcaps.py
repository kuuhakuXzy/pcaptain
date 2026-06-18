# Tyler code
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Query, UploadFile, File
from fastapi.responses import FileResponse
import os
import asyncio
import json
from services.logger import get_logger
import re
import uuid
from services.context import get_app_context, AppContext
from services.config import get_pcap_root_directories, get_upload_directory
from services.scan import PCAP_FILE_KEY_PREFIX, calculate_sha256, get_scan_service

router = APIRouter(tags=["Pcaps"])
logger = get_logger(__name__)

MAX_UPLOAD_BYTES = 200 * 1024 * 1024


@router.post("/pcaps/upload", summary="Upload a pcap file and scan it")
async def upload_pcap(
    file: UploadFile = File(...),
    context: AppContext = Depends(get_app_context),
):
    if not context.redis_client:
        raise HTTPException(status_code=503, detail="Redis unavailable")

    filename = os.path.basename(file.filename or "upload.pcap")
    ext = os.path.splitext(filename)[1].lower()
    allowed = context.config.pcap.allowed_file_extensions
    if ext not in allowed:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid extension '{ext}'. Allowed: {', '.join(sorted(allowed))}",
        )

    content = await file.read()
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"File too large. Max size is {MAX_UPLOAD_BYTES // (1024 * 1024)} MB",
        )
    if len(content) == 0:
        raise HTTPException(status_code=400, detail="Empty file")

    upload_dir = get_upload_directory(context.config.pcap)
    await asyncio.to_thread(os.makedirs, upload_dir, exist_ok=True)

    base, ext_name = os.path.splitext(filename)
    dest_name = filename
    dest_path = os.path.join(upload_dir, dest_name)
    if await asyncio.to_thread(os.path.exists, dest_path):
        dest_name = f"{base}_{uuid.uuid4().hex[:8]}{ext_name}"
        dest_path = os.path.join(upload_dir, dest_name)

    def _write_file():
        with open(dest_path, "wb") as f:
            f.write(content)

    await asyncio.to_thread(_write_file)
    logger.info("Uploaded pcap saved to %s", dest_path)

    scan_service = get_scan_service()
    result = await scan_service.scan_single_file(dest_path, context=context)

    if result.get("status") == "error":
        raise HTTPException(status_code=500, detail=result.get("message", "Scan failed"))

    if result.get("status") == "no_protocols":
        return {
            "status": "uploaded",
            "message": "File uploaded but no protocols detected",
            "filename": dest_name,
            "path": dest_path,
            "file_hash": result.get("file_hash"),
        }

    return {
        "status": "success",
        "message": "File uploaded and indexed",
        "filename": dest_name,
        "path": dest_path,
        "file_hash": result.get("file_hash"),
        "protocols": result.get("protocols", []),
        "alerts": result.get("alerts", []),
    }


@router.get(
    "/pcaps/download/{file_hash}", summary="Download a specific pcap file by hash"
)
async def download_pcap_by_hash(
    file_hash: str,
    background_tasks: BackgroundTasks,

    # display filter
    filter: str | None = Query(default=None, description="Filter to apply when downloading a subset of the pcap"),
    context: AppContext = Depends(get_app_context)
):
    if not context.redis_client:
        raise HTTPException(
            status_code=503, detail="Service unavailable: Redis connection failed."
        )

    file_metadata = await asyncio.to_thread(
        context.redis_client.hgetall, f"{PCAP_FILE_KEY_PREFIX}:{file_hash}"
    )
    if not file_metadata:
        raise HTTPException(status_code=404, detail="File not found")

    file_path = file_metadata.get("path")
    filename = file_metadata.get("filename")

    abs_path = await asyncio.to_thread(os.path.abspath, file_path)
    allowed_abs_dirs = [
        await asyncio.to_thread(os.path.abspath, root)
        for root in get_pcap_root_directories(context.config.pcap)
    ]
    if not any(abs_path.startswith(d) for d in allowed_abs_dirs):
        raise HTTPException(status_code=403, detail="Forbidden: Access is denied.")

    # No filter -> return original file
    if not filter or not filter.strip():
        return FileResponse(abs_path, media_type="application/vnd.tcpdump.pcap", filename=filename)

    filter = filter.strip()

    temp_filename = f"filtered_df_{uuid.uuid4()}.pcap"
    temp_filepath = f"/tmp/{temp_filename}"

    cmd = ["tshark", "-r", abs_path, "-Y", filter, "-w", temp_filepath]
    logger.info(f"Starting display-filter export: {' '.join(cmd)}")

    try:
        process = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await process.communicate()

        if process.returncode != 0:
            err = stderr.decode(errors="ignore")
            logger.error(f"Tshark display filter failed: {err}")
            raise HTTPException(status_code=400, detail=f"Invalid display filter: {err}")

        if not os.path.exists(temp_filepath) or os.path.getsize(temp_filepath) == 0:
            raise HTTPException(status_code=404, detail=f"No packets found matching display filter '{filter}'")

    except HTTPException:
        if os.path.exists(temp_filepath):
            os.remove(temp_filepath)
        raise
    except Exception as e:
        logger.error(f"Error executing tshark for display filter: {e}")
        if os.path.exists(temp_filepath):
            os.remove(temp_filepath)
        raise HTTPException(status_code=500, detail="Internal Server Error during display filtering")

    background_tasks.add_task(remove_file, temp_filepath)

    return FileResponse(
        temp_filepath, media_type="application/vnd.tcpdump.pcap", filename=filename
    )


def remove_file(path: str):
    try:
        os.remove(path)
        logger.info(f"Cleaned up temporary file: {path}")
    except Exception as e:
        logger.error(f"Error deleting temporary file {path}: {e}")


@router.get(
    "/pcaps/download/{file_hash}/filter", summary="Download a filtered subset of a pcap"
)
async def download_filtered_pcap(
    file_hash: str,
    protocol: str,
    background_tasks: BackgroundTasks,
    context: AppContext = Depends(get_app_context),
):
    if not context.redis_client:
        raise HTTPException(status_code=503, detail="Service unavailable")

    file_metadata = await asyncio.to_thread(
        context.redis_client.hgetall, f"{PCAP_FILE_KEY_PREFIX}:{file_hash}"
    )
    if not file_metadata:
        raise HTTPException(status_code=404, detail="File not found")

    original_path = file_metadata.get("path")
    original_filename = file_metadata.get("filename")

    if not re.match(r"^[a-zA-Z0-9_.-]+$", protocol):
        raise HTTPException(status_code=400, detail="Invalid protocol format")

    temp_filename = f"filtered_{protocol}_{uuid.uuid4()}.pcap"
    temp_filepath = f"/tmp/{temp_filename}"

    cmd = ["tshark", "-r", original_path, "-Y", protocol, "-w", temp_filepath]

    logger.info(f"Starting filtered export: {' '.join(cmd)}")

    try:
        process = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await process.communicate()

        if process.returncode != 0:
            logger.error(f"Tshark filter failed: {stderr.decode()}")
            raise HTTPException(status_code=500, detail="Failed to filter pcap file.")

        if not os.path.exists(temp_filepath) or os.path.getsize(temp_filepath) == 0:
            raise HTTPException(
                status_code=404, detail=f"No packets found for protocol '{protocol}'"
            )

    except Exception as e:
        logger.error(f"Error executing tshark: {e}")
        # Clean up if it failed halfway
        if os.path.exists(temp_filepath):
            os.remove(temp_filepath)
        raise HTTPException(
            status_code=500, detail="Internal Server Error during filtering"
        )

    background_tasks.add_task(remove_file, temp_filepath)

    return FileResponse(
        temp_filepath,
        media_type="application/vnd.tcpdump.pcap",
        filename=f"subset_{protocol}_{original_filename}",
    )
