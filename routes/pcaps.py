from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from fastapi.responses import FileResponse
import os
import asyncio
from services.logger import get_logger
import re
import uuid
from services.context import get_app_context, AppContext
from services.scan import PCAP_FILE_KEY_PREFIX

router = APIRouter(tags=["Pcaps"])
logger = get_logger(__name__)


@router.get(
    "/pcaps/download/{file_hash}", summary="Download a specific pcap file by hash"
)
async def download_pcap_by_hash(
    file_hash: str, context: AppContext = Depends(get_app_context)
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
        await asyncio.to_thread(os.path.abspath, d) for d in context.PCAP_DIRECTORIES
    ]
    if not any(abs_path.startswith(d) for d in allowed_abs_dirs):
        raise HTTPException(status_code=403, detail="Forbidden: Access is denied.")

    return FileResponse(
        abs_path, media_type="application/vnd.tcpdump.pcap", filename=filename
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
