from fastapi import APIRouter, Request, HTTPException, Query
from fastapi.responses import JSONResponse
from typing import Optional, List, Dict, Any
import asyncio
import logging
from enum import Enum

from container import container
from services.redis_service import RedisService
from services.scanner_service import ScannerService
from config.config_service import ConfigService

router = APIRouter()

# Get service instances from container
config_service = container.get(ConfigService)
redis_service = container.get(RedisService)
scanner_service = container.get(ScannerService)


class ScanState(str, Enum):
    IDLE = "idle"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


scan_status: Dict[str, Any] = {
    "state": ScanState.IDLE,
    "indexed_files": 0,
    "message": "Ready",
}


@router.post("/reindex", summary="Rescan pcap directories and rebuild the index")
async def reindex_pcaps(request: Request, exclude: Optional[List[str]] = Query(None)):
    if scan_status["state"] == ScanState.RUNNING:
        return JSONResponse(
            content={"status": "busy", "message": "A scan is already running."},
            status_code=409,
        )

    settings = config_service.init()
    base_url = settings.FULL_BASE_URL or str(request.base_url).rstrip("/")

    loop = asyncio.get_event_loop()

    def _background():
        try:
            scan_status["state"] = ScanState.RUNNING
            scan_status["indexed_files"] = 0
            scan_status["message"] = "Scanning in progress..."
            logging.info("Background scan started.")

            result = asyncio.run(
                scanner_service.scan(
                    settings.PCAP_DIRECTORY, base_url=base_url, exclude=exclude
                )
            )
            scan_status["indexed_files"] = result
            scan_status["state"] = ScanState.COMPLETED
            scan_status["message"] = f"Completed successfully. Indexed {result} files."
            logging.info("Background scan completed.")
        except Exception as e:
            logging.error(f"Scan failed: {e}")
            scan_status["state"] = ScanState.FAILED
            scan_status["message"] = str(e)
        finally:
            if scan_status["state"] != ScanState.FAILED:
                scan_status["state"] = ScanState.IDLE

    loop.run_in_executor(None, _background)
    return JSONResponse(content={"status": "started"})


@router.get("/scan-status")
async def scan_status_endpoint():
    return scan_status


@router.post(
    "/reindex/{folder_name}", summary="Reindex a specific folder under PCAP directories"
)
async def reindex_specific_folder(
    folder_name: str, request: Request, exclude: Optional[List[str]] = Query(None)
):
    settings = config_service.init()
    base_url = settings.FULL_BASE_URL or str(request.base_url).rstrip("/")

    result = await scanner_service.scan(
        settings.PCAP_DIRECTORY,
        base_url=base_url,
        target_folder=folder_name,
        exclude=exclude,
    )
    if isinstance(result, int):
        return JSONResponse(content={"status": "success", "indexed_files": result})
    elif isinstance(result, dict) and "error" in result:
        raise HTTPException(status_code=500, detail=result["error"])
    else:
        return JSONResponse(content={"status": "success", "indexed_files": result})
