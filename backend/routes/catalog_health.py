import asyncio
import os
import shutil
import subprocess

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse

from services.context import AppContext, get_app_context
from services.scan import get_scan_service, PCAP_FILE_KEY_PREFIX

router = APIRouter(tags=["Health"])


def _tool_version(command: list[str]) -> str | None:
    try:
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=5,
        )
        if result.returncode != 0:
            return None
        return (result.stdout or result.stderr).split("\n", 1)[0].strip()
    except Exception:
        return None


@router.get("/health/ready", summary="Deep readiness check")
async def health_ready(context: AppContext = Depends(get_app_context)):
    checks: dict = {}
    ok = True

    redis = context.redis_client
    if redis:
        try:
            await asyncio.to_thread(redis.ping)
            checks["redis"] = "ok"
        except Exception as exc:
            checks["redis"] = f"error: {exc}"
            ok = False
    else:
        checks["redis"] = "unavailable"
        ok = False

    pcap_root = context.config.pcap.root_directory
    if os.path.isdir(pcap_root) and os.access(pcap_root, os.R_OK):
        checks["pcap_root"] = "readable"
    else:
        checks["pcap_root"] = f"not readable: {pcap_root}"
        ok = False

    for name, cmd in (
        ("tshark", ["tshark", "-v"]),
        ("capinfos", ["capinfos", "-v"]),
        ("fastscan", ["fastscan"]),
    ):
        if name == "fastscan":
            if shutil.which("fastscan"):
                checks[name] = "ok"
            else:
                checks[name] = "missing"
        else:
            version = _tool_version(cmd)
            checks[name] = version or "missing"
            if not version:
                ok = False

    indexed_files = 0
    if redis:
        try:
            indexed_files = len(
                await asyncio.to_thread(redis.keys, f"{PCAP_FILE_KEY_PREFIX}:*")
            )
        except Exception:
            pass

    scan_service = get_scan_service()
    return JSONResponse(
        status_code=200 if ok else 503,
        content={
            "status": "ready" if ok else "degraded",
            "checks": checks,
            "indexed_files": indexed_files,
            "scan_state": scan_service.scan_status.get("state"),
        },
    )
