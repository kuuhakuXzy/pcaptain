"""Aggregated health payload for ops dashboard UI."""

import asyncio
import os
import shutil
import subprocess
from typing import Any

from redis import Redis

from services.catalog_constants import PCAP_FILE_KEY_PREFIX
from services.scan import get_scan_service


def _disk_usage(path: str) -> dict[str, Any]:
    try:
        usage = shutil.disk_usage(path)
        return {
            "path": path,
            "total_bytes": usage.total,
            "used_bytes": usage.used,
            "free_bytes": usage.free,
            "used_percent": round(100 * usage.used / usage.total, 1) if usage.total else 0,
        }
    except OSError as exc:
        return {"path": path, "error": str(exc)}


def _tool_ok(command: list[str], name: str) -> str:
    if name == "fastscan":
        return "ok" if shutil.which("fastscan") else "missing"
    try:
        r = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=5,
        )
        return "ok" if r.returncode == 0 else "missing"
    except Exception:
        return "missing"


async def build_health_dashboard(redis: Redis | None, context) -> dict[str, Any]:
    checks: dict[str, str] = {}
    ok = True

    if redis:
        try:
            await asyncio.to_thread(redis.ping)
            checks["redis"] = "ok"
            indexed = len(
                await asyncio.to_thread(redis.keys, f"{PCAP_FILE_KEY_PREFIX}:*")
            )
        except Exception as exc:
            checks["redis"] = f"error: {exc}"
            indexed = 0
            ok = False
    else:
        checks["redis"] = "unavailable"
        indexed = 0
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
        ("mergecap", ["mergecap", "-v"]),
    ):
        status = _tool_ok(cmd, name)
        checks[name] = status
        if status != "ok":
            ok = False
    checks["fastscan"] = _tool_ok([], "fastscan")

    scan_service = get_scan_service()
    scan_state = scan_service.scan_status.get("state")
    if hasattr(scan_state, "value"):
        scan_state = scan_state.value

    import json
    from services.catalog_constants import NEW_IPS_SNAPSHOT_KEY, SCAN_FAILURES_KEY

    new_ips_raw = await asyncio.to_thread(redis.get, NEW_IPS_SNAPSHOT_KEY) if redis else None
    new_ips = json.loads(new_ips_raw) if new_ips_raw else {}
    failure_count = (
        await asyncio.to_thread(redis.llen, SCAN_FAILURES_KEY) if redis else 0
    )

    return {
        "status": "healthy" if ok else "degraded",
        "checks": checks,
        "indexed_files": indexed,
        "scan_state": scan_state,
        "scan_message": scan_service.scan_status.get("message", ""),
        "disk": _disk_usage(pcap_root),
        "new_ips": new_ips,
        "scan_failure_count": failure_count or 0,
        "public_url": context.config.public_url,
        "root_directory": pcap_root,
    }
