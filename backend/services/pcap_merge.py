"""Merge multiple PCAP files via mergecap."""

import asyncio
import os
import shutil
import subprocess
import uuid
from typing import Sequence

from redis import Redis

from services.catalog_constants import PCAP_FILE_KEY_PREFIX


async def resolve_pcap_paths(
    redis: Redis,
    file_hashes: Sequence[str],
    root_directory: str,
) -> list[tuple[str, str]]:
    """Return list of (hash, absolute_path) for existing indexed files."""
    resolved: list[tuple[str, str]] = []
    for fh in file_hashes:
        row = await asyncio.to_thread(redis.hgetall, f"{PCAP_FILE_KEY_PREFIX}:{fh}")
        if not row:
            continue
        path = row.get("path")
        if not path:
            continue
        abs_path = await asyncio.to_thread(os.path.abspath, path)
        if not abs_path.startswith(await asyncio.to_thread(os.path.abspath, root_directory)):
            continue
        if await asyncio.to_thread(os.path.isfile, abs_path):
            resolved.append((fh, abs_path))
    return resolved


async def merge_pcaps_to_file(
    paths: list[str],
    *,
    max_files: int = 20,
) -> str:
    if not paths:
        raise ValueError("No PCAP paths to merge")
    if len(paths) > max_files:
        raise ValueError(f"Maximum {max_files} files per merge")

    if not shutil.which("mergecap"):
        raise RuntimeError("mergecap is not installed (install Wireshark tools)")

    out_name = f"merged_{uuid.uuid4().hex}.pcap"
    out_path = os.path.join("/tmp", out_name)

    cmd = ["mergecap", "-w", out_path, *paths]
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    _stdout, stderr = await proc.communicate()
    if proc.returncode != 0:
        err = stderr.decode(errors="ignore")
        if os.path.exists(out_path):
            os.remove(out_path)
        raise RuntimeError(f"mergecap failed: {err}")

    if not os.path.isfile(out_path) or os.path.getsize(out_path) == 0:
        raise RuntimeError("mergecap produced an empty file")

    return out_path
