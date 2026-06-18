#!/usr/bin/env python3
"""Benchmark skip overhead: legacy (full-file SHA256) vs fast path fingerprint."""

import asyncio
import copy
import os
import sys
import time
from typing import List, Tuple

sys.path.insert(0, "/app")

from redis import Redis

from services.config import ScanMode, load_config, get_pcap_root_directories
from services.scan import (
    ScanService,
    PCAP_FILE_KEY_PREFIX,
    calculate_sha256_sync,
    get_effective_scan_mode,
    parse_size_bytes,
)


def collect_pcap_files(roots: List[str], extensions: tuple) -> List[str]:
    files: List[str] = []
    for root in roots:
        if not os.path.isdir(root):
            continue
        for dirpath, _, names in os.walk(root):
            for name in sorted(names):
                if name.lower().endswith(extensions):
                    files.append(os.path.join(dirpath, name))
    return files


def scan_params(config, file_size: int):
    qs = config.pcap.quick_scan
    quick_min = (
        qs.min_file_size
        if isinstance(qs.min_file_size, int)
        else parse_size_bytes(str(qs.min_file_size), 0)
    )
    mode, pebc, cfg_ver = get_effective_scan_mode(
        file_size,
        config.pcap.scan_mode,
        quick_scan_pebc=qs.pebc,
        quick_scan_min_file_size_bytes=quick_min,
        quick_scan_config_version=qs.config_version,
    )
    return mode, pebc, cfg_ver


async def legacy_skip_pass(
    service: ScanService,
    files: List[str],
    redis: Redis,
    config,
    parallel: int,
) -> dict:
    """Simulate pre-update behavior: always hash full file, then Redis skip check."""
    sem = asyncio.Semaphore(parallel)
    per_file = []
    skipped = 0
    bytes_hashed = 0

    async def worker(path: str):
        nonlocal skipped, bytes_hashed
        async with sem:
            t0 = time.perf_counter()
            st = os.stat(path)
            size = st.st_size
            mode, pebc, cfg_ver = scan_params(config, size)

            file_hash = await asyncio.to_thread(calculate_sha256_sync, path)
            bytes_hashed += size

            pcap_key = f"{PCAP_FILE_KEY_PREFIX}:{file_hash}"
            should = await service.should_process_file(
                redis_client=redis,
                pcap_key=pcap_key,
                file_path=path,
                current_scan_mode=mode,
                current_pebc=pebc,
                current_config_version=cfg_ver,
            )
            elapsed = time.perf_counter() - t0
            did_skip = not should
            if did_skip:
                skipped += 1
            per_file.append({"path": path, "elapsed_s": elapsed, "skipped": did_skip, "size": size})

    wall_start = time.perf_counter()
    await asyncio.gather(*[worker(f) for f in files])
    wall_elapsed = time.perf_counter() - wall_start

    return {
        "wall_time_s": round(wall_elapsed, 3),
        "sum_cpu_time_s": round(sum(x["elapsed_s"] for x in per_file), 3),
        "files": len(files),
        "skipped": skipped,
        "bytes_hashed": bytes_hashed,
        "mb_hashed": round(bytes_hashed / (1024 * 1024), 2),
    }


async def fast_skip_pass(
    service: ScanService,
    files: List[str],
    redis: Redis,
    config,
    parallel: int,
) -> dict:
    """Current behavior: path fingerprint skip without reading file content."""
    sem = asyncio.Semaphore(parallel)
    per_file = []
    fast_skipped = 0
    bytes_hashed = 0

    async def worker(path: str):
        nonlocal fast_skipped, bytes_hashed
        async with sem:
            t0 = time.perf_counter()
            st = os.stat(path)
            size = st.st_size
            mtime = st.st_mtime
            mode, pebc, cfg_ver = scan_params(config, size)

            if await service.try_fast_skip_by_path(
                redis_client=redis,
                file_path=path,
                file_size=size,
                file_mtime=mtime,
                current_scan_mode=mode,
                current_pebc=pebc,
                current_config_version=cfg_ver,
            ):
                fast_skipped += 1
                per_file.append({"path": path, "elapsed_s": time.perf_counter() - t0, "fast_skip": True, "size": size})
                return

            file_hash = await service.resolve_file_hash(path, size, mtime, redis)
            if file_hash:
                pcap_key = f"{PCAP_FILE_KEY_PREFIX}:{file_hash}"
                stored_size = size
                try:
                    meta = await asyncio.to_thread(redis.hget, pcap_key, "size_bytes")
                    if meta and int(meta) == size:
                        pass
                    else:
                        bytes_hashed += size
                except (TypeError, ValueError):
                    bytes_hashed += size
            else:
                h = await asyncio.to_thread(calculate_sha256_sync, path)
                bytes_hashed += size
                file_hash = h

            should = await service.should_process_file(
                redis_client=redis,
                pcap_key=f"{PCAP_FILE_KEY_PREFIX}:{file_hash}",
                file_path=path,
                current_scan_mode=mode,
                current_pebc=pebc,
                current_config_version=cfg_ver,
            )
            per_file.append({
                "path": path,
                "elapsed_s": time.perf_counter() - t0,
                "fast_skip": False,
                "skipped_after_hash": not should,
                "size": size,
            })

    wall_start = time.perf_counter()
    await asyncio.gather(*[worker(f) for f in files])
    wall_elapsed = time.perf_counter() - wall_start

    return {
        "wall_time_s": round(wall_elapsed, 3),
        "sum_cpu_time_s": round(sum(x["elapsed_s"] for x in per_file), 3),
        "files": len(files),
        "fast_skipped": fast_skipped,
        "bytes_hashed": bytes_hashed,
        "mb_hashed": round(bytes_hashed / (1024 * 1024), 2),
    }


async def main():
    config = load_config("/app/config/config.yaml")
    roots = get_pcap_root_directories(config.pcap)
    ext = tuple(e.lower() for e in config.pcap.allowed_file_extensions)
    files = collect_pcap_files(roots, ext)

    if not files:
        print("No PCAP files found under", roots)
        return 1

    redis = Redis(host=config.redis.host, port=config.redis.port, decode_responses=True)
    indexed = len(list(redis.scan_iter(f"{PCAP_FILE_KEY_PREFIX}:*", count=500)))
    path_indexes = len(list(redis.scan_iter("pcap:path:*", count=500)))

    total_bytes = sum(os.path.getsize(f) for f in files)
    parallel = config.pcap.max_parallel_scans
    service = ScanService()

    print("=" * 70)
    print("SKIP BENCHMARK (real files on disk + live Redis index)")
    print("=" * 70)
    print(f"PCAP roots:        {roots}")
    print(f"Files on disk:     {len(files)}")
    print(f"Total size:        {total_bytes / (1024*1024):.1f} MB")
    print(f"Indexed in Redis:  {indexed}")
    print(f"Path indexes:      {path_indexes}")
    print(f"Parallel workers:  {parallel}")
    print(f"Scan mode:         {config.pcap.scan_mode.value}")
    print()

    if indexed == 0:
        print("WARNING: Redis index empty. Run POST /reindex first for meaningful skip test.")
        return 1

    if path_indexes < indexed * 0.5:
        print("WARNING: Path index sparse. Run a full reindex once after the update.")

    print("Running LEGACY skip pass (always SHA256 full file read)...")
    legacy = await legacy_skip_pass(service, files, redis, config, parallel)

    print("Running FAST skip pass (path+size+mtime fingerprint)...")
    fast = await fast_skip_pass(service, files, redis, config, parallel)

    speedup = legacy["wall_time_s"] / fast["wall_time_s"] if fast["wall_time_s"] else 0
    io_reduction = (
        (1 - fast["bytes_hashed"] / legacy["bytes_hashed"]) * 100
        if legacy["bytes_hashed"]
        else 100.0
    )

    print()
    print("=" * 70)
    print("RESULTS")
    print("=" * 70)
    print(f"{'Metric':<32} {'Legacy (before)':<18} {'Fast (after)':<18}")
    print("-" * 70)
    print(f"{'Wall time (seconds)':<32} {legacy['wall_time_s']:<18} {fast['wall_time_s']:<18}")
    print(f"{'Sum per-file CPU time (s)':<32} {legacy['sum_cpu_time_s']:<18} {fast['sum_cpu_time_s']:<18}")
    print(f"{'Files processed':<32} {legacy['files']:<18} {fast['files']:<18}")
    print(f"{'Skipped (no protocol scan)':<32} {legacy['skipped']:<18} {fast['fast_skipped']:<18}")
    print(f"{'Bytes read for hash (MB)':<32} {legacy['mb_hashed']:<18} {fast['mb_hashed']:<18}")
    print("-" * 70)
    print(f"Wall time speedup:     {speedup:.2f}x")
    print(f"Disk read reduction:   {io_reduction:.1f}%")
    print("=" * 70)

    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
