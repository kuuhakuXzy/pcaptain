#!/usr/bin/env python3
"""Compare scan throughput: fast (baseline) vs quick + higher parallelism."""

import asyncio
import copy
import os
import sys
import time
from typing import Dict, List, Optional, Tuple

sys.path.insert(0, "/app")

from services.config import ScanMode, load_config
from services.scan import (
    ScanService,
    get_effective_scan_mode,
    parse_size_bytes,
)


def collect_pcap_files(root: str, extensions: tuple) -> List[str]:
    files = []
    for dirpath, _, names in os.walk(root):
        for name in sorted(names):
            if name.lower().endswith(extensions):
                files.append(os.path.join(dirpath, name))
    return files


def build_mode_config(base_config, scan_mode: ScanMode, max_parallel: int):
    cfg = copy.deepcopy(base_config)
    cfg.pcap.scan_mode = scan_mode
    cfg.pcap.max_parallel_scans = max_parallel
    return cfg


async def scan_one_file(
    service: ScanService,
    file_path: str,
    config,
) -> Tuple[Optional[Tuple[dict, int]], float, str]:
    file_size = os.path.getsize(file_path)
    qs = config.pcap.quick_scan

    quick_min = (
        qs.min_file_size
        if isinstance(qs.min_file_size, int)
        else parse_size_bytes(str(qs.min_file_size), 0)
    )

    mode, pebc, _ = get_effective_scan_mode(
        file_size,
        config.pcap.scan_mode,
        quick_scan_pebc=qs.pebc,
        quick_scan_min_file_size_bytes=quick_min,
        quick_scan_config_version=qs.config_version,
    )

    quick_threshold = int(file_size * pebc) if mode == ScanMode.QUICK and pebc else None
    t0 = time.perf_counter()
    result = await service.get_protocols_from_pcap(
        file_path,
        scan_mode=mode,
        quick_threshold_bytes=quick_threshold,
        sample_segments=config.pcap.quick_scan.sample_segments,
        file_size_bytes=file_size,
    )
    elapsed = time.perf_counter() - t0
    return result, elapsed, mode.value


async def run_benchmark(
    label: str,
    files: List[str],
    config,
) -> dict:
    service = ScanService()
    parallel = config.pcap.max_parallel_scans
    sem = asyncio.Semaphore(parallel)
    per_file: Dict[str, dict] = {}
    mode_counts: Dict[str, int] = {}

    async def worker(path: str):
        async with sem:
            result, elapsed, eff_mode = await scan_one_file(service, path, config)
            mode_counts[eff_mode] = mode_counts.get(eff_mode, 0) + 1
            protos = sorted(result[0].keys()) if result else []
            per_file[path] = {
                "elapsed_s": round(elapsed, 3),
                "effective_mode": eff_mode,
                "protocol_count": len(protos),
                "protocols": protos,
                "indexed": result is not None and bool(result[0]),
            }

    wall_start = time.perf_counter()
    await asyncio.gather(*[worker(f) for f in files])
    wall_elapsed = time.perf_counter() - wall_start

    indexed = sum(1 for v in per_file.values() if v["indexed"])
    cpu_sum = sum(v["elapsed_s"] for v in per_file.values())

    return {
        "label": label,
        "scan_mode": config.pcap.scan_mode.value,
        "max_parallel_scans": parallel,
        "file_count": len(files),
        "indexed_count": indexed,
        "wall_time_s": round(wall_elapsed, 2),
        "sum_cpu_time_s": round(cpu_sum, 2),
        "effective_mode_counts": mode_counts,
        "per_file": per_file,
    }


def compare_protocol_accuracy(baseline_res: dict, candidate_res: dict) -> dict:
    """Compare protocol sets between two benchmark runs."""
    matches = 0
    mismatches = []
    for path in baseline_res["per_file"]:
        if path not in candidate_res["per_file"]:
            continue
        bp = set(baseline_res["per_file"][path]["protocols"])
        cp = set(candidate_res["per_file"][path]["protocols"])
        if bp == cp:
            matches += 1
        else:
            mismatches.append({
                "file": os.path.basename(path),
                "baseline_only": sorted(bp - cp)[:8],
                "candidate_only": sorted(cp - bp)[:8],
                "baseline_count": len(bp),
                "candidate_count": len(cp),
            })
    return {
        "identical_protocol_sets": matches,
        "mismatched_files": len(mismatches),
        "samples": mismatches[:5],
    }


async def main():
    base = load_config("/app/config/config.yaml")
    root = base.pcap.root_directory
    ext = tuple(base.pcap.allowed_file_extensions)
    files = collect_pcap_files(root, ext)

    if not files:
        print("No pcap files found under", root)
        return 1

    total_mb = sum(os.path.getsize(f) for f in files) / (1024 * 1024)
    print(f"Benchmark dataset: {len(files)} files, {total_mb:.1f} MB total\n")

    cfg_fast = build_mode_config(base, ScanMode.FAST, max_parallel=4)
    print("Running baseline: scan_mode=fast, max_parallel=4 ...")
    fast_result = await run_benchmark("baseline_fast_p4", files, cfg_fast)

    cfg_quick = build_mode_config(base, ScanMode.QUICK, max_parallel=8)
    qs = cfg_quick.pcap.quick_scan
    print(
        f"Running quick: scan_mode=quick, max_parallel=8, "
        f"pebc={qs.pebc}, sample_segments={qs.sample_segments} ..."
    )
    quick_result = await run_benchmark("quick_p8", files, cfg_quick)

    accuracy = compare_protocol_accuracy(fast_result, quick_result)

    speedup = fast_result["wall_time_s"] / quick_result["wall_time_s"] if quick_result["wall_time_s"] else 0

    print("\n" + "=" * 60)
    print("BENCHMARK RESULTS")
    print("=" * 60)
    print(f"{'Metric':<28} {'Fast (p=4)':<14} {'Quick (p=8)':<14}")
    print("-" * 60)
    print(f"{'Wall time (seconds)':<28} {fast_result['wall_time_s']:<14} {quick_result['wall_time_s']:<14}")
    print(f"{'Sum per-file CPU time':<28} {fast_result['sum_cpu_time_s']:<14} {quick_result['sum_cpu_time_s']:<14}")
    print(f"{'Files indexed':<28} {fast_result['indexed_count']:<14} {quick_result['indexed_count']:<14}")
    print(f"{'Speedup (wall)':<28} {'1.00x':<14} {f'{speedup:.2f}x':<14}")
    print("-" * 60)
    print(f"Quick effective modes: {quick_result['effective_mode_counts']}")
    print(f"Protocol accuracy: {accuracy['identical_protocol_sets']}/{len(files)} identical, "
          f"{accuracy['mismatched_files']} differ")
    if accuracy["samples"]:
        print("\nSample protocol diffs:")
        for s in accuracy["samples"]:
            print(f"  {s['file']}: fast={s['baseline_count']} protos, quick={s['candidate_count']} protos")
            if s["baseline_only"]:
                print(f"    only in fast: {s['baseline_only']}")
            if s["candidate_only"]:
                print(f"    only in quick: {s['candidate_only']}")

    print("\n" + "=" * 60)
    print("=" * 60)

    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
