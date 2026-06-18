#!/usr/bin/env python3
"""Benchmark protocol/filename search before/after optimization."""

import os
import sys
import time

sys.path.insert(0, "/app")

import urllib.parse
import urllib.request
from redis import Redis

from services.scan import PCAP_FILE_KEY_PREFIX, SORT_INDEX_FILENAME


API_BASE = os.environ.get("BENCHMARK_API", "http://127.0.0.1:7000")
REDIS_HOST = os.environ.get("REDIS_HOST", "redis")
REDIS_PORT = int(os.environ.get("REDIS_PORT", "6380"))

QUERIES = [
    ("http", "pure protocol"),
    ("dns", "pure protocol"),
    ("tcp", "pure protocol"),
    ("http-server", "protocol + filename"),
    ("unreallrcd", "filename only"),
    ("", "all files"),
]


def redis_stats(redis: Redis) -> dict:
    indexed = sum(1 for _ in redis.scan_iter(f"{PCAP_FILE_KEY_PREFIX}:*", count=500))
    sort_size = redis.zcard(SORT_INDEX_FILENAME) or 0
    return {"indexed_files": indexed, "sort_index_size": sort_size}


def legacy_filename_scan(redis: Redis, query: str) -> tuple[int, int]:
    """Simulate old search_by_filename: HGETALL every file in sort index."""
    q = query.lower().strip()
    if not q:
        return 0, 0

    all_ids = redis.zrange(SORT_INDEX_FILENAME, 0, -1)
    hits = 0
    redis_calls = 0
    for i in range(0, len(all_ids), 500):
        batch = all_ids[i : i + 500]
        pipe = redis.pipeline()
        for h in batch:
            pipe.hgetall(f"{PCAP_FILE_KEY_PREFIX}:{h}")
        rows = pipe.execute()
        redis_calls += len(batch)
        for row in rows:
            if row and q in row.get("filename", "").lower():
                hits += 1
    return hits, redis_calls


def optimized_filename_scan(redis: Redis, query: str, exclude_count: int = 0) -> tuple[int, int]:
    """Simulate new path: HGET filename only, skip protocol members."""
    q = query.lower().strip()
    if not q:
        return 0, 0

    all_ids = redis.zrange(SORT_INDEX_FILENAME, 0, -1)
    hits = 0
    redis_calls = 0
    for i in range(0, len(all_ids), 500):
        batch = all_ids[i : i + 500]
        pipe = redis.pipeline()
        for h in batch:
            pipe.hget(f"{PCAP_FILE_KEY_PREFIX}:{h}", "filename")
        names = pipe.execute()
        redis_calls += len(batch)
        for fname in names:
            if fname and q in fname.lower():
                hits += 1
    return hits, redis_calls


def api_search(query: str, limit: int = 10) -> tuple[float, dict]:
    params = urllib.parse.urlencode({"protocol": query, "page": 1, "limit": limit})
    url = f"{API_BASE}/search?{params}"
    t0 = time.perf_counter()
    with urllib.request.urlopen(url, timeout=120) as resp:
        body = resp.read()
    elapsed = time.perf_counter() - t0
    import json

    data = json.loads(body)
    return elapsed, data


def main():
    print("=== PCAP Search Benchmark ===\n")
    redis = Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)
    stats = redis_stats(redis)
    print(f"Indexed files: {stats['indexed_files']}")
    print(f"Sort index size: {stats['sort_index_size']}")
    print(f"API base: {API_BASE}\n")

    if stats["indexed_files"] == 0:
        print("WARNING: Redis index empty. Run POST /reindex first.\n")

    print("--- Legacy filename scan simulation (HGETALL all files) ---")
    for query, label in [("http", "http"), ("unreallrcd", "filename")]:
        t0 = time.perf_counter()
        hits, calls = legacy_filename_scan(redis, query)
        wall = time.perf_counter() - t0
        print(f"  query={query!r} ({label}): {hits} hits, {calls} HGETALL, {wall:.3f}s")

    print("\n--- Optimized filename scan simulation (HGET filename only) ---")
    for query, label in [("http", "http"), ("unreallrcd", "filename")]:
        t0 = time.perf_counter()
        hits, calls = optimized_filename_scan(redis, query)
        wall = time.perf_counter() - t0
        print(f"  query={query!r} ({label}): {hits} hits, {calls} HGET, {wall:.3f}s")

    print("\n--- Live API /search (optimized backend) ---")
    for query, label in QUERIES:
        try:
            wall, data = api_search(query)
            total = data.get("total", 0)
            rows = len(data.get("data", []))
            print(f"  query={query!r:14} ({label:18}): total={total:4} page={rows}  {wall:.3f}s")
        except Exception as exc:
            print(f"  query={query!r:14} ({label:18}): ERROR {exc}")

    print("\nDone.")
    print("Note: pure protocol queries (http/dns/tcp) skip filename scan entirely.")


if __name__ == "__main__":
    main()
