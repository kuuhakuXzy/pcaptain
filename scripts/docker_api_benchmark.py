#!/usr/bin/env python3
"""Benchmark fast vs full scan via pcaptain Docker API."""
import json
import re
import subprocess
import time
import urllib.error
import urllib.request

API = "http://localhost:7000"
FOLDER = "first2015"
CONFIG_PATH = r"d:\New folder\pcaptain\backend\config\config.yaml"
COMPOSE_DIR = r"d:\New folder\pcaptain"


def run(cmd: list[str], check: bool = True, cwd: str | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, check=check, cwd=cwd)


def flush_redis() -> None:
    run(["docker", "exec", "redis", "redis-cli", "-p", "6380", "FLUSHDB"])


def set_scan_mode(mode: str) -> None:
    with open(CONFIG_PATH, encoding="utf-8") as f:
        text = f.read()
    new_text, n = re.subn(
        r"scan_mode:\s*\w+",
        f"scan_mode: {mode}",
        text,
        count=1,
    )
    if n != 1:
        raise RuntimeError("Could not update scan_mode in config.yaml")
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        f.write(new_text)
    run(["docker", "compose", "restart", "backend"], cwd=COMPOSE_DIR)
    for _ in range(30):
        try:
            urllib.request.urlopen(f"{API}/scan-config", timeout=2)
            cfg = json.loads(urllib.request.urlopen(f"{API}/scan-config").read())
            if cfg.get("scan_mode") == mode:
                return
        except Exception:
            pass
        time.sleep(1)
    raise RuntimeError(f"Backend did not come up with scan_mode={mode}")


def wait_scan(timeout_s: int = 600) -> dict:
    start = time.perf_counter()
    deadline = start + timeout_s
    # Wait for scan to start
    while time.perf_counter() < deadline:
        st = json.loads(urllib.request.urlopen(f"{API}/scan-status").read())
        if st.get("state") == "running":
            break
        time.sleep(0.2)
    else:
        raise TimeoutError("scan did not start")

    run_start = time.perf_counter()
    while time.perf_counter() < deadline:
        st = json.loads(urllib.request.urlopen(f"{API}/scan-status").read())
        state = st.get("state")
        if state == "failed":
            raise RuntimeError(st.get("message", "scan failed"))
        if state in ("completed", "idle") and st.get("state") != "running":
            if state == "completed" or "Completed" in st.get("message", ""):
                return {"seconds": time.perf_counter() - run_start, "status": st}
        time.sleep(0.3)
    raise TimeoutError("scan did not finish")


def post_reindex(scan_mode_label: str, body: dict | None = None) -> None:
    data = json.dumps(body or {"folder": FOLDER}).encode()
    req = urllib.request.Request(
        f"{API}/reindex",
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        resp = urllib.request.urlopen(req, timeout=10)
    except urllib.error.HTTPError as e:
        raise RuntimeError(e.read().decode()) from e
    print(f"[{scan_mode_label}] started:", resp.read().decode())


def bench_run(label: str, mode: str, body: dict | None = None) -> dict:
    print(f"\n=== {label} (config scan_mode={mode}) ===")
    set_scan_mode(mode)
    flush_redis()
    time.sleep(1)
    cfg = json.loads(urllib.request.urlopen(f"{API}/scan-config").read())
    print("scan-config:", json.dumps(cfg, indent=2))
    post_reindex(label, body)
    result = wait_scan()
    print(
        f"[{label}] done in {result['seconds']:.2f}s | "
        f"indexed={result['status'].get('indexed_files')} | "
        f"message={result['status'].get('message')}"
    )
    if result["status"].get("fast_scan_options"):
        print("fast_scan_options:", result["status"]["fast_scan_options"])
    if result["status"].get("timing_ms"):
        print("timing_ms:", json.dumps(result["status"]["timing_ms"], indent=2))
    return result


def main() -> None:
    # Ensure scan idle
    st = json.loads(urllib.request.urlopen(f"{API}/scan-status").read())
    if st.get("state") == "running":
        raise SystemExit("Scan already running; cancel first.")

    full = bench_run("NORMAL (full/tshark)", "full")
    fast_body = {
        "folder": FOLDER,
        "fast_options": {"output": "summary", "emit_fingerprint": True},
    }
    fast = bench_run("FAST (fastscan)", "fast", fast_body)

    speedup = full["seconds"] / fast["seconds"] if fast["seconds"] > 0 else 0
    print("\n=== SUMMARY (Docker API, folder first2015, 3 PCAPs ~62MB) ===")
    print(f"Normal/full: {full['seconds']:.2f}s | indexed {full['status'].get('indexed_files')}")
    print(f"Fast scan:   {fast['seconds']:.2f}s | indexed {fast['status'].get('indexed_files')}")
    print(f"Speedup:     {speedup:.2f}x")
    for label, result in [("Normal/full", full), ("Fast scan", fast)]:
        timing = result["status"].get("timing_ms")
        if timing:
            print(f"\n{label} timing breakdown (ms, per-file avg):")
            for key in (
                "protocol_ms",
                "endpoints_tshark_ms",
                "capinfos_ms",
                "redis_ms",
            ):
                if key in timing:
                    avg_key = f"avg_{key}"
                    print(
                        f"  {key}: total={timing[key]:.1f} "
                        f"avg={timing.get(avg_key, 0):.1f}"
                    )

    # restore fast mode (project default)
    set_scan_mode("fast")


if __name__ == "__main__":
    main()
