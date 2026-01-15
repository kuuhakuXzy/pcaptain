# Apply asynchronous processing (done)
# Apply incremental redis update (done)
# Apply CPU/memory usage limitation for scanning (done)
# Use backoff to check redis status for initial scanning (done)
# Fix some environment errors (done)
# Apply status health check api (done) 
# Apply packets per protocol counting, using t-shark (done)
# Apply fuzzy searching (done)
# Apply configurable mounted directory

import os
import subprocess
import threading
import redis
import json
import hashlib  
import re 
import uuid
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse
from typing import List, Optional, Dict, Any 
from dotenv import load_dotenv
import logging
import asyncio 
import backoff
import time
from concurrent.futures import ThreadPoolExecutor 
from enum import Enum
from fastapi import BackgroundTasks

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__) 

# --- Configuration ---
load_dotenv()

def parse_bool(value: Optional[str], default: bool = False) -> bool:
    """Parse common string booleans with a default fallback."""
    if value is None:
        return default
    normalized = value.strip().lower()
    if normalized in ("1", "true", "yes", "y", "on"):
        return True
    if normalized in ("0", "false", "no", "n", "off"):
        return False
    raise ValueError(f"Invalid boolean value: '{value}'")

def parse_size_bytes(value: Optional[str], default: int) -> int:
    """Parse human-friendly size strings like 500m/1g into bytes."""
    if value is None:
        return default
    stripped = value.strip()
    if not stripped:
        return default
    match = re.fullmatch(r"(?i)\s*(\d+(?:\.\d+)?)\s*([kmgt]?)\s*", stripped)
    if not match:
        raise ValueError(f"Invalid size value: '{value}'")
    number_str, suffix = match.groups()
    number = float(number_str)
    if number < 0:
        raise ValueError(f"Size value must be non-negative: '{value}'")
    multipliers = {
        "": 1,
        "k": 1024,
        "m": 1024 ** 2,
        "g": 1024 ** 3,
        "t": 1024 ** 4,
    }
    multiplier = multipliers[suffix.lower()]
    return int(number * multiplier)

def get_effective_scan_mode(file_size_bytes: int) -> str:
    """Compute whether a file should be scanned in full or quick mode."""
    if not QUICK_SCAN:
        return "full"
    if file_size_bytes < QUICK_SCAN_MIN_FILE_SIZE:
        return "full"
    return "quick"

PCAP_DIRECTORIES_STR = os.getenv("PCAP_MOUNTED_DIRECTORY", "pcaps")
PCAP_DIRECTORIES = [path.strip() for path in PCAP_DIRECTORIES_STR.split(',')]

REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_INTERNAL_PORT", 6379))

BASE_URL = os.getenv("BE_BASE_URL")
BASE_PORT = os.getenv("BE_BASE_PORT")

FULL_BASE_URL = None
if BASE_URL:
    if not BASE_URL.startswith("http://") and not BASE_URL.startswith("https://"):
        BASE_URL = f"http://{BASE_URL}" 
    if BASE_PORT:
        FULL_BASE_URL = f"{BASE_URL}:{BASE_PORT}"
    else:
        FULL_BASE_URL = BASE_URL

AUTOCOMPLETE_KEY = "pcap:protocols:autocomplete"

#--Quick scan config
#--example: QUICK_SCAN=true
#-----QUICK_SCAN_PEBC=0.10
#-----QUICK_SCAN_MIN_FILE_SIZE=50m / 1g / etc.
#-----QUICK_SCAN_CONFIG_VERSION=v1.0

QUICK_SCAN = parse_bool(os.getenv("QUICK_SCAN"), default=False)
QUICK_SCAN_PEBC = float(os.getenv("QUICK_SCAN_PEBC", "1.0"))
if QUICK_SCAN_PEBC <= 0 or QUICK_SCAN_PEBC > 1:
    raise ValueError("QUICK_SCAN_PEBC must be > 0 and <= 1")
QUICK_SCAN_MIN_FILE_SIZE_RAW = os.getenv("QUICK_SCAN_MIN_FILE_SIZE")
QUICK_SCAN_MIN_FILE_SIZE = parse_size_bytes(QUICK_SCAN_MIN_FILE_SIZE_RAW, default=0)
QUICK_SCAN_MIN_FILE_SIZE_DISPLAY = (
    QUICK_SCAN_MIN_FILE_SIZE_RAW.strip()
    if QUICK_SCAN_MIN_FILE_SIZE_RAW and QUICK_SCAN_MIN_FILE_SIZE_RAW.strip()
    else str(QUICK_SCAN_MIN_FILE_SIZE)
)
QUICK_SCAN_CONFIG_VERSION = os.getenv("QUICK_SCAN_CONFIG_VERSION", "v1")

def _normalize_scan_param(value: Optional[str]) -> Optional[str]:
    """Normalize empty strings and whitespace to None."""
    if value is None:
        return None
    stripped = value.strip()
    return stripped if stripped else None

def _parse_pebc(value: Optional[str]) -> Optional[float]:
    """Parse a PEBC string into a float when possible."""
    if value is None:
        return None
    try:
        return float(value)
    except ValueError:
        return None

async def ensure_scan_params(
    pcap_key: str,
    existing: Optional[Dict[str, str]] = None
) -> bool:
    """Ensure scan metadata exists for a pcap key; backfill defaults when missing."""
    if not redis_client:
        return False
    if existing is None:
        try:
            existing = await asyncio.to_thread(redis_client.hgetall, pcap_key)
        except Exception as e:
            logger.warning(f"Failed to read scan params for {pcap_key}: {e}")
            return False
    scan_mode = _normalize_scan_param(existing.get("scan_mode"))
    pebc = _normalize_scan_param(existing.get("pebc"))
    config_version = _normalize_scan_param(existing.get("config_version"))
    if scan_mode and config_version:
        if scan_mode == "full" or pebc is not None:
            return True
    defaults = {
        "scan_mode": "full",
        "config_version": QUICK_SCAN_CONFIG_VERSION,
        "pebc": "",
    }
    await asyncio.to_thread(redis_client.hset, pcap_key, mapping=defaults)
    return False

def should_scan_file(
    current_scan_mode: str,
    current_pebc: Optional[float],
    current_config_version: str,
    stored_scan_mode: Optional[str],
    stored_pebc: Optional[float],
    stored_config_version: Optional[str],
) -> bool:
    """Decide whether a file requires a rescan based on scan parameters."""
    if current_scan_mode == "full" and stored_scan_mode == "quick":
        return True
    if (
        current_scan_mode == "quick"
        and stored_scan_mode == "quick"
        and current_pebc is not None
        and stored_pebc is not None
        and current_pebc > stored_pebc
    ):
        return True
    if current_config_version != stored_config_version:
        return True
    return False

# --- Redis Connection ---
try:
    redis_client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=0, decode_responses=True)
    redis_client.ping()
    logger.info(f"Successfully connected to Redis at {REDIS_HOST}:{REDIS_PORT}")
except redis.exceptions.ConnectionError as e:
    logger.error(f"Could not connect to Redis: {e}")
    redis_client = None

app = FastAPI(
    title="Pcap Catalog Service",
    description="A service to index and search pcap files by protocol using a Redis-native inverted index."
)

executor = ThreadPoolExecutor()


# --- Core Logic ---
def calculate_sha256_sync(file_path: str) -> str:
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

async def calculate_sha256(file_path: str) -> str:
    return await asyncio.to_thread(calculate_sha256_sync, file_path)

def get_protocols_from_pcap_sync(
    pcap_file: str,
    scan_mode: str = "full",
    quick_threshold_bytes: Optional[int] = None
) -> Optional[tuple[Dict[str, int], int]]:
    """Extract protocol counts via tshark with optional quick-scan thresholding."""
    if scan_mode == "quick":
        command = [
            "tshark", "-r", pcap_file,
            "-T", "fields",
            "-e", "frame.len",
            "-e", "frame.protocols",
            "-E", "separator=\t",
        ]
    else:
        command = [
            "tshark", "-r", pcap_file,
            "-T", "fields",
            "-e", "frame.protocols",
        ]

    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        scan_process["tshark"] = process

        protocol_counts: Dict[str, int] = {}

        if scan_mode == "quick":
            bytes_scanned = 0
            packets_scanned = 0
            threshold = quick_threshold_bytes or 0
            threshold_reached = False
            logger.info(
                "Quick scan tshark started for %s (pebc=%s, min_file_size=%s, config_version=%s threshold_bytes=%s)",
                pcap_file,
                QUICK_SCAN_PEBC, 
                QUICK_SCAN_MIN_FILE_SIZE_DISPLAY,
                QUICK_SCAN_CONFIG_VERSION,
                threshold
            )
            if threshold <= 0:
                logger.warning("Quick scan threshold is <= 0 for %s; skipping scan", pcap_file)
                process.terminate()
                return {}, 0

            while True:
                if scan_cancel_event.is_set():
                    logger.info(f"Scan cancellation requested. Terminating tshark for {pcap_file}.")
                    process.terminate()
                    break

                line = process.stdout.readline()
                if line == "":
                    break

                line = line.strip()
                if not line:
                    continue

                parts = line.split("\t", 1)
                if len(parts) != 2:
                    continue

                size_str, protocols_str = parts
                try:
                    packet_size = int(size_str)
                except ValueError:
                    continue

                if bytes_scanned + packet_size > threshold:
                    threshold_reached = True
                    logger.info(
                        "Quick scan threshold reached for %s (bytes_scanned=%s, next_packet=%s, threshold=%s)",
                        pcap_file,
                        bytes_scanned,
                        packet_size,
                        threshold,
                    )
                    break

                bytes_scanned += packet_size
                packets_scanned += 1
                if not protocols_str:
                    continue

                protocols = protocols_str.split(":")
                unique_protocols = set(protocols)
                for proto in unique_protocols:
                    protocol_counts[proto] = protocol_counts.get(proto, 0) + 1

            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()

            if scan_cancel_event.is_set():
                return None
            stderr_output = process.stderr.read() if process.stderr else ""
            if process.returncode not in (0, None) and not threshold_reached:
                stderr_output = stderr_output.strip()
                if stderr_output:
                    logger.error(f"tshark exited with error for {pcap_file}: {stderr_output}")
                return None

            logger.info(
                "Quick scan finished for %s (bytes_scanned=%s, packets_scanned=%s)",
                pcap_file,
                bytes_scanned,
                packets_scanned,
            )
            return protocol_counts, packets_scanned

        stdout_lines: List[str] = []
        stderr_lines: List[str] = []

        def read_stream(stream, sink):
            for line in iter(stream.readline, ''):
                sink.append(line)
            stream.close()

        stdout_thread = threading.Thread(target=read_stream, args=(process.stdout, stdout_lines), daemon=True)
        stderr_thread = threading.Thread(target=read_stream, args=(process.stderr, stderr_lines), daemon=True)
        stdout_thread.start()
        stderr_thread.start()

        while process.poll() is None:
            if scan_cancel_event.is_set():
                logger.info(f"Scan cancellation requested. Terminating tshark for {pcap_file}.")
                process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
                break
            time.sleep(0.1)

        process.wait()
        stdout_thread.join()
        stderr_thread.join()

        if scan_cancel_event.is_set():
            return None

        if process.returncode != 0:
            stderr = "".join(stderr_lines).strip()
            logger.error(f"tshark exited with error for {pcap_file}: {stderr}")
            return None

        output = "".join(stdout_lines).strip()

        if not output:
            return {}, 0

        lines = output.splitlines()
        for line in lines:
            protocols = line.split(":")

            unique_protocols = set(protocols)

            for proto in unique_protocols:
                protocol_counts[proto] = protocol_counts.get(proto, 0) + 1

        return protocol_counts, len(lines)

    except FileNotFoundError:
        logger.error("tshark not found — please install it.")
        return None
    except Exception as e:
        logger.error(f"Unexpected error while analyzing {pcap_file}: {e}")
        return None
    finally:
        scan_process["tshark"] = None

async def get_protocols_from_pcap(
    pcap_file: str,
    scan_mode: str = "full",
    quick_threshold_bytes: Optional[int] = None
) -> Optional[tuple[Dict[str, int], int]]:
    """Async wrapper around tshark protocol extraction."""
    return await asyncio.to_thread(get_protocols_from_pcap_sync, pcap_file, scan_mode, quick_threshold_bytes)


def get_total_packets_from_pcap_sync(pcap_file: str) -> Optional[int]:
    command = ['capinfos', '-c', pcap_file]

    try:
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        if result.returncode != 0:
            stderr = result.stderr.strip()
            logger.error(f"capinfos exited with error for {pcap_file}: {stderr}")
            return None

        match = re.search(r"(?:Number of packets|Packets)\s*[:=]\s*(\d+)", result.stdout)
        if not match:
            logger.error(f"Could not find packet count in capinfos output for {pcap_file}")
            return None

        return int(match.group(1))

    except FileNotFoundError:
        logger.error("capinfos not found — please install it.")
        return None
    except Exception as e:
        logger.error(f"Unexpected error while running capinfos on {pcap_file}: {e}")
        return None

async def get_total_packets_from_pcap(pcap_file: str) -> Optional[int]:
    return await asyncio.to_thread(get_total_packets_from_pcap_sync, pcap_file)

def calculate_protocol_percentages(protocol_counts: Dict[str, int], packets_scanned: int) -> Dict[str, float]:
    """
    Calculates the presence percentage of each protocol relative to scanned packets.
    """
    if not protocol_counts:
        return {}

    if packets_scanned <= 0:
        return {k: 0.0 for k in protocol_counts}

    percentages = {
        proto: round((count / packets_scanned) * 100, 2)
        for proto, count in protocol_counts.items()
    }

    return percentages

async def backfill_total_packets() -> dict:
    if not redis_client:
        return {"error": "Redis connection is not available."}

    keys = await asyncio.to_thread(redis_client.keys, "pcap:file:*")
    processed = 0
    updated = 0
    total = len(keys)

    for key in keys:
        data = await asyncio.to_thread(redis_client.hgetall, key)
        if not data:
            continue

        processed += 1
        existing_total = data.get("total_packets")
        if existing_total not in (None, ""):
            continue

        file_path = data.get("path")
        if not file_path or not await asyncio.to_thread(os.path.exists, file_path):
            logger.warning(f"Missing file for total_packets backfill: {file_path}")
            continue

        total_packets = await get_total_packets_from_pcap(file_path)
        if total_packets is None:
            total_packets = ""

        await asyncio.to_thread(redis_client.hset, key, "total_packets", total_packets)
        updated += 1

    return {"processed": processed, "updated": updated, "total": total}

# --- Indexing Functionality ---
async def scan_and_index(exclude_files: List[str] = None, base_url: str = None, target_folder: Optional[str] = None) -> dict:
    seen_hashes = set()

    if exclude_files is None:
        exclude_files = []
    
    if not redis_client:
        return {"error": "Redis connection is not available."}

    logger.info(f"Starting scan for directories: {PCAP_DIRECTORIES}")
    files_indexed = 0

    found_matching_folder = False

    for pcap_dir in PCAP_DIRECTORIES:
        if scan_cancel_event.is_set():    #cancellation when indexing
            return {"status": "cancelled", "indexed_files": files_indexed}

        if not await asyncio.to_thread(os.path.isdir, pcap_dir):
            logger.warning(f"Directory '{pcap_dir}' does not exist. Skipping.")
            continue

        for root, dirs, files in await asyncio.to_thread(os.walk, pcap_dir):
            if target_folder:
                if os.path.basename(root) != target_folder:
                    continue
                found_matching_folder = True

            for filename in files:
                if scan_cancel_event.is_set():  #cancel scan during the loop
                    return {"status":"cancelled", "indexed_files":files_indexed}

                if filename in exclude_files or not filename.endswith((".pcap", ".pcapng", ".cap")):
                    continue

                file_path = os.path.join(root, filename)

                file_size = await asyncio.to_thread(os.path.getsize, file_path)
                current_scan_mode = get_effective_scan_mode(file_size)
                current_pebc = QUICK_SCAN_PEBC if current_scan_mode == "quick" else None
                current_config_version = QUICK_SCAN_CONFIG_VERSION

                file_hash = await calculate_sha256(file_path)
                if file_hash in seen_hashes:
                    logger.info(f"Skipping {file_path} (duplicate hash already processed in this scan)")
                    continue
                seen_hashes.add(file_hash)

                pcap_key = f"pcap:file:{file_hash}"

                if await asyncio.to_thread(redis_client.exists, pcap_key):
                    existing = await asyncio.to_thread(redis_client.hgetall, pcap_key)
                    stored_path = existing.get("path")
                    if stored_path == file_path:
                        has_params = await ensure_scan_params(pcap_key, existing)
                        if not has_params:
                            await asyncio.to_thread(redis_client.hset, pcap_key, mapping={"last_scanned": time.time()})
                            logger.info(f"Skipping {file_path} (missing scan params; defaulted to full)")
                            continue
                        stored_scan_mode = _normalize_scan_param(existing.get("scan_mode"))
                        stored_pebc = _parse_pebc(_normalize_scan_param(existing.get("pebc")))
                        stored_config_version = _normalize_scan_param(existing.get("config_version"))
                        if not should_scan_file(
                            current_scan_mode=current_scan_mode,
                            current_pebc=current_pebc,
                            current_config_version=current_config_version,
                            stored_scan_mode=stored_scan_mode,
                            stored_pebc=stored_pebc,
                            stored_config_version=stored_config_version,
                        ):
                            await asyncio.to_thread(redis_client.hset, pcap_key, mapping={"last_scanned": time.time()})
                            logger.info(f"Skipping {file_path} (scan params unchanged)")
                            continue
                        logger.info(f"Rescanning {file_path} due to scan-parameter changes")
                    elif await asyncio.to_thread(os.path.exists, stored_path): 
                        await ensure_scan_params(pcap_key, existing)
                        logger.info(f"Duplicate file detected at {stored_path} (hash exists at {file_path})")
                        continue
                    else:
                        logger.info(f"File moved. Updating Redis path for {file_path}")
                        await asyncio.to_thread(redis_client.hset, pcap_key, mapping={
                            "path": file_path,
                            "source_directory": os.path.dirname(file_path),
                            "last_modified": await asyncio.to_thread(os.path.getmtime, file_path)
                        })
                        await ensure_scan_params(pcap_key, existing)
                        continue
                
                quick_threshold_bytes = None
                if current_scan_mode == "quick":
                    quick_threshold_bytes = max(1, int(file_size * QUICK_SCAN_PEBC))
                logger.info(f"Processing file: {file_path}")
                protocol_result = await get_protocols_from_pcap(
                    file_path,
                    scan_mode=current_scan_mode,
                    quick_threshold_bytes=quick_threshold_bytes,
                )

                if protocol_result is not None:
                    protocol_data, packets_scanned = protocol_result
                    if not protocol_data:
                        logger.warning(f"No protocols found in {filename}. Skipping from index.")
                        continue

                    protocol_percentages = calculate_protocol_percentages(protocol_data, packets_scanned)

                    file_size = await asyncio.to_thread(os.path.getsize, file_path)
                    total_packets = await get_total_packets_from_pcap(file_path)
                    if total_packets is None:
                        total_packets = ""

                    file_hash = await calculate_sha256(file_path)
                    pcap_key = f"pcap:file:{file_hash}"

                    if not base_url:
                        base_url = FULL_BASE_URL or None
                    
                    download_url = f"{base_url}/pcaps/download/{file_hash}" if base_url else ""
                    
                    protocols = sorted(list(protocol_data.keys()))

                    current_time = time.time()

                    pipe = redis_client.pipeline()

                    scan_mode = current_scan_mode
                    pebc_value = f"{QUICK_SCAN_PEBC}" if scan_mode == "quick" else ""
                    pipe.hset(pcap_key, mapping={
                        "filename": filename,
                        "source_directory": pcap_dir,
                        "path": file_path,
                        "size_bytes": file_size, 
                        "total_packets": total_packets,
                        "protocols": ",".join(protocols), 
                        "protocol_counts": json.dumps(protocol_data), 
                        "protocol_percentages": json.dumps(protocol_percentages),
                        "packets_scanned": packets_scanned,
                        "download_url": download_url,
                        "last_modified": await asyncio.to_thread(os.path.getmtime, file_path),
                        "last_scanned": current_time,
                        "scan_mode": scan_mode,
                        "pebc": pebc_value,
                        "config_version": QUICK_SCAN_CONFIG_VERSION,
                    })

                    autocomplete_payload = {proto: 0 for proto in protocols}
                    if autocomplete_payload:
                        pipe.zadd(AUTOCOMPLETE_KEY, autocomplete_payload)

                    for proto in protocols:
                        index_key = f"pcap:index:protocol:{proto.lower()}"
                        pipe.sadd(index_key, file_hash)
                    await asyncio.to_thread(pipe.execute)

                    logger.info(f"Indexed file {filename} (hash: {file_hash}) with protocols: {', '.join(protocols)}")
                    files_indexed += 1
                else:
                    logger.warning(f"Skipping file {filename} from index due to processing error.")
        if target_folder and not found_matching_folder:
            logger.warning(f"No folder named '{target_folder}' found under {PCAP_DIRECTORIES}")
            return {"status": "warning", "message": f"No folder named '{target_folder}' found.", "indexed_files": 0}

    logger.info(f"Indexing successful. Processed {files_indexed} files.")
    return {"status": "success", "indexed_files": files_indexed}


from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class ScanState(str, Enum):
    IDLE = "idle"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"  #cancellation status

class BackfillState(str, Enum):
    IDLE = "idle"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"

scan_cancel_event = threading.Event() #monitor cancellation
scan_process = {"tshark": None}

scan_status: Dict[str, Any] = {
    "state": ScanState.IDLE,
    "indexed_files": 0,
    "message": "Ready"
}

backfill_status: Dict[str, Any] = {
    "state": BackfillState.IDLE,
    "processed": 0,
    "updated": 0,
    "total": 0,
    "message": "Ready"
}

def scan_wrapper(exclude_files=None, base_url=None):
    try:

        scan_cancel_event.clear()   

        scan_status["state"] = ScanState.RUNNING
        scan_status["indexed_files"] = 0
        scan_status["message"] = "Scanning in progress..."
        logger.info("Background scan started.")

        result = asyncio.run(scan_and_index(exclude_files=exclude_files, base_url=base_url))
        scan_status["indexed_files"] = result.get("indexed_files", 0)

        if scan_cancel_event.is_set():      #cancellation triggered by user
            scan_status["state"] = ScanState.CANCELLED
            scan_status["message"] = "Scan cancelled by User."
        else:
            scan_status["state"] = ScanState.COMPLETED
            scan_status["message"] = f"Completed successfully. Indexed {scan_status['indexed_files']} files."
            logger.info("Background scan completed.")

    except Exception as e:
        logger.error(f"Scan failed: {e}")
        scan_status["state"] = ScanState.FAILED
        scan_status["message"] = str(e)
    finally:
        if scan_status["state"] == ScanState.COMPLETED:
            scan_status["state"] = ScanState.IDLE

def backfill_wrapper():
    try:
        backfill_status["state"] = BackfillState.RUNNING
        backfill_status["processed"] = 0
        backfill_status["updated"] = 0
        backfill_status["total"] = 0
        backfill_status["message"] = "Backfill in progress..."
        logger.info("Background total_packets backfill started.")

        result = asyncio.run(backfill_total_packets())
        backfill_status["processed"] = result.get("processed", 0)
        backfill_status["updated"] = result.get("updated", 0)
        backfill_status["total"] = result.get("total", 0)

        backfill_status["state"] = BackfillState.COMPLETED
        backfill_status["message"] = (
            "Completed successfully. "
            f"Updated {backfill_status['updated']} of {backfill_status['processed']}."
        )
        logger.info("Background total_packets backfill completed.")

    except Exception as e:
        logger.error(f"Backfill failed: {e}")
        backfill_status["state"] = BackfillState.FAILED
        backfill_status["message"] = str(e)
    finally:
        if backfill_status["state"] == BackfillState.COMPLETED:
            backfill_status["state"] = BackfillState.IDLE

# SCAN SCHEDULER
async def scheduled_scan_loop():
    """Runs in the background and triggers a scan every X seconds."""
    while True:
        try:
            interval = int(os.getenv("SCAN_INTERVAL_SECONDS", 3600))

            await asyncio.sleep(interval)

            if scan_status["state"] == ScanState.IDLE:
                logger.info(f"Starting scheduled scan (Interval: {interval}s)...")
                loop = asyncio.get_running_loop()
                
                await loop.run_in_executor(executor, lambda: scan_wrapper(exclude_files=None, base_url=FULL_BASE_URL))
            else:
                logger.info("Scheduled scan skipped: Scanner is currently busy.")
                
        except Exception as e:
            logger.error(f"Error in scheduled scan loop: {e}")
            await asyncio.sleep(60) 


# --- API Endpoints ---
@app.on_event("startup") 
async def startup_event():
    @backoff.on_exception(backoff.expo, redis.exceptions.ConnectionError, max_tries=5, factor=0.5)
    async def check_redis_for_pcaps():
        if not redis_client:
            raise redis.exceptions.ConnectionError("Redis client not initialized.")
        return await asyncio.to_thread(redis_client.keys, "pcap:file:*")

    if redis_client:
        try:
            existing_pcap_keys = await check_redis_for_pcaps()

            if not await check_redis_for_pcaps():
                logger.info("No indexed pcaps found in Redis. Starting initial scan...")
                loop = asyncio.get_event_loop()
                loop.run_in_executor(executor, lambda: scan_wrapper(exclude_files=None, base_url=FULL_BASE_URL))
            else:
                logger.info(f"Found {len(existing_pcap_keys)} indexed pcaps in Redis. Skipping initial full scan.")
        except Exception as e:
            logger.error(f"Failed to check Redis for existing pcaps during startup: {e}")
    else:
        logger.error("Redis client is not available. Cannot perform startup check or scan.")

    asyncio.create_task(scheduled_scan_loop())

@app.get("/health")
async def health_check():
    return {"status": "OK"}

@app.post("/reindex", summary="Rescan pcap directories and rebuild the index")
async def reindex_pcaps(request: Request, exclude: Optional[List[str]] = Query(None)):
    if scan_status["state"] == ScanState.RUNNING:
        return JSONResponse(content={"status": "busy", "message": "A scan is already running."}, status_code=409)
    base_url = FULL_BASE_URL or str(request.base_url).rstrip("/")
    loop = asyncio.get_event_loop()
    loop.run_in_executor(executor, lambda: scan_wrapper(exclude_files=exclude, base_url=base_url))
    return JSONResponse(content={"status": "started"})

@app.get("/scan-status")
async def scan_status_endpoint():
    return scan_status

@app.get("/scan-config")
async def scan_config():
    """Expose current runtime scan configuration."""
    return {
        "scan_mode": "quick" if QUICK_SCAN else "full",
        "pebc": QUICK_SCAN_PEBC if QUICK_SCAN else None,
        "min_file_size": QUICK_SCAN_MIN_FILE_SIZE_DISPLAY,
        "config_version": QUICK_SCAN_CONFIG_VERSION,
    }
@app.post("/backfill/total-packets", summary="Backfill total packet counts for existing pcaps")
async def backfill_total_packets_endpoint():
    if backfill_status["state"] == BackfillState.RUNNING:
        return JSONResponse(content={"status": "busy", "message": "A backfill is already running."}, status_code=409)
    loop = asyncio.get_event_loop()
    loop.run_in_executor(executor, backfill_wrapper)
    return JSONResponse(content={"status": "started"})

@app.get("/backfill-status")
async def backfill_status_endpoint():
    return backfill_status

@app.post("/reindex/{folder_name}", summary="Reindex a specific folder under PCAP directories")
async def reindex_specific_folder(folder_name: str, request: Request, exclude: Optional[List[str]] = Query(None)):
    base_url = str(request.base_url).rstrip("/")
    result = await scan_and_index(exclude_files=exclude, base_url=base_url, target_folder=folder_name)
    if "error" in result:
        raise HTTPException(status_code=500, detail=result["error"])
    return JSONResponse(content=result)

class SortField(str, Enum):
    filename = "filename"
    size = "size_bytes"
    count = "protocol_packet_count"
    path = "path"

@app.get("/search", summary="Search for pcaps containing a specific protocol")
async def search_pcaps(
    protocol: str = Query(..., description="The protocol name to search for, e.g., sip"),
    page: int = Query(1, ge=1, description="Page number"),
    limit: int = Query(10, ge=1, le=100, description="Items per page"),
    sort_by: SortField = Query(SortField.filename, description="Field to sort by"),
    descending: bool = Query(False, description="Sort in descending order")
):
    if not redis_client:
        raise HTTPException(status_code=503, detail="Service unavailable: Redis connection failed.")

    index_key = f"pcap:index:protocol:{protocol.lower()}"

    try:
        matching_hashes = await asyncio.to_thread(redis_client.smembers, index_key)
        if not matching_hashes:
            return {"total": 0, "page": page, "limit": limit, "data": []}

        matching_hashes = list(matching_hashes)
        pipe = redis_client.pipeline()
        for file_hash in matching_hashes:
            pipe.hgetall(f"pcap:file:{file_hash}")
        raw_results = await asyncio.to_thread(pipe.execute)
        
        results = []
        for file_hash, pcap_data in zip(matching_hashes, raw_results):
            if pcap_data:
                counts_str = pcap_data.pop("protocol_counts", None)
                packet_count = 0
                if counts_str:
                    try:
                        counts_dict = json.loads(counts_str)
                        packet_count = counts_dict.get(protocol, 0)
                    except json.JSONDecodeError:
                        logger.warning(f"Could not parse protocol_counts")
                
                scan_mode = _normalize_scan_param(pcap_data.get("scan_mode"))
                pebc = _normalize_scan_param(pcap_data.get("pebc"))
                config_version = _normalize_scan_param(pcap_data.get("config_version"))
                if not scan_mode or not config_version or (scan_mode != "full" and pebc is None):
                    defaults = {
                        "scan_mode": "full",
                        "pebc": "",
                        "config_version": QUICK_SCAN_CONFIG_VERSION,
                    }
                    await asyncio.to_thread(redis_client.hset, f"pcap:file:{file_hash}", mapping=defaults)
                    scan_mode = defaults["scan_mode"]
                    pebc = defaults["pebc"]
                    config_version = defaults["config_version"]

                pcap_data["scan_mode"] = scan_mode
                pcap_data["pebc"] = pebc
                pcap_data["config_version"] = config_version
                pcap_data["searched_protocol"] = protocol
                pcap_data["protocol_packet_count"] = packet_count
                results.append(pcap_data)

        # SORTING LOGIC
        def get_sort_key(item):
            val = item.get(sort_by.value)
            if sort_by in [SortField.size, SortField.count]:
                try:
                    return int(val)
                except (ValueError, TypeError):
                    return 0
            return str(val).lower()

        results.sort(key=get_sort_key, reverse=descending)

        # PAGINATION LOGIC
        total_items = len(results)
        start_index = (page - 1) * limit
        end_index = start_index + limit
        paginated_data = results[start_index:end_index]

        return {
            "total": total_items,
            "page": page,
            "limit": limit,
            "data": paginated_data
        }

    except Exception as e:
        logger.error(f"Search error: {e}")
        raise HTTPException(status_code=500, detail=f"An error occurred while querying Redis: {e}")

@app.get("/protocols/suggest", summary="Get protocol name suggestions for autocomplete")
async def suggest_protocols(
    q: str = Query(..., min_length=1, description="The prefix text to search for (e.g., 'ht' or 'tc')")
):
    if not redis_client:
        raise HTTPException(status_code=503, detail="Service unavailable: Redis connection failed.")

    try:
        start_range = f"[{q}"
        end_range = f"[{q}\xff"

        suggestions = await asyncio.to_thread(
            redis_client.zrangebylex, AUTOCOMPLETE_KEY, start_range, end_range, start=0, num=10
        )
        return suggestions
    except Exception as e:
        logger.error(f"Error during protocol suggestion: {e}")
        raise HTTPException(status_code=500, detail="An error occurred while fetching suggestions.")

@app.get("/pcaps/download/{file_hash}", summary="Download a specific pcap file by hash")
async def download_pcap_by_hash(file_hash: str):
    if not redis_client:
        raise HTTPException(status_code=503, detail="Service unavailable: Redis connection failed.")

    file_metadata = await asyncio.to_thread(redis_client.hgetall, f"pcap:file:{file_hash}")
    if not file_metadata:
        raise HTTPException(status_code=404, detail="File not found")

    file_path = file_metadata.get("path")
    filename = file_metadata.get("filename")

    abs_path = await asyncio.to_thread(os.path.abspath, file_path)
    allowed_abs_dirs = [await asyncio.to_thread(os.path.abspath, d) for d in PCAP_DIRECTORIES]
    if not any(abs_path.startswith(d) for d in allowed_abs_dirs):
        raise HTTPException(status_code=403, detail="Forbidden: Access is denied.")
    
    return FileResponse(abs_path, media_type='application/vnd.tcpdump.pcap', filename=filename)

def remove_file(path: str):
    try:
        os.remove(path)
        logger.info(f"Cleaned up temporary file: {path}")
    except Exception as e:
        logger.error(f"Error deleting temporary file {path}: {e}")

@app.get("/pcaps/download/{file_hash}/filter", summary="Download a filtered subset of a pcap")
async def download_filtered_pcap(
    file_hash: str, 
    protocol: str, 
    background_tasks: BackgroundTasks
):
    if not redis_client:
        raise HTTPException(status_code=503, detail="Service unavailable")

    file_metadata = await asyncio.to_thread(redis_client.hgetall, f"pcap:file:{file_hash}")
    if not file_metadata:
        raise HTTPException(status_code=404, detail="File not found")
    
    original_path = file_metadata.get("path")
    original_filename = file_metadata.get("filename")
    packets_scanned_raw = file_metadata.get("packets_scanned")
    try:
        packets_scanned = int(packets_scanned_raw) if packets_scanned_raw else 0
    except (TypeError, ValueError):
        packets_scanned = 0
    
    if not re.match(r"^[a-zA-Z0-9_.-]+$", protocol):
        raise HTTPException(status_code=400, detail="Invalid protocol format")

    temp_filename = f"filtered_{protocol}_{uuid.uuid4()}.pcap"
    temp_filepath = f"/tmp/{temp_filename}"

    cmd = [
        "tshark",
        "-r", original_path,
    ]
    # Limit filtering to the same packet window used during scanning.
    if packets_scanned > 0:
        cmd.extend(["-c", str(packets_scanned)])
    cmd.extend([
        "-Y", protocol,
        "-w", temp_filepath
    ])

    logger.info(f"Starting filtered export: {' '.join(cmd)}")

    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await process.communicate()

        if process.returncode != 0:
            logger.error(f"Tshark filter failed: {stderr.decode()}")
            raise HTTPException(status_code=500, detail="Failed to filter pcap file.")
            
        if not os.path.exists(temp_filepath) or os.path.getsize(temp_filepath) == 0:
             raise HTTPException(status_code=404, detail=f"No packets found for protocol '{protocol}'")

    except Exception as e:
        logger.error(f"Error executing tshark: {e}")
        # Clean up if it failed halfway
        if os.path.exists(temp_filepath):
            os.remove(temp_filepath)
        raise HTTPException(status_code=500, detail="Internal Server Error during filtering")

    background_tasks.add_task(remove_file, temp_filepath)

    return FileResponse(
        temp_filepath, 
        media_type='application/vnd.tcpdump.pcap', 
        filename=f"subset_{protocol}_{original_filename}"
    )

@app.post("/scan-cancel", summary="Cancel the current scan")   
async def cancel_scan():
    """To flag the event of scan cancellation"""

    if scan_status["state"] != ScanState.RUNNING:
        raise HTTPException(status_code=409, detail="No scan is running to be cancelled")

    scan_cancel_event.set()

    proc = scan_process.get("tshark")
    if proc and proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()


    scan_status["state"] = ScanState.CANCELLED
    scan_status["message"] = "Scan cancelled by user"
    return {"status": "cancelled"}
    
