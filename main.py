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

# --- Configuration ---
load_dotenv()

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

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__) 

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

def get_protocols_from_pcap_sync(pcap_file: str) -> Optional[Dict[str, int]]:
    command = [
        'tshark', '-r', pcap_file,
        '-T', 'fields',
        '-e', 'frame.protocols'
    ]

    try:
        result = subprocess.run(command, capture_output=True, text=True)

        if result.returncode != 0:
            logger.error(f"tshark exited with error for {pcap_file}: {result.stderr}")
            return None

        output = result.stdout.strip()
        if not output:
            return {}

        protocol_counts: Dict[str, int] = {}

        for line in output.splitlines():
            protocols = line.split(":")

            unique_protocols = set(protocols)

            for proto in unique_protocols:
                protocol_counts[proto] = protocol_counts.get(proto, 0) + 1

        return protocol_counts

    except FileNotFoundError:
        logger.error("tshark not found — please install it.")
        return None
    except Exception as e:
        logger.error(f"Unexpected error while analyzing {pcap_file}: {e}")
        return None

async def get_protocols_from_pcap(pcap_file: str) -> Optional[Dict[str, int]]:
    return await asyncio.to_thread(get_protocols_from_pcap_sync, pcap_file)

def calculate_protocol_percentages(protocol_counts: Dict[str, int]) -> Dict[str, float]:
    """
    Calculates the presence percentage of each protocol relative to the total file.
    """
    if not protocol_counts:
        return {}

    total_packets = max(protocol_counts.values())

    if total_packets == 0:
        return {k: 0.0 for k in protocol_counts}

    percentages = {
        proto: round((count / total_packets) * 100, 2) 
        for proto, count in protocol_counts.items()
    }
    
    return percentages

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
        if not await asyncio.to_thread(os.path.isdir, pcap_dir):
            logger.warning(f"Directory '{pcap_dir}' does not exist. Skipping.")
            continue

        for root, dirs, files in await asyncio.to_thread(os.walk, pcap_dir):
            if target_folder:
                if os.path.basename(root) != target_folder:
                    continue
                found_matching_folder = True

            for filename in files:
                if filename in exclude_files or not filename.endswith((".pcap", ".pcapng", ".cap")):
                    continue

                file_path = os.path.join(root, filename)

                file_hash = await calculate_sha256(file_path)
                if file_hash in seen_hashes:
                    logger.info(f"Skipping {file_path} (duplicate hash already processed in this scan)")
                    continue
                seen_hashes.add(file_hash)

                pcap_key = f"pcap:file:{file_hash}"

                if await asyncio.to_thread(redis_client.exists, pcap_key):
                    stored_path = await asyncio.to_thread(redis_client.hget, pcap_key, "path")
                    if stored_path == file_path:
                        await asyncio.to_thread(redis_client.hset, pcap_key, mapping={"last_scanned": time.time()})
                        logger.info(f"Skipping {file_path} (already indexed and unchanged)")
                        continue
                    elif await asyncio.to_thread(os.path.exists, stored_path): 
                        logger.info(f"Duplicate file detected at {stored_path} (hash exists at {file_path})")
                        continue
                    else:
                        logger.info(f"File moved. Updating Redis path for {file_path}")
                        await asyncio.to_thread(redis_client.hset, pcap_key, mapping={
                            "path": file_path,
                            "source_directory": os.path.dirname(file_path),
                            "last_modified": await asyncio.to_thread(os.path.getmtime, file_path)
                        })
                        continue
                
                logger.info(f"Processing file: {file_path}")
                protocol_data = await get_protocols_from_pcap(file_path)

                if protocol_data is not None:
                    if not protocol_data:
                        logger.warning(f"No protocols found in {filename}. Skipping from index.")
                        continue

                    protocol_percentages = calculate_protocol_percentages(protocol_data)

                    file_size = await asyncio.to_thread(os.path.getsize, file_path)

                    file_hash = await calculate_sha256(file_path)
                    pcap_key = f"pcap:file:{file_hash}"

                    if not base_url:
                        base_url = FULL_BASE_URL or None
                    
                    download_url = f"{base_url}/pcaps/download/{file_hash}" if base_url else ""
                    
                    protocols = sorted(list(protocol_data.keys()))

                    current_time = time.time()

                    pipe = redis_client.pipeline()

                    pipe.hset(pcap_key, mapping={
                        "filename": filename,
                        "source_directory": pcap_dir,
                        "path": file_path,
                        "size_bytes": file_size, 
                        "protocols": ",".join(protocols), 
                        "protocol_counts": json.dumps(protocol_data), 
                        "protocol_percentages": json.dumps(protocol_percentages),
                        "download_url": download_url,
                        "last_modified": await asyncio.to_thread(os.path.getmtime, file_path),
                        "last_scanned": current_time,
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

scan_status: Dict[str, Any] = {
    "state": ScanState.IDLE,
    "indexed_files": 0,
    "message": "Ready"
}

def scan_wrapper(exclude_files=None, base_url=None):
    try:
        scan_status["state"] = ScanState.RUNNING
        scan_status["indexed_files"] = 0
        scan_status["message"] = "Scanning in progress..."
        logger.info("Background scan started.")

        result = asyncio.run(scan_and_index(exclude_files=exclude_files, base_url=base_url))
        scan_status["indexed_files"] = result.get("indexed_files", 0)
        scan_status["state"] = ScanState.COMPLETED
        scan_status["message"] = f"Completed successfully. Indexed {scan_status['indexed_files']} files."
        logger.info("Background scan completed.")
    except Exception as e:
        logger.error(f"Scan failed: {e}")
        scan_status["state"] = ScanState.FAILED
        scan_status["message"] = str(e)
    finally:
        if scan_status["state"] != ScanState.FAILED:
            scan_status["state"] = ScanState.IDLE

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

        pipe = redis_client.pipeline()
        for file_hash in matching_hashes:
            pipe.hgetall(f"pcap:file:{file_hash}")
        raw_results = await asyncio.to_thread(pipe.execute)
        
        results = []
        for pcap_data in raw_results:
            if pcap_data:
                counts_str = pcap_data.pop("protocol_counts", None)
                packet_count = 0
                if counts_str:
                    try:
                        counts_dict = json.loads(counts_str)
                        packet_count = counts_dict.get(protocol, 0)
                    except json.JSONDecodeError:
                        logger.warning(f"Could not parse protocol_counts")
                
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
    
    if not re.match(r"^[a-zA-Z0-9_.-]+$", protocol):
        raise HTTPException(status_code=400, detail="Invalid protocol format")

    temp_filename = f"filtered_{protocol}_{uuid.uuid4()}.pcap"
    temp_filepath = f"/tmp/{temp_filename}"

    cmd = [
        "tshark",
        "-r", original_path,
        "-Y", protocol,       
        "-w", temp_filepath   
    ]

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
