import os
import subprocess
import redis
import json
import hashlib  
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse
from typing import List, Optional
import logging

# --- Configuration ---
PCAP_DIRECTORIES_STR = os.getenv("PCAP_DIRECTORIES", "pcaps")
PCAP_DIRECTORIES = [path.strip() for path in PCAP_DIRECTORIES_STR.split(',')]

REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = 6379

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

# --- Core Logic ---
def calculate_sha256(file_path: str) -> str:
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def get_protocols_from_pcap(pcap_file: str) -> Optional[List[str]]:
    command = ['tshark', '-r', pcap_file, '-T', 'fields', '-e', 'frame.protocols']
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        unique_protocols = set()
        output = result.stdout.strip()
        if not output: 
            return []
        for line in output.splitlines():
            protocols_in_frame = line.strip().split(':')
            unique_protocols.update(p for p in protocols_in_frame if p)
        return sorted(list(unique_protocols))
    except subprocess.CalledProcessError as e:
        logger.error(f"Error analyzing {pcap_file}: {e.stderr.strip()}")
        return None

# --- Indexing Functionality ---
def scan_and_index(exclude_files: List[str] = None, base_url: str = None, target_folder: Optional[str] = None) -> dict:
    seen_hashes = set()

    if exclude_files is None:
        exclude_files = []
    
    if not redis_client:
        return {"error": "Redis connection is not available."}

    logger.info(f"Starting scan for directories: {PCAP_DIRECTORIES}")
    files_indexed = 0

    
    with redis_client.pipeline() as pipe:
        found_matching_folder = False

        for pcap_dir in PCAP_DIRECTORIES:
            if not os.path.isdir(pcap_dir):
                logger.warning(f"Directory '{pcap_dir}' does not exist. Skipping.")
                continue

            for root, dirs, files in os.walk(pcap_dir):
                if target_folder:
                    if os.path.basename(root) != target_folder:
                        continue
                    found_matching_folder = True

                for filename in files:
                    if filename in exclude_files or not filename.endswith((".pcap", ".pcapng", ".cap")):
                        continue

                    file_path = os.path.join(root, filename)

                    file_hash = calculate_sha256(file_path)
                    if file_hash in seen_hashes:
                        logger.info(f"Skipping {file_path} (duplicate hash already processed in this scan)")
                        continue
                    seen_hashes.add(file_hash)

                    pcap_key = f"pcap:file:{file_hash}"
                    if redis_client.exists(pcap_key):
                        stored_path = redis_client.hget(pcap_key, "path")

                        if stored_path == file_path:
                            logger.info(f"Skipping {file_path} (already indexed and unchanged)")
                            continue

                        elif os.path.exists(stored_path):
                            logger.info(f"Duplicate file detected at {stored_path} (hash exists at {file_path})")
                            continue

                        else:
                            logger.info(f"File moved. Updating Redis path for {file_path}")
                            redis_client.hset(pcap_key, mapping={
                                "path": file_path,
                                "source_directory": os.path.dirname(file_path),
                                "last_modified": os.path.getmtime(file_path)
                            })
                            continue
                    
                    logger.info(f"Processing file: {file_path}")
                    protocols = get_protocols_from_pcap(file_path)

                    if protocols is not None:
                        file_hash = calculate_sha256(file_path)
                        pcap_key = f"pcap:file:{file_hash}"

                        download_url = None
                        if base_url:
                            download_url = f"{base_url}/pcaps/download/{file_hash}"

                       
                        pipe.hset(pcap_key, mapping={
                            "filename": filename,
                            "source_directory": pcap_dir,
                            "path": file_path,
                            "size_bytes": os.path.getsize(file_path),
                            "protocols": ",".join(protocols), 
                            "last_modified": os.path.getmtime(file_path), 
                            "download_url": download_url or ""
                        })

                        for proto in protocols:
                            index_key = f"pcap:index:protocol:{proto.lower()}"
                            pipe.sadd(index_key, file_hash)
                        
                        files_indexed += 1
                    else:
                        logger.warning(f"Skipping file {filename} from index due to processing error.")
        if target_folder and not found_matching_folder:
            logger.warning(f"No folder named '{target_folder}' found under {PCAP_DIRECTORIES}")
            return {"status": "warning", "message": f"No folder named '{target_folder}' found.", "indexed_files": 0}

        
        pipe.execute()
        
    logger.info(f"Indexing successful. Processed {files_indexed} files.")
    return {"status": "success", "indexed_files": files_indexed}

from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(
    title="Pcap Catalog Service",
    description="A service to index and search pcap files by a Redis-native inverted index."
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- API Endpoints ---
@app.on_event("startup")
async def startup_event():
    if redis_client and not redis_client.keys("pcap:file:*"):
        logger.info("No indexed pcaps found in Redis. Starting initial scan...")
        scan_and_index()

@app.post("/reindex", summary="Rescan pcap directories and rebuild the index")
async def reindex_pcaps(request: Request, exclude: Optional[List[str]] = Query(None, description="List of files excluded from scanning.")):
    base_url = str(request.base_url).rstrip("/")
    result = scan_and_index(exclude_files=exclude, base_url=base_url)
    if "error" in result:
        raise HTTPException(status_code=500, detail=result["error"])
    return JSONResponse(content=result)

@app.post("/reindex/{folder_name}", summary="Reindex a specific folder under PCAP directories")
async def reindex_specific_folder(folder_name: str, request: Request, exclude: Optional[List[str]] = Query(None)):
    base_url = str(request.base_url).rstrip("/")
    result = scan_and_index(exclude_files=exclude, base_url=base_url, target_folder=folder_name)
    if "error" in result:
        raise HTTPException(status_code=500, detail=result["error"])
    return JSONResponse(content=result)


@app.get("/search", summary="Search for pcaps containing a specific protocol")
async def search_pcaps(protocol: str = Query(..., description="The protocol name to search for, e.g., sip")):
    if not redis_client:
        raise HTTPException(status_code=503, detail="Service unavailable: Redis connection failed.")

    index_key = f"pcap:index:protocol:{protocol.lower()}"

    try:
        matching_hashes = redis_client.smembers(index_key)

        if not matching_hashes:
            return []

        results = []
        with redis_client.pipeline() as pipe:
            for file_hash in matching_hashes:
                pipe.hgetall(f"pcap:file:{file_hash}")
            
            results = pipe.execute()
        
        return results
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"An error occurred while querying Redis: {e}")

@app.get("/pcaps/download/{file_hash}", summary="Download a specific pcap file by hash")
async def download_pcap_by_hash(file_hash: str):
    if not redis_client:
        raise HTTPException(status_code=503, detail="Service unavailable: Redis connection failed.")

    file_metadata = redis_client.hgetall(f"pcap:file:{file_hash}")  
    if not file_metadata:
        raise HTTPException(status_code=404, detail="File not found")

    file_path = file_metadata.get("path")
    filename = file_metadata.get("filename")

    abs_path = os.path.abspath(file_path)
    allowed_abs_dirs = [os.path.abspath(d) for d in PCAP_DIRECTORIES]
    if not any(abs_path.startswith(d) for d in allowed_abs_dirs):
        raise HTTPException(status_code=403, detail="Forbidden: Access is denied.")
    
    return FileResponse(abs_path, media_type='application/vnd.tcpdump.pcap', filename=filename)
    
