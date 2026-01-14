from enum import Enum
import json
import os
import threading
from typing import Any, Dict, Optional, List
from threading import Event
import hashlib
import asyncio
import subprocess
import time
import threading

from redis import Redis

from .logger import get_logger
from .context import AppContext, with_app_context

logger = get_logger(__name__)


AUTOCOMPLETE_KEY = "pcap:protocols:autocomplete"
# Index keys
PCAP_FILE_KEY_PREFIX = "pcap:file"
PROTOCOCOL_INDEX_PREFIX = "pcap:index:protocol"

SORT_INDEX_PREFIX = "pcap:sort"

SORT_INDEX_FILENAME = f"{SORT_INDEX_PREFIX}:filename"
SORT_INDEX_PATH = f"{SORT_INDEX_PREFIX}:path"
SORT_INDEX_SIZE = f"{SORT_INDEX_PREFIX}:size_bytes"
SORT_INDEX_PACKET_COUNT = f"{SORT_INDEX_PREFIX}:protocol_packet_count"

LEX_INDEX_FILENAME = "pcap:lex:filename"
LEX_INDEX_PATH = "pcap:lex:path"

REBUILD_LOCK = "pcap:lex:rebuild:lock"
REBUILD_DIRTY = "pcap:lex:dirty"

# Temporary keys
TMP_RESULT_PREFIX = "pcap:tmp:search"
TMP_KEY_TTL_SECONDS = 5


def calculate_sha256_sync(file_path: str) -> str:
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


async def calculate_sha256(file_path: str) -> str:
    return await asyncio.to_thread(calculate_sha256_sync, file_path)


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


def check_cancellation(cancel_event: Optional[Event]):
    """Check if cancellation has been requested and raise CancelledError if so."""
    if cancel_event and cancel_event.is_set():
        logger.info("Scan cancelled by user")
        raise asyncio.CancelledError("Scan cancelled by user")


async def get_all_protocols(redis: Redis):
    # ZSET → list[str]
    return await asyncio.to_thread(redis.zrange, AUTOCOMPLETE_KEY, 0, -1)


class ScanState(str, Enum):
    IDLE = "idle"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class ScanService:
    scan_status: Dict[str, Any] = {
        "state": ScanState.IDLE,
        "indexed_files": 0,
        "message": "Ready",
    }
    scan_cancel_event = Event()
    scan_process: Dict[str, Optional[subprocess.Popen]] = {"tshark": None}
    
    @staticmethod
    async def should_scan(redis_client, pcap_key: str, current_scan_mode: str) -> bool:
        """Check if file should be rescanned based on stored vs current scan_mode.
        
        Returns True if:
        - File doesn't exist in Redis
        - Stored scan_mode is 'fast' and current is 'normal' (need full rescan)
        """
        if not await asyncio.to_thread(redis_client.exists, pcap_key):
            return True
        
        stored_scan_mode = await asyncio.to_thread(redis_client.hget, pcap_key, "scan_mode")
        
        if stored_scan_mode is None:
            # Old data without scan_mode, rescan
            return True
        
        if isinstance(stored_scan_mode, bytes):
            stored_scan_mode = stored_scan_mode.decode('utf-8')
        
        # If stored is 'fast' and current is 'normal', we need full rescan
        if stored_scan_mode == "fast" and current_scan_mode == "normal":
            return True
        
        # Otherwise, don't rescan (same mode or downgrading to fast)
        return False

    @with_app_context
    async def scan_and_index(
        self,
        exclude_files: List[str] = None,
        target_folder: Optional[str] = None,
        *,
        context: AppContext = None,
    ) -> dict:
        seen_hashes = set()

        if exclude_files is None:
            exclude_files = []

        redis_client = context.redis_client
        config = context.config
        if not redis_client:
            return {"error": "Redis connection is not available."}

        logger.info(
            f"Starting scan for directories: {config.pcap.root_directory} with exclusions: {exclude_files}"
        )
        files_indexed = 0

        found_matching_folder = False

        try:
            check_cancellation(self.scan_cancel_event)
            if not await asyncio.to_thread(os.path.isdir, config.pcap.root_directory):
                logger.warning(f"Directory '{config.pcap.root_directory}' does not exist. Skipping.")
                return { "status": "warning", "message": f"Directory '{config.pcap.root_directory}' does not exist.", "indexed_files": 0 }
        
            for root, dirs, files in await asyncio.to_thread(os.walk, config.pcap.root_directory):
                check_cancellation(self.scan_cancel_event)

                if target_folder:
                    if os.path.basename(root) != target_folder:
                        continue
                    found_matching_folder = True

                for filename in files:
                    check_cancellation(self.scan_cancel_event)

                    if filename in exclude_files or not filename.endswith(
                        tuple(config.pcap.allowed_file_extensions)
                    ):
                        continue

                    file_path = os.path.join(root, filename)

                    file_hash = await calculate_sha256(file_path)
                    if file_hash in seen_hashes:
                        logger.info(
                            f"Skipping {file_path} (duplicate hash already processed in this scan)"
                        )
                        continue
                    seen_hashes.add(file_hash)

                    pcap_key = f"{PCAP_FILE_KEY_PREFIX}:{file_hash}"
                    current_scan_mode = config.pcap.scan_mode.value

                    if await asyncio.to_thread(redis_client.exists, pcap_key):
                        stored_path = await asyncio.to_thread(
                            redis_client.hget, pcap_key, "path"
                        )
                        if stored_path == file_path:
                            # Check if we need to rescan based on scan_mode
                            if await self.should_scan(redis_client, pcap_key, current_scan_mode):
                                logger.info(
                                    f"Rescanning {file_path} due to scan_mode change"
                                )
                            else:
                                await asyncio.to_thread(
                                    redis_client.hset,
                                    pcap_key,
                                    mapping={"last_scanned": time.time()},
                                )
                                logger.info(
                                    f"Skipping {file_path} (already indexed and unchanged)"
                                )
                                continue
                        elif await asyncio.to_thread(os.path.exists, stored_path):
                            logger.info(
                                f"Duplicate file detected at {stored_path} (hash exists at {file_path})"
                            )
                            continue
                        else:
                            logger.info(
                                f"File moved. Updating Redis path for {file_path}"
                            )
                            await asyncio.to_thread(
                                redis_client.hset,
                                pcap_key,
                                mapping={
                                    "path": file_path,
                                    "CancelledErrorsource_directory": os.path.dirname(
                                        file_path
                                    ),
                                    "last_modified": await asyncio.to_thread(
                                        os.path.getmtime, file_path
                                    ),
                                },
                            )
                            continue

                    logger.info(f"Processing file: {file_path} (scan_mode: {current_scan_mode})")
                    protocol_data = await self.get_protocols_from_pcap(
                        file_path, 
                        excluded_protocols=config.pcap.excluded_protocols,
                        scan_mode=current_scan_mode
                    )

                    if protocol_data is not None:
                        if not protocol_data:
                            logger.warning(
                                f"No protocols found in {filename}. Skipping from index."
                            )
                            continue

                        protocol_percentages = calculate_protocol_percentages(
                            protocol_data
                        )

                        file_size = await asyncio.to_thread(
                            os.path.getsize, file_path
                        )

                        file_hash = await calculate_sha256(file_path)
                        pcap_key = f"{PCAP_FILE_KEY_PREFIX}:{file_hash}"

                        protocols = sorted(list(protocol_data.keys()))
                        download_url = f"{context.config.public_url}/pcaps/download/{file_hash}"
                        protocol_packet_count = sum(protocol_data.values())
                        filename_norm = filename.lower()
                        path_norm = file_path.lower()

                        current_time = time.time()

                        pipe = redis_client.pipeline()

                        pipe.hset(
                            pcap_key,
                            mapping={
                                "filename": filename,
                                "filename_sort": filename_norm,
                                "source_directory": os.path.dirname(file_path),
                                "path": file_path,
                                "path_sort": path_norm,
                                "size_bytes": file_size,
                                "download_url": download_url,
                                "protocols": " ".join(protocols),
                                "protocol_packet_count": protocol_packet_count,
                                "protocol_counts": json.dumps(protocol_data),
                                "protocol_percentages": json.dumps(
                                    protocol_percentages
                                ),
                                "last_modified": await asyncio.to_thread(
                                    os.path.getmtime, file_path
                                ),
                                "last_scanned": current_time,
                                "scan_mode": current_scan_mode,
                            },
                        )

                        autocomplete_payload = {proto: 0 for proto in protocols}
                        if autocomplete_payload:
                            pipe.zadd(AUTOCOMPLETE_KEY, autocomplete_payload)

                        for proto in protocols:
                            index_key = f"{PROTOCOCOL_INDEX_PREFIX}:{proto.lower()}"
                            pipe.sadd(index_key, file_hash)
                        
                        # ---- LEXICOGRAPHICAL INDEXES ----
                        pipe.zadd(LEX_INDEX_FILENAME, {filename_norm: 0}, nx=True)
                        pipe.zadd(LEX_INDEX_PATH, {path_norm: 0}, nx=True)

                        # ---- SORT INDEXES ----
                        # Numeric sort (true score)
                        pipe.zadd(SORT_INDEX_SIZE, {file_hash: file_size})

                        pipe.zadd(SORT_INDEX_PACKET_COUNT, {file_hash: protocol_packet_count})

                        pipe.zadd(SORT_INDEX_FILENAME, {file_hash: 0}) # placeholder
                        pipe.zadd(SORT_INDEX_PATH, {file_hash: 0})

                        await asyncio.to_thread(pipe.execute)

                        logger.info(
                            f"Indexed file {filename} (hash: {file_hash}) with protocols: {', '.join(protocols)}"
                        )
                        files_indexed += 1
                    else:
                        logger.warning(
                            f"Skipping file {filename} from index due to processing error."
                        )
                
                if target_folder and not found_matching_folder:
                    logger.warning(
                        f"No folder named '{target_folder}' found under {config.pcap.root_directory}."
                    )
                    return {
                        "status": "warning",
                        "message": f"No folder named '{target_folder}' found.",
                        "indexed_files": 0,
                    }

            logger.info(f"Indexing successful. Processed {files_indexed} files.")
            return {"status": "success", "indexed_files": files_indexed}

        except asyncio.CancelledError:
            logger.info(
                f"Scan cancelled. Indexed {files_indexed} files before cancellation."
            )
            return {"status": "cancelled", "indexed_files": files_indexed}

    @with_app_context
    def scan_wrapper(self, exclude_files=None, *, context: AppContext = None):
        redis = context.redis_client
        if not redis:
            logger.error("Redis connection is not available. Scan aborted.")
            return
        
        try:
            # dirty the lex indexes
            redis.set(REBUILD_DIRTY, 1)

            self.scan_status["state"] = ScanState.RUNNING
            self.scan_status["indexed_files"] = 0
            self.scan_status["message"] = "Scanning in progress..."
            logger.info("Background scan started.")

            result = asyncio.run(
                self.scan_and_index(exclude_files=exclude_files)
            )
            self.scan_status["indexed_files"] = result.get("indexed_files", 0)

            if result.get("status") == "cancelled":
                self.scan_status["state"] = ScanState.IDLE
                self.scan_status["message"] = (
                    f"Scan cancelled. Indexed {self.scan_status['indexed_files']} files before cancellation."
                )
                logger.info("Background scan cancelled.")
            else:
                self.scan_status["state"] = ScanState.COMPLETED
                self.scan_status["message"] = (
                    f"Completed successfully. Indexed {self.scan_status['indexed_files']} files."
                )
                logger.info("Background scan completed.")
        except Exception as e:
            logger.error(f"Scan failed: {e}")
            self.scan_status["state"] = ScanState.FAILED
            self.scan_status["message"] = str(e)
        finally:
            if (
                self.scan_status["state"] != ScanState.FAILED
                and self.scan_status["state"] != ScanState.IDLE
            ):
                self.scan_status["state"] = ScanState.IDLE
            
            self.__schedule_lex_rebuild__()

    @with_app_context
    def __schedule_lex_rebuild__(self, delay_seconds: int = 10, *, context: AppContext = None):

        def worker():
            redis = context.redis_client
            if not redis:
                return
            
            time.sleep(delay_seconds)
            # if new changes happened, abort (another worker will handle it)
            if redis.get(REBUILD_DIRTY) is None:
                return

            # acquire rebuild lock
            if not redis.set(REBUILD_LOCK, 1, nx=True, ex=300):
                return

            try:
                redis.delete(REBUILD_DIRTY)
                asyncio.run(rebuild_lex_sort_indexes())
            finally:
                redis.delete(REBUILD_LOCK)

        threading.Thread(target=worker, daemon=True).start()
    
    def get_protocols_from_pcap_fast_sync(self, pcap_file: str, excluded_protocols: Optional[set[str]] = None) -> Optional[Dict[str, int]]:
        """Fast protocol scan using fastscan binary."""
        scan_cancel_event = self.scan_cancel_event
        scan_process = self.scan_process
        
        if not os.path.exists(pcap_file):
            logger.error(f"fastscan binary not found at {pcap_file}. Please build it first.")
            return None
        
        # /usr/local/bin/fastscan
        command = ['fastscan', pcap_file]
        
        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            scan_process["fastscan"] = process
            
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
                    logger.info(f"Scan cancellation requested. Terminating fastscan for {pcap_file}.")
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
                logger.error(f"fastscan exited with error for {pcap_file}: {stderr}")
                return None
            
            output = "".join(stdout_lines).strip()
            
            if not output:
                return {}
            
            protocol_counts: Dict[str, int] = {}
            
            # Parse fastscan output: each line is "eth:ip:tcp:http" etc.
            for line in output.splitlines():
                protocols = line.split(":")
                
                unique_protocols = set(protocols) - (excluded_protocols or set())
                
                for proto in unique_protocols:
                    protocol_counts[proto] = protocol_counts.get(proto, 0) + 1
            
            return protocol_counts
        
        except FileNotFoundError:
            logger.error(f"fastscan not found at {pcap_file}. Please build it first.")
            return None
        except Exception as e:
            logger.error(f"Unexpected error while analyzing {pcap_file} with fastscan: {e}")
            return None
        finally:
            scan_process["fastscan"] = None
    
    def get_protocols_from_pcap_sync(self, pcap_file: str, excluded_protocols: Optional[set[str]] = None) -> Optional[Dict[str, int]]:
        # Normal mode: use tshark
        scan_cancel_event = self.scan_cancel_event
        scan_process = self.scan_process
        command = [
            'tshark', '-r', pcap_file,
            '-T', 'fields',
            '-e', 'frame.protocols'
        ]

        try:
            
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            scan_process["tshark"] = process

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
                return {} 

            protocol_counts: Dict[str, int] = {}

            for line in output.splitlines():
                protocols = line.split(":")

                unique_protocols = set(protocols) - (excluded_protocols or set())

                for proto in unique_protocols:
                    protocol_counts[proto] = protocol_counts.get(proto, 0) + 1

            return protocol_counts

        except FileNotFoundError:
            logger.error("tshark not found — please install it.")
            return None
        except Exception as e:
            logger.error(f"Unexpected error while analyzing {pcap_file}: {e}")
            return None
        finally:
            scan_process["tshark"] = None


    async def get_protocols_from_pcap(self, pcap_file: str, excluded_protocols: Optional[set[str]] = None, scan_mode: str = "normal") -> Optional[Dict[str, int]]:
        match scan_mode:
            case "fast":
                return await asyncio.to_thread(self.get_protocols_from_pcap_fast_sync, pcap_file, excluded_protocols=excluded_protocols)
            case "normal":
                return await asyncio.to_thread(self.get_protocols_from_pcap_sync, pcap_file, excluded_protocols=excluded_protocols)
            case _:
                logger.error(f"Unknown scan mode: {scan_mode}")
                return None



@with_app_context
def get_scan_service(*, context: AppContext = None) -> ScanService:
    if not hasattr(context, "_scan_service"):
        context._scan_service = ScanService()
    return context._scan_service

@with_app_context
async def rebuild_lex_sort_indexes(*, context: AppContext = None):
    redis = context.redis_client
    if not redis:
        return

    logger.info("Rebuilding lexicographic sort indexes (atomic)")

    filename_new = f"{SORT_INDEX_FILENAME}:new"
    path_new = f"{SORT_INDEX_PATH}:new"

    filename_map: dict[str, list[str]] = {}
    path_map: dict[str, list[str]] = {}

    for key in redis.scan_iter(f"{PCAP_FILE_KEY_PREFIX}:*"):
        file_hash = key.split(":")[-1]

        fname, fpath = redis.hmget(key, "filename_sort", "path_sort")

        if fname:
            filename_map.setdefault(fname, []).append(file_hash)
        if fpath:
            path_map.setdefault(fpath, []).append(file_hash)

    # filename sort index
    filenames = await asyncio.to_thread(
        redis.zrange, LEX_INDEX_FILENAME, 0, -1
    )

    pipe = redis.pipeline()
    pipe.delete(filename_new)

    for rank, fname in enumerate(filenames):
        hashes = filename_map.get(fname)
        if hashes:
            pipe.zadd(
                filename_new,
                {h: rank for h in hashes}
            )

    pipe.execute()

    # path sort index
    paths = await asyncio.to_thread(
        redis.zrange, LEX_INDEX_PATH, 0, -1
    )

    pipe = redis.pipeline()
    pipe.delete(path_new)

    for rank, fpath in enumerate(paths):
        hashes = path_map.get(fpath)
        if hashes:
            pipe.zadd(
                path_new,
                {h: rank for h in hashes}
            )

    pipe.execute()

    # swap in new indexes atomically
    pipe = redis.pipeline()
    pipe.rename(filename_new, SORT_INDEX_FILENAME)
    pipe.rename(path_new, SORT_INDEX_PATH)
    pipe.execute()

    logger.info("Lexicographic sort indexes rebuilt successfully.")
