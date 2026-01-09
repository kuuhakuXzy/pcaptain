from enum import Enum
import json
import os
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


def get_protocols_from_pcap_sync(pcap_file: str) -> Optional[Dict[str, int]]:
    command = ["tshark", "-r", pcap_file, "-T", "fields", "-e", "frame.protocols"]

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

    @with_app_context
    async def scan_and_index(
        self,
        exclude_files: List[str] = None,
        base_url: str = None,
        target_folder: Optional[str] = None,
        *,
        context: AppContext = None,
    ) -> dict:
        seen_hashes = set()

        if exclude_files is None:
            exclude_files = []

        redis_client = context.redis_client
        if not redis_client:
            return {"error": "Redis connection is not available."}

        logger.info(
            f"Starting scan for directories: {context.PCAP_DIRECTORIES} with exclusions: {exclude_files}"
        )
        files_indexed = 0

        found_matching_folder = False

        try:
            for pcap_dir in context.PCAP_DIRECTORIES:
                check_cancellation(self.scan_cancel_event)
                if not await asyncio.to_thread(os.path.isdir, pcap_dir):
                    logger.warning(f"Directory '{pcap_dir}' does not exist. Skipping.")
                    continue

                for root, dirs, files in await asyncio.to_thread(os.walk, pcap_dir):
                    check_cancellation(self.scan_cancel_event)

                    if target_folder:
                        if os.path.basename(root) != target_folder:
                            continue
                        found_matching_folder = True

                    for filename in files:
                        check_cancellation(self.scan_cancel_event)

                        if filename in exclude_files or not filename.endswith(
                            (".pcap", ".pcapng", ".cap")
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

                        if await asyncio.to_thread(redis_client.exists, pcap_key):
                            stored_path = await asyncio.to_thread(
                                redis_client.hget, pcap_key, "path"
                            )
                            if stored_path == file_path:
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

                        logger.info(f"Processing file: {file_path}")
                        protocol_data = await get_protocols_from_pcap(file_path)

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

                            if not base_url:
                                base_url = context.FULL_BASE_URL or None

                            download_url = (
                                f"{base_url}/pcaps/download/{file_hash}"
                                if base_url
                                else ""
                            )

                            protocols = sorted(list(protocol_data.keys()))
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
                                    "source_directory": pcap_dir,
                                    "path": file_path,
                                    "path_sort": path_norm,
                                    "size_bytes": file_size,
                                    "protocols": " ".join(protocols),
                                    "protocol_packet_count": protocol_packet_count,
                                    "protocol_counts": json.dumps(protocol_data),
                                    "protocol_percentages": json.dumps(
                                        protocol_percentages
                                    ),
                                    "download_url": download_url,
                                    "last_modified": await asyncio.to_thread(
                                        os.path.getmtime, file_path
                                    ),
                                    "last_scanned": current_time,
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
                        f"No folder named '{target_folder}' found under {context.PCAP_DIRECTORIES}."
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
    def scan_wrapper(self, exclude_files=None, base_url=None, *, context: AppContext = None):
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
                self.scan_and_index(exclude_files=exclude_files, base_url=base_url)
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
