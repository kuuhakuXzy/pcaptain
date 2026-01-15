from enum import Enum
import json
import os
import re
from typing import Any, Dict, Optional, List, Tuple
from threading import Event
import hashlib
import asyncio
import subprocess
import time
import threading

from redis import Redis

from .logger import get_logger
from .context import AppContext, with_app_context
from .config import ScanMode

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


def parse_size_bytes(value: Optional[str], default: int) -> int:
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
        "m": 1024**2,
        "g": 1024**3,
        "t": 1024**4,
    }
    return int(number * multipliers[suffix.lower()])



def get_effective_scan_mode(
    file_size_bytes: int,
    base_scan_mode: ScanMode,
    *,
    quick_scan_pebc: float,
    quick_scan_min_file_size_bytes: int,
    quick_scan_config_version: str,
) -> Tuple[ScanMode, Optional[float], str]:
    """Compute per-file scan mode.

    - base_scan_mode == 'fast'  -> always 'fast' (fastscan binary)
    - base_scan_mode == 'quick' -> always 'quick' if file size >= min_file_size
    - base_scan_mode == 'normal'
    """
    if base_scan_mode == ScanMode.FAST:
        return ScanMode.FAST, None, quick_scan_config_version

    if base_scan_mode == ScanMode.QUICK and file_size_bytes >= quick_scan_min_file_size_bytes:
        return ScanMode.QUICK, quick_scan_pebc, quick_scan_config_version

    return ScanMode.NORMAL, None, quick_scan_config_version


def _normalize_scan_param(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, bytes):
        value = value.decode("utf-8")
    stripped = str(value).strip()
    return stripped if stripped else None


def _parse_float(value: Optional[str]) -> Optional[float]:
    normalized = _normalize_scan_param(value)
    if normalized is None:
        return None
    try:
        return float(normalized)
    except ValueError:
        return None


def should_rescan_file(
    *,
    current_scan_mode: str,
    current_pebc: Optional[float],
    current_config_version: str,
    stored_scan_mode: Optional[str],
    stored_pebc: Optional[float],
    stored_config_version: Optional[str],
) -> bool:
    """Decide whether a file requires a rescan based on scan parameters."""
    stored_scan_mode = _normalize_scan_param(stored_scan_mode)
    stored_config_version = _normalize_scan_param(stored_config_version)

    if stored_scan_mode is None:
        return True

    # upgrading from partial sampling -> full-file modes
    if stored_scan_mode == "quick" and current_scan_mode in {"normal", "fast"}:
        return True

    # preserve previous behavior: switching from fast -> normal triggers full rescan
    if stored_scan_mode == "fast" and current_scan_mode == "normal":
        return True

    # quick scan parameter changes
    if current_scan_mode == "quick" and stored_scan_mode == "quick":
        if (
            current_pebc is not None
            and stored_pebc is not None
            and current_pebc > stored_pebc
        ):
            return True
        if current_config_version != stored_config_version:
            return True

    return False


def calculate_sha256_sync(file_path: str) -> str:
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


async def calculate_sha256(file_path: str) -> str:
    return await asyncio.to_thread(calculate_sha256_sync, file_path)


def calculate_protocol_percentages(protocol_counts: Dict[str, int], packets_scanned: int) -> Dict[str, float]:
    """Calculate protocol presence percentage relative to scanned packets."""
    if not protocol_counts:
        return {}

    if packets_scanned <= 0:
        return {k: 0.0 for k in protocol_counts}

    return {
        proto: round((count / packets_scanned) * 100, 2)
        for proto, count in protocol_counts.items()
    }


def check_cancellation(cancel_event: Optional[Event]):
    """Check if cancellation has been requested and raise CancelledError if so."""
    if cancel_event and cancel_event.is_set():
        logger.info("Scan cancelled by user")
        raise asyncio.CancelledError("Scan cancelled by user")


async def get_all_protocols(redis: Redis):
    # ZSET → list[str]
    return await asyncio.to_thread(redis.zrange, AUTOCOMPLETE_KEY, 0, -1)


def get_total_packets_from_pcap_sync(pcap_file: str) -> Optional[int]:
    command = ["capinfos", "-c", pcap_file]

    try:
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        if result.returncode != 0:
            logger.error(
                "capinfos exited with error for %s: %s",
                pcap_file,
                result.stderr.strip(),
            )
            return None

        match = re.search(
            r"(?:Number of packets|Packets)\s*[:=]\s*(\d+)",
            result.stdout,
        )
        if not match:
            logger.error(
                "Could not parse packet count from capinfos output for %s",
                pcap_file,
            )
            return None

        return int(match.group(1))

    except FileNotFoundError:
        logger.error("capinfos not found — please install it.")
        return None
    except Exception as e:
        logger.error("Unexpected error while running capinfos on %s: %s", pcap_file, e)
        return None


async def get_total_packets_from_pcap(pcap_file: str) -> Optional[int]:
    return await asyncio.to_thread(get_total_packets_from_pcap_sync, pcap_file)


class ScanState(str, Enum):
    IDLE = "idle"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class BackfillState(str, Enum):
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

    backfill_status: Dict[str, Any] = {
        "state": BackfillState.IDLE,
        "processed": 0,
        "updated": 0,
        "total": 0,
        "message": "Ready",
    }

    scan_cancel_event = Event()
    scan_process: Dict[str, Optional[subprocess.Popen]] = {"tshark": None}
    
    async def should_process_file(
        self,
        *,
        redis_client,
        pcap_key: str,
        file_path: str,
        current_scan_mode: ScanMode,
        current_pebc: Optional[float],
        current_config_version: str,
    ) -> bool:
        """Return True if we should scan/index the file now.

        This collapses the nested "exists/path/moved/duplicate/rescan" logic into one place.
        """
        if not await asyncio.to_thread(redis_client.exists, pcap_key):
            return True

        stored = await asyncio.to_thread(redis_client.hgetall, pcap_key)
        stored_path = stored.get("path")

        if stored_path == file_path:
            stored_scan_mode = stored.get("scan_mode")
            stored_pebc = _parse_float(stored.get("pebc"))
            stored_config_version = stored.get("config_version")

            if should_rescan_file(
                current_scan_mode=current_scan_mode.value,
                current_pebc=current_pebc,
                current_config_version=current_config_version,
                stored_scan_mode=stored_scan_mode,
                stored_pebc=stored_pebc,
                stored_config_version=stored_config_version,
            ):
                logger.info(
                    "Rescanning %s due to scan param change (stored_mode=%s current_mode=%s)",
                    file_path,
                    stored_scan_mode,
                    current_scan_mode,
                )
                return True

            await asyncio.to_thread(
                redis_client.hset,
                pcap_key,
                mapping={"last_scanned": time.time()},
            )
            logger.info("Skipping %s (already indexed and unchanged)", file_path)
            return False

        if stored_path and await asyncio.to_thread(os.path.exists, stored_path):
            logger.info(
                "Duplicate file detected at %s (hash exists at %s)",
                stored_path,
                file_path,
            )
            return False

        # stored_path missing or points to a file that no longer exists -> consider it moved
        logger.info("File moved. Updating Redis path for %s", file_path)
        await asyncio.to_thread(
            redis_client.hset,
            pcap_key,
            mapping={
                "path": file_path,
                "source_directory": os.path.dirname(file_path),
                "last_modified": await asyncio.to_thread(os.path.getmtime, file_path),
                "last_scanned": time.time(),
            },
        )
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

                    file_size = await asyncio.to_thread(os.path.getsize, file_path)

                    file_hash = await calculate_sha256(file_path)
                    if file_hash in seen_hashes:
                        logger.info(
                            f"Skipping {file_path} (duplicate hash already processed in this scan)"
                        )
                        continue
                    seen_hashes.add(file_hash)

                    pcap_key = f"{PCAP_FILE_KEY_PREFIX}:{file_hash}"
                    base_scan_mode = config.pcap.scan_mode

                    qs = config.pcap.quick_scan
                    if isinstance(qs.min_file_size, int):
                        quick_min_size_bytes = qs.min_file_size
                    else:
                        quick_min_size_bytes = parse_size_bytes(str(qs.min_file_size), default=0)

                    current_scan_mode, current_pebc, current_config_version = get_effective_scan_mode(
                        file_size,
                        base_scan_mode,
                        quick_scan_pebc=qs.pebc,
                        quick_scan_min_file_size_bytes=quick_min_size_bytes,
                        quick_scan_config_version=qs.config_version,
                    )

                    should_scan_now = await self.should_process_file(
                        redis_client=redis_client,
                        pcap_key=pcap_key,
                        file_path=file_path,
                        current_scan_mode=current_scan_mode,
                        current_pebc=current_pebc,
                        current_config_version=current_config_version,
                    )
                    if not should_scan_now:
                        continue

                    quick_threshold_bytes: Optional[int] = None
                    if current_scan_mode == ScanMode.QUICK and current_pebc is not None:
                        quick_threshold_bytes = int(file_size * current_pebc)

                    logger.info(
                        "Processing file: %s (scan_mode: %s)",
                        file_path,
                        current_scan_mode.value,
                    )
                    protocol_result = await self.get_protocols_from_pcap(
                        file_path,
                        excluded_protocols=config.pcap.excluded_protocols,
                        scan_mode=current_scan_mode,
                        quick_threshold_bytes=quick_threshold_bytes,
                    )

                    if protocol_result is not None:
                        protocol_data, packets_scanned = protocol_result
                        if not protocol_data:
                            logger.warning(
                                f"No protocols found in {filename}. Skipping from index."
                            )
                            continue

                        protocol_percentages = calculate_protocol_percentages(
                            protocol_data,
                            packets_scanned,
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
                                "packets_scanned": packets_scanned,
                                "last_modified": await asyncio.to_thread(
                                    os.path.getmtime, file_path
                                ),
                                "last_scanned": current_time,
                                "scan_mode": current_scan_mode.value,
                                "pebc": "" if current_pebc is None else current_pebc,
                                "config_version": current_config_version,
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

    async def backfill_total_packets(self, redis_client: Redis) -> dict:
        if not redis_client:
            return {"error": "Redis connection is not available."}

        keys = await asyncio.to_thread(redis_client.keys, f"{PCAP_FILE_KEY_PREFIX}:*")
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
                logger.warning("Missing file for total_packets backfill: %s", file_path)
                continue

            total_packets = await get_total_packets_from_pcap(file_path)
            if total_packets is None:
                total_packets = ""

            await asyncio.to_thread(redis_client.hset, key, "total_packets", total_packets)
            updated += 1

        return {"processed": processed, "updated": updated, "total": total}

    @with_app_context
    def backfill_wrapper(self, *, context: AppContext = None):
        redis = context.redis_client
        if not redis:
            logger.error("Redis connection is not available. Backfill aborted.")
            return

        try:
            self.backfill_status["state"] = BackfillState.RUNNING
            self.backfill_status["processed"] = 0
            self.backfill_status["updated"] = 0
            self.backfill_status["total"] = 0
            self.backfill_status["message"] = "Backfill in progress..."
            logger.info("Background total_packets backfill started.")

            result = asyncio.run(self.backfill_total_packets(redis))
            self.backfill_status["processed"] = result.get("processed", 0)
            self.backfill_status["updated"] = result.get("updated", 0)
            self.backfill_status["total"] = result.get("total", 0)

            self.backfill_status["state"] = BackfillState.COMPLETED
            self.backfill_status["message"] = (
                "Completed successfully. "
                f"Updated {self.backfill_status['updated']} of {self.backfill_status['processed']} keys."
            )
            logger.info("Background total_packets backfill completed.")

        except Exception as e:
            logger.error("Backfill failed: %s", e)
            self.backfill_status["state"] = BackfillState.FAILED
            self.backfill_status["message"] = str(e)
        finally:
            if self.backfill_status["state"] != BackfillState.FAILED:
                self.backfill_status["state"] = BackfillState.IDLE

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
    
    def get_protocols_from_pcap_fast_sync(
        self,
        pcap_file: str,
        excluded_protocols: Optional[set[str]] = None,
    ) -> Optional[Tuple[Dict[str, int], int]]:
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
                return {}, 0
            
            protocol_counts: Dict[str, int] = {}
            packets_scanned = 0
            
            # Parse fastscan output: each line is "eth:ip:tcp:http" etc.
            for line in output.splitlines():
                if not line:
                    continue
                packets_scanned += 1
                protocols = line.split(":")
                
                unique_protocols = set(protocols) - (excluded_protocols or set())
                
                for proto in unique_protocols:
                    protocol_counts[proto] = protocol_counts.get(proto, 0) + 1
            
            return protocol_counts, packets_scanned
        
        except FileNotFoundError:
            logger.error(f"fastscan not found at {pcap_file}. Please build it first.")
            return None
        except Exception as e:
            logger.error(f"Unexpected error while analyzing {pcap_file} with fastscan: {e}")
            return None
        finally:
            scan_process["fastscan"] = None
    
    def get_protocols_from_pcap_quick_sync(
        self,
        pcap_file: str,
        *,
        quick_threshold_bytes: Optional[int],
        excluded_protocols: Optional[set[str]] = None,
    ) -> Optional[Tuple[Dict[str, int], int]]:
        """Quick scan via tshark, stopping after threshold bytes."""
        scan_cancel_event = self.scan_cancel_event
        scan_process = self.scan_process

        threshold = quick_threshold_bytes or 0
        if threshold <= 0:
            logger.warning("Quick scan threshold is <= 0 for %s; skipping", pcap_file)
            return {}, 0

        command = [
            "tshark",
            "-r",
            pcap_file,
            "-T",
            "fields",
            "-e",
            "frame.len",
            "-e",
            "frame.protocols",
            "-E",
            "separator=\t",
        ]

        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            scan_process["tshark"] = process

            protocol_counts: Dict[str, int] = {}
            bytes_scanned = 0
            packets_scanned = 0
            threshold_reached = False

            logger.info(
                "Quick scan tshark started for %s (threshold_bytes=%s)",
                pcap_file,
                threshold,
            )

            while True:
                if scan_cancel_event.is_set():
                    logger.info(
                        "Scan cancellation requested. Terminating tshark for %s.",
                        pcap_file,
                    )
                    process.terminate()
                    break

                line = process.stdout.readline() if process.stdout else ""
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
                unique_protocols = set(protocols) - (excluded_protocols or set())
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
                    logger.error(
                        "tshark exited with error for %s: %s",
                        pcap_file,
                        stderr_output,
                    )
                return None

            logger.info(
                "Quick scan finished for %s (bytes_scanned=%s, packets_scanned=%s)",
                pcap_file,
                bytes_scanned,
                packets_scanned,
            )
            return protocol_counts, packets_scanned

        except FileNotFoundError:
            logger.error("tshark not found — please install it.")
            return None
        except Exception as e:
            logger.error(
                "Unexpected error while analyzing %s with quickscan: %s",
                pcap_file,
                e,
            )
            return None
        finally:
            scan_process["tshark"] = None

    def get_protocols_from_pcap_sync(
        self, pcap_file: str, excluded_protocols: Optional[set[str]] = None
    ) -> Optional[Tuple[Dict[str, int], int]]:
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
                return {}, 0

            protocol_counts: Dict[str, int] = {}

            lines = [ln for ln in output.splitlines() if ln]
            for line in lines:
                protocols = line.split(":")

                unique_protocols = set(protocols) - (excluded_protocols or set())

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
        self,
        pcap_file: str,
        excluded_protocols: Optional[set[str]] = None,
        scan_mode: ScanMode = ScanMode.NORMAL,
        quick_threshold_bytes: Optional[int] = None,
    ) -> Optional[Tuple[Dict[str, int], int]]:
        match scan_mode:
            case ScanMode.FAST:
                return await asyncio.to_thread(
                    self.get_protocols_from_pcap_fast_sync,
                    pcap_file,
                    excluded_protocols=excluded_protocols,
                )
            case ScanMode.NORMAL:
                return await asyncio.to_thread(
                    self.get_protocols_from_pcap_sync,
                    pcap_file,
                    excluded_protocols=excluded_protocols,
                )
            case ScanMode.QUICK:
                return await asyncio.to_thread(
                    self.get_protocols_from_pcap_quick_sync,
                    pcap_file,
                    quick_threshold_bytes=quick_threshold_bytes,
                    excluded_protocols=excluded_protocols,
                )
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
