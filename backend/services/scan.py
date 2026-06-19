from enum import Enum
import json
import os
import re
from typing import Any, Dict, Optional, List, Tuple, Set
from threading import Event
import hashlib
import asyncio
import subprocess
import time
import threading
import tempfile

from redis import Redis

from .logger import get_logger
from .context import AppContext, with_app_context
from .config import ScanMode, get_pcap_root_directories

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

# Default parallel scans (overridden by config.pcap.max_parallel_scans)
MAX_PARALLEL_SCANS = 4

PATH_INDEX_PREFIX = "pcap:path"


def _path_index_key(file_path: str) -> str:
    return f"{PATH_INDEX_PREFIX}:{file_path.replace(chr(92), '/')}"


def _mtime_index_value(mtime: float) -> str:
    return str(int(mtime))


def _normalize_folder_path(folder: Optional[str]) -> Optional[str]:
    if not folder:
        return None
    normalized = str(folder).strip().replace("\\", "/").strip("/")
    return normalized or None


def _file_matches_target_folder(
    file_path: str,
    root_directory: str,
    target_norm: Optional[str],
) -> bool:
    if not target_norm:
        return True
    rel = os.path.relpath(file_path, root_directory).replace("\\", "/")
    parent_rel = os.path.dirname(rel)
    if parent_rel == ".":
        parent_rel = ""
    return (
        parent_rel == target_norm
        or parent_rel.startswith(f"{target_norm}/")
        or rel.startswith(f"{target_norm}/")
    )


def _target_folder_exists(root_directory: str, target_norm: Optional[str]) -> bool:
    if not target_norm:
        return True
    target_path = os.path.join(root_directory, *target_norm.split("/"))
    return os.path.isdir(target_path)


def get_max_parallel_scans(config) -> int:
    return getattr(config.pcap, "max_parallel_scans", MAX_PARALLEL_SCANS) or MAX_PARALLEL_SCANS


def get_effective_scan_mode(
    file_size_bytes: int,
    base_scan_mode: ScanMode,
    *,
    quick_scan_pebc: float,
    quick_scan_min_file_size_bytes: int,
    quick_scan_config_version: str,
) -> Tuple[ScanMode, Optional[float], str]:
    """Compute per-file scan mode.

    - fast   -> always fastscan (full file read)
    - quick  -> quick sample when file >= min_file_size, else full tshark
    - full   -> full tshark
    """
    if base_scan_mode == ScanMode.FAST:
        return ScanMode.FAST, None, quick_scan_config_version

    if base_scan_mode == ScanMode.QUICK and file_size_bytes >= quick_scan_min_file_size_bytes:
        return ScanMode.QUICK, quick_scan_pebc, quick_scan_config_version

    return ScanMode.FULL, None, quick_scan_config_version


def parse_size_bytes(value: Optional[str], default: int) -> int:
    if value is None:
        return default
    if isinstance(value, int):
        return value
    stripped = str(value).strip()
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


def _parse_int(value: Any) -> Optional[int]:
    normalized = _normalize_scan_param(value)
    if normalized is None:
        return None
    try:
        return int(normalized)
    except ValueError:
        try:
            return int(float(normalized))
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

    if stored_scan_mode != current_scan_mode:
        return True

    if current_config_version != stored_config_version:
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


def hash_bytes_sync(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


async def calculate_sha256(file_path: str) -> str:
    return await asyncio.to_thread(calculate_sha256_sync, file_path)


async def _write_path_index(
    redis_client,
    file_path: str,
    file_hash: str,
    file_size: int,
    file_mtime: float,
    scan_mode: str,
    pebc: Optional[float],
    config_version: str,
) -> None:
    await asyncio.to_thread(
        redis_client.hset,
        _path_index_key(file_path),
        mapping={
            "file_hash": file_hash,
            "size_bytes": str(file_size),
            "last_modified": _mtime_index_value(file_mtime),
            "scan_mode": scan_mode,
            "pebc": "" if pebc is None else str(pebc),
            "config_version": config_version,
        },
    )


async def _delete_path_index(redis_client, file_path: str) -> None:
    await asyncio.to_thread(redis_client.delete, _path_index_key(file_path))


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


def get_capinfos_metadata_sync(pcap_file: str) -> dict:
    """Read packet count and capture start/end times via capinfos."""
    command = ["capinfos", "-M", "-a", "-e", "-c", pcap_file]
    result = {
        "total_packets": None,
        "capture_start": None,
        "capture_end": None,
        "capture_year": None,
    }

    try:
        proc = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        if proc.returncode != 0:
            logger.error(
                "capinfos exited with error for %s: %s",
                pcap_file,
                proc.stderr.strip(),
            )
            return result

        output = proc.stdout
        packet_match = re.search(
            r"(?:Number of packets|Packets)\s*[:=]\s*(\d+)",
            output,
        )
        if packet_match:
            result["total_packets"] = int(packet_match.group(1))

        start_match = re.search(r"Earliest packet time:\s*(.+)", output)
        end_match = re.search(r"Latest packet time:\s*(.+)", output)

        if start_match:
            start_raw = start_match.group(1).strip()
            result["capture_start"] = _parse_capinfos_timestamp(start_raw)
            year_match = re.match(r"(\d{4})", start_raw)
            if year_match:
                result["capture_year"] = int(year_match.group(1))

        if end_match:
            result["capture_end"] = _parse_capinfos_timestamp(end_match.group(1).strip())

    except FileNotFoundError:
        logger.error("capinfos not found — please install it.")
    except Exception as e:
        logger.error("Unexpected error while running capinfos on %s: %s", pcap_file, e)

    return result


def _parse_capinfos_timestamp(raw: str) -> Optional[float]:
    from datetime import datetime

    if not raw or raw.lower() in {"n/a", "unknown", "(none)"}:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(raw, fmt).timestamp()
        except ValueError:
            continue
    return None


def get_total_packets_from_pcap_sync(pcap_file: str) -> Optional[int]:
    return get_capinfos_metadata_sync(pcap_file).get("total_packets")


async def get_capinfos_metadata_from_pcap(pcap_file: str) -> dict:
    return await asyncio.to_thread(get_capinfos_metadata_sync, pcap_file)


async def get_total_packets_from_pcap(pcap_file: str) -> Optional[int]:
    meta = await get_capinfos_metadata_from_pcap(pcap_file)
    return meta.get("total_packets")


def build_segment_packet_ranges(
    total_packets: int,
    segments: int,
    packets_per_segment: int,
) -> List[Tuple[int, int]]:
    """Packet ranges for head, evenly-spaced middles, and tail."""
    total = max(total_packets, 1)
    p = max(1, min(packets_per_segment, total))
    if segments <= 1:
        return [(1, min(p, total))]

    ranges: List[Tuple[int, int]] = []
    for i in range(segments):
        if i == 0:
            ranges.append((1, min(p, total)))
        elif i == segments - 1:
            ranges.append((max(1, total - p + 1), total))
        else:
            center = int(total * i / (segments - 1))
            start = max(1, min(center - p // 2, total - p + 1))
            end = min(total, start + p - 1)
            ranges.append((start, end))
    return ranges


def extract_pcap_segments_sync(
    pcap_file: str,
    ranges: List[Tuple[int, int]],
    output_path: str,
) -> bool:
    """Extract multiple packet ranges in one editcap pass."""
    if not ranges:
        return False
    command = ["editcap", "-r", pcap_file, output_path]
    for start, end in ranges:
        command.append(f"{start}-{end}")
    try:
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if result.returncode != 0:
            logger.warning(
                "editcap failed for %s: %s",
                pcap_file,
                result.stderr.strip(),
            )
            return False
        return os.path.getsize(output_path) > 0
    except FileNotFoundError:
        logger.error("editcap not found — please install wireshark tools.")
        return False
    except Exception as e:
        logger.error("Unexpected editcap error for %s: %s", pcap_file, e)
        return False


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


class RebuildSearchIndexState(str, Enum):
    IDLE = "idle"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class ScanService:
    scan_status: Dict[str, Any] = {
        "state": ScanState.IDLE,
        "indexed_files": 0,
        "message": "Ready",
        "last_run": None,
    }

    backfill_status: Dict[str, Any] = {
        "state": BackfillState.IDLE,
        "processed": 0,
        "updated": 0,
        "total": 0,
        "message": "Ready",
    }

    rebuild_searchindex_status: Dict[str, Any] = {
        "state": RebuildSearchIndexState.IDLE,
        "processed": 0,
        "backfilled": 0,
        "total": 0,
        "message": "Ready",
    }

    scan_cancel_event = Event()
    scan_process: Dict[str, Optional[subprocess.Popen]] = {"tshark": None}

    async def try_fast_skip_by_path(
        self,
        *,
        redis_client,
        file_path: str,
        file_size: int,
        file_mtime: float,
        current_scan_mode: ScanMode,
        current_pebc: Optional[float],
        current_config_version: str,
    ) -> bool:
        """Skip unchanged files using path+size+mtime fingerprint (no file read)."""
        path_key = _path_index_key(file_path)
        stored = await asyncio.to_thread(redis_client.hgetall, path_key)
        if not stored:
            return False

        try:
            stored_size = int(stored.get("size_bytes", -1))
            stored_mtime = int(stored.get("last_modified", -1))
        except (TypeError, ValueError):
            return False

        if stored_size != file_size or stored_mtime != int(file_mtime):
            return False

        file_hash = stored.get("file_hash")
        if not file_hash:
            return False

        pcap_key = f"{PCAP_FILE_KEY_PREFIX}:{file_hash}"
        if not await asyncio.to_thread(redis_client.exists, pcap_key):
            await _delete_path_index(redis_client, file_path)
            return False

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
            return False

        now = time.time()
        await asyncio.to_thread(
            redis_client.hset,
            pcap_key,
            mapping={"last_scanned": now},
        )
        await _write_path_index(
            redis_client,
            file_path,
            file_hash,
            file_size,
            file_mtime,
            current_scan_mode.value,
            current_pebc,
            current_config_version,
        )
        logger.info("Fast-skipped %s (path fingerprint unchanged)", file_path)
        return True

    async def resolve_file_hash(
        self,
        file_path: str,
        file_size: int,
        file_mtime: float,
        redis_client,
    ) -> str:
        """Reuse hash from path index when fingerprint matches, else read full file."""
        path_key = _path_index_key(file_path)
        stored = await asyncio.to_thread(redis_client.hgetall, path_key)
        if stored:
            try:
                if (
                    int(stored.get("size_bytes", -1)) == file_size
                    and int(stored.get("last_modified", -1)) == int(file_mtime)
                ):
                    file_hash = stored.get("file_hash")
                    if file_hash:
                        pcap_key = f"{PCAP_FILE_KEY_PREFIX}:{file_hash}"
                        if await asyncio.to_thread(redis_client.exists, pcap_key):
                            return file_hash
            except (TypeError, ValueError):
                pass
        return await calculate_sha256(file_path)
    
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
        if stored_path and stored_path != file_path:
            await _delete_path_index(redis_client, stored_path)
        file_mtime = await asyncio.to_thread(os.path.getmtime, file_path)
        await asyncio.to_thread(
            redis_client.hset,
            pcap_key,
            mapping={
                "path": file_path,
                "source_directory": os.path.dirname(file_path),
                "last_modified": file_mtime,
                "last_scanned": time.time(),
            },
        )
        stored_meta = await asyncio.to_thread(redis_client.hgetall, pcap_key)
        await _write_path_index(
            redis_client,
            file_path,
            pcap_key.split(":")[-1],
            int(stored_meta.get("size_bytes") or 0),
            file_mtime,
            stored_meta.get("scan_mode") or "full",
            _parse_float(stored_meta.get("pebc")),
            stored_meta.get("config_version") or "v1",
        )
        return False

    # Collect the list of files to scan
    async def collect_files(
        self,
        root_directory: str,
        exclude_files: List[str],
        allowed_extensions: tuple,
        target_folder: Optional[str],
    ) -> Tuple[List[str], bool]:
        collected: List[str] = []
        target_norm = _normalize_folder_path(target_folder)
        found_matching_folder = _target_folder_exists(root_directory, target_norm)

        for root, dirs, files in await asyncio.to_thread(os.walk, root_directory):
            check_cancellation(self.scan_cancel_event)

            for filename in files:
                if filename in exclude_files or not filename.endswith(allowed_extensions):
                    continue
                file_path = os.path.join(root, filename)
                if _file_matches_target_folder(file_path, root_directory, target_norm):
                    collected.append(file_path)

        return collected, found_matching_folder

    # Process a signle file
    async def process_one_file(
        self,
        file_path: str,
        *,
        semaphore: asyncio.Semaphore,
        seen_hashes: Set[str],
        seen_hashes_lock: asyncio.Lock,
        counter_lock: asyncio.Lock,
        files_indexed_container: List[int],
        fast_skipped_container: List[int],
        redis_client,
        config,
        context: AppContext,
    ) -> None:
        # Scan and index a single pcap file
        async with semaphore:
            check_cancellation(self.scan_cancel_event)

            filename = os.path.basename(file_path)

            file_stat = await asyncio.to_thread(os.stat, file_path)
            file_size = file_stat.st_size
            file_mtime = file_stat.st_mtime

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

            if await self.try_fast_skip_by_path(
                redis_client=redis_client,
                file_path=file_path,
                file_size=file_size,
                file_mtime=file_mtime,
                current_scan_mode=current_scan_mode,
                current_pebc=current_pebc,
                current_config_version=current_config_version,
            ):
                async with counter_lock:
                    fast_skipped_container[0] += 1
                return

            file_hash = await self.resolve_file_hash(
                file_path, file_size, file_mtime, redis_client
            )

            async with seen_hashes_lock:
                if file_hash in seen_hashes:
                    logger.info(
                        f"Skipping {file_path} (duplicate hash already processed in this scan)"
                    )
                    return
                seen_hashes.add(file_hash)

            # Determine scan mode
            pcap_key = f"{PCAP_FILE_KEY_PREFIX}:{file_hash}"

            should_scan_now = await self.should_process_file(
                redis_client=redis_client,
                pcap_key=pcap_key,
                file_path=file_path,
                current_scan_mode=current_scan_mode,
                current_pebc=current_pebc,
                current_config_version=current_config_version,
            )

            if not should_scan_now:
                await _write_path_index(
                    redis_client,
                    file_path,
                    file_hash,
                    file_size,
                    file_mtime,
                    current_scan_mode.value,
                    current_pebc,
                    current_config_version,
                )
                return

            quick_threshold_bytes: Optional[int] = None
            if current_scan_mode == ScanMode.QUICK and current_pebc is not None:
                quick_threshold_bytes = int(file_size * current_pebc)
            
            logger.info("Processing file: %s (scan_mode: %s)", file_path, current_scan_mode.value)

            # Call fastscan
            check_cancellation(self.scan_cancel_event)
            protocol_result = await self.get_protocols_from_pcap(
                file_path,
                excluded_protocols=None,
                scan_mode=current_scan_mode,
                quick_threshold_bytes=quick_threshold_bytes,
                sample_segments=qs.sample_segments,
                file_size_bytes=file_size,
            )

            if protocol_result is None:
                logger.warning(f"Skipping file {filename} from index due to processing error.")
                return
            
            protocol_data, packets_scanned = protocol_result

            if not protocol_data:
                logger.warning(f"No protocols found in {filename}. Skipping from index.")
                return

            # Compute metadata
            protocol_percentages = calculate_protocol_percentages(protocol_data, packets_scanned)

            # Recompute hash in case the file changed during scan
            file_hash = await calculate_sha256(file_path)
            pcap_key = f"{PCAP_FILE_KEY_PREFIX}:{file_hash}"

            protocols = sorted(list(protocol_data.keys()))
            download_url = f"{context.config.public_url}/pcaps/download/{file_hash}"
            cap_meta = await get_capinfos_metadata_from_pcap(file_path)
            total_packets = cap_meta.get("total_packets")
            capture_start = cap_meta.get("capture_start")
            capture_end = cap_meta.get("capture_end")
            capture_year = cap_meta.get("capture_year")

            if total_packets is None:
                logger.warning(f"capinfos failed for {file_path}; continuing without total_packets")
                total_packets = 0

            filename_norm = filename.lower()
            path_norm = file_path.lower()
            current_time = time.time()

            # Write to Redis
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
                    "protocols": ",".join(protocols),
                    "total_packets": total_packets,
                    "protocol_counts": json.dumps(protocol_data),
                    "protocol_percentages": json.dumps(protocol_percentages),
                    "packets_scanned": packets_scanned,
                    "last_modified": file_mtime,
                    "last_scanned": current_time,
                    "scan_mode": current_scan_mode.value,
                    "pebc": "" if current_pebc is None else current_pebc,
                    "config_version": current_config_version,
                    "capture_start": "" if capture_start is None else capture_start,
                    "capture_end": "" if capture_end is None else capture_end,
                    "capture_year": "" if capture_year is None else capture_year,
                }
            )

            autocomplete_payload = {proto: 0 for proto in protocols}

            if autocomplete_payload:
                pipe.zadd(AUTOCOMPLETE_KEY, autocomplete_payload)

            for proto in protocols:
                index_key = f"{PROTOCOCOL_INDEX_PREFIX}:{proto.lower()}"
                pipe.sadd(index_key, file_hash)
            
            # Lexicographical indexes
            pipe.zadd(LEX_INDEX_FILENAME, {filename_norm: 0}, nx=True)
            pipe.zadd(LEX_INDEX_PATH, {path_norm: 0}, nx=True)

            # Sort indexes
            pipe.zadd(SORT_INDEX_SIZE, {file_hash: file_size})
            pipe.zadd(SORT_INDEX_PACKET_COUNT, {file_hash: total_packets or 0})
            pipe.zadd(SORT_INDEX_FILENAME, {file_hash: 0})
            pipe.zadd(SORT_INDEX_PATH, {file_hash: 0})

            await asyncio.to_thread(pipe.execute)

            await _write_path_index(
                redis_client,
                file_path,
                file_hash,
                file_size,
                file_mtime,
                current_scan_mode.value,
                current_pebc,
                current_config_version,
            )

            from services.alerts import evaluate_and_store_alerts

            alerts = evaluate_and_store_alerts(
                redis_client,
                file_hash,
                {
                    "filename": filename,
                    "size_bytes": file_size,
                    "protocols": protocols,
                    "protocol_percentages": protocol_percentages,
                },
            )

            logger.info(
                "Indexed file %s (hash: %s) with protocols: %s%s",
                filename,
                file_hash,
                ", ".join(protocols),
                f" [{len(alerts)} alert(s)]" if alerts else "",
            )

            async with counter_lock:
                files_indexed_container[0] += 1

    @with_app_context
    async def scan_and_index(
        self,
        exclude_files: List[str] = None,
        target_folder: Optional[str] = None,
        *,
        context: AppContext = None,
    ) -> dict:
        if exclude_files is None:
            exclude_files = []

        redis_client = context.redis_client
        config = context.config

        if not redis_client:
            return {"error": "Redis connection is not available."}

        max_parallel = get_max_parallel_scans(config)
        root_dirs = get_pcap_root_directories(config.pcap)

        logger.info(
            "Starting PARALLEL scan for: %s (max_concurrent=%d, exclusions=%s)",
            root_dirs,
            max_parallel,
            exclude_files,
        )

        try: 
            check_cancellation(self.scan_cancel_event)

            all_files: List[str] = []
            found_matching_folder = not target_folder
            valid_roots = 0

            for root_dir in root_dirs:
                if not await asyncio.to_thread(os.path.isdir, root_dir):
                    logger.warning("Directory '%s' does not exist. Skipping.", root_dir)
                    continue
                valid_roots += 1
                files, found_here = await self.collect_files(
                    root_directory=root_dir,
                    exclude_files=exclude_files,
                    allowed_extensions=tuple(config.pcap.allowed_file_extensions),
                    target_folder=target_folder,
                )
                all_files.extend(files)
                found_matching_folder = found_matching_folder or found_here

            if valid_roots == 0:
                return {
                    "status": "warning",
                    "message": f"No valid PCAP directories found among: {root_dirs}",
                    "indexed_files": 0,
                }

            if target_folder and not found_matching_folder:
                logger.warning(
                    "No folder '%s' found under %s.",
                    target_folder,
                    root_dirs,
                )
                return {
                    "status": "warning",
                    "message": f"No folder named '{target_folder}' found.",
                    "indexed_files": 0,
                }

            logger.info(f"Collected {len(all_files)} files to scan after applying exclusions.")

            all_files.sort(
                key=lambda p: os.path.getmtime(p) if os.path.exists(p) else 0,
                reverse=True,
            )

            # Prepare shared state
            semaphore = asyncio.Semaphore(max_parallel)
            seen_hashes_lock = asyncio.Lock() # protect seen_hashes
            seen_hashes : Set[str] = set()
            counter_lock = asyncio.Lock() # protect files_indexed
            files_indexed_container : List[int] = [0]
            fast_skipped_container: List[int] = [0]

            # Create all tasks and run them concurrently
            tasks = [
                self.process_one_file(
                    file_path,
                    semaphore=semaphore,
                    seen_hashes_lock=seen_hashes_lock,
                    seen_hashes=seen_hashes,
                    counter_lock=counter_lock,
                    files_indexed_container=files_indexed_container,
                    fast_skipped_container=fast_skipped_container,
                    redis_client=redis_client,
                    config=config,
                    context=context,
                )
                for file_path in all_files
            ]

            results = await asyncio.gather(*tasks, return_exceptions=True)

            # Check if cancelled
            if self.scan_cancel_event.is_set():
                logger.info(f"Scan cancelled. Indexed {files_indexed_container[0]} files before cancellation.")
                return {
                    "status": "cancelled",
                    "indexed_files": files_indexed_container[0],
                    "total_files": len(all_files),
                    "fast_skipped": fast_skipped_container[0],
                }

            # Log any unhandled exceptions from individual file tasks
            for i, result in enumerate(results):
                if isinstance(result, asyncio.CancelledError):
                    pass
                elif isinstance(result, Exception):
                    logger.error(f"Error processing file {all_files[i]}: {result}")
            
            logger.info(
                "Parallel scan completed successfully. Indexed %d / %d files (%d fast-skipped).",
                files_indexed_container[0],
                len(all_files),
                fast_skipped_container[0],
            )

            return {
                "status": "success",
                "indexed_files": files_indexed_container[0],
                "total_files": len(all_files),
                "fast_skipped": fast_skipped_container[0],
            }

        except asyncio.CancelledError:
            logger.info(f"Scan cancelled")
            return {"status": "cancelled", "indexed_files": 0}

    @with_app_context
    async def scan_single_file(
        self,
        file_path: str,
        *,
        context: AppContext = None,
    ) -> dict:
        redis_client = context.redis_client
        config = context.config

        if not redis_client:
            return {"status": "error", "message": "Redis unavailable"}

        if not await asyncio.to_thread(os.path.isfile, file_path):
            return {"status": "error", "message": f"File not found: {file_path}"}

        seen_hashes: Set[str] = set()
        files_indexed_container: List[int] = [0]
        fast_skipped_container: List[int] = [0]
        semaphore = asyncio.Semaphore(1)

        await self.process_one_file(
            file_path,
            semaphore=semaphore,
            seen_hashes_lock=asyncio.Lock(),
            seen_hashes=seen_hashes,
            counter_lock=asyncio.Lock(),
            files_indexed_container=files_indexed_container,
            fast_skipped_container=fast_skipped_container,
            redis_client=redis_client,
            config=config,
            context=context,
        )

        file_hash = await calculate_sha256(file_path)
        pcap_key = f"{PCAP_FILE_KEY_PREFIX}:{file_hash}"
        meta = await asyncio.to_thread(redis_client.hgetall, pcap_key)

        if not meta:
            return {
                "status": "no_protocols",
                "file_hash": file_hash,
                "message": "File processed but not indexed (no protocols or error)",
            }

        protocols = [p.strip() for p in meta.get("protocols", "").split(",") if p.strip()]
        alerts_raw = meta.get("alerts", "[]")
        try:
            alerts = json.loads(alerts_raw)
        except json.JSONDecodeError:
            alerts = []

        indexed = files_indexed_container[0] > 0
        stored_path = meta.get("path", "")
        is_duplicate = (
            not indexed
            and stored_path
            and stored_path != file_path
            and await asyncio.to_thread(os.path.exists, stored_path)
        )

        if is_duplicate:
            return {
                "status": "duplicate",
                "file_hash": file_hash,
                "message": "Identical content already indexed at another path",
                "existing_filename": meta.get("filename"),
                "existing_path": stored_path,
                "protocols": protocols,
                "alerts": alerts,
                "indexed": False,
            }

        return {
            "status": "success",
            "file_hash": file_hash,
            "filename": meta.get("filename"),
            "protocols": protocols,
            "alerts": alerts,
            "indexed": indexed,
            "already_indexed": not indexed and stored_path == file_path,
        }

    @with_app_context
    def scan_wrapper(
        self,
        exclude_files=None,
        target_folder: Optional[str] = None,
        *,
        context: AppContext = None,
    ):
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
                self.scan_and_index(
                    exclude_files=exclude_files,
                    target_folder=target_folder,
                )
            )
            self.scan_status["indexed_files"] = result.get("indexed_files", 0)
            last_run = {
                "finished_at": time.time(),
                "status": result.get("status", "success"),
                "total_files": result.get("total_files", 0),
                "fast_skipped": result.get("fast_skipped", 0),
                "indexed_files": result.get("indexed_files", 0),
            }
            self.scan_status["last_run"] = last_run

            if result.get("status") == "cancelled":
                self.scan_status["state"] = ScanState.IDLE
                self.scan_status["message"] = (
                    f"Scan cancelled. Indexed {self.scan_status['indexed_files']} files before cancellation."
                )
                logger.info("Background scan cancelled.")
            elif result.get("status") == "warning":
                self.scan_status["state"] = ScanState.IDLE
                self.scan_status["message"] = result.get("message", "Scan finished with a warning.")
                logger.warning("Background scan warning: %s", self.scan_status["message"])
            else:
                self.scan_status["state"] = ScanState.COMPLETED
                indexed = last_run["indexed_files"]
                total = last_run["total_files"]
                skipped = last_run["fast_skipped"]
                if indexed == 0 and skipped > 0:
                    self.scan_status["message"] = (
                        f"Completed. {skipped}/{total} file(s) fast-skipped (unchanged), 0 newly indexed."
                    )
                elif indexed == 0:
                    self.scan_status["message"] = (
                        f"Completed. Scanned {total} file(s), 0 newly indexed."
                    )
                else:
                    self.scan_status["message"] = (
                        f"Completed successfully. Indexed {indexed}/{total} file(s)"
                        f" ({skipped} fast-skipped)."
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

            if redis:
                from services.dashboard_cache import invalidate_dashboard_summary

                invalidate_dashboard_summary(redis)
                try:
                    from routes.dashboard import build_dashboard_summary

                    asyncio.run(build_dashboard_summary(context))
                except Exception as exc:
                    logger.warning("Dashboard cache rebuild after scan failed: %s", exc)

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
                logger.warning(
                    f"capinfos failed for {file_path}; continuing without total_packets"
                )
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

    def rebuild_search_indexes_sync(self, redis_client: Redis) -> dict:
        if not redis_client:
            return {"error": "Redis connection is not available."}

        keys = list(redis_client.scan_iter(f"{PCAP_FILE_KEY_PREFIX}:*"))
        total = len(keys)
        if total == 0:
            redis_client.delete(
                LEX_INDEX_FILENAME,
                LEX_INDEX_PATH,
                SORT_INDEX_FILENAME,
                SORT_INDEX_PATH,
                SORT_INDEX_SIZE,
                SORT_INDEX_PACKET_COUNT,
            )
            return {"processed": 0, "backfilled": 0, "total": 0}

        filename_map: Dict[str, List[str]] = {}
        path_map: Dict[str, List[str]] = {}
        size_map: Dict[str, int] = {}
        packet_map: Dict[str, int] = {}

        processed = 0
        backfilled = 0

        for key in keys:
            processed += 1
            data = redis_client.hgetall(key)
            if not data:
                continue

            file_hash = key.split(":")[-1]

            filename_sort = _normalize_scan_param(data.get("filename_sort"))
            if not filename_sort:
                raw = _normalize_scan_param(data.get("filename"))
                if raw:
                    filename_sort = raw.lower()
                    redis_client.hset(key, "filename_sort", filename_sort)
                    backfilled += 1

            path_sort = _normalize_scan_param(data.get("path_sort"))
            if not path_sort:
                raw = _normalize_scan_param(data.get("path"))
                if raw:
                    path_sort = raw.lower()
                    redis_client.hset(key, "path_sort", path_sort)
                    backfilled += 1

            if filename_sort:
                filename_map.setdefault(filename_sort, []).append(file_hash)
            if path_sort:
                path_map.setdefault(path_sort, []).append(file_hash)

            size_bytes = _parse_int(data.get("size_bytes"))
            if size_bytes is not None:
                size_map[file_hash] = max(size_bytes, 0)

            # The score used by SORT_INDEX_PACKET_COUNT has drifted historically;
            # prefer `total_packets`, fall back to `protocol_packet_count`.
            packet_count = _parse_int(data.get("total_packets"))
            if packet_count is None:
                packet_count = _parse_int(data.get("protocol_packet_count"))
            packet_map[file_hash] = max(packet_count or 0, 0)

        lex_filename_new = f"{LEX_INDEX_FILENAME}:new"
        lex_path_new = f"{LEX_INDEX_PATH}:new"
        filename_new = f"{SORT_INDEX_FILENAME}:new"
        path_new = f"{SORT_INDEX_PATH}:new"
        size_new = f"{SORT_INDEX_SIZE}:new"
        packet_new = f"{SORT_INDEX_PACKET_COUNT}:new"

        pipe = redis_client.pipeline()
        pipe.delete(lex_filename_new, lex_path_new, filename_new, path_new, size_new, packet_new)

        # Rebuild lex sets (score=0 => zrange is lexicographic)
        if filename_map:
            pipe.zadd(lex_filename_new, {k: 0 for k in filename_map.keys()})
        if path_map:
            pipe.zadd(lex_path_new, {k: 0 for k in path_map.keys()})

        # Numeric sorts
        if size_map:
            pipe.zadd(size_new, size_map)
        if packet_map:
            pipe.zadd(packet_new, packet_map)

        # Lex-derived sorts for file hashes
        for rank, fname in enumerate(sorted(filename_map.keys())):
            hashes = filename_map.get(fname)
            if hashes:
                pipe.zadd(filename_new, {h: rank for h in hashes})

        for rank, fpath in enumerate(sorted(path_map.keys())):
            hashes = path_map.get(fpath)
            if hashes:
                pipe.zadd(path_new, {h: rank for h in hashes})

        pipe.execute()

        # Swap in rebuilt indexes atomically
        pipe = redis_client.pipeline()
        pipe.rename(lex_filename_new, LEX_INDEX_FILENAME)
        pipe.rename(lex_path_new, LEX_INDEX_PATH)
        pipe.rename(filename_new, SORT_INDEX_FILENAME)
        pipe.rename(path_new, SORT_INDEX_PATH)
        pipe.rename(size_new, SORT_INDEX_SIZE)
        pipe.rename(packet_new, SORT_INDEX_PACKET_COUNT)
        pipe.execute()

        return {"processed": processed, "backfilled": backfilled, "total": total}

    @with_app_context
    def rebuild_searchindex_wrapper(self, *, context: AppContext = None):
        redis = context.redis_client
        if not redis:
            logger.error("Redis connection is not available. Rebuild aborted.")
            return

        try:
            self.rebuild_searchindex_status["state"] = RebuildSearchIndexState.RUNNING
            self.rebuild_searchindex_status["processed"] = 0
            self.rebuild_searchindex_status["backfilled"] = 0
            self.rebuild_searchindex_status["total"] = 0
            self.rebuild_searchindex_status["message"] = "Rebuild in progress..."
            logger.info("Background rebuild-searchindex started.")

            result = self.rebuild_search_indexes_sync(redis)
            self.rebuild_searchindex_status["processed"] = result.get("processed", 0)
            self.rebuild_searchindex_status["backfilled"] = result.get("backfilled", 0)
            self.rebuild_searchindex_status["total"] = result.get("total", 0)

            self.rebuild_searchindex_status["state"] = RebuildSearchIndexState.COMPLETED
            self.rebuild_searchindex_status["message"] = (
                "Completed successfully. "
                f"Rebuilt sort indexes from {self.rebuild_searchindex_status['processed']} keys "
                f"(backfilled={self.rebuild_searchindex_status['backfilled']})."
            )
            logger.info("Background rebuild-searchindex completed.")

        except Exception as e:
            logger.error("Rebuild-searchindex failed: %s", e)
            self.rebuild_searchindex_status["state"] = RebuildSearchIndexState.FAILED
            self.rebuild_searchindex_status["message"] = str(e)
        finally:
            if self.rebuild_searchindex_status["state"] != RebuildSearchIndexState.FAILED:
                self.rebuild_searchindex_status["state"] = RebuildSearchIndexState.IDLE

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
        sample_segments: int = 1,
        file_size_bytes: Optional[int] = None,
    ) -> Optional[Tuple[Dict[str, int], int]]:
        """Quick scan via tshark, stopping after threshold bytes.

        When sample_segments > 1, extracts head/middle/tail packet ranges with
        editcap (same byte budget) before parsing.
        """
        threshold = quick_threshold_bytes or 0
        if threshold <= 0:
            logger.warning("Quick scan threshold is <= 0 for %s; skipping", pcap_file)
            return {}, 0

        scan_target = pcap_file
        temp_sample_path: Optional[str] = None

        if sample_segments > 1 and file_size_bytes and file_size_bytes > 0:
            total_packets = get_total_packets_from_pcap_sync(pcap_file)
            if total_packets and total_packets > 0:
                avg_packet_bytes = max(64, file_size_bytes / total_packets)
                packets_per_segment = max(
                    50,
                    int((threshold / sample_segments) / avg_packet_bytes),
                )
                ranges = build_segment_packet_ranges(
                    total_packets,
                    sample_segments,
                    packets_per_segment,
                )
                fd, temp_sample_path = tempfile.mkstemp(suffix=".pcap")
                os.close(fd)
                if extract_pcap_segments_sync(pcap_file, ranges, temp_sample_path):
                    scan_target = temp_sample_path
                    threshold = os.path.getsize(temp_sample_path)
                    logger.info(
                        "Segmented quick scan for %s: segments=%s ranges=%s sample_bytes=%s",
                        pcap_file,
                        sample_segments,
                        ranges,
                        threshold,
                    )
                else:
                    os.unlink(temp_sample_path)
                    temp_sample_path = None

        try:
            return self._tshark_quick_protocol_scan(
                scan_target,
                threshold_bytes=threshold,
                excluded_protocols=excluded_protocols,
                source_label=pcap_file if scan_target != pcap_file else None,
            )
        finally:
            if temp_sample_path and os.path.exists(temp_sample_path):
                os.unlink(temp_sample_path)

    def _tshark_quick_protocol_scan(
        self,
        pcap_file: str,
        *,
        threshold_bytes: int,
        excluded_protocols: Optional[set[str]] = None,
        source_label: Optional[str] = None,
    ) -> Optional[Tuple[Dict[str, int], int]]:
        scan_cancel_event = self.scan_cancel_event
        scan_process = self.scan_process
        log_name = source_label or pcap_file
        threshold = threshold_bytes

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
                log_name,
                threshold,
            )

            while True:
                if scan_cancel_event.is_set():
                    logger.info(
                        "Scan cancellation requested. Terminating tshark for %s.",
                        log_name,
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
                        log_name,
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
                        log_name,
                        stderr_output,
                    )
                return None

            logger.info(
                "Quick scan finished for %s (bytes_scanned=%s, packets_scanned=%s)",
                log_name,
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
                log_name,
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
        scan_mode: ScanMode = ScanMode.FULL,
        quick_threshold_bytes: Optional[int] = None,
        sample_segments: int = 1,
        file_size_bytes: Optional[int] = None,
    ) -> Optional[Tuple[Dict[str, int], int]]:
        match scan_mode:
            case ScanMode.FAST:
                return await asyncio.to_thread(
                    self.get_protocols_from_pcap_fast_sync,
                    pcap_file,
                    excluded_protocols=excluded_protocols,
                )
            case ScanMode.FULL:
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
                    sample_segments=sample_segments,
                    file_size_bytes=file_size_bytes,
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

    pipe = redis.pipeline()
    if await asyncio.to_thread(redis.exists, filename_new):
        pipe.rename(filename_new, SORT_INDEX_FILENAME)
    else:
        pipe.delete(SORT_INDEX_FILENAME)

    if await asyncio.to_thread(redis.exists, path_new):
        pipe.rename(path_new, SORT_INDEX_PATH)
    else:
        pipe.delete(SORT_INDEX_PATH)
    pipe.execute()

    logger.info("Lexicographic sort indexes rebuilt successfully.")
