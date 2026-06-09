"""PCAP file metadata: capinfos with in-process cache keyed by path/size/mtime."""

from __future__ import annotations

import os
import re
import subprocess
import threading
import time
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

from .capture_info import _parse_capinfos_timestamp
from .logger import get_logger

logger = get_logger(__name__)

_PACKET_COUNT_RE = re.compile(
    r"(?:Number of packets|Packets)\s*[:=]\s*(\d+)",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class PcapMetadata:
    total_packets: Optional[int]
    capture_start: Optional[float]
    capture_end: Optional[float]


@dataclass
class _CacheEntry:
    metadata: PcapMetadata
    expires_at: float


class PcapMetadataCache:
    """Thread-safe TTL cache for capinfos results."""

    def __init__(self, ttl_seconds: int = 3600) -> None:
        self._ttl = max(0, ttl_seconds)
        self._lock = threading.Lock()
        self._entries: Dict[str, _CacheEntry] = {}

    def _cache_key(self, pcap_file: str) -> Optional[str]:
        try:
            stat = os.stat(pcap_file)
        except OSError:
            return None
        return f"{pcap_file}:{stat.st_size}:{stat.st_mtime_ns}"

    def get(self, pcap_file: str) -> Optional[PcapMetadata]:
        if self._ttl <= 0:
            return None
        key = self._cache_key(pcap_file)
        if key is None:
            return None
        now = time.monotonic()
        with self._lock:
            entry = self._entries.get(key)
            if entry is None or entry.expires_at <= now:
                return None
            return entry.metadata

    def set(self, pcap_file: str, metadata: PcapMetadata) -> None:
        if self._ttl <= 0:
            return
        key = self._cache_key(pcap_file)
        if key is None:
            return
        with self._lock:
            self._entries[key] = _CacheEntry(
                metadata=metadata,
                expires_at=time.monotonic() + self._ttl,
            )

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()

    @property
    def ttl_seconds(self) -> int:
        return self._ttl


# Module-level cache; TTL updated per resolve call from config.
_metadata_cache = PcapMetadataCache(ttl_seconds=3600)


def reset_metadata_cache(ttl_seconds: Optional[int] = None) -> None:
    global _metadata_cache
    if ttl_seconds is not None:
        _metadata_cache = PcapMetadataCache(ttl_seconds=ttl_seconds)
    else:
        _metadata_cache.clear()


def _ensure_cache_ttl(ttl_seconds: int) -> PcapMetadataCache:
    global _metadata_cache
    if _metadata_cache.ttl_seconds != ttl_seconds:
        _metadata_cache = PcapMetadataCache(ttl_seconds=ttl_seconds)
    return _metadata_cache


def _parse_capinfos_output(stdout: str) -> PcapMetadata:
    total_packets: Optional[int] = None
    capture_start: Optional[float] = None
    capture_end: Optional[float] = None

    count_match = _PACKET_COUNT_RE.search(stdout)
    if count_match:
        total_packets = int(count_match.group(1))

    for line in stdout.splitlines():
        lower = line.lower()
        if "start time" in lower or "earliest packet" in lower:
            capture_start = _parse_capinfos_timestamp(line)
        elif "end time" in lower or "latest packet" in lower:
            capture_end = _parse_capinfos_timestamp(line)

    return PcapMetadata(
        total_packets=total_packets,
        capture_start=capture_start,
        capture_end=capture_end,
    )


def get_pcap_metadata_sync(
    pcap_file: str,
    *,
    include_packet_count: bool = True,
    include_time_range: bool = True,
) -> PcapMetadata:
    """
    Run capinfos once for packet count and/or capture time range.
    """
    flags: list[str] = []
    if include_packet_count:
        flags.extend(["-M", "-c"])
    if include_time_range:
        flags.extend(["-u", "-a"])
    if not flags:
        return PcapMetadata(None, None, None)

    command = ["capinfos", *flags, pcap_file]
    try:
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=120,
        )
        if result.returncode != 0:
            logger.warning(
                "capinfos metadata failed for %s: %s",
                pcap_file,
                result.stderr.strip()[:300],
            )
            return PcapMetadata(None, None, None)
        return _parse_capinfos_output(result.stdout)
    except FileNotFoundError:
        logger.error("capinfos not found — install wireshark-common.")
        return PcapMetadata(None, None, None)
    except Exception as exc:
        logger.error("capinfos metadata error for %s: %s", pcap_file, exc)
        return PcapMetadata(None, None, None)


def resolve_pcap_metadata(
    pcap_file: str,
    *,
    packets_seen_hint: Optional[int] = None,
    cache_ttl_seconds: int = 3600,
) -> Tuple[Optional[int], Optional[float], Optional[float]]:
    """
    Resolve total_packets and capture time range with cache and fastscan hint.

    When packets_seen_hint is set (full-file fastscan read), skip capinfos packet
  count and only fetch time range on cache miss.
    """
    cache = _ensure_cache_ttl(cache_ttl_seconds)

    cached = cache.get(pcap_file)
    if cached is not None:
        total = packets_seen_hint if packets_seen_hint is not None else cached.total_packets
        return total, cached.capture_start, cached.capture_end

    need_count = packets_seen_hint is None
    meta = get_pcap_metadata_sync(
        pcap_file,
        include_packet_count=need_count,
        include_time_range=True,
    )
    if need_count and (
        meta.total_packets is not None
        or meta.capture_start is not None
        or meta.capture_end is not None
    ):
        cache.set(pcap_file, meta)
    elif not need_count:
        # Cache time range together with hint count for future hits.
        combined = PcapMetadata(
            total_packets=packets_seen_hint,
            capture_start=meta.capture_start,
            capture_end=meta.capture_end,
        )
        cache.set(pcap_file, combined)

    total_packets = packets_seen_hint if packets_seen_hint is not None else meta.total_packets
    return total_packets, meta.capture_start, meta.capture_end
