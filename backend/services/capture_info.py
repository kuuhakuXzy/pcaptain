"""capinfos helpers for capture time range metadata."""

import re
import subprocess
from datetime import datetime, timezone
from typing import Optional, Tuple

from .logger import get_logger

logger = get_logger(__name__)

_EPOCH_RE = re.compile(r"(\d{10,})")


def _parse_capinfos_timestamp(line: str) -> Optional[float]:
    """Parse capinfos time lines to Unix epoch seconds."""
    match = _EPOCH_RE.search(line)
    if match:
        return float(match.group(1))

    for fmt in (
        "%Y-%m-%d %H:%M:%S %z",
        "%Y-%m-%d %H:%M:%S.%f %z",
        "%b %d, %Y %H:%M:%S %Z",
    ):
        value = line.split(":", 1)[-1].strip() if ":" in line else line.strip()
        try:
            parsed = datetime.strptime(value, fmt)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.timestamp()
        except ValueError:
            continue
    return None


def get_capture_time_range_sync(pcap_file: str) -> Tuple[Optional[float], Optional[float]]:
    """
    Return (capture_start_epoch, capture_end_epoch) from capinfos, if available.
    """
    command = ["capinfos", "-u", "-a", pcap_file]
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
                "capinfos time range failed for %s: %s",
                pcap_file,
                result.stderr.strip(),
            )
            return None, None

        start_ts: Optional[float] = None
        end_ts: Optional[float] = None
        for line in result.stdout.splitlines():
            lower = line.lower()
            if "start time" in lower or "earliest packet" in lower:
                start_ts = _parse_capinfos_timestamp(line)
            elif "end time" in lower or "latest packet" in lower:
                end_ts = _parse_capinfos_timestamp(line)

        return start_ts, end_ts
    except FileNotFoundError:
        logger.error("capinfos not found — install wireshark-common.")
        return None, None
    except Exception as exc:
        logger.error("capture time range error for %s: %s", pcap_file, exc)
        return None, None
