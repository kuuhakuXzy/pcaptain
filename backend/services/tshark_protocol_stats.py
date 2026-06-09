"""Protocol statistics from tshark (Wireshark dissectors), used to validate fast-scan results."""

from __future__ import annotations

import re
import subprocess
import threading
import time
from typing import Dict, Optional

from .logger import get_logger

logger = get_logger(__name__)

# Protocol Hierarchy Statistics lines: "  tcp  frames:123 bytes:456"
_PHS_PROTOCOL_RE = re.compile(r"^\s*(\S+?)\s+frames:(\d+)\b", re.IGNORECASE)


def parse_io_phs_output(stdout: str) -> Dict[str, int]:
    """Parse `tshark -q -z io,phs` hierarchy output into protocol -> frame counts."""
    counts: Dict[str, int] = {}
    in_section = False

    for line in stdout.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("="):
            in_section = not in_section
            continue
        if not in_section:
            continue
        if stripped.lower().startswith("protocol hierarchy statistics"):
            continue
        if stripped.lower().startswith("filter:"):
            continue

        match = _PHS_PROTOCOL_RE.match(line)
        if not match:
            continue
        proto = match.group(1).lower()
        counts[proto] = int(match.group(2))

    return counts


def build_protocol_fingerprint(protocol_counts: Dict[str, int]) -> str:
    """Build a stable fingerprint string from protocol counts (sorted by name)."""
    if not protocol_counts:
        return "PCAPTAIN_FP v1"
    parts = "|".join(f"{name}={count}" for name, count in sorted(protocol_counts.items()))
    return f"PCAPTAIN_FP v1|{parts}"


def get_protocol_counts_from_phs_sync(
    pcap_file: str,
    *,
    scan_cancel_event=None,
    scan_process: Optional[dict] = None,
    timeout_seconds: int = 600,
) -> Optional[Dict[str, int]]:
    """
    Run tshark protocol hierarchy stats for dissector-accurate protocol frame counts.

    Returns None when tshark is unavailable, cancelled, or fails.
    """
    command = ["tshark", "-r", pcap_file, "-q", "-z", "io,phs"]

    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if scan_process is not None:
            scan_process["tshark"] = process

        stdout_lines: list[str] = []
        stderr_lines: list[str] = []

        def read_stream(stream, sink):
            for line in iter(stream.readline, ""):
                sink.append(line)
            stream.close()

        stdout_thread = threading.Thread(
            target=read_stream, args=(process.stdout, stdout_lines), daemon=True
        )
        stderr_thread = threading.Thread(
            target=read_stream, args=(process.stderr, stderr_lines), daemon=True
        )
        stdout_thread.start()
        stderr_thread.start()

        deadline = time.monotonic() + timeout_seconds
        while process.poll() is None:
            if scan_cancel_event is not None and scan_cancel_event.is_set():
                logger.info("Scan cancellation requested. Terminating tshark phs for %s.", pcap_file)
                process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
                return None
            if time.monotonic() > deadline:
                logger.error("tshark phs timed out for %s", pcap_file)
                process.kill()
                return None
            time.sleep(0.1)

        process.wait()
        stdout_thread.join()
        stderr_thread.join()

        if scan_cancel_event is not None and scan_cancel_event.is_set():
            return None

        if process.returncode != 0:
            stderr = "".join(stderr_lines).strip()
            logger.error("tshark phs failed for %s: %s", pcap_file, stderr[:500])
            return None

        counts = parse_io_phs_output("".join(stdout_lines))
        if not counts:
            logger.warning("tshark phs returned no protocol counts for %s", pcap_file)
            return None
        return counts

    except FileNotFoundError:
        logger.error("tshark not found — install wireshark/tshark for accurate protocol stats.")
        return None
    except Exception as exc:
        logger.error("tshark phs error for %s: %s", pcap_file, exc)
        return None
    finally:
        if scan_process is not None:
            scan_process["tshark"] = None
