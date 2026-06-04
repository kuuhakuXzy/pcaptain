"""Extract IP addresses and L4 ports from PCAP files via tshark."""

import ipaddress
import re
import subprocess
from typing import Dict, Set

from .logger import get_logger

logger = get_logger(__name__)

_FIELD_SPECS = [
    ("ip.src", "ips"),
    ("ip.dst", "ips"),
    ("ipv6.src", "ips"),
    ("ipv6.dst", "ips"),
    ("tcp.srcport", "ports"),
    ("tcp.dstport", "ports"),
    ("udp.srcport", "ports"),
    ("udp.dstport", "ports"),
]


def _is_valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip())
        return True
    except ValueError:
        return False


def _normalize_port(value: str) -> str | None:
    value = value.strip()
    if not value or not re.fullmatch(r"\d+", value):
        return None
    port = int(value)
    if 0 < port <= 65535:
        return str(port)
    return None


def extract_endpoints_sync(
    pcap_file: str,
    *,
    max_packets: int = 10000,
) -> Dict[str, Set[str]]:
    """
    Sample up to max_packets and collect unique IPs and ports.
    """
    empty: Dict[str, Set[str]] = {"ips": set(), "ports": set()}
    fields = [spec[0] for spec in _FIELD_SPECS]
    command = [
        "tshark",
        "-r",
        pcap_file,
        "-c",
        str(max_packets),
        "-T",
        "fields",
        "-E",
        "header=n",
        "-E",
        "separator=\t",
        "-E",
        "quote=n",
        "-E",
        "occurrence=f",
    ]
    for field in fields:
        command.extend(["-e", field])

    try:
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=300,
        )
        if result.returncode != 0:
            logger.warning(
                "endpoint extract failed for %s: %s",
                pcap_file,
                result.stderr.strip()[:500],
            )
            return empty

        ips: Set[str] = set()
        ports: Set[str] = set()
        for line in result.stdout.splitlines():
            if not line.strip():
                continue
            parts = line.split("\t")
            for idx, (_, bucket) in enumerate(_FIELD_SPECS):
                if idx >= len(parts):
                    continue
                raw = parts[idx].strip()
                if not raw:
                    continue
                for token in raw.split(","):
                    token = token.strip()
                    if not token:
                        continue
                    if bucket == "ips" and _is_valid_ip(token):
                        ips.add(token)
                    elif bucket == "ports":
                        port = _normalize_port(token)
                        if port:
                            ports.add(port)

        return {"ips": ips, "ports": ports}
    except FileNotFoundError:
        logger.error("tshark not found for endpoint extraction.")
        return empty
    except subprocess.TimeoutExpired:
        logger.warning("endpoint extract timed out for %s", pcap_file)
        return empty
    except Exception as exc:
        logger.error("endpoint extract error for %s: %s", pcap_file, exc)
        return empty
