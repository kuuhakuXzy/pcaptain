# Tyler code
import json
import math
import re
import subprocess
from collections import Counter, defaultdict
from typing import Any, Dict, List, Optional, Tuple

from .logger import get_logger

logger = get_logger(__name__)

MAX_IOC_PACKETS = 50_000
MAX_TIMELINE_PACKETS = 100_000
DEFAULT_BUCKET_SECONDS = 1
ANALYSIS_VERSION = "v1"

PRIVATE_IP_RE = re.compile(
    r"^(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.|127\.|0\.|169\.254\.|::1|fe80:)"
)


def _run_tshark_fields(pcap_file: str, fields: List[str], max_packets: int) -> List[List[str]]:
    command = [
        "tshark", "-r", pcap_file,
        "-c", str(max_packets),
        "-T", "fields",
        *sum([["-e", f] for f in fields], []),
        "-E", "separator=\t",
        "-E", "occurrence=f",
    ]
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
        )
        if result.returncode not in (0, 1):
            logger.warning("tshark IOC/timeline failed for %s: %s", pcap_file, result.stderr[:500])
            return []

        rows = []
        for line in result.stdout.splitlines():
            if not line.strip():
                continue
            rows.append(line.split("\t"))
        return rows
    except subprocess.TimeoutExpired:
        logger.error("tshark timed out for %s", pcap_file)
        return []
    except Exception as e:
        logger.error("tshark error for %s: %s", pcap_file, e)
        return []


def extract_ioc_sync(
    pcap_file: str,
    max_packets: int = MAX_IOC_PACKETS,
    total_packets: Optional[int] = None,
) -> Dict[str, Any]:
    fields = [
        "ip.src", "ip.dst", "ipv6.src", "ipv6.dst",
        "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport",
        "dns.qry.name", "http.host",
    ]
    rows = _run_tshark_fields(pcap_file, fields, max_packets)

    ip_src = Counter()
    ip_dst = Counter()
    port_tcp = Counter()
    port_udp = Counter()
    domains = Counter()
    flows = Counter()

    for row in rows:
        while len(row) < len(fields):
            row.append("")
        (
            ip_s, ip_d, ip6_s, ip6_d,
            tcp_sp, tcp_dp, udp_sp, udp_dp,
            dns_name, http_host,
        ) = row[: len(fields)]

        for ip in filter(None, [ip_s, ip6_s]):
            ip_src[ip.strip()] += 1
        for ip in filter(None, [ip_d, ip6_d]):
            ip_dst[ip.strip()] += 1

        if tcp_sp and tcp_sp.isdigit():
            port_tcp[int(tcp_sp)] += 1
        if tcp_dp and tcp_dp.isdigit():
            port_tcp[int(tcp_dp)] += 1
        if udp_sp and udp_sp.isdigit():
            port_udp[int(udp_sp)] += 1
        if udp_dp and udp_dp.isdigit():
            port_udp[int(udp_dp)] += 1

        for domain in filter(None, [dns_name, http_host]):
            domain = domain.strip().lower().rstrip(".")
            if domain and len(domain) > 1:
                domains[domain] += 1

        src_ip = ip_s or ip6_s
        dst_ip = ip_d or ip6_d
        if src_ip and dst_ip:
            if tcp_sp or tcp_dp:
                flow_key = f"{src_ip}:{tcp_sp or '*'} → {dst_ip}:{tcp_dp or '*'}"
                flows[(flow_key, "tcp")] += 1
            elif udp_sp or udp_dp:
                flow_key = f"{src_ip}:{udp_sp or '*'} → {dst_ip}:{udp_dp or '*'}"
                flows[(flow_key, "udp")] += 1

    all_ips = set(ip_src) | set(ip_dst)
    ip_list = []
    for ip in all_ips:
        sc, dc = ip_src[ip], ip_dst[ip]
        role = "both" if sc and dc else ("src" if sc else "dst")
        ip_list.append({
            "ip": ip,
            "count": sc + dc,
            "src_count": sc,
            "dst_count": dc,
            "role": role,
            "is_private": bool(PRIVATE_IP_RE.match(ip)),
        })
    ip_list.sort(key=lambda x: x["count"], reverse=True)

    port_list = []
    for port, count in port_tcp.most_common(30):
        port_list.append({"port": port, "protocol": "tcp", "count": count})
    for port, count in port_udp.most_common(30):
        port_list.append({"port": port, "protocol": "udp", "count": count})
    port_list.sort(key=lambda x: x["count"], reverse=True)

    domain_list = [
        {"domain": d, "count": c}
        for d, c in domains.most_common(50)
    ]

    flow_list = [
        {"flow": fk, "protocol": proto, "count": c}
        for (fk, proto), c in flows.most_common(30)
    ]

    truncated = total_packets is not None and total_packets > max_packets

    return {
        "ips": ip_list[:50],
        "ports": port_list[:40],
        "domains": domain_list,
        "flows": flow_list,
        "packets_analyzed": len(rows),
        "truncated": truncated,
        "version": ANALYSIS_VERSION,
    }


def extract_timeline_sync(
    pcap_file: str,
    bucket_seconds: int = DEFAULT_BUCKET_SECONDS,
    max_packets: int = MAX_TIMELINE_PACKETS,
    total_packets: Optional[int] = None,
) -> Dict[str, Any]:
    fields = ["frame.time_relative", "frame.protocols"]
    rows = _run_tshark_fields(pcap_file, fields, max_packets)

    buckets: Dict[int, Dict[str, Any]] = defaultdict(lambda: {"packets": 0, "protocols": Counter()})
    max_time = 0.0

    for row in rows:
        if not row or not row[0]:
            continue
        try:
            t = float(row[0])
        except ValueError:
            continue
        max_time = max(max_time, t)
        bucket_idx = int(t // bucket_seconds)
        buckets[bucket_idx]["packets"] += 1
        if len(row) > 1 and row[1]:
            for proto in row[1].split(":"):
                proto = proto.strip().lower()
                if proto:
                    buckets[bucket_idx]["protocols"][proto] += 1

    bucket_list = []
    for idx in sorted(buckets.keys()):
        b = buckets[idx]
        top_protos = dict(b["protocols"].most_common(8))
        bucket_list.append({
            "time_start": round(idx * bucket_seconds, 2),
            "time_end": round((idx + 1) * bucket_seconds, 2),
            "packets": b["packets"],
            "protocols": top_protos,
        })

    truncated = total_packets is not None and total_packets > max_packets

    return {
        "buckets": bucket_list,
        "bucket_seconds": bucket_seconds,
        "total_duration": round(max_time, 2),
        "packets_analyzed": len(rows),
        "truncated": truncated,
        "version": ANALYSIS_VERSION,
    }


def protocol_similarity(pct_a: Dict[str, float], pct_b: Dict[str, float]) -> float:
    all_protos = set(pct_a) | set(pct_b)
    if not all_protos:
        return 100.0 if pct_a == pct_b else 0.0

    dot = sum(float(pct_a.get(p, 0)) * float(pct_b.get(p, 0)) for p in all_protos)
    mag_a = math.sqrt(sum(float(v) ** 2 for v in pct_a.values()))
    mag_b = math.sqrt(sum(float(v) ** 2 for v in pct_b.values()))
    if mag_a == 0 or mag_b == 0:
        return 0.0
    return round((dot / (mag_a * mag_b)) * 100, 1)


def _parse_pct(raw: Any) -> Dict[str, float]:
    if isinstance(raw, dict):
        return {k: float(v) for k, v in raw.items()}
    if isinstance(raw, str):
        try:
            return {k: float(v) for k, v in json.loads(raw).items()}
        except (json.JSONDecodeError, TypeError, ValueError):
            return {}
    return {}


def find_similar_files(
    target_hash: str,
    target_pct: Dict[str, float],
    all_files: List[Dict[str, Any]],
    limit: int = 10,
    min_similarity: float = 50.0,
) -> List[Dict[str, Any]]:
    results = []
    for f in all_files:
        fh = f.get("file_hash")
        if fh == target_hash:
            continue
        sim = protocol_similarity(target_pct, f.get("protocol_percentages", {}))
        if sim >= min_similarity:
            results.append({
                "file_hash": fh,
                "filename": f.get("filename"),
                "similarity_pct": sim,
                "protocols": f.get("protocols", []),
            })
    results.sort(key=lambda x: x["similarity_pct"], reverse=True)
    return results[:limit]


def cluster_files(
    all_files: List[Dict[str, Any]],
    threshold: float = 70.0,
) -> List[Dict[str, Any]]:
    if not all_files:
        return []

    n = len(all_files)
    parent = list(range(n))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    def union(i: int, j: int) -> None:
        ri, rj = find(i), find(j)
        if ri != rj:
            parent[rj] = ri

    for i in range(n):
        for j in range(i + 1, n):
            sim = protocol_similarity(
                all_files[i]["protocol_percentages"],
                all_files[j]["protocol_percentages"],
            )
            if sim >= threshold:
                union(i, j)

    groups: Dict[int, List[int]] = defaultdict(list)
    for i in range(n):
        groups[find(i)].append(i)

    clusters = []
    for idx, (_root, members) in enumerate(groups.items()):
        member_files = [all_files[i] for i in members]
        all_protos: Counter = Counter()
        for mf in member_files:
            for p, v in mf["protocol_percentages"].items():
                all_protos[p] += v
        top_protos = [p for p, _ in all_protos.most_common(3)]
        label = " + ".join(top_protos).upper() if top_protos else "Mixed"

        avg_sim = 0.0
        if len(members) > 1:
            sims = []
            for i in range(len(members)):
                for j in range(i + 1, len(members)):
                    sims.append(protocol_similarity(
                        all_files[members[i]]["protocol_percentages"],
                        all_files[members[j]]["protocol_percentages"],
                    ))
            avg_sim = round(sum(sims) / len(sims), 1)

        clusters.append({
            "cluster_id": idx,
            "label": label,
            "file_count": len(members),
            "avg_internal_similarity": avg_sim,
            "files": [
                {
                    "file_hash": mf["file_hash"],
                    "filename": mf["filename"],
                    "path": mf.get("path"),
                    "protocols": mf.get("protocols", []),
                }
                for mf in sorted(member_files, key=lambda x: x.get("filename", ""))
            ],
        })

    clusters.sort(key=lambda c: c["file_count"], reverse=True)
    return clusters
