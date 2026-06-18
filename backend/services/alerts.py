import json
import uuid
from enum import Enum
from typing import Any, Dict, List, Optional

from .logger import get_logger

logger = get_logger(__name__)

ALERT_RULES_KEY = "pcap:alert:rules"
ALERT_INDEX_KEY = "pcap:alert:index"


class RuleType(str, Enum):
    PROTOCOL_PCT_ABOVE = "protocol_pct_above"
    FILENAME_CONTAINS = "filename_contains"
    PROTOCOL_PRESENT = "protocol_present"
    SIZE_ABOVE = "size_above"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


DEFAULT_RULES: List[Dict[str, Any]] = [
    {
        "id": "default-ssh-flood",
        "name": "High SSH traffic (>80%)",
        "type": RuleType.PROTOCOL_PCT_ABOVE.value,
        "protocol": "ssh",
        "threshold": 80.0,
        "severity": Severity.HIGH.value,
        "enabled": True,
    },
    {
        "id": "default-smtp-flood",
        "name": "High SMTP traffic (>80%)",
        "type": RuleType.PROTOCOL_PCT_ABOVE.value,
        "protocol": "smtp",
        "threshold": 80.0,
        "severity": Severity.MEDIUM.value,
        "enabled": True,
    },
    {
        "id": "default-hydra-name",
        "name": "Filename contains 'hydra'",
        "type": RuleType.FILENAME_CONTAINS.value,
        "keyword": "hydra",
        "severity": Severity.HIGH.value,
        "enabled": True,
    },
    {
        "id": "default-malware-name",
        "name": "Filename contains malware keyword",
        "type": RuleType.FILENAME_CONTAINS.value,
        "keyword": "mirai,zeus,blackenergy,backdoor",
        "severity": Severity.HIGH.value,
        "enabled": True,
    },
    {
        "id": "default-large-file",
        "name": "Large file (>50 MB)",
        "type": RuleType.SIZE_ABOVE.value,
        "threshold": 50 * 1024 * 1024,
        "severity": Severity.LOW.value,
        "enabled": True,
    },
    {
        "id": "default-ftp-brute",
        "name": "High FTP traffic (>80%)",
        "type": RuleType.PROTOCOL_PCT_ABOVE.value,
        "protocol": "ftp",
        "threshold": 80.0,
        "severity": Severity.MEDIUM.value,
        "enabled": True,
    },
]


def seed_default_rules(redis_client) -> None:
    if redis_client.exists(ALERT_RULES_KEY):
        return
    for rule in DEFAULT_RULES:
        redis_client.hset(ALERT_RULES_KEY, rule["id"], json.dumps(rule))
    logger.info("Seeded %d default alert rules", len(DEFAULT_RULES))


def get_all_rules(redis_client) -> List[Dict[str, Any]]:
    raw = redis_client.hgetall(ALERT_RULES_KEY)
    rules = []
    for rule_id, payload in raw.items():
        try:
            rule = json.loads(payload)
            rule["id"] = rule_id
            rules.append(rule)
        except json.JSONDecodeError:
            logger.warning("Skipping malformed alert rule: %s", rule_id)
    return sorted(rules, key=lambda r: r.get("name", ""))


def save_rule(redis_client, rule: Dict[str, Any]) -> Dict[str, Any]:
    rule_id = rule.get("id") or str(uuid.uuid4())
    stored = {k: v for k, v in rule.items() if k != "id"}
    stored.setdefault("enabled", True)
    redis_client.hset(ALERT_RULES_KEY, rule_id, json.dumps(stored))
    return {"id": rule_id, **stored}


def delete_rule(redis_client, rule_id: str) -> bool:
    return redis_client.hdel(ALERT_RULES_KEY, rule_id) > 0


def _match_rule(rule: Dict[str, Any], metadata: Dict[str, Any]) -> Optional[str]:
    if not rule.get("enabled", True):
        return None

    rule_type = rule.get("type")
    filename = (metadata.get("filename") or "").lower()
    size_bytes = int(metadata.get("size_bytes") or 0)
    protocols = metadata.get("protocols") or []
    if isinstance(protocols, str):
        protocols = [p.strip() for p in protocols.split(",") if p.strip()]

    pct_map = metadata.get("protocol_percentages") or {}
    if isinstance(pct_map, str):
        try:
            pct_map = json.loads(pct_map)
        except json.JSONDecodeError:
            pct_map = {}

    if rule_type == RuleType.PROTOCOL_PCT_ABOVE.value:
        proto = (rule.get("protocol") or "").lower()
        threshold = float(rule.get("threshold", 0))
        pct = float(pct_map.get(proto, 0))
        if pct >= threshold:
            return f"{proto.upper()} traffic is {pct:.1f}% (threshold {threshold}%)"
        return None

    if rule_type == RuleType.FILENAME_CONTAINS.value:
        keywords = rule.get("keyword", "")
        for kw in keywords.split(","):
            kw = kw.strip().lower()
            if kw and kw in filename:
                return f"Filename contains '{kw}'"
        return None

    if rule_type == RuleType.PROTOCOL_PRESENT.value:
        proto = (rule.get("protocol") or "").lower()
        if proto in [p.lower() for p in protocols]:
            return f"Protocol {proto.upper()} detected"
        return None

    if rule_type == RuleType.SIZE_ABOVE.value:
        threshold = int(rule.get("threshold", 0))
        if size_bytes >= threshold:
            mb = size_bytes / (1024 * 1024)
            return f"File size {mb:.1f} MB exceeds threshold"
        return None

    return None


def evaluate_alerts(redis_client, metadata: Dict[str, Any]) -> List[Dict[str, Any]]:
    triggered = []
    for rule in get_all_rules(redis_client):
        message = _match_rule(rule, metadata)
        if message:
            triggered.append({
                "rule_id": rule["id"],
                "name": rule.get("name", rule["id"]),
                "severity": rule.get("severity", Severity.MEDIUM.value),
                "message": message,
            })
    return triggered


def evaluate_and_store_alerts(
    redis_client,
    file_hash: str,
    metadata: Dict[str, Any],
) -> List[Dict[str, Any]]:
    from .scan import PCAP_FILE_KEY_PREFIX

    alerts = evaluate_alerts(redis_client, metadata)
    pcap_key = f"{PCAP_FILE_KEY_PREFIX}:{file_hash}"

    from .risk import RISK_INDEX_KEY, compute_risk

    risk = compute_risk(alerts)

    redis_client.hset(
        pcap_key,
        mapping={
            "alerts": json.dumps(alerts),
            "alert_count": len(alerts),
            "has_alerts": "1" if alerts else "0",
            "risk_score": risk["risk_score"],
            "risk_level": risk["risk_level"],
        },
    )

    redis_client.zadd(RISK_INDEX_KEY, {file_hash: risk["risk_score"]})

    redis_client.srem(ALERT_INDEX_KEY, file_hash)
    if alerts:
        redis_client.sadd(ALERT_INDEX_KEY, file_hash)

    return alerts


def get_alerted_files(redis_client, limit: int = 100) -> List[str]:
    return list(redis_client.smembers(ALERT_INDEX_KEY))[:limit]
