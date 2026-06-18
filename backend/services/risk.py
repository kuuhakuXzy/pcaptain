from typing import List, Dict, Any

RISK_INDEX_KEY = "pcap:sort:risk_score"

LEVEL_ORDER = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def risk_level_meets(min_level: str, actual_level: str) -> bool:
    min_level = (min_level or "").lower().strip()
    actual_level = (actual_level or "none").lower().strip()
    return LEVEL_ORDER.get(actual_level, 0) >= LEVEL_ORDER.get(min_level, 0)


def compute_risk(alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
    if not alerts:
        return {"risk_score": 0, "risk_level": "none"}

    score = 0
    max_severity = "none"
    for alert in alerts:
        sev = (alert.get("severity") or "medium").lower()
        if sev == "high":
            score += 30
        elif sev == "medium":
            score += 15
        else:
            score += 5
        if LEVEL_ORDER.get(sev, 0) > LEVEL_ORDER.get(max_severity, 0):
            max_severity = sev

    score = min(100, score)
    if score >= 60:
        level = "high"
    elif score >= 30:
        level = "medium"
    elif score > 0:
        level = "low"
    else:
        level = "none"

    return {"risk_score": score, "risk_level": level}
