import asyncio
import json

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import Optional

from services.context import get_app_context, AppContext
from services.logger import get_logger
from services.alerts import (
    ALERT_INDEX_KEY,
    ALERT_RULES_KEY,
    delete_rule,
    evaluate_and_store_alerts,
    get_all_rules,
    save_rule,
    seed_default_rules,
)
from services.scan import PCAP_FILE_KEY_PREFIX

router = APIRouter(tags=["Alerts"])
logger = get_logger(__name__)


class AlertRuleCreate(BaseModel):
    name: str
    type: str
    protocol: Optional[str] = None
    keyword: Optional[str] = None
    threshold: Optional[float] = None
    severity: str = "medium"
    enabled: bool = True


class AlertRuleUpdate(BaseModel):
    name: Optional[str] = None
    type: Optional[str] = None
    protocol: Optional[str] = None
    keyword: Optional[str] = None
    threshold: Optional[float] = None
    severity: Optional[str] = None
    enabled: Optional[bool] = None


@router.get("/alerts/rules", summary="List all alert rules")
async def list_rules(context: AppContext = Depends(get_app_context)):
    if not context.redis_client:
        raise HTTPException(status_code=503, detail="Redis unavailable")
    seed_default_rules(context.redis_client)
    return {"rules": get_all_rules(context.redis_client)}


@router.post("/alerts/rules", summary="Create a new alert rule")
async def create_rule(
    body: AlertRuleCreate,
    context: AppContext = Depends(get_app_context),
):
    if not context.redis_client:
        raise HTTPException(status_code=503, detail="Redis unavailable")
    rule = save_rule(context.redis_client, body.model_dump())
    return rule


@router.put("/alerts/rules/{rule_id}", summary="Update an alert rule")
async def update_rule(
    rule_id: str,
    body: AlertRuleUpdate,
    context: AppContext = Depends(get_app_context),
):
    if not context.redis_client:
        raise HTTPException(status_code=503, detail="Redis unavailable")

    existing_raw = context.redis_client.hget(ALERT_RULES_KEY, rule_id)
    if not existing_raw:
        raise HTTPException(status_code=404, detail="Rule not found")

    existing = json.loads(existing_raw)
    updates = {k: v for k, v in body.model_dump().items() if v is not None}
    existing.update(updates)
    rule = save_rule(context.redis_client, {"id": rule_id, **existing})
    return rule


@router.delete("/alerts/rules/{rule_id}", summary="Delete an alert rule")
async def remove_rule(
    rule_id: str,
    context: AppContext = Depends(get_app_context),
):
    if not context.redis_client:
        raise HTTPException(status_code=503, detail="Redis unavailable")
    if not delete_rule(context.redis_client, rule_id):
        raise HTTPException(status_code=404, detail="Rule not found")
    return {"status": "deleted", "id": rule_id}


@router.get("/alerts", summary="List files with triggered alerts")
async def list_alerted_files(
    limit: int = 50,
    context: AppContext = Depends(get_app_context),
):
    if not context.redis_client:
        raise HTTPException(status_code=503, detail="Redis unavailable")

    redis = context.redis_client
    hashes = list(redis.smembers(ALERT_INDEX_KEY))[:limit]
    results = []

    for file_hash in hashes:
        meta = redis.hgetall(f"{PCAP_FILE_KEY_PREFIX}:{file_hash}")
        if not meta:
            continue
        alerts_raw = meta.get("alerts", "[]")
        try:
            alerts = json.loads(alerts_raw)
        except json.JSONDecodeError:
            alerts = []
        results.append({
            "file_hash": file_hash,
            "filename": meta.get("filename"),
            "path": meta.get("path"),
            "alert_count": len(alerts),
            "alerts": alerts,
        })

    return {"total": len(results), "data": results}


@router.post("/alerts/evaluate-all", summary="Re-evaluate alerts for all indexed files")
async def evaluate_all_alerts(context: AppContext = Depends(get_app_context)):
    if not context.redis_client:
        raise HTTPException(status_code=503, detail="Redis unavailable")

    seed_default_rules(context.redis_client)
    redis = context.redis_client
    keys = list(redis.scan_iter(f"{PCAP_FILE_KEY_PREFIX}:*"))
    evaluated = 0
    triggered = 0

    for key in keys:
        meta = redis.hgetall(key)
        if not meta:
            continue
        file_hash = key.split(":")[-1]
        alerts = evaluate_and_store_alerts(redis, file_hash, meta)
        evaluated += 1
        if alerts:
            triggered += 1

    return {"evaluated": evaluated, "files_with_alerts": triggered}
