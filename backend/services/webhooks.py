"""Webhook notifications after catalog scan events."""

import asyncio
import hashlib
import hmac
import json
from typing import Any, Optional

import httpx
from redis import Redis

from services.catalog_constants import WEBHOOKS_CONFIG_KEY
from services.logger import get_logger

logger = get_logger(__name__)


def get_webhooks(redis: Redis) -> list[dict]:
    raw = redis.get(WEBHOOKS_CONFIG_KEY)
    if not raw:
        return []
    try:
        data = json.loads(raw)
        return data if isinstance(data, list) else []
    except json.JSONDecodeError:
        return []


def save_webhooks(redis: Redis, hooks: list[dict]) -> None:
    redis.set(WEBHOOKS_CONFIG_KEY, json.dumps(hooks))


def _sign_payload(secret: str, body: bytes) -> str:
    return hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


async def dispatch_scan_webhooks(
    redis: Redis,
    *,
    event: str,
    indexed_files: int,
    status: str,
    message: str,
) -> None:
    hooks = await asyncio.to_thread(get_webhooks, redis)
    if not hooks:
        return

    payload = {
        "event": event,
        "indexed_files": indexed_files,
        "status": status,
        "message": message,
    }
    body = json.dumps(payload).encode()

    async with httpx.AsyncClient(timeout=10.0) as client:
        for hook in hooks:
            url = hook.get("url")
            if not url:
                continue
            events = hook.get("events") or ["scan.completed"]
            if event not in events:
                continue
            headers = {"Content-Type": "application/json"}
            secret = hook.get("secret")
            if secret:
                headers["X-Pcaptain-Signature"] = _sign_payload(secret, body)
            try:
                response = await client.post(url, content=body, headers=headers)
                if response.status_code >= 400:
                    logger.warning(
                        "Webhook %s returned %s", url, response.status_code
                    )
            except Exception as exc:
                logger.warning("Webhook delivery failed for %s: %s", url, exc)
