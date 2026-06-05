import asyncio

from fastapi import APIRouter, Depends, HTTPException

from models.catalog import WebhookRegistration
from services.context import AppContext, get_app_context
from services.webhooks import get_webhooks, save_webhooks

router = APIRouter(tags=["Catalog Webhooks"])


@router.get("/webhooks", summary="List configured webhooks")
async def list_webhooks(context: AppContext = Depends(get_app_context)):
    redis = context.redis_client
    if not redis:
        raise HTTPException(503, "Redis unavailable")
    return {"webhooks": await asyncio.to_thread(get_webhooks, redis)}


@router.post("/webhooks", summary="Register a webhook URL")
async def register_webhook(
    body: WebhookRegistration,
    context: AppContext = Depends(get_app_context),
):
    redis = context.redis_client
    if not redis:
        raise HTTPException(503, "Redis unavailable")

    hooks = await asyncio.to_thread(get_webhooks, redis)
    entry = body.model_dump()
    hooks = [h for h in hooks if h.get("url") != body.url]
    hooks.append(entry)
    await asyncio.to_thread(save_webhooks, redis, hooks)
    return {"status": "registered", "webhook": entry}


@router.delete("/webhooks", summary="Remove webhook by URL")
async def delete_webhook(
    url: str,
    context: AppContext = Depends(get_app_context),
):
    redis = context.redis_client
    if not redis:
        raise HTTPException(503, "Redis unavailable")

    hooks = await asyncio.to_thread(get_webhooks, redis)
    new_hooks = [h for h in hooks if h.get("url") != url]
    await asyncio.to_thread(save_webhooks, redis, new_hooks)
    return {"status": "removed", "remaining": len(new_hooks)}
