import asyncio
import json
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from services.catalog_constants import (
    IP_INDEX_PREFIX,
    PCAP_FILE_KEY_PREFIX,
    PORT_INDEX_PREFIX,
    PROTOCOL_INDEX_PREFIX,
)
from services.context import AppContext, get_app_context
from services.endpoint_index import _split_csv_field

router = APIRouter(tags=["Catalog Index"])


class IndexImportPayload(BaseModel):
    files: list[dict]
    merge: bool = True


@router.get("/index/export", summary="Export catalog file metadata as JSON")
async def export_index(
    context: AppContext = Depends(get_app_context),
):
    redis = context.redis_client
    if not redis:
        raise HTTPException(503, "Redis unavailable")

    cursor = 0
    files = []
    while True:
        cursor, keys = await asyncio.to_thread(
            redis.scan,
            cursor=cursor,
            match=f"{PCAP_FILE_KEY_PREFIX}:*",
            count=200,
        )
        pipe = redis.pipeline()
        for key in keys:
            pipe.hgetall(key)
        rows = await asyncio.to_thread(pipe.execute)
        for key, row in zip(keys, rows):
            if row:
                row["_redis_key"] = key
                files.append(row)
        if cursor == 0:
            break

    return {
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "file_count": len(files),
        "files": files,
    }


@router.post("/index/import", summary="Import catalog file metadata into Redis")
async def import_index(
    body: IndexImportPayload,
    context: AppContext = Depends(get_app_context),
):
    redis = context.redis_client
    if not redis:
        raise HTTPException(503, "Redis unavailable")

    imported = 0
    for row in body.files:
        file_hash = row.get("file_hash") or row.get("hash")
        if not file_hash and row.get("_redis_key"):
            file_hash = row["_redis_key"].split(":")[-1]
        if not file_hash:
            continue

        pcap_key = f"{PCAP_FILE_KEY_PREFIX}:{file_hash}"
        mapping = {k: v for k, v in row.items() if not k.startswith("_")}
        await asyncio.to_thread(redis.hset, pcap_key, mapping=mapping)

        for proto in row.get("protocols", "").split(","):
            proto = proto.strip().lower()
            if proto:
                await asyncio.to_thread(
                    redis.sadd, f"{PROTOCOL_INDEX_PREFIX}:{proto}", file_hash
                )
        for ip in _split_csv_field(row.get("indexed_ips")):
            await asyncio.to_thread(
                redis.sadd, f"{IP_INDEX_PREFIX}:{ip}", file_hash
            )
        for port in _split_csv_field(row.get("indexed_ports")):
            await asyncio.to_thread(
                redis.sadd, f"{PORT_INDEX_PREFIX}:{port}", file_hash
            )
        imported += 1

    return {"status": "ok", "imported": imported, "merge": body.merge}
