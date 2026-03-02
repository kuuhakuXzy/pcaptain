# Apply asynchronous processing (done)
# Apply incremental redis update (done)
# Apply CPU/memory usage limitation for scanning (done)
# Use backoff to check redis status for initial scanning (done)
# Fix some environment errors (done)
# Apply status health check api (done)
# Apply packets per protocol counting, using t-shark (done)
# Apply fuzzy searching (done)
# Apply configurable mounted directory

import redis
import contextlib
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import asyncio
import backoff

from services.context import init_app_context
from services.logger import get_logger, setup_logging
from services.scan import ScanState, get_scan_service
from services.config import load_config

from routes.scan import router as scan_router
from routes.protocols import router as protocols_router
from routes.pcaps import router as pcaps_router
from routes.search import router as search_router
from routes.dashboard import router as dashboard_router

config = load_config()
setup_logging(config.log.level)
logger = get_logger(__name__)
context = init_app_context(config)

# SCAN SCHEDULER
async def scheduled_scan_loop():
    """Runs in the background and triggers a scan every X seconds."""
    while True:
        try:
            interval = config.pcap.scan_interval_seconds
            scan_service = get_scan_service()

            await asyncio.sleep(interval)

            if scan_service.scan_status["state"] == ScanState.IDLE:
                logger.info(f"Starting scheduled scan (Interval: {interval}s)...")
                loop = asyncio.get_running_loop()

                await loop.run_in_executor(
                    context.thread_executor,
                    lambda: scan_service.scan_wrapper(
                        exclude_files=None
                    ),
                )
            else:
                logger.info("Scheduled scan skipped: Scanner is currently busy.")

        except Exception as e:
            logger.error(f"Error in scheduled scan loop: {e}")
            await asyncio.sleep(60)

@contextlib.asynccontextmanager
async def lifespan(app: FastAPI):
    redis_client = context.redis_client
    await context.initialize_async()
    scan_service = get_scan_service()

    @backoff.on_exception(
        backoff.expo,
        redis.exceptions.ConnectionError,
        max_tries=5,
        factor=0.5,
    )
    async def check_redis_for_pcaps():
        if not redis_client:
            raise redis.exceptions.ConnectionError("Redis client not initialized.")
        return await asyncio.to_thread(redis_client.keys, "pcap:file:*")

    if redis_client:
        try:
            existing_pcap_keys = await check_redis_for_pcaps()

            if not existing_pcap_keys:
                logger.info("No indexed pcaps found in Redis. Starting initial scan...")
                loop = asyncio.get_running_loop()
                loop.run_in_executor(
                    context.thread_executor,
                    lambda: scan_service.scan_wrapper(
                        exclude_files=None,
                    ),
                )
            else:
                logger.info(
                    f"Found {len(existing_pcap_keys)} indexed pcaps in Redis. Skipping initial scan."
                )
        except Exception as e:
            logger.error(f"Startup Redis check failed: {e}")
    else:
        logger.error("Redis client unavailable at startup.")

    # Start background task
    scan_task = asyncio.create_task(scheduled_scan_loop())

    try:
        yield
    finally:
        logger.info("Shutting down background tasks...")
        scan_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await scan_task

app = FastAPI(
    title="Pcap Catalog Service",
    description="A service to index and search pcap files by protocol using a Redis-native inverted index.",
    lifespan=lifespan,
)

app.include_router(scan_router)
app.include_router(protocols_router)
app.include_router(pcaps_router)
app.include_router(search_router)
app.include_router(dashboard_router)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/health")
async def health_check():
    return {"status": "OK"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
