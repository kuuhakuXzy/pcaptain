import logging
import os
import asyncio
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from concurrent.futures import ThreadPoolExecutor

# Import container and services
from container import container
from config.config_service import ConfigService
from services.redis_service import RedisService
from services.scanner_service import ScannerService
from api import search, scan, download, health, errors
from utils.logging import setup_logging

# Initialize logging
setup_logging()
logger = logging.getLogger(__name__)

# Get service instances from container
config_service = container.get(ConfigService)
redis_service = container.get(RedisService)
scanner_service = container.get(ScannerService)

# Load config
settings = config_service.init()

# Init Redis
REDIS_HOST = settings.get("redis_host", "localhost")
REDIS_PORT = settings.get("redis_port", 6379)
redis_client = redis_service.init(REDIS_HOST, int(REDIS_PORT))

# Create app
app = FastAPI(title="Pcap Catalog Service")

# CORS (if needed)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        origin for origin in settings.get("backend", {}).get("allowed_origins", [])
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register exception handlers
errors.register_exception_handlers(app)

# Include routers
app.include_router(search.router)
app.include_router(scan.router)
app.include_router(download.router)
app.include_router(health.router)

# Executor for background tasks
executor = ThreadPoolExecutor()


async def scheduled_scan_loop():
    """Runs in the background and triggers a scan every X seconds."""
    while True:
        try:
            interval = int(os.getenv("SCAN_INTERVAL_SECONDS", 3600))
            await asyncio.sleep(interval)

            # Import scan_status from scan module
            from api.scan import scan_status, ScanState

            if scan_status["state"] == ScanState.IDLE:
                logger.info("Starting scheduled background scan.")
                pcap_dir = settings.get("pcap_directory")
                public_base_url = settings.get("backend", {}).get("public_base_url")
                asyncio.create_task(
                    scanner_service.scan(pcap_dir, base_url=public_base_url)
                )
            else:
                logger.info(f"Scan already running, state: {scan_status['state']}")

        except Exception as e:
            logger.error(f"Error in scheduled scan loop: {e}")
            await asyncio.sleep(60)


@app.on_event("startup")
async def startup_event():
    # Optionally check Redis and kick off initial scan
    if redis_client:
        try:
            keys = await asyncio.to_thread(redis_client.keys, "pcap:file:*")
            if not keys:
                logger.info(
                    "No indexed pcaps found. Starting initial scan in background."
                )
                loop = asyncio.get_event_loop()
                pcap_dir = settings.get("pcap_directory")
                public_base_url = settings.get("backend", {}).get("public_base_url")
                loop.run_in_executor(
                    executor,
                    lambda: asyncio.run(
                        scanner_service.scan(pcap_dir, base_url=public_base_url)
                    ),
                )
            else:
                logger.info(
                    f"Found {len(keys)} indexed pcaps. Skipping initial full scan."
                )
        except Exception as e:
            logger.exception("Failed to check Redis during startup")
    else:
        logger.error("Redis client not available at startup")

    # Start scheduled scan loop
    asyncio.create_task(scheduled_scan_loop())
