import asyncio
from redis import Redis
from redis.exceptions import ConnectionError
import os
from concurrent.futures import ThreadPoolExecutor
from typing import Optional

from .logger import get_logger
from .config import AppConfig, load_config

logger = get_logger(__name__)

class AppContext:

    def __init__(self, config: AppConfig = None):
        self.config = config or load_config()
        self.redis_client: Optional[Redis] = None
        self.thread_executor = ThreadPoolExecutor()
        self.dynamic_excluded_protocols = set()

    
    def initialize(self):
        self.__initialize_redis__()
    
    async def initialize_async(self):
        await self.refresh_dynamic_excluded_protocols()
    
    ## Redis Initialization ##
    def __initialize_redis__(self):
        redis_host = self.config.redis.host
        redis_port = self.config.redis.port
        try:
            self.redis_client = Redis(host=redis_host, port=redis_port, db=0, decode_responses=True)
            self.redis_client.ping()
            logger.info(f"Successfully connected to Redis at {redis_host}:{redis_port}")
        except ConnectionError as e:
            logger.error(f"Could not connect to Redis: {e}")
            self.redis_client = None

    def get_excluded_protocols(self) -> set:
        return self.config.pcap.excluded_protocols.union(self.dynamic_excluded_protocols)
    
    def get_dynamic_excluded_protocols(self) -> set:
        return self.dynamic_excluded_protocols

    async def refresh_dynamic_excluded_protocols(self):
        if self.redis_client is None:
            logger.warning("Redis client not initialized. Cannot refresh excluded protocols.")
            return
        
        try:
            protocols_str = await asyncio.to_thread(self.redis_client.get, "pcap:config:excluded_protocols")
            if protocols_str:
                protocols = set(p.strip().lower() for p in protocols_str.split() if p.strip())
                self.dynamic_excluded_protocols = protocols
                logger.info(f"Refreshed dynamic excluded protocols: {self.dynamic_excluded_protocols}")
            else:
                self.dynamic_excluded_protocols = set()
                logger.info("No dynamic excluded protocols found in Redis.")
        except Exception as e:
            logger.error(f"Error while refreshing excluded protocols from Redis: {e}")
    
_app_context: Optional[AppContext] = None

def init_app_context(config: AppConfig) -> AppContext:
    global _app_context
    if _app_context is not None:
        return _app_context

    _app_context = AppContext(config)
    _app_context.initialize()
    return _app_context

def get_app_context() -> AppContext:
    if _app_context is None:
        raise RuntimeError("AppContext not initialized")
    return _app_context

from functools import wraps
from inspect import signature
from typing import Callable, TypeVar
from typing_extensions import ParamSpec

P = ParamSpec("P")
R = TypeVar("R")

def with_app_context(func: Callable[P, R]) -> Callable[P, R]:
    sig = signature(func)
    if "context" not in sig.parameters:
        raise ValueError(
            "The decorated function must have a 'context' parameter."
        )

    @wraps(func)
    def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
        if kwargs.get("context") is None:
            kwargs["context"] = get_app_context()
        return func(*args, **kwargs)
    return wrapper