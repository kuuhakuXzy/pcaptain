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

    
    def initialize(self):
        self.__initialize_redis__()
    
    async def initialize_async(self):
        pass
    
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