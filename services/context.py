import asyncio
from redis import Redis
from redis.exceptions import ConnectionError
import os
from concurrent.futures import ThreadPoolExecutor
from dotenv import load_dotenv
from typing import Optional

from .logger import get_logger

load_dotenv()

logger = get_logger(__name__)

class AppContext:
    redis_client: Optional[Redis] = None
    default_excluded_protocols = set()
    dynamic_excluded_protocols = set()

    def __init__(self):
        self.thread_executor = ThreadPoolExecutor()
    
    def initialize(self):
        self.__init_config__()
        self.__initialize_redis__()
        self.__initialize_excluded_protocols__()
    
    async def initialize_async(self):
        await self.refresh_dynamic_excluded_protocols()
    
    ## Redis Initialization ##
    def __initialize_redis__(self):
        REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
        REDIS_PORT = int(os.getenv("REDIS_INTERNAL_PORT", 6379))
        try:
            self.redis_client = Redis(host=REDIS_HOST, port=REDIS_PORT, db=0, decode_responses=True)
            self.redis_client.ping()
            logger.info(f"Successfully connected to Redis at {REDIS_HOST}:{REDIS_PORT}")
        except ConnectionError as e:
            logger.error(f"Could not connect to Redis: {e}")
            self.redis_client = None


    ## Excluded Protocols Management ##
    def __initialize_excluded_protocols__(self):
        protocols = os.getenv("DEFAULT_EXCLUDED_PROTOCOLS", "")
        default_protocols = set(protocols.split(",")) if protocols else set()

        self.default_excluded_protocols = default_protocols
        self.dynamic_excluded_protocols = set()
        logger.info(f"Initialized excluded protocols: {self.default_excluded_protocols}")

    def get_excluded_protocols(self) -> set:
        return self.default_excluded_protocols.union(self.dynamic_excluded_protocols)
    
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
    

    ## Environment Variables ##
    def __init_config__(self):        
        self.PCAP_DIRECTORIES_STR = os.getenv("PCAP_MOUNTED_DIRECTORY", "pcaps")
        self.PCAP_DIRECTORIES = [path.strip() for path in self.PCAP_DIRECTORIES_STR.split(',')]

        BASE_URL = os.getenv("BE_BASE_URL")
        BASE_PORT = os.getenv("BE_BASE_PORT")

        self.FULL_BASE_URL = None
        if BASE_URL:
            if not BASE_URL.startswith("http://") and not BASE_URL.startswith("https://"):
                BASE_URL = f"http://{BASE_URL}" 
            if BASE_PORT:
                self.FULL_BASE_URL = f"{BASE_URL}:{BASE_PORT}"
            else:
                self.FULL_BASE_URL = BASE_URL
        
        self.PCAP_FILE_PREFIX = os.getenv("PCAP_FILE_PREFIX")
        self.SCANNER_INTERVAL_SECONDS = int(os.getenv("SCAN_INTERVAL_SECONDS", 3600))
            
_app_context: Optional[AppContext] = None

def get_app_context() -> AppContext:
    global _app_context
    if _app_context is None:
        _app_context = AppContext()
        _app_context.initialize()
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