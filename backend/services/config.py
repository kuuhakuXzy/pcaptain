import yaml
from enum import Enum
from pathlib import Path
from typing import Optional, Set
from pydantic import BaseModel, Field
from .logger import get_logger

logger = get_logger(__name__)


class RedisConfig(BaseModel):
    host: str = "redis"
    port: int = 6379


class ScanMode(str, Enum):
    NORMAL = "normal"
    FAST = "fast"

class PcapConfig(BaseModel):
    root_directory: str = "/pcaps"
    prefix_str: Optional[str] = None
    excluded_protocols: Set[str] = Field(default_factory=set)
    allowed_file_extensions: Set[str] = Field(default_factory=lambda: {".pcap", ".pcapng", ".cap"})
    scan_interval_seconds: int = 300
    scan_mode: ScanMode = ScanMode.NORMAL


class LogConfig(BaseModel):
    level: str = "INFO"


class AppConfig(BaseModel):
    port: int = 8080
    public_url: str = "http://localhost:8080"
    redis: RedisConfig = Field(default_factory=RedisConfig)
    pcap: PcapConfig = Field(default_factory=PcapConfig)
    log: LogConfig = Field(default_factory=LogConfig)


def load_config(config_path: str = "/app/config/config.yaml") -> AppConfig:
    """
    Load configuration from YAML file and parse into AppConfig model.
    """
    config_file = Path(config_path)

    if not config_file.exists():
        print(f"[config] Config file not found at {config_path}, using defaults")
        return AppConfig()

    try:
        with open(config_file, "r") as f:
            yaml_data = yaml.safe_load(f)

        if yaml_data is None:
            print(f"[config] Empty config file at {config_path}, using defaults")
            return AppConfig()

        print(f"[config] Successfully loaded configuration from {config_path}")
        return AppConfig(**yaml_data)

    except yaml.YAMLError as e:
        print(f"[config] Error parsing YAML config: {e}")
        raise
    except Exception as e:
        print(f"[config] Error loading config: {e}")
        raise