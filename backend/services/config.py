import os
import yaml
from enum import Enum
from pathlib import Path
from typing import List, Optional, Set
from pydantic import BaseModel, Field, field_validator
from .logger import get_logger

logger = get_logger(__name__)


class RedisConfig(BaseModel):
    host: str = "redis"
    port: int = 6379


class ScanMode(str, Enum):
    FULL = "full"
    QUICK = "quick"
    FAST = "fast"


class QuickScanConfig(BaseModel):
    pebc: float = 1.0
    min_file_size: int | str = 0
    config_version: str = "v1"
    # Quick sample from head/middle/tail (via editcap) instead of head-only.
    sample_segments: int = Field(default=1, ge=1, le=8)

    @field_validator("pebc")
    @classmethod
    def validate_pebc(cls, v: float) -> float:
        if v <= 0 or v > 1:
            raise ValueError("quick_scan.pebc must be > 0 and <= 1")
        return v


class PcapConfig(BaseModel):
    root_directory: str = "/pcaps"
    root_directories: List[str] = Field(default_factory=list)
    prefix_str: Optional[str] = None
    allowed_file_extensions: Set[str] = Field(default_factory=lambda: {".pcap", ".pcapng", ".cap"})
    scan_interval_seconds: int = 300
    scan_mode: ScanMode = ScanMode.FULL
    max_parallel_scans: int = Field(default=4, ge=1, le=32)
    quick_scan: QuickScanConfig = Field(default_factory=QuickScanConfig)


def get_pcap_root_directories(pcap_config: PcapConfig) -> List[str]:
    """Return configured PCAP scan roots (multi-mount aware)."""
    if pcap_config.root_directories:
        return [p.rstrip("/\\") for p in pcap_config.root_directories if p and str(p).strip()]
    return [pcap_config.root_directory.rstrip("/\\")]


def get_pcap_display_paths(pcap_config: PcapConfig) -> List[str]:
    """Host-facing path labels aligned with root_directories."""
    roots = get_pcap_root_directories(pcap_config)
    if pcap_config.prefix_str:
        parts = [p.strip() for p in str(pcap_config.prefix_str).split(",") if p.strip()]
        if len(parts) == len(roots):
            return parts
        if len(parts) == 1 and len(roots) == 1:
            return parts
    return roots


def get_upload_directory(pcap_config: PcapConfig) -> str:
    """Upload target under the primary PCAP root."""
    primary = get_pcap_root_directories(pcap_config)[0].rstrip("/\\")
    return f"{primary}/uploads"


def map_path_to_display(file_path: str, pcap_config: PcapConfig) -> str:
    """Replace internal container paths with host display paths."""
    if not file_path:
        return file_path
    roots = get_pcap_root_directories(pcap_config)
    displays = get_pcap_display_paths(pcap_config)
    normalized = file_path.replace("\\", "/")
    for i, root in enumerate(roots):
        root_norm = root.replace("\\", "/")
        if normalized.startswith(root_norm):
            display = displays[i] if i < len(displays) else displays[0]
            return file_path.replace(root, display, 1)
    if pcap_config.prefix_str and len(roots) == 1:
        return file_path.replace(roots[0], str(pcap_config.prefix_str).split(",")[0].strip(), 1)
    return file_path


def list_pcap_scan_folders(pcap_config: PcapConfig) -> List[dict]:
    """List scannable subfolders under each configured PCAP root."""
    extensions = tuple(ext.lower() for ext in pcap_config.allowed_file_extensions)
    folders: List[dict] = []

    def count_pcaps(directory: str) -> int:
        total = 0
        for dirpath, _, files in os.walk(directory):
            total += sum(
                1 for name in files if name.lower().endswith(extensions)
            )
        return total

    for root in get_pcap_root_directories(pcap_config):
        if not os.path.isdir(root):
            continue
        root_count = count_pcaps(root)
        folders.append({
            "root": root,
            "folder": "(root)",
            "relative_path": "",
            "file_count": root_count,
        })
        try:
            for entry in sorted(os.scandir(root), key=lambda e: e.name.lower()):
                if not entry.is_dir():
                    continue
                if entry.name == "uploads":
                    continue
                rel = entry.name
                sub_count = count_pcaps(entry.path)
                if sub_count == 0:
                    continue
                folders.append({
                    "root": root,
                    "folder": rel,
                    "relative_path": rel,
                    "file_count": sub_count,
                })
        except OSError as exc:
            logger.warning("Failed to list folders under %s: %s", root, exc)

    return folders


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