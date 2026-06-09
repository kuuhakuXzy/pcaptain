from typing import Literal, Optional

from pydantic import BaseModel, Field, field_validator


class FastScanUserOptions(BaseModel):
    """Per-scan fastscan options (user-selected in UI or API)."""

    output: Literal["summary", "lines"] = Field(
        "summary",
        description="summary = one PCAPTAIN_SUMMARY line; lines = legacy per-packet output",
    )
    sample_every: Optional[int] = Field(
        None,
        ge=1,
        le=1_000_000,
        description="Process every Nth packet (e.g. 10 = 10% sample when N=10)",
    )
    max_packets: Optional[int] = Field(
        None,
        ge=1,
        le=100_000_000,
        description="Stop reading after this many packets",
    )
    bpf_filter: Optional[str] = Field(
        None,
        max_length=512,
        description="libpcap BPF filter, e.g. tcp port 443",
    )
    emit_fingerprint: bool = Field(
        False,
        description="Emit PCAPTAIN_FP line for duplicate / near-duplicate hints",
    )
    ports_file: Optional[str] = Field(
        None,
        max_length=1024,
        description="Optional port overlay file (PORT l4proto app per line)",
    )

    @field_validator("bpf_filter")
    @classmethod
    def strip_bpf(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        stripped = v.strip()
        return stripped if stripped else None


class ReindexRequest(BaseModel):
    folder: Optional[str] = Field(
        None,
        description="Immediate subfolder under PCAP root",
    )
    exclude: list[str] = Field(default_factory=list)
    fast_options: Optional[FastScanUserOptions] = None
