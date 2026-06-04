from typing import Optional

from pydantic import BaseModel, Field


class ProtocolFilter(BaseModel):
    include: list[str] = Field(default_factory=list)
    exclude: list[str] = Field(default_factory=list)


class CatalogQueryRequest(BaseModel):
    protocol_query: str = ""
    protocols: Optional[ProtocolFilter] = None
    filename_contains: Optional[str] = None
    path_prefix: Optional[str] = None
    size_bytes: Optional[dict] = None
    modified: Optional[dict] = None
    capture: Optional[dict] = None
    ip: Optional[str] = None
    port: Optional[int] = Field(None, ge=1, le=65535)
    page: int = Field(1, ge=1)
    limit: int = Field(10, ge=1, le=100)
    sort_by: str = "filename"
    descending: bool = False


class WebhookRegistration(BaseModel):
    url: str
    secret: Optional[str] = None
    events: list[str] = Field(default_factory=lambda: ["scan.completed"])


class MergePcapsRequest(BaseModel):
    file_hashes: list[str] = Field(..., min_length=1, max_length=20)
    display_filter: Optional[str] = None


class ReindexFolderRequest(BaseModel):
    folder: Optional[str] = Field(
        None,
        description="Immediate subdirectory name under PCAP root (e.g. blahblah)",
    )
