"""
Open Cybersecurity Schema Framework (OCSF) event model.
https://schema.ocsf.io/
"""

from dataclasses import dataclass, field, asdict
from typing import Optional
import json


@dataclass
class Actor:
    user: Optional[str] = None
    process: Optional[str] = None
    session_uid: Optional[str] = None


@dataclass
class Device:
    hostname: Optional[str] = None
    ip: Optional[str] = None
    os: Optional[str] = None
    uid: Optional[str] = None


@dataclass
class NetworkEndpoint:
    ip: Optional[str] = None
    port: Optional[int] = None
    hostname: Optional[str] = None


@dataclass
class OCSFEvent:
    """
    Normalized OCSF event. All fields use unified names regardless of source.
    This unified schema reduces query complexity by eliminating per-source field mapping.
    """
    # Core OCSF fields
    class_uid: int = 0               # OCSF event class
    class_name: str = ""             # Human-readable class
    activity_id: int = 0             # Activity type
    activity_name: str = ""          # Human-readable activity
    severity_id: int = 0             # 0=Unknown,1=Info,2=Low,3=Medium,4=High,5=Critical
    severity: str = "Unknown"
    status: str = "Unknown"

    # Time
    time: Optional[str] = None       # ISO 8601
    start_time: Optional[str] = None
    end_time: Optional[str] = None

    # Source metadata
    metadata_product_name: str = ""
    metadata_product_version: str = ""
    metadata_log_source: str = ""
    raw_data: Optional[str] = None

    # Actor
    actor: Actor = field(default_factory=Actor)

    # Device
    device: Device = field(default_factory=Device)

    # Network
    src_endpoint: NetworkEndpoint = field(default_factory=NetworkEndpoint)
    dst_endpoint: NetworkEndpoint = field(default_factory=NetworkEndpoint)

    # Process
    process_name: Optional[str] = None
    process_pid: Optional[int] = None
    process_cmd_line: Optional[str] = None
    parent_process_name: Optional[str] = None

    # File
    file_path: Optional[str] = None
    file_name: Optional[str] = None
    file_hash_md5: Optional[str] = None
    file_hash_sha256: Optional[str] = None

    # Cloud / API
    api_operation: Optional[str] = None
    api_service_name: Optional[str] = None
    cloud_region: Optional[str] = None
    cloud_account_uid: Optional[str] = None

    # Enrichment
    tags: list[str] = field(default_factory=list)
    unmapped: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str)
