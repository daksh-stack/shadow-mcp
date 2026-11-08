from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


def utcnow() -> datetime:
    return datetime.now(UTC)


class Transport(StrEnum):
    STDIO = "stdio"
    SSE = "sse"
    STREAMABLE_HTTP = "streamable-http"
    UNKNOWN = "unknown"


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class EvidenceKind(StrEnum):
    CONFIG_FILE = "config_file"
    PROCESS = "process"
    LISTEN_PORT = "listen_port"
    CAPABILITY_PROBE = "capability_probe"


class Evidence(BaseModel):
    kind: EvidenceKind
    source: str
    observed_at: datetime = Field(default_factory=utcnow)
    detail: dict[str, Any] = Field(default_factory=dict)


class ScanError(BaseModel):
    code: str
    message: str
    source: str | None = None


class ProcessMatch(BaseModel):
    pid: int
    name: str
    cmdline: list[str]
    username: str | None
    create_time: float | None
    confidence: float
    reason: str


class ListenCheck(BaseModel):
    host: str
    port: int
    listening: bool
    pids: list[int] = Field(default_factory=list)


class ToolSpec(BaseModel):
    name: str
    description: str = ""
    input_schema: dict[str, Any] = Field(default_factory=dict)


class CapabilitySnapshot(BaseModel):
    protocol_version: str | None = None
    server_name: str | None = None
    server_version: str | None = None
    tools: list[ToolSpec] = Field(default_factory=list)
    ok: bool
    error: str | None = None


class RiskFlag(BaseModel):
    rule_id: str
    severity: Severity
    title: str
    explanation: str
    evidence: list[str] = Field(default_factory=list)


class ServerRecord(BaseModel):
    id: str
    name: str
    client: str
    transport: Transport
    command: str | None = None
    args: list[str] = Field(default_factory=list)
    env_keys: list[str] = Field(default_factory=list)
    url: str | None = None
    cwd: str | None = None
    config_path: str
    processes: list[ProcessMatch] = Field(default_factory=list)
    listen: ListenCheck | None = None
    capabilities: CapabilitySnapshot | None = None
    risk_flags: list[RiskFlag] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)


class Coverage(BaseModel):
    clients_requested: list[str]
    config_paths_checked: list[str]
    config_paths_found: list[str]
    project_roots: list[str]
    introspect_enabled: bool
    limitations: list[str]


class HostInfo(BaseModel):
    os: str
    hostname: str


class Inventory(BaseModel):
    schema_version: str = "1"
    tool_version: str
    scanned_at: datetime = Field(default_factory=utcnow)
    host: HostInfo
    servers: list[ServerRecord] = Field(default_factory=list)
    errors: list[ScanError] = Field(default_factory=list)
    coverage: Coverage


class Transport(StrEnum):
    STDIO = "stdio"
    SSE = "sse"
    STREAMABLE_HTTP = "streamable-http"
    UNKNOWN = "unknown"


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class EvidenceKind(StrEnum):
    CONFIG_FILE = "config_file"
    PROCESS = "process"
    LISTEN_PORT = "listen_port"
    CAPABILITY_PROBE = "capability_probe"
