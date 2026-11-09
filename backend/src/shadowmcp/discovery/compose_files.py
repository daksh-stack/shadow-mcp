from __future__ import annotations

from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml

from shadowmcp.domain.ids import server_id
from shadowmcp.domain.models import (
    Evidence,
    EvidenceKind,
    ScanError,
    ServerRecord,
    Transport,
)

CLIENT_COMPOSE = "compose"


def load_compose(path: Path) -> tuple[list[ServerRecord], list[ScanError]]:
    if not path.is_file():
        return [], [ScanError(code="compose_missing", message="file not found", source=str(path))]
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        return [], [ScanError(code="compose_unreadable", message=str(exc), source=str(path))]
    if not isinstance(raw, dict) or not isinstance(raw.get("services"), dict):
        return [], [
            ScanError(code="compose_shape", message="services map missing", source=str(path))
        ]

    servers: list[ServerRecord] = []
    errors: list[ScanError] = []
    for name, spec in raw["services"].items():
        if not isinstance(name, str) or not isinstance(spec, dict):
            errors.append(
                ScanError(code="compose_shape", message=f"bad service {name!r}", source=str(path))
            )
            continue
        record = _service(name, spec, path)
        if record is not None:
            servers.append(record)
    return servers, errors


def _service(name: str, spec: dict[str, Any], path: Path) -> ServerRecord | None:
    image = spec.get("image") if isinstance(spec.get("image"), str) else None
    command = _command(spec.get("command"))
    env_keys = _env_keys(spec.get("environment"))
    ports = _ports(spec.get("ports"))
    interesting = _looks_like_mcp(name, image, command, env_keys)
    if not interesting:
        return None

    url = _first_http_url(command)
    transport = Transport.STDIO
    if url:
        path_part = urlparse(url).path or ""
        transport = Transport.SSE if path_part.rstrip("/").endswith("/sse") else Transport.STREAMABLE_HTTP

    bin_cmd = command[0] if command else image
    args = command[1:] if command else []
    return ServerRecord(
        id=server_id(
            client=CLIENT_COMPOSE,
            name=name,
            transport=transport,
            command=bin_cmd,
            args=args,
            url=url,
            config_path=str(path),
        ),
        name=name,
        client=CLIENT_COMPOSE,
        transport=transport,
        command=bin_cmd,
        args=args,
        env_keys=env_keys,
        url=url,
        config_path=str(path),
        evidence=[
            Evidence(
                kind=EvidenceKind.COMPOSE,
                source=str(path),
                detail={"service": name, "image": image, "ports": ports},
            )
        ],
    )


def _looks_like_mcp(
    name: str,
    image: str | None,
    command: list[str],
    env_keys: list[str],
) -> bool:
    blob = " ".join([name, image or "", *command, *env_keys]).lower()
    return "mcp" in blob


def _command(value: Any) -> list[str]:
    if isinstance(value, str):
        return value.split()
    if isinstance(value, list) and all(isinstance(p, str) for p in value):
        return list(value)
    return []


def _env_keys(value: Any) -> list[str]:
    if isinstance(value, dict):
        return sorted(str(k) for k in value)
    if isinstance(value, list):
        keys: list[str] = []
        for item in value:
            if isinstance(item, str) and "=" in item:
                keys.append(item.split("=", 1)[0])
        return sorted(keys)
    return []


def _ports(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value]


def _first_http_url(command: list[str]) -> str | None:
    for part in command:
        if part.startswith("http://") or part.startswith("https://"):
            return part
    return None