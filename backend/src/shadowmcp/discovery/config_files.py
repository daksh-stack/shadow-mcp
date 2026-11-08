from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from shadowmcp.domain.ids import server_id
from shadowmcp.domain.models import (
    Evidence,
    EvidenceKind,
    ScanError,
    ServerRecord,
    Transport,
)

CLIENT_CLAUDE = "claude-desktop"
CLIENT_CURSOR = "cursor"


def load_servers(path: Path, client: str) -> tuple[list[ServerRecord], list[ScanError]]:
    if not path.is_file():
        return [], []
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        return [], [ScanError(code="config_unreadable", message=str(exc), source=str(path))]
    if not isinstance(raw, dict):
        return [], [ScanError(code="config_shape", message="root is not an object", source=str(path))]

    block = raw.get("mcpServers", raw.get("mcp_servers"))
    if block is None:
        return [], [ScanError(code="config_shape", message="mcpServers missing", source=str(path))]
    if not isinstance(block, dict):
        return [], [ScanError(code="config_shape", message="mcpServers is not an object", source=str(path))]

    servers: list[ServerRecord] = []
    errors: list[ScanError] = []
    for name, spec in block.items():
        if not isinstance(name, str) or not isinstance(spec, dict):
            errors.append(ScanError(code="server_shape", message=f"bad entry {name!r}", source=str(path)))
            continue
        record, err = _one(name, spec, client, path)
        if record:
            servers.append(record)
        if err:
            errors.append(err)
    return servers, errors


def _one(name: str, spec: dict[str, Any], client: str, path: Path) -> tuple[ServerRecord | None, ScanError | None]:
    command = spec.get("command")
    args = spec.get("args") or []
    url = spec.get("url")
    env = spec.get("env") or {}
    cwd = spec.get("cwd")

    if command is not None and not isinstance(command, str):
        return None, ScanError(code="server_shape", message=f"{name}: command not a string", source=str(path))
    if url is not None and not isinstance(url, str):
        return None, ScanError(code="server_shape", message=f"{name}: url not a string", source=str(path))
    if not isinstance(args, list) or not all(isinstance(a, str) for a in args):
        return None, ScanError(code="server_shape", message=f"{name}: args must be string list", source=str(path))
    if not isinstance(env, dict):
        return None, ScanError(code="server_shape", message=f"{name}: env must be an object", source=str(path))
    if command is None and url is None:
        return None, ScanError(code="server_shape", message=f"{name}: no command or url", source=str(path))

    transport = _transport(spec, url)
    env_keys = sorted(str(k) for k in env.keys())
    rec = ServerRecord(
        id=server_id(
            client=client,
            name=name,
            transport=transport,
            command=command,
            args=list(args),
            url=url,
            config_path=str(path),
        ),
        name=name,
        client=client,
        transport=transport,
        command=command,
        args=list(args),
        env_keys=env_keys,
        url=url,
        cwd=str(cwd) if isinstance(cwd, str) else None,
        config_path=str(path),
        evidence=[
            Evidence(
                kind=EvidenceKind.CONFIG_FILE,
                source=str(path),
                detail={
                    "client": client,
                    "server": name,
                    "transport": transport.value,
                    "has_env": bool(env_keys),
                },
            )
        ],
    )
    return rec, None


def _transport(spec: dict[str, Any], url: str | None) -> Transport:
    declared = spec.get("transport") or spec.get("type")
    if isinstance(declared, str):
        key = declared.lower().replace("_", "-")
        if key in {"stdio"}:
            return Transport.STDIO
        if key in {"sse"}:
            return Transport.SSE
        if key in {"http", "streamable-http", "streamablehttp"}:
            return Transport.STREAMABLE_HTTP
    if url:
        path = urlparse(url).path or ""
        if path.rstrip("/").endswith("/sse"):
            return Transport.SSE
        return Transport.STREAMABLE_HTTP
    if spec.get("command"):
        return Transport.STDIO
    return Transport.UNKNOWN
