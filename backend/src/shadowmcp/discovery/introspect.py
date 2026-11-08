from __future__ import annotations

import asyncio

from shadowmcp.domain.models import (
    CapabilitySnapshot,
    Evidence,
    EvidenceKind,
    ServerRecord,
    ToolSpec,
    Transport,
)


async def introspect_all(servers: list[ServerRecord], timeout_s: float) -> None:
    for server in servers:
        if server.transport is not Transport.STDIO or not server.command:
            continue
        snap = await _one(server, timeout_s)
        server.capabilities = snap
        server.evidence.append(
            Evidence(
                kind=EvidenceKind.CAPABILITY_PROBE,
                source=server.config_path,
                detail={"ok": snap.ok, "tool_count": len(snap.tools), "error": snap.error},
            )
        )


async def _one(server: ServerRecord, timeout_s: float) -> CapabilitySnapshot:
    try:
        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client
    except ImportError as exc:
        return CapabilitySnapshot(ok=False, error=f"mcp sdk missing: {exc}")

    params = StdioServerParameters(command=server.command or "", args=server.args, cwd=server.cwd)
    try:
        async with asyncio.timeout(timeout_s):
            async with stdio_client(params) as (read, write):
                async with ClientSession(read, write) as session:
                    init = await session.initialize()
                    listed = await session.list_tools()
        tools = [
            ToolSpec(
                name=t.name,
                description=t.description or "",
                input_schema=dict(t.inputSchema or {}),
            )
            for t in listed.tools
        ]
        info = init.serverInfo
        return CapabilitySnapshot(
            protocol_version=str(init.protocolVersion),
            server_name=info.name if info else None,
            server_version=info.version if info else None,
            tools=tools,
            ok=True,
        )
    except Exception as exc:  # probe must not abort the scan
        return CapabilitySnapshot(ok=False, error=f"{type(exc).__name__}: {exc}")
