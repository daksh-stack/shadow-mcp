from __future__ import annotations

from urllib.parse import urlparse

import psutil

from shadowmcp.domain.models import Evidence, EvidenceKind, ListenCheck, ServerRecord

_LOCAL = {"127.0.0.1", "localhost", "::1", "0.0.0.0", "::"}


def check_configured_urls(servers: list[ServerRecord]) -> None:
    listening = _listeners()
    for server in servers:
        if not server.url:
            continue
        parsed = urlparse(server.url)
        host = parsed.hostname
        port = parsed.port
        if not host or port is None:
            continue
        if host not in _LOCAL:
            server.listen = ListenCheck(host=host, port=port, listening=False, pids=[])
            continue
        key_ports = {port}
        pids = sorted({pid for (h, p, pid) in listening if p in key_ports and _host_compatible(host, h)})
        server.listen = ListenCheck(host=host, port=port, listening=bool(pids), pids=pids)
        server.evidence.append(
            Evidence(
                kind=EvidenceKind.LISTEN_PORT,
                source=f"{host}:{port}",
                detail={"listening": bool(pids), "pids": pids},
            )
        )


def _listeners() -> list[tuple[str, int, int]]:
    rows: list[tuple[str, int, int]] = []
    try:
        conns = psutil.net_connections(kind="inet")
    except psutil.Error:
        return rows
    for c in conns:
        if c.status != psutil.CONN_LISTEN or not c.laddr:
            continue
        rows.append((c.laddr.ip, int(c.laddr.port), int(c.pid or 0)))
    return rows


def _host_compatible(configured: str, bound: str) -> bool:
    if configured in {"0.0.0.0", "::"} or bound in {"0.0.0.0", "::", "*"}:
        return True
    if configured == "localhost" and bound in {"127.0.0.1", "::1"}:
        return True
    return configured == bound
