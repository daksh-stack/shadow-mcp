from __future__ import annotations

from urllib.parse import urlparse

from shadowmcp.domain.models import ServerRecord


def merge_servers(servers: list[ServerRecord]) -> list[ServerRecord]:
    kept: list[ServerRecord] = []
    index: dict[str, ServerRecord] = {}
    for server in servers:
        key = _key(server)
        prior = index.get(key)
        if prior is None:
            index[key] = server
            kept.append(server)
            continue
        _fold(prior, server)
    return kept


def _key(server: ServerRecord) -> str:
    if server.url:
        parsed = urlparse(server.url)
        path = (parsed.path or "").rstrip("/")
        return f"url:{parsed.scheme}:{parsed.hostname}:{parsed.port}{path}"
    if server.command:
        args = " ".join(server.args)
        return f"cmd:{server.command}:{args}"
    return f"id:{server.id}"


def _fold(into: ServerRecord, extra: ServerRecord) -> None:
    into.merged_from.append(extra.id)
    into.evidence.extend(extra.evidence)
    if into.container is None:
        into.container = extra.container
    if not into.processes:
        into.processes = extra.processes
    if into.listen is None:
        into.listen = extra.listen
    if into.tls is None:
        into.tls = extra.tls
    if into.auth is None:
        into.auth = extra.auth
    into.env_keys = sorted(set(into.env_keys) | set(extra.env_keys))