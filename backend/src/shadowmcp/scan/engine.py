from __future__ import annotations

import asyncio
import platform
import socket
from pathlib import Path

from shadowmcp import __version__
from shadowmcp.discovery.cidr_targets import expand_targets
from shadowmcp.discovery.compose_files import load_compose
from shadowmcp.discovery.config_files import CLIENT_CLAUDE, CLIENT_CURSOR, load_servers
from shadowmcp.discovery.docker_discover import load_docker
from shadowmcp.discovery.http_probe import endpoint_record, probe
from shadowmcp.discovery.introspect import introspect_all
from shadowmcp.discovery.merge import merge_servers
from shadowmcp.discovery.ports import check_configured_urls
from shadowmcp.discovery.processes import correlate
from shadowmcp.domain.models import Coverage, HostInfo, Inventory
from shadowmcp.platform.locations import (
    claude_desktop_config,
    cursor_global_config,
    cursor_project_config,
)
from shadowmcp.risk.flags import apply_flags


def run_scan(
    *,
    project_roots: list[Path],
    compose_files: list[Path],
    endpoints: list[str],
    cidrs: list[str],
    ports: list[int],
    use_docker: bool,
    probe_http: bool,
    probe_timeout_s: float,
    introspect: bool,
    introspect_timeout_s: float,
    correlate_processes: bool,
    check_ports: bool,
) -> Inventory:
    targets: list[tuple[Path, str]] = [
        (claude_desktop_config(), CLIENT_CLAUDE),
        (cursor_global_config(), CLIENT_CURSOR),
    ]
    for root in project_roots:
        targets.append((cursor_project_config(root), CLIENT_CURSOR))

    servers = []
    errors = []
    found: list[str] = []
    for path, client in targets:
        if path.is_file():
            found.append(str(path))
        batch, errs = load_servers(path, client)
        servers.extend(batch)
        errors.extend(errs)

    for path in compose_files:
        batch, errs = load_compose(path)
        servers.extend(batch)
        errors.extend(errs)

    if use_docker:
        batch, errs = load_docker()
        servers.extend(batch)
        errors.extend(errs)

    for url in endpoints:
        record, err = endpoint_record(url)
        if record:
            servers.append(record)
        if err:
            errors.append(err)

    cidr_urls, cidr_errors = expand_targets(cidrs, ports)
    errors.extend(cidr_errors)
    for url in cidr_urls:
        record, err = endpoint_record(url)
        if record:
            servers.append(record)
        if err:
            errors.append(err)

    if correlate_processes:
        correlate(servers)
    if check_ports:
        check_configured_urls(servers)
    if probe_http:
        probe(servers, probe_timeout_s)
    if introspect:
        asyncio.run(introspect_all(servers, introspect_timeout_s))

    servers = merge_servers(servers)
    apply_flags(servers)

    return Inventory(
        schema_version="2",
        tool_version=__version__,
        host=HostInfo(os=platform.platform(), hostname=socket.gethostname()),
        servers=servers,
        errors=errors,
        coverage=Coverage(
            clients_requested=[CLIENT_CLAUDE, CLIENT_CURSOR],
            config_paths_checked=[str(p) for p, _ in targets],
            config_paths_found=found,
            project_roots=[str(r) for r in project_roots],
            introspect_enabled=introspect,
            limitations=[
                "Only Claude Desktop and Cursor configs are read by default.",
                "Project discovery is limited to the roots you pass. There is no home-directory walk.",
                "Process matches are heuristic and include a confidence and a reason.",
                "Listen checks cover only hosts and ports already present in configured URLs.",
                "Capability data is the server's declaration. Tools are never called.",
                "Env values and header values are not stored.",
                "Compose files are read only when you pass --compose.",
                "Docker is queried only for running containers whose metadata contains 'mcp'.",
                "CIDR targets are generated only when both --cidr and --port are set, and capped at 256.",
                "HTTP checks are GET-only. They do not complete an MCP handshake.",
            ],
        ),
    )