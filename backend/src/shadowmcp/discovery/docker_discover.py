from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from shadowmcp.domain.ids import server_id
from shadowmcp.domain.models import (
    ContainerMatch,
    Evidence,
    EvidenceKind,
    ScanError,
    ServerRecord,
    Transport,
)

CLIENT_DOCKER = "docker"


def load_docker() -> tuple[list[ServerRecord], list[ScanError]]:
    try:
        import docker
        from docker.errors import DockerException
    except ImportError:
        return [], [
            ScanError(
                code="docker_sdk_missing",
                message="Install the docker extra: pip install -e .[docker]",
                source="docker",
            )
        ]
    try:
        client = docker.from_env()
        client.ping()
        containers = client.containers.list(all=False)
    except DockerException as exc:
        return [], [ScanError(code="docker_unavailable", message=str(exc), source="docker")]

    servers: list[ServerRecord] = []
    for container in containers:
        record = _one(container)
        if record is not None:
            servers.append(record)
    return servers, []


def _one(container: Any) -> ServerRecord | None:
    attrs = container.attrs or {}
    cfg = attrs.get("Config") or {}
    name = str(container.name)
    image = str(cfg.get("Image") or container.image.tags[0] if container.image.tags else "")
    command = [str(p) for p in (cfg.get("Cmd") or [])]
    env_keys = _env_keys(cfg.get("Env") or [])
    ports = _published(attrs.get("NetworkSettings") or {})
    blob = " ".join([name, image, *command, *env_keys]).lower()
    if "mcp" not in blob and not ports:
        return None
    if "mcp" not in blob:
        return None

    url = next((p for p in command if p.startswith("http://") or p.startswith("https://")), None)
    transport = Transport.STDIO
    if url:
        path = urlparse(url).path or ""
        transport = Transport.SSE if path.rstrip("/").endswith("/sse") else Transport.STREAMABLE_HTTP

    match = ContainerMatch(
        container_id=str(container.id)[:12],
        name=name,
        image=image,
        status=str(container.status),
        ports=ports,
        env_keys=env_keys,
        command=command,
    )
    bin_cmd = command[0] if command else None
    rec = ServerRecord(
        id=server_id(
            client=CLIENT_DOCKER,
            name=name,
            transport=transport,
            command=bin_cmd,
            args=command[1:],
            url=url,
            config_path=f"docker://{match.container_id}",
        ),
        name=name,
        client=CLIENT_DOCKER,
        transport=transport,
        command=bin_cmd,
        args=command[1:],
        env_keys=env_keys,
        url=url,
        config_path=f"docker://{match.container_id}",
        container=match,
        evidence=[
            Evidence(
                kind=EvidenceKind.CONTAINER,
                source=match.container_id,
                detail={"name": name, "image": image, "ports": ports},
            )
        ],
    )
    return rec


def _env_keys(pairs: list[str]) -> list[str]:
    keys: list[str] = []
    for item in pairs:
        if "=" in item:
            keys.append(item.split("=", 1)[0])
    return sorted(keys)


def _published(network: dict) -> list[str]:
    ports = network.get("Ports") or {}
    out: list[str] = []
    for private, bindings in ports.items():
        if not bindings:
            out.append(str(private))
            continue
        for binding in bindings:
            host_ip = binding.get("HostIp") or ""
            host_port = binding.get("HostPort") or ""
            out.append(f"{host_ip}:{host_port}->{private}")
    return out