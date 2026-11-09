from __future__ import annotations

import socket
import ssl
from urllib.parse import urlparse

from shadowmcp.domain.ids import server_id
from shadowmcp.domain.models import (
    AuthObservation,
    Evidence,
    EvidenceKind,
    ScanError,
    ServerRecord,
    TlsObservation,
    Transport,
)

CLIENT_ENDPOINT = "endpoint"


def endpoint_record(url: str) -> tuple[ServerRecord | None, ScanError | None]:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.port is None:
        return None, ScanError(
            code="endpoint_shape",
            message="need http(s) URL with an explicit port",
            source=url,
        )
    path = parsed.path or ""
    transport = Transport.SSE if path.rstrip("/").endswith("/sse") else Transport.STREAMABLE_HTTP
    return (
        ServerRecord(
            id=server_id(
                client=CLIENT_ENDPOINT,
                name=parsed.hostname,
                transport=transport,
                command=None,
                args=[],
                url=url,
                config_path=url,
            ),
            name=parsed.hostname,
            client=CLIENT_ENDPOINT,
            transport=transport,
            url=url,
            config_path=url,
            evidence=[Evidence(kind=EvidenceKind.HTTP_PROBE, source=url, detail={"declared": True})],
        ),
        None,
    )


def probe(servers: list[ServerRecord], timeout_s: float) -> None:
    for server in servers:
        if not server.url:
            continue
        parsed = urlparse(server.url)
        host = parsed.hostname
        port = parsed.port
        if not host or port is None:
            continue
        tls, auth = _check(server.url, host, port, parsed.scheme, timeout_s)
        server.tls = tls
        server.auth = auth
        server.evidence.append(
            Evidence(
                kind=EvidenceKind.HTTP_PROBE,
                source=server.url,
                detail={
                    "tls_error": tls.error,
                    "status": auth.status,
                    "auth_required": auth.required,
                },
            )
        )


def _check(
    url: str,
    host: str,
    port: int,
    scheme: str,
    timeout_s: float,
) -> tuple[TlsObservation, AuthObservation]:
    tls = TlsObservation(scheme=scheme)
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout_s) as sock:
            if scheme == "https":
                with context.wrap_socket(sock, server_hostname=host) as wrapped:
                    cert = wrapped.getpeercert()
                    tls.subject = _name(cert.get("subject")) if cert else None
                    tls.issuer = _name(cert.get("issuer")) if cert else None
                    tls.not_after = cert.get("notAfter") if cert else None
                    status, schemes = _request(wrapped, url, host)
            else:
                status, schemes = _request(sock, url, host)
    except OSError as exc:
        tls.error = f"{type(exc).__name__}: {exc}"
        return tls, AuthObservation(required=None, error=tls.error)
    required = status in {401, 403} or bool(schemes)
    return tls, AuthObservation(required=required, status=status, www_authenticate_schemes=schemes)


def _request(sock: socket.socket, url: str, host: str) -> tuple[int | None, list[str]]:
    parsed = urlparse(url)
    path = parsed.path or "/"
    payload = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
    sock.settimeout(5)
    sock.sendall(payload.encode())
    data = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
        if len(data) > 65536:
            break
    text = data.decode("iso-8859-1", errors="replace")
    line = text.split("\r\n", 1)[0]
    parts = line.split()
    status = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else None
    schemes: list[str] = []
    for header in text.split("\r\n"):
        if header.lower().startswith("www-authenticate:"):
            schemes.append(header.split(":", 1)[1].strip().split(" ", 1)[0])
    return status, schemes


def _name(rdns: object) -> str | None:
    if not isinstance(rdns, tuple):
        return None
    bits: list[str] = []
    for group in rdns:
        for key, value in group:
            bits.append(f"{key}={value}")
    return ",".join(bits) or None