from __future__ import annotations

import ipaddress

from shadowmcp.domain.models import ScanError


def expand_targets(
    cidrs: list[str],
    ports: list[int],
    limit: int = 256,
) -> tuple[list[str], list[ScanError]]:
    if not cidrs and not ports:
        return [], []
    if cidrs and not ports:
        return [], [
            ScanError(
                code="cidr_refused",
                message="Pass at least one --port with --cidr. There is no default port sweep.",
                source="cidr",
            )
        ]
    if ports and not cidrs:
        return [], [
            ScanError(
                code="cidr_refused",
                message="--port only applies with --cidr.",
                source="cidr",
            )
        ]
    urls: list[str] = []
    errors: list[ScanError] = []
    for raw in cidrs:
        try:
            network = ipaddress.ip_network(raw, strict=False)
        except ValueError as exc:
            errors.append(ScanError(code="cidr_shape", message=str(exc), source=raw))
            continue
        for host in network.hosts():
            for port in ports:
                urls.append(f"http://{host}:{port}/mcp")
                if len(urls) > limit:
                    errors.append(
                        ScanError(
                            code="cidr_capped",
                            message=f"stopped at {limit} host-port pairs",
                            source=raw,
                        )
                    )
                    return urls, errors
    return urls, errors