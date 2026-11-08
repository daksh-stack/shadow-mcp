from __future__ import annotations

import os
from pathlib import Path

import psutil

from shadowmcp.domain.models import Evidence, EvidenceKind, ProcessMatch, ServerRecord, Transport


def correlate(servers: list[ServerRecord]) -> None:
    procs = _snapshot()
    for server in servers:
        if server.transport is not Transport.STDIO or not server.command:
            continue
        matches = [_score(server, p) for p in procs]
        matches = [m for m in matches if m is not None and m.confidence >= 0.5]
        matches.sort(key=lambda m: m.confidence, reverse=True)
        server.processes = matches[:5]
        for m in server.processes:
            server.evidence.append(
                Evidence(
                    kind=EvidenceKind.PROCESS,
                    source=f"pid:{m.pid}",
                    detail={
                        "confidence": m.confidence,
                        "reason": m.reason,
                        "cmdline": m.cmdline[:12],
                    },
                )
            )


def _snapshot() -> list[tuple[int, str, list[str], str | None, float | None]]:
    rows = []
    for proc in psutil.process_iter(["pid", "name", "cmdline", "username", "create_time"]):
        try:
            info = proc.info
            cmd = info.get("cmdline") or []
            if not cmd:
                continue
            rows.append(
                (
                    int(info["pid"]),
                    str(info.get("name") or ""),
                    [str(c) for c in cmd],
                    info.get("username"),
                    info.get("create_time"),
                )
            )
        except (psutil.Error, OSError, KeyError, TypeError, ValueError):
            continue
    return rows


def _score(
    server: ServerRecord,
    proc: tuple[int, str, list[str], str | None, float | None],
) -> ProcessMatch | None:
    pid, name, cmdline, user, created = proc
    command = server.command or ""
    base = Path(command).name
    joined = " ".join(cmdline)
    if base not in joined and command not in joined:
        return None

    interesting = [a for a in server.args if len(a) >= 3 and not a.startswith("-")]
    if not interesting:
        confidence = 0.55
        reason = "command basename matched; config has no distinctive args"
    else:
        hit = sum(1 for a in interesting if a in joined)
        ratio = hit / len(interesting)
        if ratio == 0:
            return None
        confidence = 0.5 + 0.5 * ratio
        reason = f"command matched; {hit}/{len(interesting)} distinctive args matched"
    if os.path.basename(cmdline[0]) == base or cmdline[0] == command:
        confidence = min(1.0, confidence + 0.05)
    return ProcessMatch(
        pid=pid,
        name=name,
        cmdline=cmdline,
        username=user,
        create_time=created,
        confidence=round(confidence, 3),
        reason=reason,
    )
