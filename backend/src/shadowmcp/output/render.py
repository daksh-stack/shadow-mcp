from __future__ import annotations

import json
import sys

from shadowmcp.domain.models import Inventory


def to_json(inv: Inventory) -> str:
    return json.dumps(inv.model_dump(mode="json"), indent=2)


def to_terminal(inv: Inventory) -> str:
    lines: list[str] = []
    lines.append(f"shadowmcp {inv.tool_version}  {inv.host.hostname}  {inv.host.os}")
    lines.append(f"scanned_at {inv.scanned_at.isoformat()}")
    lines.append(
        f"configs found {len(inv.coverage.config_paths_found)} / checked {len(inv.coverage.config_paths_checked)}"
    )
    lines.append(f"servers {len(inv.servers)}  errors {len(inv.errors)}")
    if not inv.servers:
        lines.append("no MCP servers in the configs that exist on this machine")
    for s in inv.servers:
        proc = ""
        if s.processes:
            top = s.processes[0]
            proc = f"  pid={top.pid} confidence={top.confidence}"
        listen = ""
        if s.listen:
            listen = f"  listen={s.listen.listening}:{s.listen.port}"
        lines.append(f"- {s.client}  {s.name}  {s.transport.value}{proc}{listen}")
        lines.append(f"    config {s.config_path}")
        if s.command:
            lines.append(f"    cmd {s.command} {' '.join(s.args)}")
        if s.url:
            lines.append(f"    url {s.url}")
        for flag in s.risk_flags:
            lines.append(f"    [{flag.severity.value}] {flag.rule_id}  {flag.title}")
        if s.capabilities:
            if s.capabilities.ok:
                names = ", ".join(t.name for t in s.capabilities.tools) or "(none declared)"
                lines.append(f"    tools {names}")
            else:
                lines.append(f"    introspect failed: {s.capabilities.error}")
    for err in inv.errors:
        lines.append(f"! {err.code} {err.source or ''} {err.message}")
    lines.append("limitations:")
    for item in inv.coverage.limitations:
        lines.append(f"  - {item}")
    return "\n".join(lines)


def emit(inv: Inventory, *, as_json: bool, out_path: str | None) -> None:
    text = to_json(inv) if as_json or out_path else to_terminal(inv)
    if out_path:
        with open(out_path, "w", encoding="utf-8") as fh:
            fh.write(to_json(inv))
            fh.write("\n")
    stream = sys.stdout
    stream.write(text)
    stream.write("\n")
