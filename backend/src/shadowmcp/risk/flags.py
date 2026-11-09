from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse

from shadowmcp.domain.models import RiskFlag, ServerRecord, Severity, Transport

_SECRETISH = ("TOKEN", "SECRET", "PASSWORD", "KEY", "CREDENTIAL")
_SHELLS = {"bash", "sh", "zsh", "cmd", "powershell", "pwsh"}
_LOOPBACK = {"127.0.0.1", "localhost", "::1"}


def apply_flags(servers: list[ServerRecord]) -> None:
    for server in servers:
        server.risk_flags = _flags(server)


def _flags(s: ServerRecord) -> list[RiskFlag]:
    out: list[RiskFlag] = []
    base = Path(s.command).name if s.command else ""
    if base in _SHELLS and any(a in {"-c", "/c"} for a in s.args):
        out.append(
            RiskFlag(
                rule_id="stdio.shell_wrapper",
                severity=Severity.HIGH,
                title="Server is started through a shell -c",
                explanation=(
                    "The configured command is a shell executing a string. "
                    "The real binary is hidden from process matching and from reviewers."
                ),
                evidence=[f"command={s.command}", f"args={s.args}"],
            )
        )
    broad = [a for a in s.args if a in {"/", str(Path.home())}]
    if s.transport is Transport.STDIO and broad:
        out.append(
            RiskFlag(
                rule_id="stdio.broad_filesystem_arg",
                severity=Severity.MEDIUM,
                title="Argument is filesystem root or the user home",
                explanation=(
                    "A configured argument is an entire home directory or filesystem root. "
                    "That is not proof the server grants that access. It is the configured input."
                ),
                evidence=[f"args={broad}"],
            )
        )
    secret_keys = [k for k in s.env_keys if any(tok in k.upper() for tok in _SECRETISH)]
    if secret_keys:
        out.append(
            RiskFlag(
                rule_id="config.secret_env_names",
                severity=Severity.INFO,
                title="Config references credential-like environment names",
                explanation=(
                    "Key names only were recorded. Values were not read into the inventory."
                ),
                evidence=[f"env_keys={secret_keys}"],
            )
        )
    if s.url:
        host = urlparse(s.url).hostname or ""
        if host in {"0.0.0.0", "::"}:
            out.append(
                RiskFlag(
                    rule_id="http.unspecified_bind",
                    severity=Severity.HIGH,
                    title="Configured URL uses an unspecified bind address",
                    explanation=(
                        "0.0.0.0 or :: is not a client target. "
                        "If this value is also the listen address, the server is exposed "
                        "beyond loopback."
                    ),
                    evidence=[f"url={s.url}"],
                )
            )
        elif host not in _LOOPBACK:
            out.append(
                RiskFlag(
                    rule_id="http.non_loopback",
                    severity=Severity.MEDIUM,
                    title="Configured URL is not loopback",
                    explanation=(
                        "Phase 1 does not probe remote hosts by default. "
                        "The URL itself is off-machine or on a LAN address."
                    ),
                    evidence=[f"url={s.url}"],
                )
            )
        if (
            s.auth
            and s.auth.required is False
            and host not in _LOOPBACK
        ):
            out.append(
                RiskFlag(
                    rule_id="http.no_auth_non_loopback",
                    severity=Severity.HIGH,
                    title="Non-loopback URL responded without an auth challenge",
                    explanation=(
                        "A GET did not return 401 or 403 and sent no WWW-Authenticate. "
                        "This does not prove the MCP endpoint is unauthenticated."
                    ),
                    evidence=[f"url={s.url}", f"status={s.auth.status}"],
                )
            )
    if s.container and any(
        "0.0.0.0" in p or p.startswith(":") for p in s.container.ports
    ):
        out.append(
            RiskFlag(
                rule_id="container.published_all_interfaces",
                severity=Severity.MEDIUM,
                title="Container publishes a port on all interfaces",
                explanation="Docker reports a binding on 0.0.0.0 or an empty host IP.",
                evidence=[f"ports={s.container.ports}"],
            )
        )
    if s.capabilities and s.capabilities.ok:
        risky = [
            t.name
            for t in s.capabilities.tools
            if _tool_looks_powerful(t.name, t.description)
        ]
        if risky:
            out.append(
                RiskFlag(
                    rule_id="capability.powerful_tool_name",
                    severity=Severity.INFO,
                    title="Declared tool name or description suggests a powerful operation",
                    explanation=(
                        "This is the server's own description. "
                        "It is not evidence the tool succeeds or that the process is privileged."
                    ),
                    evidence=[f"tools={risky}"],
                )
            )
    return out


def _tool_looks_powerful(name: str, description: str) -> bool:
    text = f"{name} {description}".lower()
    needles = ("shell", "exec", "delete", "rm ", "write_file", "sql", "credential", "sudo")
    return any(n in text for n in needles)