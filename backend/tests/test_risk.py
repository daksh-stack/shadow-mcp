from shadowmcp.domain.models import ServerRecord, Transport
from shadowmcp.risk.flags import apply_flags


def test_shell_wrapper_is_high() -> None:
    s = ServerRecord(
        id="abc",
        name="x",
        client="cursor",
        transport=Transport.STDIO,
        command="bash",
        args=["-c", "npx some-server"],
        config_path="/tmp/mcp.json",
    )
    apply_flags([s])
    assert any(f.rule_id == "stdio.shell_wrapper" and f.severity.value == "high" for f in s.risk_flags)
