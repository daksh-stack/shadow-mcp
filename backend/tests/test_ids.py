from shadowmcp.domain.ids import server_id
from shadowmcp.domain.models import Transport


def test_id_is_stable() -> None:
    kwargs = dict(
        client="cursor",
        name="fs",
        transport=Transport.STDIO,
        command="npx",
        args=["-y", "pkg"],
        url=None,
        config_path="/tmp/mcp.json",
    )
    assert server_id(**kwargs) == server_id(**kwargs)


def test_id_changes_when_args_change() -> None:
    base = dict(
        client="cursor",
        name="fs",
        transport=Transport.STDIO,
        command="npx",
        args=["a"],
        url=None,
        config_path="/tmp/mcp.json",
    )
    other = {**base, "args": ["b"]}
    assert server_id(**base) != server_id(**other)
