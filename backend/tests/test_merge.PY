from shadowmcp.discovery.merge import merge_servers
from shadowmcp.domain.models import ServerRecord, Transport


def test_same_url_collapses() -> None:
    a = ServerRecord(
        id="a",
        name="from-config",
        client="cursor",
        transport=Transport.STREAMABLE_HTTP,
        url="http://127.0.0.1:3333/mcp",
        config_path="/tmp/mcp.json",
    )
    b = ServerRecord(
        id="b",
        name="from-docker",
        client="docker",
        transport=Transport.STREAMABLE_HTTP,
        url="http://127.0.0.1:3333/mcp",
        config_path="docker://abc",
    )
    merged = merge_servers([a, b])
    assert len(merged) == 1
    assert merged[0].id == "a"
    assert merged[0].merged_from == ["b"]