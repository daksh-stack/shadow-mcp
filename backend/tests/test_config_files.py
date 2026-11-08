import json
from pathlib import Path

from shadowmcp.discovery.config_files import CLIENT_CURSOR, load_servers

FIXTURE = Path(__file__).parent / "fixtures" / "cursor_mcp.json"


def test_parses_stdio_and_http() -> None:
    servers, errors = load_servers(FIXTURE, CLIENT_CURSOR)
    assert errors == []
    by_name = {s.name: s for s in servers}
    assert by_name["filesystem"].command == "npx"
    assert by_name["filesystem"].transport.value == "stdio"
    assert by_name["filesystem"].env_keys == ["API_TOKEN"]
    blob = json.dumps([s.model_dump(mode="json") for s in servers])
    assert "do-not-keep-this" not in blob
    assert by_name["remote"].url == "http://127.0.0.1:3333/mcp"
    assert by_name["remote"].transport.value == "streamable-http"


def test_missing_file_is_empty_not_error() -> None:
    servers, errors = load_servers(Path("/no/such/mcp.json"), CLIENT_CURSOR)
    assert servers == [] and errors == []
