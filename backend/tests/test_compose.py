import json
from pathlib import Path

from shadowmcp.discovery.compose_files import load_compose

FIXTURE = Path(__file__).parent / "fixtures" / "mcp-compose.yml"

def test_keeps_mcp_service_and_drops_postgress() -> None :
    servers, errors = load_compose(FIXTURE)
    assert errors == []
    assert [s.name for s in servers] == ["files"]
    blob = json.dumps([s.model_dump(mode="json") for s in servers])
    assert "do-not-keep-this" not in blob


def test_env_key_is_kept()-> None:
    servers, _ = load_compose(FIXTURE)
    assert servers[0].env_keys == ["API_TOKEN"]
    