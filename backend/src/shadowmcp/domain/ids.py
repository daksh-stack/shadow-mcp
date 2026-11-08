import hashlib
import json

from shadowmcp.domain.models import Transport


def server_id(
    *,  # forces keyword-only arguments
    client: str,
    name: str,
    transport: Transport,
    command: str | None,
    args: list[str],
    url: str | None,
    config_path: str,
) -> str:
    payload = {
        "client": client,
        "name": name,
        "transport": transport.value,
        "command": command,
        "args": args,
        "url": url,
        "config_path": config_path,
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(raw).hexdigest()[:16]
