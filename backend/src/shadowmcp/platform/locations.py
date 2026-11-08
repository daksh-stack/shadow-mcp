import os
import sys
from pathlib import Path


def _home() -> Path:
    return Path.home()


def claude_desktop_config() -> Path:
    if sys.platform == "darwin":
        return _home() / "Library/Application Support/Claude/claude_desktop_config.json"
    if sys.platform == "win32":
        appdata = os.environ.get("APPDATA")
        base = Path(appdata) if appdata else _home() / "AppData/Roaming"
        return base / "Claude/claude_desktop_config.json"
    xdg = os.environ.get("XDG_CONFIG_HOME")
    base = Path(xdg) if xdg else _home() / ".config"
    return base / "Claude/claude_desktop_config.json"


def cursor_global_config() -> Path:
    return _home() / ".cursor" / "mcp.json"


def cursor_project_config(root: Path) -> Path:
    return root / ".cursor" / "mcp.json"
    
