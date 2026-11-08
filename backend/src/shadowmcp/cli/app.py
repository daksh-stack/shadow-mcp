from pathlib import Path
from typing import Annotated

import typer

from shadowmcp import __version__
from shadowmcp.output.render import emit
from shadowmcp.scan.engine import run_scan

app = typer.Typer(add_completion=False, no_args_is_help=True)


@app.command()
def version() -> None:
    """Print the tool version."""
    typer.echo(__version__)


@app.command()
def scan(
    project_root: Annotated[
        list[Path] | None,
        typer.Option(
            "--project-root",
            exists=True,
            file_okay=False,
            dir_okay=True,
            help=("Directory whose .cursor/mcp.json should be read. Repeatable. No default walk."),
        ),
    ] = None,
    introspect: Annotated[
        bool,
        typer.Option(
            "--introspect",
            help=("Start each configured STDIO server and call tools/list. Never calls a tool."),
        ),
    ] = False,
    introspect_timeout: Annotated[
        float,
        typer.Option("--introspect-timeout"),
    ] = 8.0,
    no_process: Annotated[
        bool,
        typer.Option("--no-process"),
    ] = False,
    no_ports: Annotated[
        bool,
        typer.Option("--no-ports"),
    ] = False,
    json_output: Annotated[
        bool,
        typer.Option("--json"),
    ] = False,
    out: Annotated[
        Path | None,
        typer.Option(
            "--out",
            help="Write the inventory JSON to this path.",
        ),
    ] = None,
) -> None:
    """Discover configured MCP servers on this machine."""
    roots = list(project_root) if project_root else []
    inv = run_scan(
        project_roots=roots,
        introspect=introspect,
        introspect_timeout_s=introspect_timeout,
        correlate_processes=not no_process,
        check_ports=not no_ports,
    )
    emit(inv, as_json=json_output, out_path=str(out) if out else None)


@app.command("list")
def list_servers(
    project_root: Annotated[
        list[Path] | None,
        typer.Option("--project-root"),
    ] = None,
) -> None:
    """Print server name, client, and transport only."""
    roots = list(project_root) if project_root else []
    inv = run_scan(
        project_roots=roots,
        introspect=False,
        introspect_timeout_s=0,
        correlate_processes=False,
        check_ports=False,
    )
    for s in inv.servers:
        typer.echo(f"{s.client}\t{s.name}\t{s.transport.value}\t{s.config_path}")


@app.command()
def report(
    inventory: Annotated[
        Path,
        typer.Argument(exists=True, dir_okay=False),
    ],
) -> None:
    """Render a previously written inventory JSON to the terminal."""
    from shadowmcp.domain.models import Inventory
    from shadowmcp.output.render import to_terminal

    inv = Inventory.model_validate_json(inventory.read_text(encoding="utf-8"))
    typer.echo(to_terminal(inv))


def main() -> None:
    app()


if __name__ == "__main__":
    main()
