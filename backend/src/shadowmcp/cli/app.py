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
            help=(
                "Directory whose .cursor/mcp.json should be read. "
                "Repeatable. No default walk."
            ),
        ),
    ] = None,
    compose: Annotated[
        list[Path] | None,
        typer.Option(
            "--compose",
            exists=True,
            dir_okay=False,
            help="Compose file to read. Only services that look like MCP are kept.",
        ),
    ] = None,
    endpoint: Annotated[
        list[str] | None,
        typer.Option(
            "--endpoint",
            help="Explicit http(s) URL with a port. Repeatable.",
        ),
    ] = None,
    cidr: Annotated[
        list[str] | None,
        typer.Option(
            "--cidr",
            help="Authorized CIDR. Requires --port. Cap 256 host-port pairs.",
        ),
    ] = None,
    port: Annotated[
        list[int] | None,
        typer.Option(
            "--port",
            help="Port for --cidr targets. Required with --cidr.",
        ),
    ] = None,
    no_docker: Annotated[
        bool,
        typer.Option("--no-docker", help="Skip Docker engine discovery."),
    ] = False,
    probe_http: Annotated[
        bool,
        typer.Option(
            "--probe-http",
            help="GET each discovered URL once. No MCP handshake. No tool calls.",
        ),
    ] = False,
    probe_timeout: Annotated[
        float,
        typer.Option("--probe-timeout"),
    ] = 3.0,
    introspect: Annotated[
        bool,
        typer.Option(
            "--introspect",
            help=(
                "Start each configured STDIO server and call tools/list. "
                "Never calls a tool."
            ),
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
    inv = run_scan(
        project_roots=list(project_root) if project_root else [],
        compose_files=list(compose) if compose else [],
        endpoints=list(endpoint) if endpoint else [],
        cidrs=list(cidr) if cidr else [],
        ports=list(port) if port else [],
        use_docker=not no_docker,
        probe_http=probe_http,
        probe_timeout_s=probe_timeout,
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
    inv = run_scan(
        project_roots=list(project_root) if project_root else [],
        compose_files=[],
        endpoints=[],
        cidrs=[],
        ports=[],
        use_docker=False,
        probe_http=False,
        probe_timeout_s=0,
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