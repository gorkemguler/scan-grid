"""``scangrid`` command-line entry point."""

from __future__ import annotations

import secrets

import typer
from rich.console import Console
from rich.table import Table

from . import __version__
from .config import get_settings

app = typer.Typer(
    add_completion=False, help="ScanGrid - distributed authorised vulnerability scanner."
)
console = Console()


@app.command()
def version() -> None:
    console.print(f"scan-grid {__version__}")


@app.command("gen-token")
def gen_token() -> None:
    """Print a fresh API token."""
    console.print(secrets.token_hex(32))


@app.command()
def config() -> None:
    """Show the effective configuration (secrets masked)."""
    s = get_settings()
    t = Table(title="ScanGrid configuration", show_header=False)
    masked = {"api_token", "nvd_api_key", "telegram_bot_token", "dashboard_password"}
    for k, v in s.model_dump().items():
        t.add_row(k, "********" if k in masked and v else str(v))
    console.print(t)


@app.command()
def orchestrator(
    host: str = typer.Option(None),
    port: int = typer.Option(None),
    reload: bool = typer.Option(False),
) -> None:
    """Run the orchestrator (API + dashboard + scheduler)."""
    import uvicorn

    s = get_settings()
    uvicorn.run(
        "scangrid.orchestrator.app:app",
        host=host or s.api_host,
        port=port or s.api_port,
        reload=reload,
        log_level=s.log_level.lower(),
    )


@app.command()
def worker() -> None:
    """Run a scan worker."""
    from .worker.runner import main

    main()


@app.command("check-allowlist")
def check_allowlist(
    spec: str = typer.Argument(..., help="Spec to test, e.g. '192.168.1.0/24'"),
) -> None:
    """Show which hosts a spec resolves to and whether they're authorised."""
    from .allowlist import resolve_spec

    res = resolve_spec(spec)
    console.print(
        f"[green]in scope[/green] ({len(res.allowed)}): {res.allowed[:20]}"
        + (" ..." if len(res.allowed) > 20 else "")
    )
    if res.rejected:
        console.print(f"[red]rejected[/red] ({len(res.rejected)}):")
        for item, reason in res.rejected[:20]:
            console.print(f"  {item}  -  {reason}")


@app.command("add-target")
def add_target(
    name: str,
    spec: str,
    every: int = typer.Option(1440, help="Minutes between scans; 0 = manual only."),
    nmap_args: str = typer.Option("", help="Override the default nmap args."),
    scan_now: bool = typer.Option(False, help="Queue a scan immediately."),
) -> None:
    """Create a target directly in the database (orchestrator host only)."""
    from .allowlist import resolve_spec
    from .db import init_db, session_scope
    from .models import Target
    from .orchestrator.queue import enqueue_target

    res = resolve_spec(spec)
    if not res.allowed:
        console.print(f"[red]nothing in {spec!r} is inside SCANGRID_ALLOWLIST[/red]")
        raise typer.Exit(1)
    init_db()
    with session_scope() as s:
        t = Target(name=name, spec=spec, nmap_args=nmap_args, interval_minutes=every)
        s.add(t)
        s.flush()
        console.print(
            f"[green]added[/green] target {name} (id {t.id}); {len(res.allowed)} host(s) in scope"
        )
        if scan_now:
            job = enqueue_target(s, t, force=True)
            console.print(f"queued job {job.id}" if job else "could not queue")


@app.command()
def selftest() -> None:
    """Initialise the DB and print a summary."""
    from .allowlist import _allow_networks
    from .db import init_db

    init_db()
    s = get_settings()
    nets = [str(n) for n in _allow_networks()]
    console.print(f"[green]OK[/green] db at {s.db_path}")
    console.print(f"role={s.role}  cve_provider={s.cve_provider}  notify={s.notify_backend}")
    console.print(f"allowlist={nets}  allow_public={s.allow_public_targets}")


if __name__ == "__main__":
    app()
