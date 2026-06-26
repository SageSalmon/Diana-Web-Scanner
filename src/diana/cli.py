"""Diana CLI — Typer-based command-line interface."""

from __future__ import annotations

import asyncio
import os
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from diana import __version__
from diana.config import ScanConfig
from diana.core.models import ScanStatus, Severity
from diana.core.orchestrator import ScanOrchestrator
from diana.engagement.models import EngagementConfig


def _load_dotenv() -> None:
    """Load .env file if present."""
    env_path = Path.cwd() / ".env"
    if env_path.exists():
        for line in env_path.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, _, value = line.partition("=")
                os.environ.setdefault(key.strip(), value.strip())


def _ai_enabled() -> bool:
    """Check DIANA_AI_ENABLED env var. Defaults to true (for ECS)."""
    return os.environ.get("DIANA_AI_ENABLED", "true").lower() in ("true", "1", "yes")

app = typer.Typer(
    name="diana",
    help="Diana — AI-Enabled Web Vulnerability Scanner",
    no_args_is_help=True,
)
console = Console()


@app.command()
def scan(
    target: str = typer.Argument(..., help="Target URL to scan"),
    engagement: str = typer.Option(
        ..., "--engagement", "-e", help="Path to engagement.yaml"
    ),
    config: Optional[str] = typer.Option(
        None, "--config", "-c", help="Path to scan configuration file"
    ),
    modules: Optional[str] = typer.Option(
        None, "--modules", "-m", help="Comma-separated list of scan modules"
    ),
    sitemap_cache: Optional[str] = typer.Option(
        None, "--sitemap-cache",
        help="Path to a cached sitemap JSON. Loaded (skipping the crawl) if it "
             "exists; otherwise the crawl runs and the sitemap is saved here.",
    ),
    depth: int = typer.Option(3, "--depth", "-d", help="Maximum crawl depth"),
    rate_limit: int = typer.Option(10, "--rate-limit", "-r", help="Max requests/second"),
    timeout: int = typer.Option(30, "--timeout", help="Request timeout in seconds"),
    output: str = typer.Option("./reports", "--output", "-o", help="Report output directory"),
    format: str = typer.Option("html", "--format", "-f", help="Report format: html, json, sarif"),
    no_ai: bool = typer.Option(False, "--no-ai", help="Disable AI analysis"),
    local: bool = typer.Option(False, "--local", help="Local mode (allow private IPs for Docker targets)"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
):
    """Run a vulnerability scan against a target."""
    _load_dotenv()

    # --no-ai flag overrides env var; env var defaults to true
    ai_disabled = no_ai or not _ai_enabled()

    console.print(Panel.fit(
        f"[bold blue]Diana[/bold blue] — AI-Enabled Web Scanner\nv{__version__}",
        border_style="blue",
    ))

    # Load engagement config
    try:
        eng_config = EngagementConfig.from_yaml(engagement)
    except Exception as e:
        console.print(f"[red]Failed to load engagement file: {e}[/red]")
        raise typer.Exit(1)

    console.print(f"  Engagement: [cyan]{eng_config.engagement.id}[/cyan]")
    console.print(f"  Client: [cyan]{eng_config.engagement.client}[/cyan]")
    console.print(f"  Target: [cyan]{target}[/cyan]")
    console.print(f"  AI: [cyan]{'enabled' if not ai_disabled else 'disabled'}[/cyan]")
    console.print()

    # Build scan config
    if config:
        scan_config = ScanConfig.from_yaml(config)
    else:
        scan_config = ScanConfig(
            target=target,
            engagement_file=engagement,
            depth=depth,
            rate_limit=rate_limit,
            timeout=timeout,
            no_ai=ai_disabled,
            verbose=verbose,
        )

    if modules:
        scan_config.scan.modules = [m.strip() for m in modules.split(",")]

    if sitemap_cache:
        scan_config.sitemap_cache = sitemap_cache

    scan_config.reporting.format = format
    scan_config.reporting.output = output

    # Run the scan
    result = asyncio.run(_run_scan(eng_config, scan_config, allow_private=local))

    # Print results
    console.print()
    console.print("[bold]Results Summary[/bold]")
    console.print("─" * 50)

    severity_colors = {
        Severity.CRITICAL: "red",
        Severity.HIGH: "bright_red",
        Severity.MEDIUM: "yellow",
        Severity.LOW: "cyan",
        Severity.INFO: "dim",
    }

    by_severity = result.findings_by_severity
    for sev in Severity:
        count = len(by_severity[sev])
        color = severity_colors[sev]
        bar = "█" * count
        console.print(f"  [{color}]{sev.value.upper():10s}[/{color}]  {count}  [{color}]{bar}[/{color}]")

    total = len(result.findings)
    console.print()
    console.print(f"  Total findings: [bold]{total}[/bold]")
    console.print(f"  False positives rejected by AI: [green]{result.false_positives_rejected}[/green]")
    console.print(f"  Duration: {result.duration_seconds:.1f}s")
    console.print()

    if result.status == ScanStatus.COMPLETED:
        console.print("[green]Scan completed successfully.[/green]")
    else:
        console.print(f"[red]Scan ended with status: {result.status.value}[/red]")


async def _run_scan(
    engagement: EngagementConfig,
    config: ScanConfig,
    allow_private: bool = False,
) -> "ScanResult":
    orchestrator = ScanOrchestrator(engagement, config, allow_private=allow_private)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Starting scan...", total=None)

        # Monkey-patch status updates into progress display
        original_run = orchestrator.run

        async def tracked_run():
            result = await original_run()
            return result

        progress.update(task, description="Running scan pipeline...")
        result = await tracked_run()
        progress.update(task, description="Done!")

    return result


@app.command()
def serve(
    host: str = typer.Option("0.0.0.0", "--host", help="API server host"),
    port: int = typer.Option(8000, "--port", "-p", help="API server port"),
):
    """Start the Diana REST API server."""
    import uvicorn
    from diana.api import create_app

    console.print(Panel.fit(
        f"[bold blue]Diana API Server[/bold blue]\nListening on {host}:{port}",
        border_style="blue",
    ))
    uvicorn.run(create_app(), host=host, port=port)


@app.command()
def modules():
    """List available scanner modules."""
    table = Table(title="Scanner Modules")
    table.add_column("Name", style="cyan")
    table.add_column("Description")

    from diana.scanners.registry import ScannerRegistry
    # Can't instantiate without HTTP client, so just list the known modules
    module_info = {
        "xss": "Cross-Site Scripting (Reflected, Stored, DOM)",
        "sqli": "SQL Injection (error-based, boolean-blind, time-blind)",
        "ssrf": "Server-Side Request Forgery",
        "headers": "Security headers analysis (HSTS, CSP, CORS, cookies)",
        "info_disclosure": "Information disclosure, debug endpoints, exposed secrets",
        "auth": "Broken authentication, IDOR, path traversal, open redirect",
    }
    for name, desc in module_info.items():
        table.add_row(name, desc)

    console.print(table)


@app.command()
def version():
    """Show version information."""
    console.print(f"Diana v{__version__}")


if __name__ == "__main__":
    app()
