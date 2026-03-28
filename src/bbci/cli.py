"""CLI entry point for bb-crypto-inventory."""

from __future__ import annotations

import asyncio
import logging
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.logging import RichHandler
from rich.panel import Panel
from rich.table import Table

from bbci.agent.orchestrator import AgentOrchestrator
from bbci.config import Config

console = Console()


def setup_logging(verbose: bool = False) -> None:
    """Configure logging with rich handler."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(message)s",
        handlers=[RichHandler(console=console, show_time=True, show_path=False)],
    )


@click.group()
@click.version_option(version="0.1.0", prog_name="bbci")
def main() -> None:
    """Blackbox Cryptographic Inventory Tool.

    Automated crypto asset discovery using only endpoint URLs.
    """
    pass


@main.command()
@click.argument("url")
@click.option("-o", "--output", type=click.Path(), help="Output file path")
@click.option(
    "--phase", "phases", type=str, default=None,
    help="Comma-separated phase numbers (e.g., '0,1')"
)
@click.option("--full", is_flag=True, help="Run all phases (0,1,2,3)")
@click.option("--min-confidence", type=float, default=None, help="Minimum confidence threshold")
@click.option("--model", type=str, default=None, help="LLM model to use")
@click.option("--slow-pace", is_flag=True, help="Enable slow-pace mode for WAF evasion")
@click.option("-c", "--config", "config_path", type=click.Path(), help="Config file path")
@click.option("-v", "--verbose", is_flag=True, help="Verbose output")
@click.option("--format", "output_format", type=click.Choice(["cyclonedx", "json", "markdown"]),
              default=None, help="Output format")
def scan(
    url: str,
    output: str | None,
    phases: str | None,
    full: bool,
    min_confidence: float | None,
    model: str | None,
    slow_pace: bool,
    config_path: str | None,
    verbose: bool,
    output_format: str | None,
) -> None:
    """Scan an endpoint for cryptographic assets and vulnerabilities."""
    setup_logging(verbose)

    # Load config
    if config_path:
        config = Config.from_file(config_path)
    else:
        config = Config.load()

    # Override config with CLI options
    if phases:
        config.scan.phases = [int(p.strip()) for p in phases.split(",")]
    elif full:
        config.scan.phases = [0, 1, 2, 3]

    if min_confidence is not None:
        config.scan.min_confidence = min_confidence
    if model:
        config.agent.model = model
    if slow_pace:
        config.scan.slow_pace = True
    if output_format:
        config.output.format = output_format

    # Display scan config
    console.print(Panel.fit(
        f"[bold]Target:[/bold] {url}\n"
        f"[bold]Phases:[/bold] {config.scan.phases}\n"
        f"[bold]Model:[/bold] {config.agent.model}\n"
        f"[bold]Max iterations:[/bold] {config.agent.max_iterations}\n"
        f"[bold]Timeout:[/bold] {config.agent.timeout_minutes} min\n"
        f"[bold]Min confidence:[/bold] {config.scan.min_confidence}",
        title="🔐 bb-crypto-inventory",
        border_style="cyan",
    ))

    # Run scan
    orchestrator = AgentOrchestrator(config)

    try:
        report = asyncio.run(orchestrator.scan(url))
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user[/yellow]")
        sys.exit(1)
    except Exception as e:
        console.print(f"\n[red]Scan failed: {e}[/red]")
        if verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

    # Display results
    _display_results(report, orchestrator.findings)

    # Write output
    report_json = report.to_json(pretty=config.output.pretty)

    if output:
        Path(output).write_text(report_json)
        console.print(f"\n[green]Report written to {output}[/green]")
    else:
        console.print("\n[bold]CBOM Report (JSON):[/bold]")
        console.print(report_json)


def _display_results(report, findings) -> None:  # type: ignore[no-untyped-def]
    """Display scan results in a rich table."""
    if not findings:
        console.print("\n[yellow]No cryptographic findings detected.[/yellow]")
        return

    # Summary
    summary = report.vulnerabilities_summary
    console.print(Panel.fit(
        f"[bold]Total findings:[/bold] {summary.get('total_findings', 0)}\n"
        f"[bold]PQ-vulnerable:[/bold] {summary.get('pq_vulnerable_count', 0)}\n"
        f"[bold]Unique algorithms:[/bold] {', '.join(summary.get('unique_algorithms', []))}",
        title="📊 Scan Summary",
        border_style="green",
    ))

    # Findings table
    table = Table(title="Findings", show_header=True, header_style="bold")
    table.add_column("ID", style="dim")
    table.add_column("Category")
    table.add_column("Severity")
    table.add_column("Algorithm")
    table.add_column("PQ Vuln")
    table.add_column("Confidence")
    table.add_column("Channel")

    severity_colors = {
        "critical": "red bold",
        "high": "red",
        "medium": "yellow",
        "low": "blue",
        "info": "dim",
    }

    for f in findings:
        sev_style = severity_colors.get(f.severity.value, "")
        pq = "⚠️ YES" if f.pq_vulnerable else "✅ No"
        table.add_row(
            f.id,
            f.category.value,
            f"[{sev_style}]{f.severity.value.upper()}[/{sev_style}]",
            f.algorithm,
            pq,
            f"{f.confidence:.1%}",
            f.detection_channel.value,
        )

    console.print(table)


if __name__ == "__main__":
    main()
