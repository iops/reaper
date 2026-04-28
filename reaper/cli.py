"""
REAPER CLI — Command-line interface for the scanner engine.

Usage:
    reaper scan <path> [--framework <fw>] [--output <format>] [--out-file <path>]
    reaper probe <endpoint> [--transport <type>] [--output <format>]
    reaper list-checks
    reaper validate-check <check_file>
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

import click

from reaper import __version__
from reaper.adapters.base import FrameworkAdapter
from reaper.adapters.mcp_generic import McpGenericAdapter
from reaper.adapters.openclaw import OpenClawAdapter
from reaper.engine import ScannerEngine
from reaper.report import json_report, sarif

logger = logging.getLogger("reaper")

ADAPTERS: dict[str, FrameworkAdapter] = {
    "openclaw": OpenClawAdapter(),
    "mcp_generic": McpGenericAdapter(),
}


@click.group()
@click.version_option(__version__, prog_name="reaper")
@click.option("--verbose", "-v", is_flag=True, help="Enable debug logging.")
def cli(verbose: bool) -> None:
    """REAPER — AI Agent Vulnerability Scanner."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(levelname)s %(name)s: %(message)s",
    )


@cli.command()
@click.argument("path", type=click.Path(exists=True))
@click.option(
    "--framework", "-f",
    type=click.Choice(list(ADAPTERS.keys()) + ["auto"]),
    default="auto",
    help="Framework adapter to use (default: auto-detect).",
)
@click.option(
    "--output", "-o",
    type=click.Choice(["json", "sarif"]),
    default="json",
    help="Output format.",
)
@click.option(
    "--out-file",
    type=click.Path(),
    default=None,
    help="Write output to file instead of stdout.",
)
@click.option(
    "--checks-dir",
    type=click.Path(),
    default="checks",
    help="Directory containing check modules.",
)
def scan(
    path: str,
    framework: str,
    output: str,
    out_file: str | None,
    checks_dir: str,
) -> None:
    """Scan an agent deployment for vulnerabilities."""
    engine = ScannerEngine(checks_dir)
    loaded = engine.load_checks()
    if loaded == 0:
        click.echo("No checks loaded. Nothing to scan.", err=True)
        sys.exit(1)

    click.echo(f"Loaded {loaded} checks", err=True)

    # Determine which adapters to use
    if framework == "auto":
        adapters_to_use = list(ADAPTERS.values())
    else:
        adapters_to_use = [ADAPTERS[framework]]

    # Discover and scan
    all_results = []
    for adapter in adapters_to_use:
        agents = adapter.discover_agents(path)
        if agents:
            click.echo(
                f"[{adapter.framework_id}] Found {len(agents)} agent(s)", err=True
            )
        for agent in agents:
            target = adapter.build_target(agent)
            result = engine.scan(target)
            all_results.append(result)
            finding_count = len(result.findings)
            label = "finding" if finding_count == 1 else "findings"
            click.echo(
                f"  {agent.get('name', '?')}: {finding_count} {label} "
                f"({result.duration_ms:.0f}ms)",
                err=True,
            )

    if not all_results:
        click.echo("No agents discovered. Check the target path.", err=True)
        sys.exit(1)

    # Generate report
    if output == "sarif":
        report = sarif.generate(all_results)
    else:
        report = json_report.generate(all_results)

    if out_file:
        Path(out_file).write_text(report)
        click.echo(f"Report written to {out_file}", err=True)
    else:
        click.echo(report)


@cli.command()
@click.argument("endpoint")
@click.option(
    "--transport", "-t",
    type=click.Choice(["stdio", "sse"]),
    default="stdio",
    help="MCP transport type.",
)
@click.option(
    "--server-name",
    default="",
    help="Human-readable name for the MCP server.",
)
@click.option(
    "--output", "-o",
    type=click.Choice(["json", "sarif"]),
    default="json",
    help="Output format.",
)
@click.option(
    "--out-file",
    type=click.Path(),
    default=None,
    help="Write output to file instead of stdout.",
)
@click.option(
    "--checks-dir",
    type=click.Path(),
    default="checks",
    help="Directory containing check modules.",
)
def probe(
    endpoint: str,
    transport: str,
    server_name: str,
    output: str,
    out_file: str | None,
    checks_dir: str,
) -> None:
    """Probe an MCP server endpoint for infrastructure vulnerabilities (Wedge 2)."""
    from reaper.sdk import ProbeTarget

    engine = ScannerEngine(checks_dir)
    loaded = engine.load_checks()
    wedge2_count = sum(1 for c in engine.checks if c.wedge == 2)

    if wedge2_count == 0:
        click.echo("No Wedge 2 (probe) checks loaded.", err=True)
        sys.exit(1)

    click.echo(f"Loaded {loaded} checks ({wedge2_count} probe checks)", err=True)

    target = ProbeTarget(
        endpoint=endpoint,
        transport=transport,
        server_name=server_name or endpoint,
        metadata={"framework": "mcp_generic"},
    )

    result = engine.probe_scan([target])

    finding_count = len(result.findings)
    label = "finding" if finding_count == 1 else "findings"
    click.echo(
        f"Probed {target.server_name}: {finding_count} {label} "
        f"({result.duration_ms:.0f}ms, {result.probes_executed} probes)",
        err=True,
    )

    if output == "sarif":
        report = sarif.generate([result])
    else:
        report = json_report.generate([result])

    if out_file:
        Path(out_file).write_text(report)
        click.echo(f"Report written to {out_file}", err=True)
    else:
        click.echo(report)


@cli.command("list-checks")
@click.option(
    "--checks-dir",
    type=click.Path(),
    default="checks",
    help="Directory containing check modules.",
)
def list_checks(checks_dir: str) -> None:
    """List all loaded detection checks."""
    engine = ScannerEngine(checks_dir)
    engine.load_checks()

    if not engine.checks:
        click.echo("No checks loaded.")
        return

    click.echo(f"{'ID':<20} {'Tier':<10} {'Severity':<10} {'Name'}")
    click.echo("-" * 72)
    for check in engine.checks:
        sev = check.severity.default if check.severity else "?"
        click.echo(f"{check.check_id:<20} {check.tier:<10} {sev:<10} {check.name}")


@cli.command("validate-check")
@click.argument("check_file", type=click.Path(exists=True))
def validate_check(check_file: str) -> None:
    """Validate a single check module against the contract."""
    loader = __import__("reaper.engine", fromlist=["CheckLoader"]).CheckLoader(
        Path(check_file).parent
    )
    check = loader._load_module(Path(check_file))
    if check is None:
        click.echo("FAIL: Check did not load or failed validation.", err=True)
        sys.exit(1)
    click.echo(f"OK: {check.check_id} — {check.name}")


def main() -> None:
    cli()


if __name__ == "__main__":
    main()
