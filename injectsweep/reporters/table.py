"""Human-readable table reporter using rich (falls back to plain text)."""

from __future__ import annotations

import io

from ..models import ScanReport, Severity

_SEV_STYLE = {
    "critical": "bold white on red",
    "high": "bold red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim",
}


def render(report: ScanReport) -> str:
    try:
        from rich.console import Console
        from rich.table import Table
        from rich.text import Text
    except Exception:  # pragma: no cover - rich always installed, but be safe
        return _render_plain(report)

    buf = io.StringIO()
    console = Console(file=buf, width=120, force_terminal=False)

    total = len(report.findings)
    scanned = len(report.results)
    if total == 0:
        console.print(f"[green]injectsweep: no injection indicators in {scanned} file(s).[/green]")
        return buf.getvalue()

    for result in report.results:
        if not result.findings:
            continue
        table = Table(title=f"{result.path}  ({result.format})", title_justify="left",
                      show_lines=False, expand=False)
        table.add_column("Severity", no_wrap=True)
        table.add_column("Rule", no_wrap=True)
        table.add_column("Layer", no_wrap=True)
        table.add_column("Where", no_wrap=True)
        table.add_column("Finding", overflow="fold")
        for f in sorted(result.findings, key=lambda x: -x.severity):
            sev = f.severity.label
            table.add_row(
                Text(sev.upper(), style=_SEV_STYLE.get(sev, "")),
                f"{f.rule_id} {f.name}",
                f.layer,
                f.location or "-",
                Text(f.message),  # Text() renders literally (no rich markup parsing)
            )
        console.print(table)

    summary = report.to_dict()["summary"]
    console.print(
        f"\n[bold]Summary:[/bold] {summary['total_findings']} finding(s) across "
        f"{summary['files_with_findings']}/{summary['files_scanned']} file(s); "
        f"max severity = [{_SEV_STYLE.get(summary['max_severity'], '')}]"
        f"{summary['max_severity'].upper()}[/]"
    )
    return buf.getvalue()


def _render_plain(report: ScanReport) -> str:  # pragma: no cover
    lines = []
    for result in report.results:
        for f in result.findings:
            lines.append(f"[{f.severity.label.upper()}] {result.path} {f.rule_id} "
                         f"({f.layer}) {f.message}")
    if not lines:
        return f"injectsweep: no injection indicators in {len(report.results)} file(s)."
    return "\n".join(lines)
