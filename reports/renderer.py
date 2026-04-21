import json
from datetime import datetime
from pathlib import Path
from scanner.base import Finding, Severity

_SEVERITY_COLOR = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}

_SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


def print_console(findings: list[Finding]) -> None:
    from rich.console import Console
    from rich.table import Table
    from rich import box

    console = Console()
    findings = sorted(findings, key=lambda f: _SEVERITY_ORDER[f.severity])

    counts = {s: 0 for s in Severity}
    for f in findings:
        counts[f.severity] += 1

    console.print()
    console.print("[bold]Cloud Misconfiguration Scanner[/bold]", justify="center")
    console.print(f"Scan completed at [dim]{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/dim]", justify="center")
    console.print()

    # Summary bar
    summary = Table.grid(padding=(0, 2))
    summary.add_row(
        f"[bold red]CRITICAL: {counts[Severity.CRITICAL]}[/bold red]",
        f"[red]HIGH: {counts[Severity.HIGH]}[/red]",
        f"[yellow]MEDIUM: {counts[Severity.MEDIUM]}[/yellow]",
        f"[cyan]LOW: {counts[Severity.LOW]}[/cyan]",
        f"[dim]INFO: {counts[Severity.INFO]}[/dim]",
        f"Total: {len(findings)}",
    )
    console.print(summary)
    console.print()

    if not findings:
        console.print("[green]No misconfigurations detected.[/green]")
        return

    table = Table(
        box=box.ROUNDED,
        show_lines=True,
        highlight=True,
        title="Findings",
    )
    table.add_column("Severity", width=10, no_wrap=True)
    table.add_column("Provider", width=8)
    table.add_column("Category", width=22)
    table.add_column("Resource", width=30, overflow="fold")
    table.add_column("Title", overflow="fold")

    for f in findings:
        color = _SEVERITY_COLOR[f.severity]
        table.add_row(
            f"[{color}]{f.severity.value}[/{color}]",
            f.provider.upper(),
            f.category.value,
            f.resource_id,
            f.title,
        )

    console.print(table)
    console.print()


def save_json(findings: list[Finding], path: str) -> None:
    out = {
        "scan_time": datetime.now().isoformat(),
        "total": len(findings),
        "findings": [f.to_dict() for f in findings],
    }
    Path(path).write_text(json.dumps(out, indent=2, default=str), encoding="utf-8")
    print(f"JSON report saved to: {path}")


def save_html(findings: list[Finding], path: str) -> None:
    findings_sorted = sorted(findings, key=lambda f: _SEVERITY_ORDER[f.severity])
    counts = {s.value: 0 for s in Severity}
    for f in findings_sorted:
        counts[f.severity.value] += 1

    _BADGE = {
        "CRITICAL": "#dc2626",
        "HIGH": "#ea580c",
        "MEDIUM": "#d97706",
        "LOW": "#0891b2",
        "INFO": "#6b7280",
    }

    rows = ""
    for f in findings_sorted:
        color = _BADGE.get(f.severity.value, "#6b7280")
        rows += f"""
        <tr>
          <td><span class="badge" style="background:{color}">{f.severity.value}</span></td>
          <td>{f.provider.upper()}</td>
          <td>{f.category.value}</td>
          <td class="mono">{f.resource_type}</td>
          <td class="mono">{f.resource_id}</td>
          <td>{f.title}</td>
          <td>{f.recommendation}</td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <title>Cloud Misconfiguration Report</title>
  <style>
    body {{ font-family: system-ui, sans-serif; margin: 2rem; background: #f8fafc; color: #1e293b; }}
    h1 {{ font-size: 1.6rem; margin-bottom: 0.25rem; }}
    .meta {{ color: #64748b; font-size: 0.85rem; margin-bottom: 1.5rem; }}
    .summary {{ display: flex; gap: 1.5rem; margin-bottom: 1.5rem; flex-wrap: wrap; }}
    .stat {{ padding: 0.75rem 1.25rem; border-radius: 8px; font-weight: 600; color: #fff; }}
    table {{ border-collapse: collapse; width: 100%; background: #fff; border-radius: 8px; overflow: hidden;
             box-shadow: 0 1px 3px rgba(0,0,0,.1); }}
    th {{ background: #1e293b; color: #fff; padding: 0.6rem 0.8rem; text-align: left; font-size: 0.8rem; }}
    td {{ padding: 0.55rem 0.8rem; font-size: 0.82rem; border-bottom: 1px solid #e2e8f0; vertical-align: top; }}
    tr:hover td {{ background: #f1f5f9; }}
    .badge {{ padding: 2px 8px; border-radius: 4px; color: #fff; font-size: 0.75rem; font-weight: 700;
               white-space: nowrap; }}
    .mono {{ font-family: monospace; font-size: 0.78rem; }}
  </style>
</head>
<body>
  <h1>Cloud Misconfiguration Report</h1>
  <p class="meta">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} &mdash; {len(findings)} finding(s)</p>
  <div class="summary">
    <div class="stat" style="background:#dc2626">CRITICAL: {counts['CRITICAL']}</div>
    <div class="stat" style="background:#ea580c">HIGH: {counts['HIGH']}</div>
    <div class="stat" style="background:#d97706">MEDIUM: {counts['MEDIUM']}</div>
    <div class="stat" style="background:#0891b2">LOW: {counts['LOW']}</div>
    <div class="stat" style="background:#6b7280">INFO: {counts['INFO']}</div>
  </div>
  <table>
    <thead>
      <tr>
        <th>Severity</th><th>Provider</th><th>Category</th><th>Resource Type</th>
        <th>Resource ID</th><th>Finding</th><th>Recommendation</th>
      </tr>
    </thead>
    <tbody>{rows}</tbody>
  </table>
</body>
</html>"""

    Path(path).write_text(html, encoding="utf-8")
    print(f"HTML report saved to: {path}")
