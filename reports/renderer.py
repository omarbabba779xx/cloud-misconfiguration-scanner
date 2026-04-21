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
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Cloud Misconfiguration Report</title>
  <style>
    *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ font-family: system-ui, -apple-system, sans-serif; background: #f1f5f9; color: #1e293b; padding: 2rem; }}
    h1 {{ font-size: 1.6rem; font-weight: 700; }}
    .meta {{ color: #64748b; font-size: 0.85rem; margin: 0.3rem 0 1.5rem; }}

    /* ── Summary cards ── */
    .summary {{ display: flex; gap: 1rem; flex-wrap: wrap; margin-bottom: 1.5rem; }}
    .stat {{
      padding: 0.6rem 1.1rem; border-radius: 8px; font-weight: 700;
      color: #fff; cursor: pointer; user-select: none;
      transition: opacity .15s, transform .1s;
    }}
    .stat:hover {{ opacity: .85; transform: translateY(-1px); }}
    .stat.inactive {{ opacity: .35; }}

    /* ── Controls bar ── */
    .controls {{
      display: flex; gap: 0.75rem; flex-wrap: wrap;
      margin-bottom: 1rem; align-items: center;
    }}
    .search-wrap {{ position: relative; flex: 1; min-width: 200px; }}
    .search-wrap svg {{
      position: absolute; left: 10px; top: 50%;
      transform: translateY(-50%); color: #94a3b8; pointer-events: none;
    }}
    #searchInput {{
      width: 100%; padding: 0.5rem 0.75rem 0.5rem 2.2rem;
      border: 1px solid #cbd5e1; border-radius: 8px;
      font-size: 0.85rem; background: #fff; outline: none;
      transition: border-color .15s;
    }}
    #searchInput:focus {{ border-color: #6366f1; }}
    select {{
      padding: 0.5rem 0.75rem; border: 1px solid #cbd5e1;
      border-radius: 8px; font-size: 0.85rem; background: #fff;
      cursor: pointer; outline: none;
    }}
    select:focus {{ border-color: #6366f1; }}
    #clearBtn {{
      padding: 0.5rem 1rem; border: none; border-radius: 8px;
      background: #e2e8f0; font-size: 0.85rem; cursor: pointer;
      font-weight: 600; transition: background .15s;
    }}
    #clearBtn:hover {{ background: #cbd5e1; }}
    #resultCount {{ font-size: 0.82rem; color: #64748b; white-space: nowrap; }}

    /* ── Table ── */
    .table-wrap {{
      background: #fff; border-radius: 10px;
      box-shadow: 0 1px 4px rgba(0,0,0,.08); overflow: hidden;
    }}
    table {{ border-collapse: collapse; width: 100%; }}
    thead {{ position: sticky; top: 0; z-index: 2; }}
    th {{
      background: #1e293b; color: #fff; padding: 0.65rem 0.9rem;
      text-align: left; font-size: 0.78rem; white-space: nowrap;
      cursor: pointer; user-select: none;
    }}
    th:hover {{ background: #334155; }}
    th .sort-icon {{ margin-left: 4px; opacity: .5; font-style: normal; }}
    th.asc  .sort-icon::after {{ content: " ▲"; opacity: 1; }}
    th.desc .sort-icon::after {{ content: " ▼"; opacity: 1; }}
    th:not(.asc):not(.desc) .sort-icon::after {{ content: " ⇅"; }}
    td {{
      padding: 0.55rem 0.9rem; font-size: 0.82rem;
      border-bottom: 1px solid #e2e8f0; vertical-align: top;
    }}
    tbody tr:hover td {{ background: #f8fafc; }}
    tbody tr:last-child td {{ border-bottom: none; }}
    .hidden {{ display: none !important; }}

    .badge {{
      display: inline-block; padding: 2px 9px; border-radius: 4px;
      color: #fff; font-size: 0.72rem; font-weight: 700; white-space: nowrap;
    }}
    .mono {{ font-family: ui-monospace, monospace; font-size: 0.76rem; word-break: break-all; }}
    .empty-msg {{
      text-align: center; padding: 3rem; color: #94a3b8; font-size: 0.9rem;
    }}
  </style>
</head>
<body>
  <h1>Cloud Misconfiguration Report</h1>
  <p class="meta">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} &mdash; {len(findings_sorted)} total finding(s)</p>

  <!-- Severity filter cards -->
  <div class="summary">
    <div class="stat" style="background:#dc2626" data-sev="CRITICAL" onclick="toggleSev(this)">CRITICAL &nbsp;{counts['CRITICAL']}</div>
    <div class="stat" style="background:#ea580c" data-sev="HIGH"     onclick="toggleSev(this)">HIGH &nbsp;{counts['HIGH']}</div>
    <div class="stat" style="background:#d97706" data-sev="MEDIUM"   onclick="toggleSev(this)">MEDIUM &nbsp;{counts['MEDIUM']}</div>
    <div class="stat" style="background:#0891b2" data-sev="LOW"      onclick="toggleSev(this)">LOW &nbsp;{counts['LOW']}</div>
    <div class="stat" style="background:#6b7280" data-sev="INFO"     onclick="toggleSev(this)">INFO &nbsp;{counts['INFO']}</div>
  </div>

  <!-- Search + filter controls -->
  <div class="controls">
    <div class="search-wrap">
      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>
      </svg>
      <input id="searchInput" type="text" placeholder="Search findings…" oninput="applyFilters()"/>
    </div>
    <select id="providerFilter" onchange="applyFilters()">
      <option value="">All Providers</option>
      <option>AWS</option><option>AZURE</option><option>GCP</option>
    </select>
    <select id="categoryFilter" onchange="applyFilters()">
      <option value="">All Categories</option>
      <option>Public Storage</option>
      <option>IAM Permissions</option>
      <option>Logging &amp; Monitoring</option>
      <option>MFA / Authentication</option>
      <option>Network Exposure</option>
    </select>
    <button id="clearBtn" onclick="clearFilters()">Clear</button>
    <span id="resultCount"></span>
  </div>

  <!-- Findings table -->
  <div class="table-wrap">
    <table id="findingsTable">
      <thead>
        <tr>
          <th onclick="sortTable(0)">Severity<i class="sort-icon"></i></th>
          <th onclick="sortTable(1)">Provider<i class="sort-icon"></i></th>
          <th onclick="sortTable(2)">Category<i class="sort-icon"></i></th>
          <th onclick="sortTable(3)">Resource Type<i class="sort-icon"></i></th>
          <th onclick="sortTable(4)">Resource ID<i class="sort-icon"></i></th>
          <th onclick="sortTable(5)">Finding<i class="sort-icon"></i></th>
          <th>Recommendation</th>
        </tr>
      </thead>
      <tbody>{rows}</tbody>
    </table>
    <div class="empty-msg hidden" id="emptyMsg">No findings match your filters.</div>
  </div>

<script>
  // ── Severity sort order ────────────────────────────────────────────────────
  const SEV_RANK = {{CRITICAL:0, HIGH:1, MEDIUM:2, LOW:3, INFO:4}};

  // ── State ──────────────────────────────────────────────────────────────────
  let activeSevs  = new Set();   // empty = show all
  let sortCol     = -1;
  let sortAsc     = true;

  // ── Severity card toggle ───────────────────────────────────────────────────
  function toggleSev(el) {{
    const sev = el.dataset.sev;
    if (activeSevs.has(sev)) {{ activeSevs.delete(sev); el.classList.remove('inactive'); }}
    else                      {{ activeSevs.add(sev);    el.classList.add('inactive');   }}
    // If all are toggled off → reset to show-all
    if (activeSevs.size === document.querySelectorAll('.stat').length) {{
      activeSevs.clear();
      document.querySelectorAll('.stat').forEach(s => s.classList.remove('inactive'));
    }}
    applyFilters();
  }}

  // ── Master filter function ─────────────────────────────────────────────────
  function applyFilters() {{
    const query    = document.getElementById('searchInput').value.toLowerCase();
    const provider = document.getElementById('providerFilter').value.toUpperCase();
    const category = document.getElementById('categoryFilter').value.toLowerCase();
    const rows     = document.querySelectorAll('#findingsTable tbody tr');
    let visible    = 0;

    rows.forEach(row => {{
      const cells = row.querySelectorAll('td');
      const sev   = cells[0].textContent.trim();
      const prov  = cells[1].textContent.trim().toUpperCase();
      const cat   = cells[2].textContent.trim().toLowerCase();
      const text  = row.textContent.toLowerCase();

      const okSev  = activeSevs.size === 0 || !activeSevs.has(sev);
      const okProv = !provider || prov === provider;
      const okCat  = !category || cat.includes(category);
      const okText = !query    || text.includes(query);

      const show = okSev && okProv && okCat && okText;
      row.classList.toggle('hidden', !show);
      if (show) visible++;
    }});

    document.getElementById('resultCount').textContent =
      `${{visible}} of ${{rows.length}} finding(s)`;
    document.getElementById('emptyMsg').classList.toggle('hidden', visible > 0);
  }}

  // ── Clear all filters ──────────────────────────────────────────────────────
  function clearFilters() {{
    document.getElementById('searchInput').value       = '';
    document.getElementById('providerFilter').value    = '';
    document.getElementById('categoryFilter').value    = '';
    activeSevs.clear();
    document.querySelectorAll('.stat').forEach(s => s.classList.remove('inactive'));
    applyFilters();
  }}

  // ── Column sort ────────────────────────────────────────────────────────────
  function sortTable(col) {{
    const tbody = document.querySelector('#findingsTable tbody');
    const rows  = Array.from(tbody.querySelectorAll('tr'));

    if (sortCol === col) {{ sortAsc = !sortAsc; }}
    else                  {{ sortCol = col; sortAsc = true; }}

    rows.sort((a, b) => {{
      const aVal = a.querySelectorAll('td')[col].textContent.trim();
      const bVal = b.querySelectorAll('td')[col].textContent.trim();

      // Severity column: sort by rank instead of alphabet
      if (col === 0) {{
        const r = (SEV_RANK[aVal] ?? 99) - (SEV_RANK[bVal] ?? 99);
        return sortAsc ? r : -r;
      }}
      const r = aVal.localeCompare(bVal);
      return sortAsc ? r : -r;
    }});

    rows.forEach(r => tbody.appendChild(r));

    // Update header icons
    document.querySelectorAll('th').forEach((th, i) => {{
      th.classList.remove('asc', 'desc');
      if (i === col) th.classList.add(sortAsc ? 'asc' : 'desc');
    }});
  }}

  // ── Init ───────────────────────────────────────────────────────────────────
  applyFilters();
</script>
</body>
</html>"""

    Path(path).write_text(html, encoding="utf-8")
    print(f"HTML report saved to: {path}")
