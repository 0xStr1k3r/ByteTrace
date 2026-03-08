"""
``bytetrace symbols`` command.

Lists symbols from the binary with optional search and type filtering.
Uses RapidFuzz for fuzzy name search when --search is given.
"""

from __future__ import annotations

import click

from bytetrace.cli.options import binary_argument, json_option, explain_option, quiet_option
from bytetrace.formats import open_binary
from bytetrace.core.enums import SymbolType


# ── Command ───────────────────────────────────────────────────────

@click.command("symbols")
@binary_argument
@json_option
@explain_option
@quiet_option
@click.option(
    "--search", "-s",
    default="",
    metavar="QUERY",
    help="Fuzzy-search symbol names (case-insensitive).",
)
@click.option(
    "--type", "sym_type",
    default="",
    metavar="TYPE",
    type=click.Choice(
        ["function", "object", "tls", "notype", "file", "section"],
        case_sensitive=False,
    ),
    help="Filter by symbol type.",
)
@click.option(
    "--dynamic/--no-dynamic",
    "dynamic_only",
    default=False,
    help="Show only dynamic (.dynsym) symbols.",
)
@click.option(
    "--limit", "-n",
    default=0,
    metavar="N",
    help="Limit output to the first N symbols (0 = unlimited).",
)
@click.pass_context
def symbols(
    ctx:         click.Context,
    binary:      str,
    as_json:     bool,
    explain:     bool,
    quiet:       bool,
    search:      str,
    sym_type:    str,
    dynamic_only: bool,
    limit:       int,
) -> None:
    """List symbols — functions, globals, imports, and exports."""
    no_color: bool = (ctx.obj or {}).get("no_color", False)

    try:
        b = open_binary(binary)
    except (ValueError, FileNotFoundError) as exc:
        raise click.ClickException(str(exc))

    syms = list(b.symbols)

    # Apply filters
    if dynamic_only:
        syms = [s for s in syms if s.is_dynamic]

    if sym_type:
        target = SymbolType(sym_type)
        syms = [s for s in syms if s.sym_type == target]

    if search:
        syms = _fuzzy_search(syms, search)

    if limit > 0:
        syms = syms[:limit]

    if as_json:
        import json
        click.echo(json.dumps([s.to_dict() for s in syms], indent=2))
        return

    _render_symbols(b, syms, no_color, explain, quiet, search)


# ── Fuzzy search ──────────────────────────────────────────────────

def _fuzzy_search(syms, query: str):
    try:
        from rapidfuzz import process, fuzz
        results = process.extract(
            query,
            [s.name for s in syms],
            scorer=fuzz.partial_ratio,
            limit=None,
            score_cutoff=60,
        )
        matched_names = {r[0] for r in results}
        return [s for s in syms if s.name in matched_names]
    except ImportError:
        # Fallback: simple substring match
        q = query.lower()
        return [s for s in syms if q in s.name.lower()]


# ── Renderer ──────────────────────────────────────────────────────

_TYPE_COLORS: dict[str, str] = {
    "function": "cyan",
    "object":   "blue",
    "tls":      "magenta",
    "file":     "dim",
    "section":  "dim",
    "notype":   "white",
    "unknown":  "dim",
}

_BIND_COLORS: dict[str, str] = {
    "global": "green",
    "local":  "dim",
    "weak":   "yellow",
    "unknown": "dim",
}


def _render_symbols(b, syms, no_color: bool, explain: bool, quiet: bool, search: str) -> None:
    try:
        from rich.console import Console
        from rich.table import Table
        from rich import box
    except ImportError:
        _render_plain(syms)
        return

    console = Console(no_color=no_color)

    if not quiet:
        title = f"[bold cyan]Symbols[/bold cyan]  [dim]{b.name}[/dim]"
        if search:
            title += f"  [yellow]search: {search!r}[/yellow]"
        title += f"  [dim]({len(syms)} shown / {len(b.symbols)} total)[/dim]"
        console.print(f"\n{title}\n")

    if not syms:
        console.print("[dim]  No symbols match the given filters.[/dim]\n")
        return

    table = Table(box=box.SIMPLE_HEAD, show_edge=False, padding=(0, 1))
    table.add_column("Address",  style="yellow",  justify="right")
    table.add_column("Size",     justify="right",  style="dim")
    table.add_column("Type",     min_width=8)
    table.add_column("Bind",     min_width=6)
    table.add_column("Dyn", justify="center")
    table.add_column("Section",  style="dim")
    table.add_column("Name")

    for sym in syms:
        t_color = _TYPE_COLORS.get(sym.sym_type.value, "white")
        b_color = _BIND_COLORS.get(sym.binding.value, "dim")
        addr_str = f"0x{sym.address:016x}" if sym.address else "[dim]undef[/dim]"
        size_str = str(sym.size) if sym.size else "-"
        dyn_str  = "[green]●[/green]" if sym.is_dynamic else ""

        table.add_row(
            addr_str,
            size_str,
            f"[{t_color}]{sym.sym_type.value}[/{t_color}]",
            f"[{b_color}]{sym.binding.value}[/{b_color}]",
            dyn_str,
            sym.section or "-",
            f"[bold]{sym.name}[/bold]" if sym.is_function else sym.name,
        )

    console.print(table)


def _render_plain(syms) -> None:
    header = f"{'Address':>18} {'Size':>8} {'Type':<10} {'Bind':<8} {'Name'}"
    click.echo(header)
    click.echo("-" * len(header))
    for sym in syms:
        addr = f"0x{sym.address:016x}" if sym.address else "undef"
        click.echo(
            f"{addr:>18} {sym.size:>8} {sym.sym_type.value:<10} "
            f"{sym.binding.value:<8} {sym.name}"
        )
