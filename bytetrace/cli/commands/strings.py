"""
``bytetrace strings`` command.

Scans the binary for sequences of printable ASCII / UTF-8 characters,
similar to the UNIX ``strings`` utility — but section-aware and integrated
with ByteTrace's output pipeline.
"""

from __future__ import annotations

import re

import click

from bytetrace.cli.options import binary_argument, json_option, quiet_option
from bytetrace.formats import open_binary


# Regex: sequence of printable ASCII (0x20-0x7e) of at least min_len chars
_ASCII_PAT = re.compile(rb"[ -~]{%d,}")


# ── Command ───────────────────────────────────────────────────────

@click.command("strings")
@binary_argument
@json_option
@quiet_option
@click.option(
    "--min-len", "-n",
    default=4,
    show_default=True,
    metavar="N",
    help="Minimum string length to report.",
)
@click.option(
    "--section", "-s",
    default="",
    metavar="NAME",
    help="Limit search to a specific section (e.g. .rodata).",
)
@click.option(
    "--offset",
    default=False,
    is_flag=True,
    help="Show file offset alongside each string.",
)
@click.pass_context
def strings(
    ctx:      click.Context,
    binary:   str,
    as_json:  bool,
    quiet:    bool,
    min_len:  int,
    section:  str,
    offset:   bool,
) -> None:
    """Extract printable strings from a binary (like the strings utility)."""
    no_color: bool = (ctx.obj or {}).get("no_color", False)

    try:
        b = open_binary(binary)
    except (ValueError, FileNotFoundError) as exc:
        raise click.ClickException(str(exc))

    # Decide which bytes to search
    if section:
        sec = b.section_by_name(section)
        if sec is None:
            raise click.ClickException(
                f"Section {section!r} not found. "
                "Use `bytetrace sections` to list available sections."
            )
        data        = b.raw[sec.offset : sec.offset + sec.size]
        base_offset = sec.offset
        scope_label = section
    else:
        data        = b.raw
        base_offset = 0
        scope_label = "entire file"

    # Extract
    pattern = re.compile(rb"[ -~]{%d,}" % min_len)
    results = [
        {"offset": base_offset + m.start(), "string": m.group().decode("ascii")}
        for m in pattern.finditer(data)
    ]

    if as_json:
        import json
        click.echo(json.dumps(results, indent=2))
        return

    _render_strings(b, results, scope_label, no_color, quiet, offset)


# ── Renderer ──────────────────────────────────────────────────────

def _render_strings(b, results, scope_label, no_color, quiet, show_offset):
    try:
        from rich.console import Console
        from rich.table import Table
        from rich import box
    except ImportError:
        for r in results:
            pfx = f"0x{r['offset']:08x}  " if show_offset else ""
            click.echo(pfx + r["string"])
        return

    console = Console(no_color=no_color)

    if not quiet:
        console.print(
            f"\n[bold cyan]Strings[/bold cyan]  [dim]{b.name}[/dim]  "
            f"[dim]{scope_label}[/dim]  "
            f"[dim]({len(results)} found)[/dim]\n"
        )

    if not results:
        console.print("[dim]  No strings found.[/dim]")
        return

    if show_offset:
        table = Table(box=box.SIMPLE_HEAD, show_edge=False, padding=(0, 1))
        table.add_column("Offset", style="yellow", justify="right")
        table.add_column("String")
        for r in results:
            table.add_row(f"0x{r['offset']:08x}", r["string"])
        console.print(table)
    else:
        for r in results:
            console.print(r["string"])
