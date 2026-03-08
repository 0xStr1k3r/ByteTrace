"""
``bytetrace info`` command.

Prints a high-level overview of a binary:
  format, architecture, word-size, endianness, entry point,
  file size, interpreter, PIE status, and stripped status.
"""

from __future__ import annotations

import click
from pathlib import Path

from bytetrace.cli.options import binary_argument, json_option, explain_option, quiet_option
from bytetrace.formats import open_binary


# ── Section explanations ──────────────────────────────────────────

_EXPLANATIONS: dict[str, str] = {
    "format":      "The container format (ELF, PE, Mach-O). Determines how sections and symbols are laid out.",
    "arch":        "The CPU instruction-set. Determines which disassembler back-end is used.",
    "bits":        "Word size — 32-bit or 64-bit. Affects pointer sizes, calling conventions, and address space.",
    "endian":      "Byte order for multi-byte integers. x86/ARM are little-endian; some MIPS/SPARC are big-endian.",
    "entry_point": "The virtual address where execution begins (ELF e_entry). Used by the OS loader.",
    "interpreter": "Dynamic linker path embedded in PT_INTERP. Absent in statically-linked binaries.",
    "is_pie":      "Position-Independent Executable — the binary can be loaded at any base address (ASLR-friendly).",
    "is_stripped": "No symbol table found. Function names and variable names are unavailable for analysis.",
    "file_size":   "Total size of the binary file on disk.",
}


# ── Command ───────────────────────────────────────────────────────

@click.command("info")
@binary_argument
@json_option
@explain_option
@quiet_option
@click.pass_context
def info(
    ctx:     click.Context,
    binary:  str,
    as_json: bool,
    explain: bool,
    quiet:   bool,
) -> None:
    """Show an overview of a binary file."""
    no_color: bool = (ctx.obj or {}).get("no_color", False)

    try:
        b = open_binary(binary)
    except (ValueError, FileNotFoundError) as exc:
        raise click.ClickException(str(exc))

    data = b.to_dict()
    data["file_size"] = b.size_bytes

    if as_json:
        import json
        # Trim heavy lists for the info view
        data.pop("sections", None)
        data.pop("symbols", None)
        click.echo(json.dumps(data, indent=2))
        return

    _render_info(b, no_color, explain, quiet)


# ── Renderer ──────────────────────────────────────────────────────

def _render_info(b, no_color: bool, explain: bool, quiet: bool) -> None:
    try:
        from rich.console import Console
        from rich.table import Table
        from rich.text import Text
        from rich import box
    except ImportError:
        _render_plain(b)
        return

    console = Console(no_color=no_color)

    if not quiet:
        console.print(f"\n[bold cyan]◆ {b.name}[/bold cyan]  [dim]{b.path}[/dim]\n")

    table = Table(
        show_header=False,
        box=box.SIMPLE,
        padding=(0, 2, 0, 0),
        show_edge=False,
    )
    table.add_column("field", style="dim", min_width=14)
    table.add_column("value")
    if explain:
        table.add_column("note", style="dim italic", max_width=60)

    def _row(field: str, value: str, note_key: str = "") -> None:
        note = _EXPLANATIONS.get(note_key or field, "") if explain else ""
        table.add_row(field, value, note) if explain else table.add_row(field, value)

    _row("format",       b.fmt.value)
    _row("arch",         b.arch.value)
    _row("bits",         f"{b.bits}-bit")
    _row("endian",       b.endian.value)
    _row("entry point",  f"[yellow]0x{b.entry_point:016x}[/yellow]", "entry_point")
    _row("file size",    _fmt_size(b.size_bytes), "file_size")
    _row("sections",     str(len(b.sections)))
    _row("symbols",      str(len(b.symbols)))

    if b.interpreter:
        _row("interpreter", b.interpreter)

    pie_color   = "green" if b.is_pie   else "red"
    strip_color = "red"   if b.is_stripped else "green"
    _row("PIE",      f"[{pie_color}]{'yes' if b.is_pie else 'no'}[/{pie_color}]",           "is_pie")
    _row("stripped", f"[{strip_color}]{'yes' if b.is_stripped else 'no'}[/{strip_color}]",  "is_stripped")

    console.print(table)


def _render_plain(b) -> None:
    click.echo(f"file       {b.path}")
    click.echo(f"format     {b.fmt.value}")
    click.echo(f"arch       {b.arch.value}")
    click.echo(f"bits       {b.bits}")
    click.echo(f"endian     {b.endian.value}")
    click.echo(f"entry      0x{b.entry_point:x}")
    click.echo(f"size       {_fmt_size(b.size_bytes)}")
    click.echo(f"sections   {len(b.sections)}")
    click.echo(f"symbols    {len(b.symbols)}")
    if b.interpreter:
        click.echo(f"interp     {b.interpreter}")
    click.echo(f"PIE        {'yes' if b.is_pie else 'no'}")
    click.echo(f"stripped   {'yes' if b.is_stripped else 'no'}")


def _fmt_size(n: int) -> str:
    for unit in ("B", "KiB", "MiB", "GiB"):
        if n < 1024:
            return f"{n} {unit}"
        n //= 1024
    return f"{n} TiB"
