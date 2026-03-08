"""
``bytetrace sections`` command.

Displays the section header table of a binary in a readable table.
"""

from __future__ import annotations

import click

from bytetrace.cli.options import binary_argument, json_option, explain_option, quiet_option
from bytetrace.formats import open_binary


# ── Section-name explanations ─────────────────────────────────────

_SECTION_NOTES: dict[str, str] = {
    ".text":    "Executable code.",
    ".data":    "Initialised global/static variables.",
    ".bss":     "Zero-initialised globals. Takes no space in the file.",
    ".rodata":  "Read-only data (string literals, constants).",
    ".plt":     "Procedure Linkage Table — stubs for dynamic calls.",
    ".got":     "Global Offset Table — holds resolved addresses for dynamic symbols.",
    ".got.plt": "GOT entries for PLT stubs.",
    ".symtab":  "Static symbol table (stripped in production binaries).",
    ".dynsym":  "Dynamic symbol table (imported/exported symbols).",
    ".strtab":  "String table for .symtab names.",
    ".dynstr":  "String table for .dynsym names.",
    ".dynamic": "Dynamic linking information (RPATH, needed libs, etc.).",
    ".rela.plt":"Relocation entries for PLT (lazy-binding).",
    ".rela.dyn":"Relocation entries applied at load time.",
    ".init":    "Initialisation code run before main().",
    ".fini":    "Finalisation code run after main() returns.",
    ".debug_info": "DWARF debug information.",
    ".eh_frame": "Exception handling / stack-unwinding data.",
}


# ── Command ───────────────────────────────────────────────────────

@click.command("sections")
@binary_argument
@json_option
@explain_option
@quiet_option
@click.pass_context
def sections(
    ctx:     click.Context,
    binary:  str,
    as_json: bool,
    explain: bool,
    quiet:   bool,
) -> None:
    """List sections from the binary's section header table."""
    no_color: bool = (ctx.obj or {}).get("no_color", False)

    try:
        b = open_binary(binary)
    except (ValueError, FileNotFoundError) as exc:
        raise click.ClickException(str(exc))

    if as_json:
        import json
        click.echo(json.dumps([s.to_dict() for s in b.sections], indent=2))
        return

    _render_sections(b, no_color, explain, quiet)


# ── Renderer ──────────────────────────────────────────────────────

def _render_sections(b, no_color: bool, explain: bool, quiet: bool) -> None:
    try:
        from rich.console import Console
        from rich.table import Table
        from rich import box
    except ImportError:
        _render_plain(b)
        return

    console = Console(no_color=no_color)

    if not quiet:
        console.print(f"\n[bold cyan]Sections[/bold cyan]  [dim]{b.name}[/dim]  "
                      f"[dim]({len(b.sections)} sections)[/dim]\n")

    table = Table(box=box.SIMPLE_HEAD, show_edge=False, padding=(0, 1))
    table.add_column("#",       style="dim",    justify="right", min_width=3)
    table.add_column("Name",    style="cyan",   min_width=16)
    table.add_column("Offset",  style="yellow", justify="right")
    table.add_column("VAddr",   style="yellow", justify="right")
    table.add_column("Size",    justify="right")
    table.add_column("Flags",   style="magenta", min_width=5)
    table.add_column("Align",   justify="right", style="dim")
    if explain:
        table.add_column("Note", style="dim italic", max_width=50)

    for i, sec in enumerate(b.sections):
        note = _SECTION_NOTES.get(sec.name, "") if explain else ""
        size_str = _fmt_size(sec.size)
        row = [
            str(i),
            sec.name,
            f"0x{sec.offset:08x}",
            f"0x{sec.vaddr:016x}" if b.bits == 64 else f"0x{sec.vaddr:08x}",
            size_str,
            sec.flags_str(),
            f"2^{sec.align.bit_length()-1}" if sec.align > 1 else str(sec.align),
        ]
        if explain:
            row.append(note)
        table.add_row(*row)

    console.print(table)


def _render_plain(b) -> None:
    header = f"{'#':<4} {'Name':<20} {'Offset':>10} {'VAddr':>18} {'Size':>10} {'Flags':<6}"
    click.echo(header)
    click.echo("-" * len(header))
    for i, sec in enumerate(b.sections):
        click.echo(
            f"{i:<4} {sec.name:<20} "
            f"0x{sec.offset:08x} "
            f"0x{sec.vaddr:016x} "
            f"{sec.size:>10} "
            f"{sec.flags_str():<6}"
        )


def _fmt_size(n: int) -> str:
    if n == 0:
        return "0"
    for unit in ("B", "K", "M", "G"):
        if n < 1024:
            return f"{n}{unit}"
        n //= 1024
    return f"{n}T"
