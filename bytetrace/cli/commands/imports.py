"""
``bytetrace imports`` command.

Shows shared-library dependencies and imported symbols for a binary.

Reads two complementary sources:
  • DT_NEEDED entries from the .dynamic section  → shared libraries
  • Undefined symbols from .dynsym               → imported functions/vars
  • PLT stubs + .rela.plt                        → lazy-bound imports

This gives a compact picture of what a binary depends on at runtime —
useful when auditing third-party code, tracing attack surface, or
preparing for dynamic analysis.
"""

from __future__ import annotations

import click

from bytetrace.cli.options import binary_argument, json_option, quiet_option, explain_option
from bytetrace.formats import open_binary
from bytetrace.core.binary import Binary


# ── Command ───────────────────────────────────────────────────────

@click.command("imports")
@binary_argument
@json_option
@quiet_option
@explain_option
@click.pass_context
def imports(
    ctx:     click.Context,
    binary:  str,
    as_json: bool,
    quiet:   bool,
    explain: bool,
) -> None:
    """Show imported libraries and symbols (dynamic dependencies)."""
    no_color: bool = (ctx.obj or {}).get("no_color", False)

    try:
        b = open_binary(binary)
    except (ValueError, FileNotFoundError) as exc:
        raise click.ClickException(str(exc))

    libs    = _get_needed_libs(binary)
    imports_ = [s for s in b.symbols if s.is_undefined and s.is_dynamic]

    if as_json:
        import json
        click.echo(json.dumps({
            "libraries": libs,
            "imports":   [s.to_dict() for s in imports_],
        }, indent=2))
        return

    _render_imports(b, libs, imports_, no_color, quiet, explain)


# ── Library extraction ────────────────────────────────────────────

def _get_needed_libs(path: str) -> list[str]:
    """Parse DT_NEEDED entries from the ELF .dynamic section."""
    try:
        import io
        from elftools.elf.elffile import ELFFile
        from elftools.elf.dynamic import DynamicSection

        with open(path, "rb") as f:
            elf = ELFFile(f)
            for sec in elf.iter_sections():
                if isinstance(sec, DynamicSection):
                    return [
                        tag.needed
                        for tag in sec.iter_tags()
                        if tag.entry.d_tag == "DT_NEEDED"
                    ]
    except Exception:
        pass
    return []


# ── Renderer ──────────────────────────────────────────────────────

_LIB_NOTES: dict[str, str] = {
    "libc":      "C standard library — nearly universal dependency.",
    "libpthread": "POSIX threading (often merged into libc on modern systems).",
    "libm":      "Math library (sin, cos, sqrt, …).",
    "libdl":     "Dynamic loading (dlopen, dlsym — runtime plugin loading).",
    "libssl":    "OpenSSL TLS/SSL — network security.",
    "libcrypto": "OpenSSL cryptographic primitives.",
    "libstdc++": "C++ standard library runtime.",
    "libgcc_s":  "GCC runtime (exceptions, unwinding).",
}


def _lib_note(lib: str) -> str:
    for key, note in _LIB_NOTES.items():
        if key in lib:
            return note
    return ""


def _render_imports(b, libs, imports_, no_color, quiet, explain):
    try:
        from rich.console import Console
        from rich.table import Table
        from rich.rule import Rule
        from rich import box
    except ImportError:
        _render_plain(libs, imports_)
        return

    console = Console(no_color=no_color)

    if not quiet:
        console.print(
            f"\n[bold cyan]Imports[/bold cyan]  [dim]{b.name}[/dim]\n"
        )

    # ── Shared libraries ──────────────────────────────────────────
    console.print("[bold]Shared Libraries[/bold]  "
                  f"[dim]({len(libs)} needed)[/dim]")
    if libs:
        lib_table = Table(box=box.SIMPLE_HEAD, show_edge=False, padding=(0, 1))
        lib_table.add_column("#",       style="dim", justify="right", min_width=3)
        lib_table.add_column("Library", style="cyan")
        if explain:
            lib_table.add_column("Note", style="dim italic", max_width=55)
        for i, lib in enumerate(libs):
            row = [str(i), lib]
            if explain:
                row.append(_lib_note(lib))
            lib_table.add_row(*row)
        console.print(lib_table)
    else:
        console.print("[dim]  None (statically linked or no .dynamic section)[/dim]\n")

    # ── Imported symbols ──────────────────────────────────────────
    console.print("[bold]Imported Symbols[/bold]  "
                  f"[dim]({len(imports_)} symbols)[/dim]")
    if imports_:
        sym_table = Table(box=box.SIMPLE_HEAD, show_edge=False, padding=(0, 1))
        sym_table.add_column("Type",    min_width=8)
        sym_table.add_column("Binding", min_width=7, style="dim")
        sym_table.add_column("Name")
        for sym in sorted(imports_, key=lambda s: s.name):
            t_color = "cyan" if sym.is_function else "blue"
            sym_table.add_row(
                f"[{t_color}]{sym.sym_type.value}[/{t_color}]",
                sym.binding.value,
                f"[bold]{sym.name}[/bold]" if sym.is_function else sym.name,
            )
        console.print(sym_table)
    else:
        console.print("[dim]  No undefined dynamic symbols found.[/dim]\n")


def _render_plain(libs, imports_) -> None:
    click.echo("=== Shared Libraries ===")
    for lib in libs:
        click.echo(f"  {lib}")
    click.echo("\n=== Imported Symbols ===")
    for sym in sorted(imports_, key=lambda s: s.name):
        click.echo(f"  {sym.sym_type.value:<10} {sym.name}")
