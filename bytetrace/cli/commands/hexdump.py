"""
``bytetrace hexdump`` command.

Renders a classic hex + ASCII dump for a section or a raw byte range.
Useful for inspecting data sections, finding embedded payloads, or
following disassembly results into raw bytes.
"""

from __future__ import annotations

import click

from bytetrace.cli.options import binary_argument, json_option, quiet_option
from bytetrace.formats import open_binary


# ── Command ───────────────────────────────────────────────────────

@click.command("hexdump")
@binary_argument
@json_option
@quiet_option
@click.option(
    "--section", "-s",
    default="",
    metavar="NAME",
    help="Section to dump (e.g. .rodata, .text).",
)
@click.option(
    "--offset", "-o",
    default="",
    metavar="OFFSET",
    help="File offset to start from (hex 0x… or decimal).",
)
@click.option(
    "--size", "-z",
    default=256,
    show_default=True,
    metavar="BYTES",
    help="Number of bytes to dump (used with --offset).",
)
@click.option(
    "--width", "-w",
    default=16,
    show_default=True,
    metavar="N",
    help="Bytes per line.",
)
@click.pass_context
def hexdump(
    ctx:     click.Context,
    binary:  str,
    as_json: bool,
    quiet:   bool,
    section: str,
    offset:  str,
    size:    int,
    width:   int,
) -> None:
    """Hex + ASCII dump of a section or byte range."""
    if not section and not offset:
        raise click.UsageError("Provide --section NAME or --offset OFFSET.")

    no_color: bool = (ctx.obj or {}).get("no_color", False)

    try:
        b = open_binary(binary)
    except (ValueError, FileNotFoundError) as exc:
        raise click.ClickException(str(exc))

    # Resolve source bytes
    if section:
        sec = b.section_by_name(section)
        if sec is None:
            raise click.ClickException(
                f"Section {section!r} not found. "
                "Use `bytetrace sections` to list sections."
            )
        data        = b.raw[sec.offset : sec.offset + sec.size]
        base_offset = sec.offset
        label       = section
    else:
        try:
            start = int(offset, 0)
        except ValueError:
            raise click.ClickException(f"Invalid offset: {offset!r}.")
        data        = b.raw[start : start + size]
        base_offset = start
        label       = f"0x{start:x} ({size} bytes)"

    if not data:
        raise click.ClickException("No data found at the specified location.")

    if as_json:
        import json
        rows = _build_rows(data, base_offset, width)
        click.echo(json.dumps(rows, indent=2))
        return

    _render_hexdump(b, data, base_offset, width, label, no_color, quiet)


# ── Core ──────────────────────────────────────────────────────────

def _build_rows(data: bytes, base: int, width: int) -> list[dict]:
    rows = []
    for i in range(0, len(data), width):
        chunk = data[i : i + width]
        rows.append({
            "offset": base + i,
            "hex":    " ".join(f"{b:02x}" for b in chunk),
            "ascii":  "".join(chr(b) if 0x20 <= b <= 0x7e else "." for b in chunk),
        })
    return rows


# ── Renderer ──────────────────────────────────────────────────────

def _render_hexdump(b, data, base, width, label, no_color, quiet):
    try:
        from rich.console import Console
        from rich.text import Text
    except ImportError:
        _render_plain(data, base, width)
        return

    console = Console(no_color=no_color)

    if not quiet:
        console.print(
            f"\n[bold cyan]Hexdump[/bold cyan]  [dim]{b.name}[/dim]  "
            f"[bold]{label}[/bold]  "
            f"[dim]({len(data)} bytes)[/dim]\n"
        )

    for i in range(0, len(data), width):
        chunk = data[i : i + width]

        # Offset
        line = Text()
        line.append(f"  {base + i:08x}  ", style="yellow dim")

        # Hex bytes — highlight non-zero
        hex_parts = []
        for j, byte in enumerate(chunk):
            if j == width // 2:
                hex_parts.append(" ")
            color = "white" if byte else "dim"
            hex_parts.append(f"[{color}]{byte:02x}[/{color}] ")
        # Pad if last row is short
        pad = width - len(chunk)
        hex_parts.extend(["   "] * pad)
        if pad > width // 2:
            hex_parts.insert(width // 2 - (pad - width // 2), " ")
        line.append_text(Text.from_markup("".join(hex_parts)))

        # ASCII
        line.append(" │ ", style="dim")
        for byte in chunk:
            if 0x20 <= byte <= 0x7e:
                line.append(chr(byte), style="green")
            else:
                line.append(".", style="dim")

        console.print(line)

    console.print()


def _render_plain(data: bytes, base: int, width: int) -> None:
    for i in range(0, len(data), width):
        chunk = data[i : i + width]
        hex_part   = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 0x20 <= b <= 0x7e else "." for b in chunk)
        click.echo(f"{base + i:08x}  {hex_part:<{width * 3}}  {ascii_part}")
