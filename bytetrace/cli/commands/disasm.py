"""
``bytetrace disasm`` command.

Disassembles a function or address range using the Capstone engine.
Accepts a symbol name (fuzzy-matched) or a raw virtual address.
"""

from __future__ import annotations

import click

from bytetrace.cli.options import binary_argument, json_option, explain_option, quiet_option
from bytetrace.formats import open_binary
from bytetrace.core.binary import Binary
from bytetrace.core.enums import Architecture, Endianness


# ── Capstone architecture map ─────────────────────────────────────

def _get_cs_arch(arch: Architecture, bits: int, endian: Endianness):
    """Return (cs_arch, cs_mode) tuple for the given binary parameters."""
    import capstone as cs

    arch_map = {
        Architecture.X86:    (cs.CS_ARCH_X86, cs.CS_MODE_32),
        Architecture.X86_64: (cs.CS_ARCH_X86, cs.CS_MODE_64),
        Architecture.ARM:    (
            cs.CS_ARCH_ARM,
            cs.CS_MODE_ARM | (cs.CS_MODE_BIG_ENDIAN if endian == Endianness.BIG else cs.CS_MODE_LITTLE_ENDIAN),
        ),
        Architecture.ARM64:  (cs.CS_ARCH_ARM64, cs.CS_MODE_ARM),
        Architecture.MIPS:   (
            cs.CS_ARCH_MIPS,
            (cs.CS_MODE_MIPS64 if bits == 64 else cs.CS_MODE_MIPS32) |
            (cs.CS_MODE_BIG_ENDIAN if endian == Endianness.BIG else cs.CS_MODE_LITTLE_ENDIAN),
        ),
        Architecture.PPC:    (
            cs.CS_ARCH_PPC,
            cs.CS_MODE_64 if bits == 64 else cs.CS_MODE_32,
        ),
    }

    if arch not in arch_map:
        raise click.ClickException(
            f"Disassembly not supported for architecture: {arch.value}"
        )
    return arch_map[arch]


# ── Command ───────────────────────────────────────────────────────

@click.command("disasm")
@binary_argument
@json_option
@explain_option
@quiet_option
@click.option(
    "--func", "-f",
    default="",
    metavar="NAME",
    help="Symbol name to disassemble (fuzzy-matched).",
)
@click.option(
    "--addr", "-a",
    default="",
    metavar="ADDR",
    help="Virtual address to start disassembly (hex or decimal).",
)
@click.option(
    "--count", "-n",
    default=50,
    show_default=True,
    metavar="N",
    help="Maximum number of instructions to disassemble.",
)
@click.pass_context
def disasm(
    ctx:     click.Context,
    binary:  str,
    as_json: bool,
    explain: bool,
    quiet:   bool,
    func:    str,
    addr:    str,
    count:   int,
) -> None:
    """Disassemble a function or address range."""
    if not func and not addr:
        raise click.UsageError("Provide --func NAME or --addr ADDRESS.")

    no_color: bool = (ctx.obj or {}).get("no_color", False)

    try:
        b = open_binary(binary)
    except (ValueError, FileNotFoundError) as exc:
        raise click.ClickException(str(exc))

    # Resolve start address and byte size
    start_vaddr, byte_size, label = _resolve_target(b, func, addr)

    # Read bytes from the binary
    try:
        code = b.read_at_vaddr(start_vaddr, byte_size)
    except ValueError as exc:
        raise click.ClickException(str(exc))

    # Disassemble
    insns = _disassemble(b, code, start_vaddr, count)

    if as_json:
        import json
        out = {
            "label":   label,
            "address": start_vaddr,
            "insns":   insns,
        }
        click.echo(json.dumps(out, indent=2))
        return

    _render_disasm(insns, label, start_vaddr, no_color, quiet)


# ── Target resolution ─────────────────────────────────────────────

def _resolve_target(b: Binary, func: str, addr: str) -> tuple[int, int, str]:
    """Return (start_vaddr, byte_size, label)."""
    if func:
        # Try exact match first, then fuzzy
        sym = b.symbol_by_name(func)
        if sym is None:
            results = b.symbols_search(func)
            func_results = [s for s in results if s.is_function]
            candidates = func_results or results
            if not candidates:
                raise click.ClickException(
                    f"No symbol found matching {func!r}. "
                    "Use `bytetrace symbols --search <name>` to explore."
                )
            sym = candidates[0]

        if sym.address == 0:
            raise click.ClickException(
                f"Symbol {sym.name!r} has no address (it's an import resolved at runtime)."
            )

        size = sym.size if sym.size else 256
        return sym.address, size, sym.name

    # Raw address mode
    try:
        start = int(addr, 0)
    except ValueError:
        raise click.ClickException(f"Invalid address: {addr!r}. Use hex (0x…) or decimal.")

    # Try to find a symbol at this address for a nice label
    sym = b.symbol_at_address(start)
    label = sym.name if sym else f"0x{start:x}"
    return start, 256, label


# ── Disassembler ──────────────────────────────────────────────────

def _disassemble(b: Binary, code: bytes, start_vaddr: int, count: int) -> list[dict]:
    try:
        import capstone as cs
    except ImportError:
        raise click.ClickException(
            "capstone is not installed. Run: pip install capstone"
        )

    cs_arch, cs_mode = _get_cs_arch(b.arch, b.bits, b.endian)
    md = cs.Cs(cs_arch, cs_mode)
    md.detail = False

    insns = []
    for insn in md.disasm(code, start_vaddr):
        insns.append({
            "address": insn.address,
            "mnemonic": insn.mnemonic,
            "op_str":  insn.op_str,
            "bytes":   insn.bytes.hex(),
        })
        if len(insns) >= count:
            break

    return insns


# ── Renderer ──────────────────────────────────────────────────────

# Common mnemonics that deserve visual distinction
_CALL_INSNS  = {"call", "bl", "blx", "blr", "jal", "jalr"}
_JUMP_INSNS  = {"jmp", "je", "jne", "jz", "jnz", "jl", "jle", "jg", "jge",
                "jb", "jbe", "ja", "jae", "js", "jns", "jo", "jno",
                "b", "beq", "bne", "blt", "bge", "bgt", "ble",
                "br"}
_RET_INSNS   = {"ret", "retn", "retq", "iret", "iretd", "iretq", "bx lr"}
_INT_INSNS   = {"int", "syscall", "svc", "ecall"}


def _mnemonic_style(mnem: str) -> str:
    m = mnem.lower().split()[0]
    if m in _RET_INSNS:
        return "bold red"
    if m in _CALL_INSNS:
        return "bold green"
    if m in _JUMP_INSNS:
        return "yellow"
    if m in _INT_INSNS:
        return "bold magenta"
    return "white"


def _render_disasm(insns: list[dict], label: str, start: int, no_color: bool, quiet: bool) -> None:
    try:
        from rich.console import Console
        from rich.text import Text
        from rich.table import Table
        from rich import box
    except ImportError:
        _render_plain(insns, label)
        return

    console = Console(no_color=no_color)

    if not quiet:
        console.print(f"\n[bold cyan]disasm[/bold cyan]  "
                      f"[bold]{label}[/bold]  "
                      f"[dim]@ 0x{start:x}[/dim]  "
                      f"[dim]({len(insns)} insns)[/dim]\n")

    if not insns:
        console.print("[dim]  No instructions disassembled.[/dim]")
        return

    table = Table(box=None, show_header=False, padding=(0, 2, 0, 0), show_edge=False)
    table.add_column("addr",    style="dim yellow", justify="right")
    table.add_column("bytes",   style="dim")
    table.add_column("mnem",    min_width=8)
    table.add_column("operands")

    for insn in insns:
        style = _mnemonic_style(insn["mnemonic"])
        # Format bytes in groups
        byte_str = " ".join(
            insn["bytes"][i:i+2] for i in range(0, len(insn["bytes"]), 2)
        )
        table.add_row(
            f"0x{insn['address']:x}",
            byte_str,
            f"[{style}]{insn['mnemonic']}[/{style}]",
            insn["op_str"],
        )

    console.print(table)


def _render_plain(insns: list[dict], label: str) -> None:
    click.echo(f"\n{label}:")
    for insn in insns:
        click.echo(f"  0x{insn['address']:x}  {insn['mnemonic']:<10} {insn['op_str']}")
