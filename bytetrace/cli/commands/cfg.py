"""
``bytetrace cfg`` command.

Builds and displays a control-flow graph for a function.
Uses Capstone for disassembly and NetworkX for graph construction.

The CFG is a directed graph where nodes are basic blocks (sequences of
instructions ending in a branch/return) and edges represent possible
control-flow transfers.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

import click

from bytetrace.cli.options import binary_argument, json_option, quiet_option
from bytetrace.formats import open_binary
from bytetrace.core.binary import Binary
from bytetrace.core.enums import Architecture, Endianness


# ── Basic block ───────────────────────────────────────────────────

@dataclass
class BasicBlock:
    start: int
    insns: list[dict] = field(default_factory=list)
    successors: list[int] = field(default_factory=list)

    @property
    def end(self) -> int:
        if not self.insns:
            return self.start
        last = self.insns[-1]
        return last["address"] + len(last["bytes"]) // 2

    @property
    def terminator(self) -> Optional[dict]:
        return self.insns[-1] if self.insns else None


# ── Jump/branch mnemonic sets ─────────────────────────────────────

_RET_MNEMS   = {"ret", "retn", "retq", "iret", "iretq"}
_UNCOND_JUMP = {"jmp", "b", "br", "j"}
_COND_JUMP   = {
    "je", "jne", "jz", "jnz", "jl", "jle", "jg", "jge",
    "jb", "jbe", "ja", "jae", "js", "jns", "jo", "jno",
    "beq", "bne", "blt", "bge", "bgt", "ble",
}
_CALL_MNEMS  = {"call", "bl", "blx", "blr", "jal", "jalr"}
_TERM_MNEMS  = _RET_MNEMS | _UNCOND_JUMP | _COND_JUMP


# ── Command ───────────────────────────────────────────────────────

@click.command("cfg")
@binary_argument
@json_option
@quiet_option
@click.option(
    "--func", "-f",
    default="",
    metavar="NAME",
    help="Function name to analyse (fuzzy-matched).",
)
@click.option(
    "--addr", "-a",
    default="",
    metavar="ADDR",
    help="Start virtual address (hex or decimal).",
)
@click.option(
    "--max-insns",
    default=500,
    show_default=True,
    metavar="N",
    help="Maximum instructions to analyse (safety cap).",
)
@click.pass_context
def cfg(
    ctx:       click.Context,
    binary:    str,
    as_json:   bool,
    quiet:     bool,
    func:      str,
    addr:      str,
    max_insns: int,
) -> None:
    """Build and display a control-flow graph for a function."""
    if not func and not addr:
        raise click.UsageError("Provide --func NAME or --addr ADDRESS.")

    no_color: bool = (ctx.obj or {}).get("no_color", False)

    try:
        b = open_binary(binary)
    except (ValueError, FileNotFoundError) as exc:
        raise click.ClickException(str(exc))

    start_vaddr, byte_size, label = _resolve_target(b, func, addr)

    try:
        code = b.read_at_vaddr(start_vaddr, byte_size)
    except ValueError as exc:
        raise click.ClickException(str(exc))

    insns = _disassemble_all(b, code, start_vaddr, max_insns)
    if not insns:
        raise click.ClickException("No instructions disassembled at the given address.")

    blocks = _build_cfg(insns, start_vaddr)

    try:
        import networkx as nx
        G = _to_networkx(blocks)
    except ImportError:
        G = None

    if as_json:
        import json
        out = {
            "label":   label,
            "address": start_vaddr,
            "blocks":  [_block_to_dict(bl) for bl in blocks.values()],
        }
        if G is not None:
            out["edges"] = [[u, v] for u, v in G.edges()]
        click.echo(json.dumps(out, indent=2))
        return

    _render_cfg(blocks, G, label, start_vaddr, no_color, quiet)


# ── Target resolution ─────────────────────────────────────────────

def _resolve_target(b: Binary, func: str, addr: str) -> tuple[int, int, str]:
    if func:
        sym = b.symbol_by_name(func)
        if sym is None:
            candidates = [s for s in b.symbols_search(func) if s.is_function]
            if not candidates:
                candidates = b.symbols_search(func)
            if not candidates:
                raise click.ClickException(
                    f"No symbol found matching {func!r}."
                )
            sym = candidates[0]
        if sym.address == 0:
            raise click.ClickException(
                f"Symbol {sym.name!r} is an undefined import."
            )
        size = sym.size if sym.size else 512
        return sym.address, size, sym.name

    try:
        start = int(addr, 0)
    except ValueError:
        raise click.ClickException(f"Invalid address: {addr!r}.")

    sym = b.symbol_at_address(start)
    label = sym.name if sym else f"0x{start:x}"
    return start, 512, label


# ── Disassembly ───────────────────────────────────────────────────

def _get_cs(b: Binary):
    try:
        import capstone as cs
    except ImportError:
        raise click.ClickException("capstone is not installed. Run: pip install capstone")

    from bytetrace.cli.commands.disasm import _get_cs_arch
    cs_arch, cs_mode = _get_cs_arch(b.arch, b.bits, b.endian)
    md = cs.Cs(cs_arch, cs_mode)
    md.detail = False
    return md


def _disassemble_all(b: Binary, code: bytes, start: int, max_insns: int) -> list[dict]:
    md = _get_cs(b)
    insns = []
    for insn in md.disasm(code, start):
        insns.append({
            "address":  insn.address,
            "mnemonic": insn.mnemonic,
            "op_str":   insn.op_str,
            "bytes":    insn.bytes.hex(),
        })
        if len(insns) >= max_insns:
            break
    return insns


# ── CFG builder ───────────────────────────────────────────────────

def _build_cfg(insns: list[dict], entry: int) -> dict[int, BasicBlock]:
    """
    Split the linear instruction list into basic blocks.

    A block ends when:
    - A branch/return/jump instruction is encountered (inclusive).
    - The *next* instruction is a branch target.
    """
    # Pass 1: collect all branch targets
    targets: set[int] = {entry}
    for insn in insns:
        mnem = insn["mnemonic"].lower().split()[0]
        if mnem in _TERM_MNEMS:
            op = insn["op_str"].strip()
            if op:
                try:
                    targets.add(int(op, 0))
                except ValueError:
                    pass
            # Instruction following a conditional branch is also a target
            if mnem in _COND_JUMP:
                # find next insn
                pass  # handled in pass 2

    # Pass 2: build blocks
    blocks: dict[int, BasicBlock] = {}
    current: Optional[BasicBlock] = None

    for i, insn in enumerate(insns):
        addr = insn["address"]

        # Start a new block at targets or the very first instruction
        if addr in targets or current is None:
            current = BasicBlock(start=addr)
            blocks[addr] = current

        current.insns.append(insn)

        mnem = insn["mnemonic"].lower().split()[0]
        if mnem in _TERM_MNEMS:
            # Record successors
            op = insn["op_str"].strip()
            if mnem in _COND_JUMP:
                # Conditional: two successors — taken + fall-through
                if op:
                    try:
                        current.successors.append(int(op, 0))
                    except ValueError:
                        pass
                # Fall-through is next instruction
                if i + 1 < len(insns):
                    ft = insns[i + 1]["address"]
                    current.successors.append(ft)
                    targets.add(ft)
            elif mnem in _UNCOND_JUMP:
                if op:
                    try:
                        current.successors.append(int(op, 0))
                    except ValueError:
                        pass
            elif mnem in _RET_MNEMS:
                pass  # no successors
            current = None  # force new block on next insn

    return blocks


# ── NetworkX graph ────────────────────────────────────────────────

def _to_networkx(blocks: dict[int, BasicBlock]):
    import networkx as nx
    G = nx.DiGraph()
    for addr, blk in blocks.items():
        G.add_node(addr, insns=len(blk.insns))
        for succ in blk.successors:
            G.add_edge(addr, succ)
    return G


# ── Serialisation ─────────────────────────────────────────────────

def _block_to_dict(blk: BasicBlock) -> dict:
    return {
        "start":      blk.start,
        "end":        blk.end,
        "insn_count": len(blk.insns),
        "successors": blk.successors,
        "insns":      blk.insns,
    }


# ── Renderer ──────────────────────────────────────────────────────

def _render_cfg(
    blocks: dict[int, BasicBlock],
    G,
    label: str,
    start: int,
    no_color: bool,
    quiet: bool,
) -> None:
    try:
        from rich.console import Console
        from rich.panel import Panel
        from rich.text import Text
        from rich.columns import Columns
        from rich import box
        from rich.table import Table
    except ImportError:
        _render_plain(blocks, label)
        return

    console = Console(no_color=no_color)

    if not quiet:
        n_blocks = len(blocks)
        n_edges  = sum(len(b.successors) for b in blocks.values())
        info = f"[dim]{n_blocks} blocks, {n_edges} edges[/dim]"
        if G is not None:
            try:
                import networkx as nx
                if nx.is_weakly_connected(G):
                    info += "  [dim]connected[/dim]"
            except Exception:
                pass
        console.print(
            f"\n[bold cyan]cfg[/bold cyan]  [bold]{label}[/bold]  "
            f"[dim]@ 0x{start:x}[/dim]  {info}\n"
        )

    # Print each block as a panel
    for blk_addr in sorted(blocks):
        blk = blocks[blk_addr]
        lines = Text()
        for insn in blk.insns:
            lines.append(f"  0x{insn['address']:x}  ", style="dim yellow")
            mnem = insn["mnemonic"]
            m = mnem.lower().split()[0]
            if m in _RET_MNEMS:
                lines.append(f"{mnem:<10}", style="bold red")
            elif m in _CALL_MNEMS:
                lines.append(f"{mnem:<10}", style="bold green")
            elif m in _COND_JUMP | _UNCOND_JUMP:
                lines.append(f"{mnem:<10}", style="yellow")
            else:
                lines.append(f"{mnem:<10}")
            lines.append(f" {insn['op_str']}\n", style="")

        succ_str = (
            "  → " + "  ".join(f"[cyan]0x{s:x}[/cyan]" for s in blk.successors)
            if blk.successors else "  [dim]↩ return[/dim]"
        )

        console.print(
            Panel(
                lines,
                title=f"[yellow]0x{blk_addr:x}[/yellow]  [dim]({len(blk.insns)} insns)[/dim]",
                subtitle=succ_str,
                border_style="dim",
                expand=False,
            )
        )


def _render_plain(blocks: dict[int, BasicBlock], label: str) -> None:
    click.echo(f"\nCFG: {label}")
    click.echo("=" * 60)
    for blk_addr in sorted(blocks):
        blk = blocks[blk_addr]
        click.echo(f"\n[block @ 0x{blk_addr:x}]")
        for insn in blk.insns:
            click.echo(f"  0x{insn['address']:x}  {insn['mnemonic']:<10} {insn['op_str']}")
        if blk.successors:
            click.echo(f"  -> {', '.join(f'0x{s:x}' for s in blk.successors)}")
        else:
            click.echo("  -> (return)")
