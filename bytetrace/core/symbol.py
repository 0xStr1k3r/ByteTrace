"""
Symbol model.

A Symbol represents a named location in the binary — a function, a
global variable, an imported library call, etc.  ELF stores these in
``.symtab`` (static) and ``.dynsym`` (dynamic / exported).

Design rules
────────────
• No CLI, no rendering, no I/O — pure data.
• Frozen so symbols can be stored in sets / used as dict keys.
• ``is_undefined`` covers imported symbols (addr == 0, size == 0).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from bytetrace.core.enums import SymbolBinding, SymbolType


@dataclass(frozen=True)
class Symbol:
    """
    A named location within a binary image.

    Attributes
    ──────────
    name        Demangled symbol name (raw if demangling failed).
    address     Virtual address of the symbol, or 0 if undefined.
    size        Size in bytes, or 0 if unknown / not applicable.
    sym_type    Functional category (function, object, …).
    binding     Visibility / linkage (local, global, weak).
    section     Name of the containing section, or '' if absolute/undef.
    is_dynamic  True when sourced from .dynsym (imported/exported).
    """

    name:       str
    address:    int
    size:       int                = 0
    sym_type:   SymbolType         = SymbolType.NOTYPE
    binding:    SymbolBinding      = SymbolBinding.LOCAL
    section:    str                = ""
    is_dynamic: bool               = False

    # ── Convenience helpers ───────────────────────────────────────

    @property
    def is_function(self) -> bool:
        return self.sym_type == SymbolType.FUNC

    @property
    def is_object(self) -> bool:
        return self.sym_type == SymbolType.OBJECT

    @property
    def is_undefined(self) -> bool:
        """
        Undefined symbols have no address — they are resolved at
        load time by the dynamic linker (imports from shared libs).
        """
        return self.address == 0 and self.section == ""

    @property
    def is_global(self) -> bool:
        return self.binding == SymbolBinding.GLOBAL

    @property
    def is_local(self) -> bool:
        return self.binding == SymbolBinding.LOCAL

    @property
    def is_weak(self) -> bool:
        return self.binding == SymbolBinding.WEAK

    @property
    def end_address(self) -> int:
        """Exclusive end address, or ``address`` when size is unknown."""
        return self.address + self.size if self.size else self.address

    def contains(self, addr: int) -> bool:
        """Return True if *addr* falls within this symbol's range."""
        if not self.size:
            return self.address == addr
        return self.address <= addr < self.end_address

    def to_dict(self) -> dict:
        """Serialise to a plain dict suitable for JSON output."""
        return {
            "name":       self.name,
            "address":    self.address,
            "size":       self.size,
            "type":       self.sym_type.value,
            "binding":    self.binding.value,
            "section":    self.section,
            "is_dynamic": self.is_dynamic,
        }

    def __repr__(self) -> str:
        addr = f"0x{self.address:x}" if self.address else "undef"
        return (
            f"Symbol(name={self.name!r}, "
            f"addr={addr}, "
            f"type={self.sym_type.value}, "
            f"binding={self.binding.value})"
        )
