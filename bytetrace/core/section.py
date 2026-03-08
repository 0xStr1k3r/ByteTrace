"""
Section model.

A Section represents one named region of a binary (e.g. ``.text``,
``.data``, ``.rodata``).  The ELF parser populates these from the
section header table; future PE / Mach-O parsers will do the same.

Design rules
────────────
• No CLI, no rendering, no I/O — pure data.
• All fields are immutable after construction (frozen=True).
• ``flags`` is a frozenset so it supports ``SectionFlags.EXEC in s.flags``.
• ``description`` is intentionally *not* parsed here — the explain
  module is responsible for attaching human-readable meaning.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from bytetrace.core.enums import SectionFlags


@dataclass(frozen=True)
class Section:
    """
    A single named region within a binary image.

    Attributes
    ──────────
    name        Section name as it appears in the binary (e.g. ".text").
    offset      File offset (bytes from start of file).
    vaddr       Virtual address at which the section is loaded.
    size        Size of the section in bytes.
    flags       Zero or more SectionFlags values.
    align       Required alignment in bytes (power of two, or 0 if unknown).
    link        Section index of a linked section (ELF sh_link), or -1.
    entsize     Size of fixed-size entries within the section, or 0.
    """

    name:    str
    offset:  int
    vaddr:   int
    size:    int
    flags:   frozenset[SectionFlags] = field(default_factory=frozenset)
    align:   int = 0
    link:    int = -1
    entsize: int = 0

    # ── Convenience helpers ───────────────────────────────────────

    @property
    def is_executable(self) -> bool:
        return SectionFlags.EXEC in self.flags

    @property
    def is_writable(self) -> bool:
        return SectionFlags.WRITE in self.flags

    @property
    def is_allocated(self) -> bool:
        """True when the section occupies memory at runtime."""
        return SectionFlags.ALLOC in self.flags

    @property
    def is_empty(self) -> bool:
        return self.size == 0

    @property
    def end_offset(self) -> int:
        """Exclusive file-offset end of this section."""
        return self.offset + self.size

    @property
    def end_vaddr(self) -> int:
        """Exclusive virtual-address end of this section."""
        return self.vaddr + self.size

    def contains_offset(self, offset: int) -> bool:
        """Return True if *offset* falls within this section's file range."""
        return self.offset <= offset < self.end_offset

    def contains_vaddr(self, addr: int) -> bool:
        """Return True if *addr* falls within this section's virtual range."""
        return self.vaddr <= addr < self.end_vaddr

    def flags_str(self) -> str:
        """
        Compact human-readable flag string (e.g. ``"AX"``) in the
        style of readelf.
        """
        letter_map = {
            SectionFlags.ALLOC:  "A",
            SectionFlags.EXEC:   "X",
            SectionFlags.WRITE:  "W",
            SectionFlags.MERGE:  "M",
            SectionFlags.STRINGS:"S",
            SectionFlags.TLS:    "T",
        }
        return "".join(v for k, v in letter_map.items() if k in self.flags) or "-"

    def to_dict(self) -> dict:
        """Serialise to a plain dict suitable for JSON output."""
        return {
            "name":    self.name,
            "offset":  self.offset,
            "vaddr":   self.vaddr,
            "size":    self.size,
            "flags":   sorted(f.value for f in self.flags),
            "align":   self.align,
            "entsize": self.entsize,
        }

    def __repr__(self) -> str:
        return (
            f"Section(name={self.name!r}, "
            f"vaddr=0x{self.vaddr:x}, "
            f"size={self.size}, "
            f"flags={self.flags_str()!r})"
        )
