"""
Binary model — the central data object of ByteTrace.

Every format parser produces a ``Binary``; every analysis module,
disassembler, and CLI command consumes one.  The class contains no
parsing, no rendering, and no I/O — it is a pure, immutable data
container that acts as the lingua franca between all layers.

Lifecycle
─────────
1.  A format parser (formats/elf.py, etc.) reads a file and produces a
    ``Binary`` via ``Binary.from_parser_data(…)``.
2.  CLI commands pass the ``Binary`` to analysis/rendering modules.
3.  Renderers call ``.to_dict()`` for JSON output or access fields
    directly for Rich terminal output.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from bytetrace.core.enums import Architecture, BinaryFormat, Endianness
from bytetrace.core.section import Section
from bytetrace.core.symbol import Symbol


@dataclass(frozen=True)
class Binary:
    """
    A fully-parsed binary image.

    Attributes
    ──────────
    path            Resolved path to the binary file on disk.
    fmt             Container format (ELF, PE, Mach-O, …).
    arch            CPU architecture.
    bits            Word size: 32 or 64.
    endian          Byte order.
    entry_point     Virtual address of the program entry point.
    sections        Ordered list of sections (from section header table).
    symbols         Combined symbol list (.symtab + .dynsym, deduplicated).
    raw             Raw bytes of the entire file.
    interpreter     ELF PT_INTERP path (e.g. /lib64/ld-linux-x86-64.so.2).
    is_pie          True when the binary is position-independent.
    is_stripped     True when no .symtab section / symbols are present.
    """

    path:        Path
    fmt:         BinaryFormat
    arch:        Architecture
    bits:        int                    # 32 | 64
    endian:      Endianness
    entry_point: int
    sections:    tuple[Section, ...]    # tuple keeps frozen invariant
    symbols:     tuple[Symbol, ...]
    raw:         bytes
    interpreter: str                    = ""
    is_pie:      bool                   = False
    is_stripped: bool                   = False

    # ── Factory ───────────────────────────────────────────────────

    @classmethod
    def create(
        cls,
        path:        Path,
        fmt:         BinaryFormat,
        arch:        Architecture,
        bits:        int,
        endian:      Endianness,
        entry_point: int,
        sections:    list[Section],
        symbols:     list[Symbol],
        raw:         bytes,
        interpreter: str  = "",
        is_pie:      bool = False,
    ) -> "Binary":
        """
        Preferred construction path used by format parsers.

        Converts the mutable lists from the parser into immutable tuples
        and derives ``is_stripped`` automatically.
        """
        sym_tuple = tuple(symbols)
        return cls(
            path        = path,
            fmt         = fmt,
            arch        = arch,
            bits        = bits,
            endian      = endian,
            entry_point = entry_point,
            sections    = tuple(sections),
            symbols     = sym_tuple,
            raw         = raw,
            interpreter = interpreter,
            is_pie      = is_pie,
            is_stripped = len(sym_tuple) == 0,
        )

    # ── Section helpers ───────────────────────────────────────────

    def section_by_name(self, name: str) -> Optional[Section]:
        """Return the first section whose name matches exactly, or None."""
        for s in self.sections:
            if s.name == name:
                return s
        return None

    def sections_at_vaddr(self, addr: int) -> list[Section]:
        """Return all sections whose virtual range contains *addr*."""
        return [s for s in self.sections if s.contains_vaddr(addr)]

    @property
    def executable_sections(self) -> list[Section]:
        return [s for s in self.sections if s.is_executable]

    @property
    def writable_sections(self) -> list[Section]:
        return [s for s in self.sections if s.is_writable]

    # ── Symbol helpers ────────────────────────────────────────────

    def symbol_by_name(self, name: str) -> Optional[Symbol]:
        """Case-sensitive exact match, or None."""
        for sym in self.symbols:
            if sym.name == name:
                return sym
        return None

    def symbol_at_address(self, addr: int) -> Optional[Symbol]:
        """Return the first symbol whose range contains *addr*, or None."""
        for sym in self.symbols:
            if sym.contains(addr):
                return sym
        return None

    def symbols_search(self, query: str) -> list[Symbol]:
        """
        Case-insensitive substring search across all symbol names.
        Returns symbols sorted by name length (shortest first) so the
        most specific match tends to appear first.
        """
        q = query.lower()
        matches = [s for s in self.symbols if q in s.name.lower()]
        return sorted(matches, key=lambda s: len(s.name))

    @property
    def functions(self) -> list[Symbol]:
        return [s for s in self.symbols if s.is_function]

    @property
    def dynamic_symbols(self) -> list[Symbol]:
        return [s for s in self.symbols if s.is_dynamic]

    @property
    def undefined_symbols(self) -> list[Symbol]:
        """Imported symbols resolved at load time (undefined addresses)."""
        return [s for s in self.symbols if s.is_undefined]

    # ── Raw byte access ───────────────────────────────────────────

    def read_at_offset(self, offset: int, size: int) -> bytes:
        """
        Read *size* bytes from the file at *offset*.
        Raises ``ValueError`` on out-of-range access.
        """
        if offset < 0 or offset + size > len(self.raw):
            raise ValueError(
                f"read_at_offset({offset:#x}, {size}) out of range "
                f"(file size {len(self.raw):#x})"
            )
        return self.raw[offset : offset + size]

    def read_at_vaddr(self, vaddr: int, size: int) -> bytes:
        """
        Translate *vaddr* to a file offset via section headers and read.
        Raises ``ValueError`` if the address is not in any section.
        """
        for sec in self.sections:
            if sec.contains_vaddr(vaddr):
                file_offset = sec.offset + (vaddr - sec.vaddr)
                return self.read_at_offset(file_offset, size)
        raise ValueError(
            f"Virtual address {vaddr:#x} is not mapped by any section."
        )

    # ── Serialisation ─────────────────────────────────────────────

    def to_dict(self) -> dict:
        """
        Serialise the Binary to a plain dict for JSON output.
        ``raw`` bytes are omitted — callers that need them can access
        the field directly.
        """
        return {
            "path":        str(self.path),
            "format":      self.fmt.value,
            "arch":        self.arch.value,
            "bits":        self.bits,
            "endian":      self.endian.value,
            "entry_point": self.entry_point,
            "interpreter": self.interpreter,
            "is_pie":      self.is_pie,
            "is_stripped": self.is_stripped,
            "sections":    [s.to_dict() for s in self.sections],
            "symbols":     [s.to_dict() for s in self.symbols],
        }

    # ── Display helpers ───────────────────────────────────────────

    @property
    def size_bytes(self) -> int:
        return len(self.raw)

    @property
    def name(self) -> str:
        """Filename without directory prefix."""
        return self.path.name

    def __repr__(self) -> str:
        return (
            f"Binary(name={self.name!r}, "
            f"fmt={self.fmt.value}, "
            f"arch={self.arch.value}, "
            f"bits={self.bits}, "
            f"sections={len(self.sections)}, "
            f"symbols={len(self.symbols)})"
        )
