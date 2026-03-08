"""
Shared enumerations for the ByteTrace core model.

All format parsers, disassemblers, and analysis modules reference
these enums rather than raw strings — this makes comparison safe,
auto-complete friendly, and serialisation deterministic.
"""

from __future__ import annotations

from enum import Enum


class BinaryFormat(str, Enum):
    """Supported binary container formats."""
    ELF    = "ELF"
    PE     = "PE"
    MACHO  = "Mach-O"
    UNKNOWN = "Unknown"


class Architecture(str, Enum):
    """CPU instruction-set architectures."""
    X86      = "x86"
    X86_64   = "x86-64"
    ARM      = "ARM"
    ARM64    = "AArch64"
    MIPS     = "MIPS"
    RISCV    = "RISC-V"
    PPC      = "PowerPC"
    UNKNOWN  = "Unknown"


class Endianness(str, Enum):
    LITTLE  = "Little"
    BIG     = "Big"
    UNKNOWN = "Unknown"


class SectionFlags(str, Enum):
    """
    Canonical flag labels attached to sections.

    A section may carry several flags simultaneously; these are stored
    as a ``frozenset[SectionFlags]`` on the Section model.
    """
    ALLOC     = "alloc"    # loaded into memory at runtime
    EXEC      = "exec"     # contains executable instructions
    WRITE     = "write"    # writable at runtime
    MERGE     = "merge"    # mergeable duplicate data
    STRINGS   = "strings"  # null-terminated string data
    INFO      = "info"     # section holds SHT_INFO linkage
    LINK_ORDER = "link_order"
    TLS       = "tls"      # thread-local storage


class SymbolType(str, Enum):
    """ELF STT_* / PE symbol types, normalised."""
    FUNC    = "function"
    OBJECT  = "object"     # data variable
    SECTION = "section"    # section symbol
    FILE    = "file"       # source filename
    TLS     = "tls"        # thread-local storage
    NOTYPE  = "notype"     # unspecified
    UNKNOWN = "unknown"


class SymbolBinding(str, Enum):
    """ELF STB_* binding visibility."""
    LOCAL   = "local"
    GLOBAL  = "global"
    WEAK    = "weak"
    UNKNOWN = "unknown"
