"""
ELF parser — produces a :class:`~bytetrace.core.binary.Binary` from an ELF file.

Uses *pyelftools* for low-level ELF structure access and normalises everything
into the architecture-neutral ``Binary`` / ``Section`` / ``Symbol`` models.

Supported
─────────
• ELF32 and ELF64
• Little-endian and big-endian
• Architectures: x86, x86-64, ARM, AArch64, MIPS, RISC-V, PowerPC
• Section header table → Section objects
• .symtab + .dynsym → Symbol objects (deduplicated, unnamed entries stripped)
• PT_INTERP segment → interpreter string
• PT_DYNAMIC + DT_FLAGS_1 DF_1_PIE → is_pie detection (plus e_type fallback)
"""

from __future__ import annotations

import sys
from pathlib import Path

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from elftools.elf.dynamic import DynamicSection
from elftools.common.exceptions import ELFError

from bytetrace.core.binary import Binary
from bytetrace.core.enums import (
    Architecture,
    BinaryFormat,
    Endianness,
    SectionFlags,
    SymbolBinding,
    SymbolType,
)
from bytetrace.core.section import Section
from bytetrace.core.symbol import Symbol


# ── Architecture mapping ──────────────────────────────────────────

_ARCH_MAP: dict[str, Architecture] = {
    "EM_386":     Architecture.X86,
    "EM_X86_64":  Architecture.X86_64,
    "EM_ARM":     Architecture.ARM,
    "EM_AARCH64": Architecture.ARM64,
    "EM_MIPS":    Architecture.MIPS,
    "EM_RISCV":   Architecture.RISCV,
    "EM_PPC":     Architecture.PPC,
    "EM_PPC64":   Architecture.PPC,
}

# ── Symbol-type mapping ───────────────────────────────────────────

_SYM_TYPE_MAP: dict[str, SymbolType] = {
    "STT_FUNC":    SymbolType.FUNC,
    "STT_OBJECT":  SymbolType.OBJECT,
    "STT_SECTION": SymbolType.SECTION,
    "STT_FILE":    SymbolType.FILE,
    "STT_TLS":     SymbolType.TLS,
    "STT_NOTYPE":  SymbolType.NOTYPE,
}

_SYM_BIND_MAP: dict[str, SymbolBinding] = {
    "STB_LOCAL":  SymbolBinding.LOCAL,
    "STB_GLOBAL": SymbolBinding.GLOBAL,
    "STB_WEAK":   SymbolBinding.WEAK,
}

# ── Section-flag mapping ──────────────────────────────────────────

_FLAG_BIT_MAP: list[tuple[int, SectionFlags]] = [
    (0x2,   SectionFlags.ALLOC),
    (0x4,   SectionFlags.EXEC),
    (0x1,   SectionFlags.WRITE),
    (0x10,  SectionFlags.MERGE),
    (0x20,  SectionFlags.STRINGS),
    (0x80,  SectionFlags.INFO),
    (0x100, SectionFlags.LINK_ORDER),
    (0x400, SectionFlags.TLS),
]


# ── Public entry point ────────────────────────────────────────────

def parse_elf(path: Path) -> Binary:
    """
    Parse the ELF file at *path* and return a populated :class:`Binary`.

    Raises
    ------
    ValueError
        On malformed ELF data.
    """
    raw = path.read_bytes()

    try:
        import io
        elf = ELFFile(io.BytesIO(raw))
    except ELFError as exc:
        raise ValueError(f"{path.name}: ELF parse error — {exc}") from exc

    arch      = _map_arch(elf)
    bits      = elf.elfclass          # 32 or 64
    endian    = Endianness.LITTLE if elf.little_endian else Endianness.BIG
    entry     = elf.header.e_entry

    sections  = _parse_sections(elf)
    symbols   = _parse_symbols(elf)
    interp    = _get_interpreter(elf)
    is_pie    = _detect_pie(elf)

    return Binary.create(
        path        = path,
        fmt         = BinaryFormat.ELF,
        arch        = arch,
        bits        = bits,
        endian      = endian,
        entry_point = entry,
        sections    = sections,
        symbols     = symbols,
        raw         = raw,
        interpreter = interp,
        is_pie      = is_pie,
    )


# ── Architecture ──────────────────────────────────────────────────

def _map_arch(elf: ELFFile) -> Architecture:
    machine = elf.header.e_machine
    return _ARCH_MAP.get(machine, Architecture.UNKNOWN)


# ── Sections ──────────────────────────────────────────────────────

def _parse_sections(elf: ELFFile) -> list[Section]:
    sections: list[Section] = []
    for sec in elf.iter_sections():
        name = sec.name
        if not name:
            continue

        raw_flags = sec.header.sh_flags
        flags: frozenset[SectionFlags] = frozenset(
            f for bit, f in _FLAG_BIT_MAP if raw_flags & bit
        )

        sections.append(Section(
            name    = name,
            offset  = sec.header.sh_offset,
            vaddr   = sec.header.sh_addr,
            size    = sec.header.sh_size,
            flags   = flags,
            align   = sec.header.sh_addralign,
            link    = sec.header.sh_link,
            entsize = sec.header.sh_entsize,
        ))

    return sections


# ── Symbols ───────────────────────────────────────────────────────

def _parse_symbols(elf: ELFFile) -> list[Symbol]:
    seen:    set[tuple[str, int]] = set()
    symbols: list[Symbol] = []

    for sec_name, is_dynamic in ((".symtab", False), (".dynsym", True)):
        sec = elf.get_section_by_name(sec_name)
        if sec is None or not isinstance(sec, SymbolTableSection):
            continue

        for sym in sec.iter_symbols():
            name = sym.name
            if not name:
                continue

            addr    = sym.entry.st_value
            size    = sym.entry.st_size
            key     = (name, addr)
            if key in seen:
                continue
            seen.add(key)

            sym_type = _SYM_TYPE_MAP.get(
                sym.entry.st_info.type, SymbolType.UNKNOWN
            )
            binding = _SYM_BIND_MAP.get(
                sym.entry.st_info.bind, SymbolBinding.UNKNOWN
            )

            # Resolve section name
            shndx = sym.entry.st_shndx
            sec_label = ""
            if isinstance(shndx, int) and shndx < elf.num_sections():
                sec_label = elf.get_section(shndx).name or ""
            elif shndx == "SHN_ABS":
                sec_label = "<abs>"

            symbols.append(Symbol(
                name       = name,
                address    = addr,
                size       = size,
                sym_type   = sym_type,
                binding    = binding,
                section    = sec_label,
                is_dynamic = is_dynamic,
            ))

    return symbols


# ── Interpreter ───────────────────────────────────────────────────

def _get_interpreter(elf: ELFFile) -> str:
    for seg in elf.iter_segments():
        if seg.header.p_type == "PT_INTERP":
            try:
                return seg.get_interp_name()
            except Exception:
                return seg.data().rstrip(b"\x00").decode("utf-8", errors="replace")
    return ""


# ── PIE detection ─────────────────────────────────────────────────

def _detect_pie(elf: ELFFile) -> bool:
    e_type = elf.header.e_type
    if e_type == "ET_EXEC":
        return False
    if e_type == "ET_DYN":
        # Shared libraries are also ET_DYN; check DT_FLAGS_1 DF_1_PIE
        for sec in elf.iter_sections():
            if isinstance(sec, DynamicSection):
                for tag in sec.iter_tags():
                    if tag.entry.d_tag == "DT_FLAGS_1":
                        return bool(tag.entry.d_val & 0x08000000)  # DF_1_PIE
        return True  # ET_DYN without DT_FLAGS_1 is still likely PIE
    return False
