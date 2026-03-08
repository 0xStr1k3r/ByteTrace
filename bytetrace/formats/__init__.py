"""
Binary format parsers.

``open_binary(path)`` is the single entry point used by all CLI commands.
It auto-detects the file format and delegates to the appropriate parser.
"""

from __future__ import annotations

from pathlib import Path

from bytetrace.core.binary import Binary


def open_binary(path: str | Path) -> Binary:
    """
    Parse a binary file and return a :class:`~bytetrace.core.binary.Binary`.

    Format detection is done by reading the magic bytes rather than relying
    on file extensions.

    Raises
    ------
    ValueError
        When the file format is not supported or the file cannot be parsed.
    FileNotFoundError
        When *path* does not exist.
    """
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"File not found: {p}")

    magic = p.read_bytes()[:4]

    if magic[:4] == b"\x7fELF":
        from bytetrace.formats.elf import parse_elf
        return parse_elf(p)

    if magic[:2] in (b"MZ", b"ZM"):
        raise ValueError(
            f"{p.name}: PE/COFF format detected but not yet supported. "
            "Only ELF binaries are supported in this release."
        )

    if magic[:4] in (
        b"\xfe\xed\xfa\xce",  # Mach-O 32-bit LE
        b"\xfe\xed\xfa\xcf",  # Mach-O 64-bit LE
        b"\xce\xfa\xed\xfe",  # Mach-O 32-bit BE
        b"\xcf\xfa\xed\xfe",  # Mach-O 64-bit BE
        b"\xca\xfe\xba\xbe",  # Mach-O fat binary
    ):
        raise ValueError(
            f"{p.name}: Mach-O format detected but not yet supported. "
            "Only ELF binaries are supported in this release."
        )

    raise ValueError(
        f"{p.name}: unrecognised file format (magic={magic.hex()}). "
        "Only ELF binaries are supported in this release."
    )
