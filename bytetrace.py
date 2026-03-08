#!/usr/bin/env python3
"""
ByteTrace — zero-install launcher.

Usage:
    python bytetrace.py [command] [binary] [options]

Examples:
    python bytetrace.py info       ./mybinary
    python bytetrace.py sections   ./mybinary --explain
    python bytetrace.py symbols    ./mybinary --search main
    python bytetrace.py disasm     ./mybinary --func main
    python bytetrace.py cfg        ./mybinary --func main
    python bytetrace.py strings    ./mybinary
    python bytetrace.py hexdump    ./mybinary --section .text
    python bytetrace.py imports    ./mybinary
    python bytetrace.py version

On first run this script:
  1. Creates a virtual environment at .venv/
  2. Installs all dependencies automatically
  3. Re-launches itself inside the venv

Subsequent runs skip straight to step 3.
"""

from __future__ import annotations

import os
import sys
import subprocess
from pathlib import Path

# ── Paths ─────────────────────────────────────────────────────────

ROOT  = Path(__file__).resolve().parent
VENV  = ROOT / ".venv"

DEPS = [
    "click>=8.1",
    "rich>=13.0",
    "pyelftools>=0.31",
    "capstone>=5.0",
    "networkx>=3.0",
    "rapidfuzz>=3.0",
]


# ── Venv helpers ──────────────────────────────────────────────────

def _venv_python() -> Path:
    if sys.platform == "win32":
        return VENV / "Scripts" / "python.exe"
    return VENV / "bin" / "python"


def _venv_pip() -> Path:
    if sys.platform == "win32":
        return VENV / "Scripts" / "pip.exe"
    return VENV / "bin" / "pip"


def _inside_venv() -> bool:
    """Return True when we are already running inside a virtual environment."""
    return (
        sys.prefix != sys.base_prefix
        or hasattr(sys, "real_prefix")                  # virtualenv compat
        or os.environ.get("VIRTUAL_ENV") is not None
    )


def _banner(msg: str) -> None:
    print(f"\033[36m[bytetrace]\033[0m {msg}", flush=True)


# ── Setup ─────────────────────────────────────────────────────────

def _create_venv() -> None:
    _banner("Creating virtual environment at .venv/ ...")
    subprocess.check_call(
        [sys.executable, "-m", "venv", str(VENV)],
        stdout=subprocess.DEVNULL,
    )
    _banner("Virtual environment created.")


def _install_deps() -> None:
    _banner("Installing dependencies (first run only) ...")
    pip = str(_venv_pip())
    subprocess.check_call(
        [pip, "install", "--quiet", "-e", str(ROOT)],
        stdout=subprocess.DEVNULL,
    )
    _banner("Dependencies installed. Starting ByteTrace...\n")


def _needs_install() -> bool:
    """Check if bytetrace package is importable inside the venv."""
    python = str(_venv_python())
    result = subprocess.run(
        [python, "-c", "import bytetrace"],
        capture_output=True,
    )
    return result.returncode != 0


# ── Entry point ───────────────────────────────────────────────────

def main() -> None:
    # ── Already inside a venv → run the CLI directly ─────────────
    if _inside_venv():
        try:
            from bytetrace.cli.main import main as cli_main
        except ImportError as exc:
            print(f"\033[31m[bytetrace] Import error: {exc}\033[0m")
            print("Try: pip install -e .")
            sys.exit(1)
        cli_main()
        return

    # ── Not in a venv — ensure .venv exists and is populated ─────
    if not VENV.exists():
        _create_venv()
        _install_deps()
    elif _needs_install():
        _install_deps()

    # ── Re-exec this script inside the venv ──────────────────────
    python = str(_venv_python())
    argv   = [python, str(Path(__file__).resolve())] + sys.argv[1:]
    os.execv(python, argv)   # replaces the current process (Unix & Windows)


if __name__ == "__main__":
    main()
