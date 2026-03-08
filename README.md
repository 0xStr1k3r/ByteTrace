# ByteTrace

**A modern, educational binary analysis CLI tool.**

ByteTrace helps developers and security students explore compiled binaries with clean output, progressive disclosure, and inline explanations — no RE background required.

---

## Features

| Command      | Description                                      |
|-------------|--------------------------------------------------|
| `info`      | Binary overview — format, arch, PIE, stripped…  |
| `sections`  | Section header table (`.text`, `.data`, …)       |
| `symbols`   | Symbol listing with fuzzy search                 |
| `disasm`    | Disassemble a function or address range          |
| `cfg`       | Control-flow graph of a function                 |
| `version`   | Show version + dependency info                   |

**Universal flags** available on every command:

| Flag          | Effect                                  |
|--------------|-----------------------------------------|
| `--explain`   | Add inline educational annotations      |
| `--json`      | Machine-readable JSON output            |
| `--no-color`  | Strip ANSI colour (also `$NO_COLOR`)    |
| `--quiet`/`-q`| Suppress decorative headers/chrome      |

---

## Installation

```bash
# From source (recommended during development)
pip install -e ".[dev]"
```

**Requirements:** Python ≥ 3.10, and the following packages (installed automatically):

| Package      | Purpose                         |
|-------------|---------------------------------|
| click        | CLI framework                   |
| rich         | Terminal rendering              |
| pyelftools   | ELF parsing                     |
| capstone     | Multi-arch disassembly          |
| networkx     | CFG graph construction          |
| rapidfuzz    | Fuzzy symbol search             |

---

## Quick Start

```bash
# Compile a test binary
gcc -o hello hello.c

# Overview
bytetrace info hello

# Section table with explanations
bytetrace sections hello --explain

# All symbols
bytetrace symbols hello

# Fuzzy search for "main"
bytetrace symbols hello --search main

# Only functions
bytetrace symbols hello --type function

# Disassemble main
bytetrace disasm hello --func main

# Disassemble from address
bytetrace disasm hello --addr 0x401130 --count 20

# Control-flow graph of main
bytetrace cfg hello --func main

# JSON output (pipe-friendly)
bytetrace info hello --json | jq .arch
```

---

## Command Reference

### `bytetrace info <binary>`

Prints a summary table of the binary's metadata.

```
◆ hello  /home/user/hello

  format        ELF
  arch          x86-64
  bits          64-bit
  endian        Little
  entry point   0x0000000000401050
  file size     15K
  sections      28
  symbols       34
  interpreter   /lib64/ld-linux-x86-64.so.2
  PIE           no
  stripped      no
```

Use `--explain` to add annotations for each field.

---

### `bytetrace sections <binary>`

Displays the section header table.

```
  #   Name               Offset      VAddr                 Size   Flags  Align
  0   .interp            0x00000318  0x0000000000400318     28B   A      2^0
  1   .text              0x00001050  0x0000000000401050    378K   AX     2^4
  2   .data              0x00004000  0x0000000000404000      8B   AW     2^3
  ...
```

---

### `bytetrace symbols <binary> [OPTIONS]`

Lists symbols from `.symtab` and `.dynsym`.

**Options:**

| Flag                  | Description                          |
|----------------------|--------------------------------------|
| `--search`/`-s QUERY` | Fuzzy symbol name search             |
| `--type TYPE`         | Filter: function, object, tls, …     |
| `--dynamic`           | Show only dynamic (.dynsym) symbols  |
| `--limit`/`-n N`      | Truncate output to N rows            |

---

### `bytetrace disasm <binary> [OPTIONS]`

Disassembles code using Capstone. Supports x86, x86-64, ARM, AArch64, MIPS, RISC-V, PowerPC.

**Options:**

| Flag             | Description                                   |
|-----------------|-----------------------------------------------|
| `--func`/`-f`    | Symbol name (fuzzy-matched)                   |
| `--addr`/`-a`    | Virtual address (hex `0x…` or decimal)        |
| `--count`/`-n`   | Max instructions to show (default: 50)        |

---

### `bytetrace cfg <binary> [OPTIONS]`

Builds a control-flow graph by splitting disassembly at branch targets and returns.

**Options:**

| Flag          | Description                            |
|--------------|----------------------------------------|
| `--func`/`-f` | Function name (fuzzy-matched)          |
| `--addr`/`-a` | Start virtual address                  |
| `--max-insns` | Safety cap on instructions (default: 500) |

Each basic block is shown as a panel with its instructions and successor addresses.

---

## Supported Formats

| Format    | Status            |
|----------|-------------------|
| ELF      | ✅ Full support    |
| PE/COFF  | 🔜 Planned        |
| Mach-O   | 🔜 Planned        |

---

## License

MIT — see [LICENSE](LICENSE).
