# ByteTrace

**A modern, educational binary analysis CLI tool.**

ByteTrace helps developers and security students explore compiled binaries with clean output, progressive disclosure, and inline explanations — no RE background required.

---

## Running ByteTrace

### Option 1 — `bytetrace.py` launcher (easiest, no setup needed)

```bash
python bytetrace.py <command> <binary> [options]
```

On **first run** it automatically:
1. Creates a virtual environment at `.venv/`
2. Installs all dependencies
3. Launches the CLI

Every subsequent run skips straight to the CLI — fast and painless.

```bash
# Examples
python bytetrace.py info       ./mybinary
python bytetrace.py sections   ./mybinary --explain
python bytetrace.py symbols    ./mybinary --search main
python bytetrace.py disasm     ./mybinary --func main
python bytetrace.py cfg        ./mybinary --func main
python bytetrace.py strings    ./mybinary
python bytetrace.py hexdump    ./mybinary --section .rodata
python bytetrace.py imports    ./mybinary
```

### Option 2 — Install with pip

```bash
pip install -e ".[dev]"   # installs the `bytetrace` console script
bytetrace info ./mybinary
```

---

## Commands

| Command     | Description                                      |
|------------|--------------------------------------------------|
| `info`     | Binary overview — format, arch, PIE, stripped…  |
| `sections` | Section header table (`.text`, `.data`, …)       |
| `symbols`  | Symbol listing with fuzzy search                 |
| `disasm`   | Disassemble a function or address range          |
| `cfg`      | Control-flow graph of a function                 |
| `strings`  | Extract printable strings (like `strings`)       |
| `hexdump`  | Hex + ASCII dump of a section or byte range      |
| `imports`  | Shared library deps + imported symbols           |
| `version`  | Show version + dependency info                   |

### Universal flags (every command)

| Flag           | Effect                                   |
|---------------|------------------------------------------|
| `--explain`    | Add inline educational annotations       |
| `--json`       | Machine-readable JSON output             |
| `--no-color`   | Strip ANSI colour (also `$NO_COLOR`)     |
| `--quiet`/`-q` | Suppress decorative headers/chrome       |

> **Note:** Global flags (`--no-color`, `--version`) go **before** the command name:
> ```bash
> python bytetrace.py --no-color info ./binary
> ```

---

## Command Reference

### `info <binary>`
High-level overview of the binary.
```
◆ hello  /home/user/hello

  format        ELF
  arch          x86-64
  bits          64-bit
  endian        Little
  entry point   0x0000000000401040
  file size     15 KiB
  sections      29
  symbols       34
  interpreter   /lib64/ld-linux-x86-64.so.2
  PIE           no
  stripped      no
```
Add `--explain` to get an annotation on every field.

---

### `sections <binary>`
Section header table with name, offset, virtual address, size, flags, and alignment.
```bash
python bytetrace.py sections ./binary
python bytetrace.py sections ./binary --explain   # notes on .text, .bss, …
python bytetrace.py sections ./binary --json
```

---

### `symbols <binary> [OPTIONS]`
Lists symbols from `.symtab` and `.dynsym`.

| Flag                    | Description                           |
|------------------------|---------------------------------------|
| `--search`/`-s QUERY`  | Fuzzy symbol name search              |
| `--type TYPE`          | Filter: `function`, `object`, `tls`…  |
| `--dynamic`            | Show only dynamic (.dynsym) symbols   |
| `--limit`/`-n N`       | Truncate to N rows                    |

```bash
python bytetrace.py symbols ./binary --search malloc
python bytetrace.py symbols ./binary --type function --dynamic
```

---

### `disasm <binary> [OPTIONS]`
Disassembles code using Capstone. Supports x86, x86-64, ARM, AArch64, MIPS, RISC-V, PowerPC.

| Flag           | Description                             |
|---------------|-----------------------------------------|
| `--func`/`-f` | Symbol name (fuzzy-matched)             |
| `--addr`/`-a` | Virtual address (hex `0x…` or decimal)  |
| `--count`/`-n`| Max instructions (default: 50)          |

```bash
python bytetrace.py disasm ./binary --func main
python bytetrace.py disasm ./binary --addr 0x401130 --count 30
```

---

### `cfg <binary> [OPTIONS]`
Builds a control-flow graph by splitting disassembly at branch targets and returns. Each basic block is shown as a panel with its instructions and successors.

| Flag           | Description                                |
|---------------|--------------------------------------------|
| `--func`/`-f` | Function name (fuzzy-matched)              |
| `--addr`/`-a` | Start virtual address                      |
| `--max-insns` | Safety cap on instructions (default: 500)  |

```bash
python bytetrace.py cfg ./binary --func main
python bytetrace.py cfg ./binary --func main --json   # JSON graph
```

---

### `strings <binary> [OPTIONS]`
Extracts printable ASCII strings, like the UNIX `strings` utility — but section-aware.

| Flag             | Description                              |
|-----------------|------------------------------------------|
| `--min-len`/`-n` | Minimum string length (default: 4)       |
| `--section`/`-s` | Limit to a specific section (e.g. `.rodata`) |
| `--offset`       | Show file offset alongside each string   |

```bash
python bytetrace.py strings ./binary
python bytetrace.py strings ./binary --section .rodata --offset
python bytetrace.py strings ./binary --min-len 8 --json
```

---

### `hexdump <binary> [OPTIONS]`
Classic hex + ASCII dump of a section or arbitrary byte range.

| Flag             | Description                                |
|-----------------|---------------------------------------------|
| `--section`/`-s` | Section to dump (e.g. `.rodata`)           |
| `--offset`/`-o`  | File offset to start from (hex or decimal) |
| `--size`/`-z`    | Bytes to dump when using `--offset` (default: 256) |
| `--width`/`-w`   | Bytes per line (default: 16)               |

```bash
python bytetrace.py hexdump ./binary --section .rodata
python bytetrace.py hexdump ./binary --offset 0x2000 --size 128
```

---

### `imports <binary>`
Shows shared-library dependencies (DT_NEEDED) and all imported (undefined) dynamic symbols.

```bash
python bytetrace.py imports ./binary
python bytetrace.py imports ./binary --explain   # library notes
python bytetrace.py imports ./binary --json
```

---

## Supported Formats

| Format   | Status            |
|---------|-------------------|
| ELF     | ✅ Full support    |
| PE/COFF | 🔜 Planned        |
| Mach-O  | 🔜 Planned        |

---

## Requirements

Python ≥ 3.10. Dependencies are installed automatically by `bytetrace.py`:

| Package    | Purpose                  |
|-----------|--------------------------|
| click      | CLI framework            |
| rich       | Terminal rendering       |
| pyelftools | ELF parsing              |
| capstone   | Multi-arch disassembly   |
| networkx   | CFG graph construction   |
| rapidfuzz  | Fuzzy symbol search      |

---

## License

MIT — see [LICENSE](LICENSE).
