# Penterous — Automated CTF Binary Exploitation Framework

```

    ██████╗ ███████╗███╗   ██╗████████╗███████╗██████╗  ██████╗ ██╗   ██╗███████╗
    ██╔══██╗██╔════╝████╗  ██║╚══██╔══╝██╔════╝██╔══██╗██╔═══██╗██║   ██║██╔════╝
    ██████╔╝█████╗  ██╔██╗ ██║   ██║   █████╗  ██████╔╝██║   ██║██║   ██║███████╗
    ██╔═══╝ ██╔══╝  ██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗██║   ██║██║   ██║╚════██║
    ██║     ███████╗██║ ╚████║   ██║   ███████╗██║  ██║╚██████╔╝╚██████╔╝███████║
    ╚═╝     ╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚══════╝
    
  by p3nt2r0us  |  Binary Exploitation Framework  |  CTF Training Tool
```

> **Educational use only.** Use exclusively on systems you own or have explicit authorization to test.

---

## Overview

Penterous is a Python CLI tool that automates the full binary exploitation pipeline for CTF challenges:

```
INPUT → RECON → FUZZ → EXPLOIT → FLAG → REPORT
```

- **Auto-analyze** any ELF binary (x86 / x86-64)
- **Detect protections**: NX, Canary, ASLR, PIE, RELRO, FORTIFY
- **Auto-fuzz** to find the stack offset (cyclic pattern + GDB) — binary-safe, handles raw bytes
- **Auto-select** the optimal exploitation strategy
- **Execute exploit** locally, then **automatically escalate to remote** target
- **Remote-only mode**: skip local exploitation entirely, attack the server directly
- **Capture the flag** with pattern matching (flag{}, HTB{}, picoCTF{}, etc.)
- **Remote flag** shown in final terminal banner and written to the PDF report
- **Generate beautified PDF report** with full technical details + ready-to-use exploit script

---

## Supported Platforms

- pwn.college
- HackTheBox (PWN challenges)
- picoCTF
- pwnable.kr
- exploit.education

---

## Installation

### Quick install

```bash
pip install -r requirements.txt
```

### Full install (with system tools)

```bash
pip install -r requirements.txt
sudo apt install -y gdb checksec patchelf
gem install one_gadget   # optional
```

### Development install

```bash
pip install -e .
```

---

## Usage

### Full Auto Mode (recommended)

```bash
# Local only — prompts for remote escalation after success
python penterous.py auto ./binary

# Provide libc for ret2libc / leak strategies
python penterous.py auto ./binary --libc ./libc.so.6

# Local first, then auto-escalate to remote
python penterous.py auto ./binary --remote 10.0.0.1:9001

# ★ Remote-only — skip local exploitation, attack server directly
python penterous.py auto ./binary --remote-only 10.0.0.1:9001

# Remote-only with known offset (skip fuzzing too)
python penterous.py auto ./binary --remote-only 10.0.0.1:9001 --offset 44
```

### Static Analysis Only

```bash
python penterous.py analyze ./binary
python penterous.py analyze ./binary --json
python penterous.py analyze ./binary --verbose
```

### Targeted Exploitation

```bash
python penterous.py exploit ./binary --strategy ret2win
python penterous.py exploit ./binary --strategy ret2libc   --libc ./libc.so.6
python penterous.py exploit ./binary --strategy format_string
python penterous.py exploit ./binary --strategy rop_chain

# Targeted + remote-only
python penterous.py exploit ./binary --strategy ret2win --remote-only 10.0.0.1:9001 --offset 88
```

### Fuzzing Only

```bash
python penterous.py fuzz ./binary
python penterous.py fuzz ./binary --max-size 4096
```

### Generate Report from Saved Results

```bash
python penterous.py report ./binary --results last
```

---

## Options

| Option | Description |
|--------|-------------|
| `--libc PATH` | Path to target libc |
| `--remote IP:PORT` | After local success, auto-escalate to this remote target |
| `--remote-only IP:PORT` | **Skip local exploitation** — analyse binary statically then attack remote directly |
| `--offset N` | Manual offset in bytes (skip fuzzing) |
| `--strategy NAME` | Force a specific exploitation strategy (`exploit` command) |
| `--timeout N` | Timeout per step in seconds (default: 30) |
| `--no-pdf` | Skip PDF report generation |
| `--verbose / -v` | Verbose output |
| `--quiet / -q` | Only output the flag |
| `--debug` | Full traceback on errors |
| `--output-dir DIR` | Directory for reports/results (default: `./reports`) |

---

## Remote Escalation Modes

### Mode 1 — Interactive prompt (default)

Run locally first. On success, Penterous asks:

```
■■ LOCAL EXPLOIT SUCCEEDED ■■

Escalate to remote server? [y/N]: y
Enter target [HOST:PORT] (e.g. 10.0.0.1:9001): pwn.college:9001
Remote libc path (leave blank to skip):
```

### Mode 2 — `--remote` (auto-escalate)

Provide the target upfront. No prompt — Penterous runs locally then immediately attacks remote:

```bash
python penterous.py auto ./binary --remote target.ctf.com:1337
```

### Mode 3 — `--remote-only` (skip local entirely) ★ NEW

Best used when:
- You already know the offset (`--offset N`)
- The local binary environment differs too much from the server
- You want to attack the server without running anything locally

```bash
# Full pipeline — static analysis + strategy selection + remote exploit
python penterous.py auto ./binary --remote-only 13.59.203.175:61562 --offset 44

# Force strategy + remote-only
python penterous.py exploit ./binary --strategy ret2win --remote-only 13.59.203.175:61562 --offset 88
```

The remote flag is captured, displayed prominently in the terminal, and written as the primary flag in the PDF report.

---

## Flag Reporting

| Scenario | Terminal Banner | PDF Report |
|----------|----------------|------------|
| Local only | `■ FLAG CAPTURED ■` (green) | Local flag in cover + section 2 |
| Local → Remote | `■■ REMOTE FLAG CAPTURED ■■` (yellow) | Remote flag replaces local flag everywhere |
| Remote-only | `■■ REMOTE FLAG CAPTURED ■■` (yellow) | Remote flag in cover + section 2 |

---

## PDF Report Sections

1. **Cover** — Binary info, mode, status, flag banner
2. **Static Analysis** — Protections table, vulnerable functions, win functions, strategies
3. **Exploitation** — Strategy, offset, payload hex dump, flags captured
4. **Exploit Script** — Ready-to-use pwntools script generated automatically
5. **Remediation** — How to fix the vulnerabilities found
6. **Resources** — Learning links tailored to the strategy used

---

## Supported Strategies

| Strategy | Conditions | Complexity |
|----------|-----------|------------|
| `ret2win` | win() function present, PIE off | Beginner |
| `ret2shellcode` | NX disabled | Basic |
| `ret2libc` | Known libc, ASLR off | Basic |
| `leak_ret2libc` | Known libc, ASLR on | Intermediate |
| `rop_chain` | Gadgets in binary | Intermediate |
| `format_string` | printf(user_input) detected | Intermediate |
| `heap_uaf` | malloc/free + UAF pattern | Advanced |
| `srop` | syscall;ret gadget available | Advanced |

---

## Project Structure

```
penterous/
├── penterous.py          ← CLI entry point
├── requirements.txt
├── setup.py
├── README.md
├── core/
│   ├── binary.py         ← ELF analysis + checksec
│   ├── fuzzer.py         ← Cyclic pattern offset finder (binary-safe)
│   ├── exploit_engine.py ← Strategy selector + local/remote/remote-only
│   ├── rop_builder.py    ← ROP chain construction
│   ├── flag_hunter.py    ← Flag detection + extraction
│   └── report.py         ← Beautified PDF report (reportlab)
├── strategies/
│   ├── base.py           ← Abstract base class
│   ├── ret2win.py
│   ├── ret2shellcode.py
│   ├── ret2libc.py
│   ├── leak_ret2libc.py
│   ├── rop_chain.py
│   ├── format_string.py
│   ├── heap_uaf.py
│   └── srop.py
├── utils/
│   ├── logger.py         ← Rich terminal UI
│   ├── gdb_helper.py     ← Programmatic GDB (latin-1 safe, no UnicodeDecodeError)
│   ├── pwntools_wrap.py  ← pwntools wrappers
│   └── libc_db.py        ← libc identification
├── templates/
│   └── report_template.py← PDF styles + colour palette
└── tests/
    ├── test_binary_analysis.py
    ├── test_fuzzer.py
    ├── test_ret2win.py
    ├── test_rop_builder.py
    ├── test_flag_hunter.py
    └── test_report.py
```

---

## Example Sessions

### Session 1 — Local + remote escalation

```bash
$ python penterous.py auto ./vuln --libc ./libc.so.6

■■ PHASE 1: STATIC ANALYSIS ■■
[+] win() at 0x80491f6  ← TARGET

■■ PHASE 2: DYNAMIC FUZZING ■■
[+] Offset calculated: 44 bytes

■■ EXPLOITATION (LOCAL) ■■
[+] FLAG: P3NT2R0US{local_flag_here}

■■ LOCAL EXPLOIT SUCCEEDED ■■
Escalate to remote server? [y/N]: y
Enter target [HOST:PORT]: 13.59.203.175:61562

■■ EXPLOITATION (REMOTE) ■■

■■ REMOTE FLAG CAPTURED ■■
  picoCTF{addr3ss3s_ar3_3asy_5c6baa9e}

[+] PDF report saved: ./reports/vuln_penterous_20260504_143012.pdf
```

### Session 2 — Remote-only (no local execution)

```bash
$ python penterous.py auto ./vuln.elf --remote-only 13.59.203.175:9001 --offset 88

■■ PHASE 1: STATIC ANALYSIS ■■
[*] Remote-only mode — skipping local fuzzing (offset=88)

■■ EXPLOITATION (REMOTE — DIRECT) ■■
[+] Win function: win() at 0x4011d6
[+] Payload: b'AAAAAAAAAAAA'... + p64(0x4011d6)

■■ REMOTE FLAG CAPTURED ■■
  flag{r3m0t3_pwn3d_d1r3ct}

[+] PDF report saved: ./reports/vuln.elf_penterous_20260504_143055.pdf
```

---

## Running Tests

```bash
pytest tests/ -v --tb=short
pytest tests/ -v -k 'ret2win'
pytest tests/ --cov=. --cov-report=html
```

---

## License

MIT — Educational and personal use only.

**Never use Penterous on systems you don't own or don't have explicit written authorization to test.**
