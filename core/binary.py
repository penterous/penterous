"""
Penterous — Binary analysis module.
Handles ELF parsing, checksec, protection detection, dangerous function scanning.
"""
import subprocess
import re
import os
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple

from utils.logger import info, success, warning, error, print_protection_table, print_strategy_table, console
from utils.pwntools_wrap import load_elf, PWNTOOLS_AVAILABLE


DANGEROUS_FUNCTIONS: Dict[str, Tuple[int, str]] = {
    'gets':     (10, 'stack_bof'),
    'scanf':    (8,  'stack_bof'),
    'strcpy':   (7,  'stack_bof'),
    'strcat':   (6,  'stack_bof'),
    'sprintf':  (6,  'stack_bof'),
    'read':     (5,  'stack_bof'),
    'memcpy':   (4,  'stack_bof'),
    'fgets':    (3,  'stack_bof'),
    'printf':   (9,  'format_string'),
    'fprintf':  (7,  'format_string'),
    'dprintf':  (7,  'format_string'),
    'snprintf': (5,  'format_string'),
    'malloc':   (3,  'heap'),
    'free':     (3,  'heap'),
    'calloc':   (3,  'heap'),
    'realloc':  (3,  'heap'),
    'system':   (2,  'info'),
}

WIN_KEYWORDS = ['win', 'flag', 'shell', 'backdoor', 'secret', 'admin', 'root', 'get_shell', 'give_shell']
# Strings in the binary that signal a variable-overwrite "win" condition
WIN_STRING_KEYWORDS = ['you win', 'you won', 'winner', 'congratulations', 'congrats', 'correct!', 'access granted']


@dataclass
class VulnFunction:
    name: str
    address: int
    score: int
    vuln_type: str

    def __str__(self):
        return f"{self.name}() at 0x{self.address:x} [SCORE: {self.score}/10] [{self.vuln_type}]"


@dataclass
class BinaryReport:
    path: str
    arch: str
    bits: int
    protections: Dict[str, object]
    vuln_functions: List[VulnFunction]
    win_functions: List[Tuple[str, int]]
    interesting_strings: List[str]
    recommended_strategies: List[Tuple[str, int]]
    total_score: int
    checksec_raw: str = ""
    win_args: Dict[str, List[int]] = field(default_factory=dict)

    def display(self):
        from rich.table import Table
        from rich import box
        from rich.console import Console
        c = Console()

        c.print(f"\n[bold cyan]■■ BINARY ANALYSIS REPORT ■■[/]")
        c.print(f"[dim]  Binary : {self.path}[/]")
        c.print(f"[dim]  Arch   : {self.arch} | Bits: {self.bits}[/]")

        print_protection_table(self.protections)

        if self.vuln_functions:
            c.print("\n[bold yellow]Vulnerable Functions:[/]")
            for vf in self.vuln_functions:
                c.print(f"  [red]■[/] {vf}")
        else:
            c.print("\n[dim]  No dangerous function calls found.[/]")

        if self.win_functions:
            c.print("\n[bold bright_green]Win Functions:[/]")
            for name, addr in self.win_functions:
                args = self.win_args.get(name, [])
                arg_str = ""
                if args:
                    arg_str = "  [yellow]args: " + ", ".join(f"0x{a:x}" for a in args) + "[/]"
                c.print(f"  [green]■[/] {name}() at 0x{addr:x}  [bold bright_green]← TARGET![/]{arg_str}")

        if self.interesting_strings:
            c.print("\n[bold cyan]Interesting Strings:[/]")
            for s in self.interesting_strings[:10]:
                c.print(f"  [cyan]■[/] {repr(s)}")

        c.print(f"\n[bold]Vulnerability Score: [{'green' if self.total_score >= 5 else 'red'}]{self.total_score}/10[/][/]")
        print_strategy_table(self.recommended_strategies)


class Binary:
    def __init__(self, path: str, libc_path: str = None):
        if not os.path.exists(path):
            raise FileNotFoundError(f"Binary not found: {path}")

        # Auto-fix missing execute permission once here so pwntools never
        # spams the error on every iteration of the fuzzer loop.
        if not os.access(path, os.X_OK):
            try:
                import stat as _stat
                os.chmod(path, os.stat(path).st_mode | _stat.S_IXUSR | _stat.S_IXGRP | _stat.S_IXOTH)
                warning(f"Binary was not executable — added +x automatically: {path}")
            except OSError as _e:
                warning(f"Could not chmod +x '{path}': {_e}")

        self.path = os.path.abspath(path)
        self.libc_path = libc_path
        self.elf = None
        self.libc = None
        self.protections: Dict[str, object] = {}
        self.vuln_functions: List[VulnFunction] = []
        self.win_functions: List[Tuple[str, int]] = []
        self.interesting_strings: List[str] = []
        self.arch = 'amd64'
        self.bits = 64
        self.checksec_raw = ""

        if PWNTOOLS_AVAILABLE:
            try:
                self.elf = load_elf(path)
                self.arch = self.elf.arch
                self.bits = self.elf.bits
                if libc_path:
                    # Résoudre la libc : CWD d'abord, puis dossier du binaire
                    resolved_libc = libc_path
                    if not os.path.exists(resolved_libc):
                        alt = os.path.join(os.path.dirname(os.path.abspath(path)), os.path.basename(libc_path))
                        if os.path.exists(alt):
                            resolved_libc = alt
                    if os.path.exists(resolved_libc):
                        self.libc = load_elf(resolved_libc)
                        self.libc_path = resolved_libc
            except Exception as e:
                warning(f"pwntools ELF load failed: {e} — falling back to manual parsing")

        if self.elf is None:
            self._parse_arch_manually()

    def _parse_arch_manually(self):
        """Fallback ELF header parsing without pwntools."""
        try:
            with open(self.path, 'rb') as f:
                header = f.read(20)
            if header[4] == 2:
                self.bits = 64
                self.arch = 'amd64'
            else:
                self.bits = 32
                self.arch = 'i386'
        except Exception:
            pass

    def analyze(self) -> BinaryReport:
        info(f"Loading binary: {self.path}")
        if self.libc_path:
            info(f"Loading libc: {self.libc_path}")

        self._run_checksec()
        self._detect_aslr()
        self._find_dangerous_functions()
        self._find_win_functions()
        self._analyze_strings()

        strategies = self._score_strategies()
        total_score = max((vf.score for vf in self.vuln_functions), default=0)

        return BinaryReport(
            path=self.path,
            arch=self.arch,
            bits=self.bits,
            protections=self.protections,
            vuln_functions=self.vuln_functions,
            win_functions=self.win_functions,
            interesting_strings=self.interesting_strings,
            recommended_strategies=strategies,
            total_score=total_score,
            checksec_raw=self.checksec_raw,
            win_args=self.win_args,
        )

    def _run_checksec(self):
        """Run checksec to detect binary protections."""
        defaults = {
            'NX': False, 'Canary': False, 'PIE': False,
            'RELRO': 'No', 'FORTIFY': False, 'ASLR': False,
        }
        self.protections = defaults.copy()

        # Try checksec CLI
        result = self._run_cmd(['checksec', f'--file={self.path}'])
        if result:
            self.checksec_raw = result
            self.protections['NX'] = 'NX enabled' in result or 'nx enabled' in result.lower()
            self.protections['Canary'] = 'Canary found' in result or 'canary found' in result.lower()
            self.protections['PIE'] = 'PIE enabled' in result or 'pie enabled' in result.lower()
            if 'Full RELRO' in result:
                self.protections['RELRO'] = 'Full'
            elif 'Partial RELRO' in result:
                self.protections['RELRO'] = 'Partial'
            else:
                self.protections['RELRO'] = 'No'
            self.protections['FORTIFY'] = 'FORTIFY' in result and 'No FORTIFY' not in result
            return

        # Fallback: use pwntools ELF
        if self.elf:
            try:
                self.protections['NX'] = self.elf.nx
                self.protections['Canary'] = self.elf.canary
                self.protections['PIE'] = self.elf.pie
                self.protections['RELRO'] = 'Full' if self.elf.relro == 'Full' else (
                    'Partial' if self.elf.relro == 'Partial' else 'No')
                self.checksec_raw = f"NX={self.elf.nx} Canary={self.elf.canary} PIE={self.elf.pie}"
                return
            except Exception:
                pass

        # Last resort: readelf
        result = self._run_cmd(['readelf', '-l', self.path])
        if result:
            self.protections['NX'] = 'GNU_STACK' in result and 'RWE' not in result

    def _detect_aslr(self):
        try:
            with open('/proc/sys/kernel/randomize_va_space') as f:
                val = int(f.read().strip())
            self.protections['ASLR'] = val > 0
        except Exception:
            self.protections['ASLR'] = True  # assume ASLR on

    def _find_dangerous_functions(self):
        """Scan for dangerous function calls via objdump or pwntools PLT."""
        found = {}

        # Try pwntools PLT
        if self.elf:
            try:
                plt = self.elf.plt
                for fname, (score, vtype) in DANGEROUS_FUNCTIONS.items():
                    if fname in plt:
                        found[fname] = VulnFunction(
                            name=fname,
                            address=plt[fname],
                            score=score,
                            vuln_type=vtype,
                        )
            except Exception:
                pass

        # Also try objdump CALL scanning
        result = self._run_cmd(['objdump', '-d', self.path])
        if result:
            for line in result.splitlines():
                m = re.search(r'(call[q]?)\s+[0-9a-f]+\s+<([^@>]+)@', line)
                if not m:
                    m = re.search(r'(call[q]?)\s+[0-9a-f]+\s+<([^>]+)>', line)
                if m:
                    fname = m.group(2).split('@')[0].strip()
                    if fname in DANGEROUS_FUNCTIONS and fname not in found:
                        addr_m = re.match(r'\s*([0-9a-f]+):', line)
                        addr = int(addr_m.group(1), 16) if addr_m else 0
                        score, vtype = DANGEROUS_FUNCTIONS[fname]
                        found[fname] = VulnFunction(
                            name=fname, address=addr,
                            score=score, vuln_type=vtype,
                        )

        self.vuln_functions = sorted(found.values(), key=lambda x: -x.score)

    def _find_win_functions(self):
        """Find hidden win/flag/shell functions in binary symbols."""
        self.win_functions = []
        self.win_args = {}

        # pwntools symbols
        if self.elf:
            try:
                for sym, addr in self.elf.symbols.items():
                    if any(kw in sym.lower() for kw in WIN_KEYWORDS):
                        self.win_functions.append((sym, addr))
                        args = self._detect_win_args(sym, addr)
                        if args:
                            self.win_args[sym] = args
                return
            except Exception:
                pass

        # objdump symbols fallback
        result = self._run_cmd(['nm', '-D', self.path])
        if not result:
            result = self._run_cmd(['nm', self.path])
        if result:
            for line in result.splitlines():
                parts = line.split()
                if len(parts) >= 3 and parts[1].upper() == 'T':
                    sym = parts[2]
                    if any(kw in sym.lower() for kw in WIN_KEYWORDS):
                        try:
                            addr = int(parts[0], 16)
                            self.win_functions.append((sym, addr))
                            args = self._detect_win_args(sym, addr)
                            if args:
                                self.win_args[sym] = args
                        except ValueError:
                            pass

    def _detect_win_args(self, win_name: str, win_addr: int) -> List[int]:
        """
        Disassemble win() and look for cmp instructions with magic constant values.
        Covers the common CTF pattern:
          win(arg1, arg2) where arg1==0xCAFEF00D and arg2==0xF00DF00D
        Returns list of required argument values in stack order.
        """
        result = self._run_cmd(['objdump', '-d', '--no-show-raw-insn', self.path])
        if not result:
            result = self._run_cmd(['objdump', '-d', self.path])
        if not result:
            return []

        # Extract just the win() function body
        in_win = False
        win_asm_lines = []
        for line in result.splitlines():
            # Function start: e.g. "080491f6 <win>:"
            if re.search(rf'<{re.escape(win_name)}>:', line):
                in_win = True
                continue
            if in_win:
                # Next function starts
                if re.match(r'^[0-9a-f]+ <[^>]+>:', line) and win_asm_lines:
                    break
                win_asm_lines.append(line)

        if not win_asm_lines:
            return []

        win_asm = '\n'.join(win_asm_lines)

        # Find all cmp/test immediate values that look like magic constants (>= 0x1000)
        # Patterns:
        #   cmp    $0xcafef00d,%eax
        #   cmpl   $0xcafef00d,0x8(%ebp)
        #   cmp    0xcafef00d,%rdi
        magic_vals = []
        seen = set()
        for m in re.finditer(
            r'(?:cmp[lqwb]?)\s+\$0x([0-9a-f]{4,})',
            win_asm, re.IGNORECASE
        ):
            val = int(m.group(1), 16)
            if val not in seen and val >= 0x1000:
                seen.add(val)
                magic_vals.append(val)

        # Also catch: mov / test patterns like "test eax, 0xCAFEF00D"
        for m in re.finditer(
            r'(?:test|mov[lqwb]?)\s+\$0x([0-9a-f]{8,})',
            win_asm, re.IGNORECASE
        ):
            val = int(m.group(1), 16)
            if val not in seen and val >= 0x1000:
                seen.add(val)
                magic_vals.append(val)

        return magic_vals

    def _analyze_strings(self):
        """Extract interesting strings from the binary."""
        interesting = []
        result = self._run_cmd(['strings', self.path])
        if result:
            for line in result.splitlines():
                if any(kw in line.lower() for kw in
                       ['/bin/sh', 'flag', 'password', 'secret', 'cat flag', '/bin/bash',
                        'execve', '/proc/flag', 'give me', 'shell', 'win']):
                    interesting.append(line.strip())
        self.interesting_strings = interesting[:20]

    def _score_strategies(self) -> List[Tuple[str, int]]:
        """Score and rank exploitation strategies based on detections."""
        strategies = []
        prot = self.protections
        nx = prot.get('NX', False)
        canary = prot.get('Canary', False)
        pie = prot.get('PIE', False)
        aslr = prot.get('ASLR', False)
        has_win = bool(self.win_functions)
        has_libc = self.libc is not None
        has_printf = any(vf.name in ('printf', 'fprintf') for vf in self.vuln_functions)
        has_heap = any(vf.vuln_type == 'heap' for vf in self.vuln_functions)

        # Detect variable-overwrite pattern: binary has "You win!" string but no win symbol
        has_win_string = any(kw in s.lower() for s in self.interesting_strings
                             for kw in WIN_STRING_KEYWORDS)
        has_var_overwrite = has_win_string and not has_win

        # ret2win score:
        # - 95% if BOF func (gets/scanf) exists, OR if binary has a menu (heap overwrite)
        # - 60% if only printf + no BOF + no menu → pure format string
        has_bof = any(vf.name in ('gets', 'scanf', 'strcpy', 'sprintf', 'strcat')
                      for vf in self.vuln_functions)
        has_menu = any(re.search(r'\b[1-9]\s*[.)]\s*\w', s)
                       for s in self.interesting_strings)

        # Variable overwrite → treat as ret2win with high priority
        if has_var_overwrite and has_bof:
            strategies.append(('ret2win', 98))

        if has_win and not pie:
            pure_fmt = has_printf and not has_bof and not has_menu
            r2w_score = 60 if pure_fmt else 95
            strategies.append(('ret2win', r2w_score))
        elif has_win and pie:
            strategies.append(('ret2win (partial overwrite)', 60))
        if not nx:
            strategies.append(('ret2shellcode', 90 if not canary else 50))
        if has_libc and not aslr:
            strategies.append(('ret2libc', 85))
        if has_libc and aslr:
            strategies.append(('leak + ret2libc', 75 if not canary else 55))
        strategies.append(('rop_chain', 65 if not canary else 40))
        if has_printf:
            fmt_score = 70
            if not has_win and (canary or has_heap):
                fmt_score = 97
            strategies.append(('format_string', fmt_score))
        if has_heap:
            strategies.append(('heap_uaf', 40))
        strategies.append(('srop', 35))

        seen = []
        for s in sorted(strategies, key=lambda x: -x[1]):
            if s[0] not in [x[0] for x in seen]:
                seen.append(s)
        return seen[:5]

    def _run_cmd(self, cmd: list) -> Optional[str]:
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=15, errors='replace'
            )
            return result.stdout + result.stderr
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            return None
