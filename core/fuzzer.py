"""
Penterous — Automated fuzzer: offset finder, crash detector.
Uses cyclic pattern + GDB batch mode.
"""
import subprocess
import time
import struct
import resource
import os
from typing import Optional, Dict, Tuple
from dataclasses import dataclass


def _disable_core_dumps():
    """Preexec function: disable core dump generation in child process."""
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except Exception:
        pass
    try:
        with open('/proc/self/coredump_filter', 'w') as f:
            f.write('0\n')
    except Exception:
        pass

from utils.logger import info, success, warning, error, spinner
from utils.gdb_helper import run_gdb_batch, check_gdb_available, GDBResult
from utils.pwntools_wrap import (
    PWNTOOLS_AVAILABLE, cyclic_pattern, find_cyclic_offset,
    make_process, set_arch
)


@dataclass
class FuzzResult:
    offset: int
    crash_addr: int
    rsp_value: int
    approx_buffer_size: int
    method: str


class AutoFuzzer:
    def __init__(self, binary, max_size: int = 4096, timeout: int = 30, verbose: bool = False):
        self.binary = binary
        self.max_size = max_size
        self.timeout = timeout
        self.verbose = verbose
        self.offset: Optional[int] = None
        self.crash_addr: Optional[int] = None
        self.fuzz_result: Optional[FuzzResult] = None

    def find_offset(self, max_size: int = None) -> int:
        """
        3-phase offset detection:
          Phase 1 — find approximate buffer size via A-padding crash
          Phase 2 — send cyclic pattern
          Phase 3 — calculate offset from RSP/EIP at crash
        """
        info("Starting automated fuzzing...")

        # Phase 1: approximate buffer size
        approx = self._find_approx_size()
        if approx == 0:
            warning("Could not trigger crash — binary may not be vulnerable or requires special input")
            return -1

        success(f"Crash triggered at ~{approx} bytes")

        # Phase 2 & 3: cyclic pattern
        offset = self._cyclic_find_offset(approx)
        if offset >= 0:
            success(f"Offset calculated: {offset} bytes")
            self.offset = offset
            return offset

        # Fallback: manual binary search
        warning("Cyclic offset failed — trying manual binary search")
        offset = self._binary_search_offset(approx)
        if offset >= 0:
            success(f"Offset found via binary search: {offset} bytes")
            self.offset = offset
            return offset

        error("Could not determine exact offset")
        return -1  # could not determine — do not guess

    def _find_approx_size(self) -> int:
        for size in range(8, self.max_size + 1, 8):
            if self._crashes_with(b'A' * size):
                return size
        return 0

    def _crashes_with(self, payload: bytes) -> bool:
        if PWNTOOLS_AVAILABLE:
            return self._crash_pwntools(payload)
        return self._crash_subprocess(payload)

    def _crash_pwntools(self, payload: bytes) -> bool:
        try:
            import pwn
            pwn.context.log_level = 'error'
            cwd = os.path.dirname(os.path.abspath(self.binary.path))
            p = pwn.process(self.binary.path, preexec_fn=_disable_core_dumps, cwd=cwd)
            try:
                p.sendline(payload)
                p.wait(timeout=5)
                return p.returncode not in (0, None)
            except Exception:
                return True
            finally:
                try:
                    p.kill()
                except Exception:
                    pass
        except Exception:
            return False

    def _crash_subprocess(self, payload: bytes) -> bool:
        try:
            cwd = os.path.dirname(os.path.abspath(self.binary.path))
            proc = subprocess.run(
                [self.binary.path],
                input=payload + b'\n',
                capture_output=True,
                timeout=5,
                preexec_fn=_disable_core_dumps,
                cwd=cwd,
            )
            return proc.returncode not in (0, None)
        except subprocess.TimeoutExpired:
            return False
        except Exception:
            return True

    def _cyclic_find_offset(self, approx: int) -> int:
        pattern_size = approx + 128
        pattern = cyclic_pattern(pattern_size)

        info(f"Sending cyclic pattern ({pattern_size} bytes)...")

        if check_gdb_available():
            gdb_result = run_gdb_batch(
                self.binary.path, pattern,
                bits=self.binary.bits, timeout=self.timeout
            )
            if gdb_result.crashed:
                if self.binary.bits == 64:
                    # PRIMARY: read the return address that `ret` popped from [RSP-8].
                    # This is the cyclic pattern bytes placed at the overflow position.
                    ret_addr = gdb_result.ret_addr
                    if ret_addr:
                        info(f"CRASH detected! [RSP-8] = 0x{ret_addr:x}")
                        # Try lower 4 bytes
                        offset = find_cyclic_offset(ret_addr & 0xFFFFFFFF, length=4)
                        if offset >= 0:
                            self.fuzz_result = FuzzResult(
                                offset=offset, crash_addr=gdb_result.rip,
                                rsp_value=gdb_result.rsp,
                                approx_buffer_size=approx, method='gdb+cyclic'
                            )
                            return offset
                        # Try upper 4 bytes (high dword of the 8-byte value)
                        offset = find_cyclic_offset((ret_addr >> 32) & 0xFFFFFFFF, length=4)
                        if offset >= 0:
                            return offset + 4

                    # FALLBACK: if RIP contains cyclic bytes (some kernels put the
                    # attempted-but-non-canonical address directly in RIP)
                    rip = gdb_result.rip
                    rsp = gdb_result.rsp
                    if rip:
                        info(f"CRASH detected! RIP = 0x{rip:x}")
                    if rip and (rip & 0x6161616161616161):
                        offset = find_cyclic_offset(rip & 0xFFFFFFFF, length=4)
                        if offset >= 0:
                            return offset
                    # FALLBACK: first dword in stack dump = [RSP] (after pop, RSP+8)
                    if gdb_result.stack_dump:
                        for dword in gdb_result.stack_dump[:4]:
                            offset = find_cyclic_offset(dword, length=4)
                            if offset >= 0:
                                return offset
                    # FALLBACK: RSP itself may encode pattern on some setups
                    if rsp:
                        info(f"CRASH detected! RSP = 0x{rsp:x}")
                        offset = find_cyclic_offset(rsp & 0xFFFFFFFF, length=4)
                        if offset >= 0:
                            return offset
                else:
                    # 32-bit: EIP directly contains the overflowed return address
                    eip = gdb_result.eip
                    if eip:
                        info(f"CRASH detected! EIP = 0x{eip:x}")
                        offset = find_cyclic_offset(eip, length=4)
                        if offset >= 0:
                            self.fuzz_result = FuzzResult(
                                offset=offset, crash_addr=eip,
                                rsp_value=gdb_result.esp,
                                approx_buffer_size=approx, method='gdb+cyclic'
                            )
                            return offset
        else:
            warning("GDB not available — using pattern-based crash analysis (less precise)")
            try:
                if self._crashes_with(pattern):
                    info("CRASH confirmed with cyclic pattern")
                    return approx
            except UnicodeError:
                return -1

        return -1

    def _binary_search_offset(self, approx: int) -> int:
        """
        Find exact offset by verifying that 'B'*8 (0x4242...) lands in RIP/[RSP-8].
        Uses GDB when available; falls back to crash-size search otherwise.
        """
        if check_gdb_available():
            return self._binary_search_gdb(approx)
        # no GDB — find minimum crash size
        lo, hi = max(0, approx - 64), approx + 128
        while lo < hi:
            mid = (lo + hi) // 2
            if self._crashes_with(b'A' * mid + b'B' * 8):
                hi = mid
            else:
                lo = mid + 1
        return lo

    def _binary_search_gdb(self, approx: int) -> int:
        """GDB-backed binary search: verifies RIP/[RSP-8] = 0x4242424242424242."""
        target32 = 0x42424242
        target64 = 0x4242424242424242
        lo = max(0, approx - 64)
        hi = approx + 128

        # Scan linearly around approx first for speed
        for candidate in range(lo, hi + 1, 8):
            payload = b'A' * candidate + b'B' * 8
            gr = run_gdb_batch(self.binary.path, payload + b'\n',
                               bits=self.binary.bits, timeout=10)
            if not gr.crashed:
                continue
            if self.binary.bits == 64:
                raddr = gr.ret_addr
                rip = gr.rip
                if (raddr and (raddr & 0xFFFFFFFFFFFFFFFF) == target64) or \
                   (raddr and (raddr & 0xFFFFFFFF) == target32) or \
                   (rip and (rip & 0xFFFFFFFF) == target32):
                    success(f"Offset verified via GDB: {candidate} bytes")
                    return candidate
            else:
                if gr.eip == target32:
                    success(f"Offset verified via GDB: {candidate} bytes")
                    return candidate

        # GDB search failed, return approx
        return approx
