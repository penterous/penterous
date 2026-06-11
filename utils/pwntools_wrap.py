"""
Penterous — pwntools wrappers for ELF, ROP, process management.
"""
import os
import sys
import resource
from typing import Optional


def _disable_core_dumps():
    """Suppress core dump generation in child process."""
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except Exception:
        pass

try:
    import pwn
    from pwn import ELF, ROP, process, remote, cyclic, cyclic_find, p32, p64, u32, u64, context, log
    PWNTOOLS_AVAILABLE = True
except ImportError:
    PWNTOOLS_AVAILABLE = False


def check_pwntools() -> bool:
    return PWNTOOLS_AVAILABLE


def load_elf(path: str):
    """Load an ELF binary via pwntools."""
    if not PWNTOOLS_AVAILABLE:
        raise RuntimeError("pwntools is not installed. Run: pip install pwntools")
    pwn.context.log_level = 'error'
    return ELF(path, checksec=False)


def make_process(binary_path: str, env: dict = None, stdin=None):
    """Spawn a local process from the binary's own directory (core dumps disabled)."""
    if not PWNTOOLS_AVAILABLE:
        raise RuntimeError("pwntools not installed")
    pwn.context.log_level = 'error'
    cwd = os.path.dirname(os.path.abspath(binary_path))
    return process(binary_path, env=env, stdin=stdin,
                   preexec_fn=_disable_core_dumps, cwd=cwd)


def make_remote(host: str, port: int):
    """Create a remote connection."""
    if not PWNTOOLS_AVAILABLE:
        raise RuntimeError("pwntools not installed")
    pwn.context.log_level = 'error'
    return remote(host, port)


def make_rop(elf) -> Optional[object]:
    """Build ROP object from ELF."""
    if not PWNTOOLS_AVAILABLE:
        return None
    try:
        return ROP(elf)
    except Exception:
        return None


def cyclic_pattern(length: int) -> bytes:
    if not PWNTOOLS_AVAILABLE:
        return b'Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab'[:length] * (length // 44 + 1)
    return cyclic(length)


def find_cyclic_offset(value: int, length: int = 4) -> int:
    if not PWNTOOLS_AVAILABLE:
        return -1
    try:
        return cyclic_find(value, n=length)
    except Exception:
        return -1


def set_arch(arch: str, bits: int):
    if PWNTOOLS_AVAILABLE:
        pwn.context.arch = arch
        pwn.context.bits = bits
