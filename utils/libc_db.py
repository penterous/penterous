"""
Penterous — libc identification from leaked offsets (libc.blukat.me / local fallback).
"""
import urllib.request
import urllib.parse
import json
from typing import Optional, Dict
from .logger import info, warning, error


LIBC_DB_API = "https://libc.blukat.me/query"

COMMON_FUNCTIONS_TO_LEAK = ['puts', 'printf', 'read', 'write', 'gets', 'fgets',
                             '__libc_start_main', 'malloc', 'free']


def identify_libc_remote(symbol_leaks: Dict[str, int]) -> Optional[Dict]:
    """
    Query libc.blukat.me to identify libc version from leaked addresses.
    symbol_leaks: dict mapping symbol name → leaked absolute address (last 3 nibbles).
    """
    try:
        params = {}
        for name, addr in symbol_leaks.items():
            params[name] = hex(addr & 0xfff)

        query_string = urllib.parse.urlencode(params)
        url = f"{LIBC_DB_API}?{query_string}"
        info(f"Querying libc database: {url}")

        req = urllib.request.Request(url, headers={'User-Agent': 'Penterous/1.0'})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())

        if data:
            info(f"libc identified: {data[0].get('id', 'unknown')}")
            return data[0]
        else:
            warning("libc not found in database — use local libc or try more symbols")
            return None
    except Exception as e:
        warning(f"libc DB query failed: {e}")
        return None


def calculate_libc_base(leaked_addr: int, symbol_offset: int) -> int:
    """Calculate libc base from leaked absolute address and known symbol offset."""
    return leaked_addr - symbol_offset


def get_libc_offsets(libc_elf, symbol_name: str) -> int:
    """Get symbol offset from a known libc ELF."""
    try:
        return libc_elf.symbols[symbol_name]
    except KeyError:
        return 0


def find_one_gadget(libc_path: str) -> list:
    """
    Run one_gadget to find execve one-gadgets in libc.
    Requires: gem install one_gadget
    """
    import subprocess
    try:
        result = subprocess.run(
            ['one_gadget', libc_path, '--raw'],
            capture_output=True, text=True, timeout=15
        )
        offsets = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith('0x'):
                offsets.append(int(line, 16))
        return offsets
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []
