"""
Penterous — Programmatic GDB interface via subprocess.
"""
import subprocess
import re
import tempfile
import os
import resource
from dataclasses import dataclass, field
from typing import Optional


def _disable_core_dumps():
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except Exception:
        pass


@dataclass
class GDBResult:
    rip: int = 0
    rsp: int = 0
    rbp: int = 0
    rax: int = 0
    eip: int = 0
    esp: int = 0
    ebp: int = 0
    ret_addr: int = 0
    stack_dump: list = field(default_factory=list)
    crashed: bool = False
    raw_output: str = ""


GDB_SCRIPT_64 = '''set pagination off
set confirm off
set disable-randomization on
handle SIGSEGV stop nopass
handle SIGABRT stop nopass
shell ulimit -c 0
run <<< $(python3 -c "import sys; sys.stdout.buffer.write(bytes.fromhex('{payload_hex}'))")
info registers rip rsp rbp rax
x/1gx $rsp-8
x/16wx $rsp
quit
'''

GDB_SCRIPT_32 = '''set pagination off
set confirm off
set disable-randomization on
handle SIGSEGV stop nopass
handle SIGABRT stop nopass
shell ulimit -c 0
run <<< $(python3 -c "import sys; sys.stdout.buffer.write(bytes.fromhex('{payload_hex}'))")
info registers eip esp ebp eax
x/16wx $esp
quit
'''


def run_gdb_batch(binary_path: str, payload: bytes, bits: int = 64, timeout: int = 30) -> GDBResult:
    """Run GDB in batch mode, capture registers at crash."""
    script_tmpl = GDB_SCRIPT_64 if bits == 64 else GDB_SCRIPT_32
    script = script_tmpl.format(payload_hex=payload.hex())

    with tempfile.NamedTemporaryFile(mode='w', suffix='.gdb', delete=False) as f:
        f.write(script)
        script_path = f.name

    try:
        result = subprocess.run(
            ['gdb', '-q', '-batch', '-x', script_path, binary_path],
            capture_output=True,
            timeout=timeout,
            preexec_fn=_disable_core_dumps,
            cwd=os.path.dirname(os.path.abspath(binary_path)),
        )
        # latin-1 accepts every byte value 0x00-0xff — no UnicodeDecodeError possible
        stdout = result.stdout.decode('latin-1', errors='replace')
        stderr = result.stderr.decode('latin-1', errors='replace')
        output = stdout + stderr
        return parse_gdb_output(output, bits)
    except subprocess.TimeoutExpired:
        return GDBResult(crashed=True, raw_output="timeout")
    except FileNotFoundError:
        return GDBResult(crashed=False, raw_output="gdb not found")
    finally:
        try:
            os.unlink(script_path)
        except Exception:
            pass


def parse_gdb_output(output: str, bits: int = 64) -> GDBResult:
    res = GDBResult(raw_output=output, crashed=False)

    if any(sig in output for sig in [
        'SIGSEGV', 'SIGBUS', 'SIGILL', 'Segmentation fault',
        'SIGABRT', 'Aborted', 'stack smashing detected',
    ]):
        res.crashed = True

    lines = output.splitlines()

    if bits == 64:
        ret_addr_captured = False
        for line in lines:
            m = re.search(r'\brip\s+0x([0-9a-f]+)', line)
            if m:
                res.rip = int(m.group(1), 16)
            m = re.search(r'\brsp\s+0x([0-9a-f]+)', line)
            if m:
                res.rsp = int(m.group(1), 16)
            m = re.search(r'\brbp\s+0x([0-9a-f]+)', line)
            if m:
                res.rbp = int(m.group(1), 16)
            m = re.search(r'\brax\s+0x([0-9a-f]+)', line)
            if m:
                res.rax = int(m.group(1), 16)
            if not ret_addr_captured:
                m = re.search(r'0x[0-9a-f]+:\s+0x([0-9a-f]{16})', line)
                if m:
                    val = int(m.group(1), 16)
                    if val < 0x7f0000000000:
                        res.ret_addr = val
                        ret_addr_captured = True
        for line in lines:
            m = re.search(r'0x[0-9a-f]+:\s+((?:0x[0-9a-f]+\s*)+)', line)
            if m:
                vals = re.findall(r'0x([0-9a-f]+)', m.group(1))
                res.stack_dump.extend(int(v, 16) for v in vals)
    else:
        for line in lines:
            m = re.search(r'\beip\s+0x([0-9a-f]+)', line)
            if m:
                res.eip = int(m.group(1), 16)
            m = re.search(r'\besp\s+0x([0-9a-f]+)', line)
            if m:
                res.esp = int(m.group(1), 16)
            m = re.search(r'\bebp\s+0x([0-9a-f]+)', line)
            if m:
                res.ebp = int(m.group(1), 16)
        for line in lines:
            m = re.search(r'0x[0-9a-f]+:\s+((?:0x[0-9a-f]+\s*)+)', line)
            if m:
                vals = re.findall(r'0x([0-9a-f]+)', m.group(1))
                res.stack_dump.extend(int(v, 16) for v in vals)

    return res


def check_gdb_available() -> bool:
    try:
        subprocess.run(['gdb', '--version'], capture_output=True, timeout=5)
        return True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def check_checksec_available() -> bool:
    try:
        subprocess.run(['checksec', '--version'], capture_output=True, timeout=5)
        return True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        try:
            subprocess.run(['checksec', '--file=/bin/ls'], capture_output=True, timeout=5)
            return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False
