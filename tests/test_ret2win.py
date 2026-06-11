"""
End-to-end test: ret2win strategy.
"""
import pytest
import os
import sys
import tempfile
import subprocess

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

RET2WIN_C = r"""
#include <stdio.h>
void win() {
    puts("flag{ret2win_test_success}");
    fflush(stdout);
}
void vuln() {
    char buf[56];
    printf("Enter input: ");
    fflush(stdout);
    gets(buf);
}
int main() {
    vuln();
    return 0;
}
"""


@pytest.fixture(scope='module')
def ret2win_binary():
    fd, src = tempfile.mkstemp(suffix='.c')
    os.write(fd, RET2WIN_C.encode())
    os.close(fd)
    out = src.replace('.c', '')
    ret = subprocess.run(
        ['gcc', '-m64', '-fno-stack-protector', '-no-pie', '-o', out, src],
        capture_output=True, timeout=15
    )
    os.unlink(src)
    if ret.returncode != 0:
        pytest.skip("gcc not available")
    yield out
    try:
        os.unlink(out)
    except Exception:
        pass


def test_win_function_found(ret2win_binary):
    from core.binary import Binary
    b = Binary(ret2win_binary)
    b.analyze()
    assert any('win' in n.lower() for n, _ in b.win_functions)


def test_ret2win_full(ret2win_binary):
    from core.binary import Binary
    from core.fuzzer import AutoFuzzer
    from core.exploit_engine import ExploitEngine
    from core.flag_hunter import FlagHunter

    b = Binary(ret2win_binary)
    report = b.analyze()

    fuzzer = AutoFuzzer(b, max_size=256, timeout=15)
    offset = fuzzer.find_offset()
    assert offset > 0, "Fuzzer should find a positive offset"

    engine = ExploitEngine(b, offset, report, timeout=15, verbose=False)
    result = engine.run(force_strategy='ret2win')

    assert result.success, f"ret2win should succeed. Error: {result.error_msg}"
    assert result.flag is not None
    assert 'flag{' in result.flag.lower() or 'ret2win' in result.flag.lower()
