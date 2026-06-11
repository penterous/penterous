"""
Tests for core/fuzzer.py — offset calculation.
"""
import pytest
import os
import sys
import tempfile
import subprocess

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

OFFSET_C = r"""
#include <stdio.h>
void vuln() {
    char buf[48];
    printf("Input: ");
    fflush(stdout);
    gets(buf);
}
int main() { vuln(); return 0; }
"""


@pytest.fixture(scope='module')
def overflow_binary():
    fd, src = tempfile.mkstemp(suffix='.c')
    os.write(fd, OFFSET_C.encode())
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


def test_crash_detection(overflow_binary):
    from core.binary import Binary
    from core.fuzzer import AutoFuzzer
    b = Binary(overflow_binary)
    fuzzer = AutoFuzzer(b, max_size=512, timeout=10)
    assert fuzzer._crashes_with(b'A' * 200)
    assert not fuzzer._crashes_with(b'A' * 4)


def test_approx_size(overflow_binary):
    from core.binary import Binary
    from core.fuzzer import AutoFuzzer
    b = Binary(overflow_binary)
    fuzzer = AutoFuzzer(b, max_size=512, timeout=10)
    approx = fuzzer._find_approx_size()
    assert approx > 0
    assert approx <= 512


def test_offset_in_range(overflow_binary):
    from core.binary import Binary
    from core.fuzzer import AutoFuzzer
    b = Binary(overflow_binary)
    b.analyze()
    fuzzer = AutoFuzzer(b, max_size=512, timeout=20)
    offset = fuzzer.find_offset()
    # buf[48] + saved_rbp(8) = 56, some compilers add alignment
    assert 40 <= offset <= 80, f"Expected offset ~56, got {offset}"
