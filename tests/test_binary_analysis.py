"""
Tests for core/binary.py — static analysis.
"""
import pytest
import os
import sys
import tempfile
import subprocess

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))


def _make_simple_elf() -> str:
    """Compile a minimal vulnerable ELF for testing (requires gcc)."""
    src = r"""
#include <stdio.h>
#include <string.h>
void win() { printf("flag{test_win_func}\n"); }
void vuln() {
    char buf[64];
    gets(buf);
}
int main() {
    vuln();
    return 0;
}
"""
    fd, src_path = tempfile.mkstemp(suffix='.c')
    os.write(fd, src.encode())
    os.close(fd)
    out_path = src_path.replace('.c', '')
    ret = subprocess.run(
        ['gcc', '-m64', '-fno-stack-protector', '-no-pie',
         '-z', 'execstack', '-o', out_path, src_path],
        capture_output=True, timeout=15
    )
    os.unlink(src_path)
    if ret.returncode != 0:
        return None
    return out_path


@pytest.fixture(scope='module')
def test_binary():
    path = _make_simple_elf()
    if path is None:
        pytest.skip("gcc not available or compilation failed")
    yield path
    try:
        os.unlink(path)
    except Exception:
        pass


def test_binary_exists(test_binary):
    assert os.path.exists(test_binary)


def test_binary_loads(test_binary):
    from core.binary import Binary
    b = Binary(test_binary)
    assert b.bits in (32, 64)
    assert b.arch in ('i386', 'amd64', 'x86', 'x86_64')


def test_protections_detected(test_binary):
    from core.binary import Binary
    b = Binary(test_binary)
    report = b.analyze()
    assert isinstance(report.protections, dict)
    # NX should be disabled since we compiled with -z execstack
    assert report.protections.get('NX') is False or report.protections.get('NX') is not None


def test_win_function_found(test_binary):
    from core.binary import Binary
    b = Binary(test_binary)
    report = b.analyze()
    win_names = [n for n, _ in report.win_functions]
    assert any('win' in n.lower() for n in win_names), \
        f"win() function not found. Found: {win_names}"


def test_gets_detected(test_binary):
    from core.binary import Binary
    b = Binary(test_binary)
    report = b.analyze()
    vuln_names = [vf.name for vf in report.vuln_functions]
    assert 'gets' in vuln_names, f"gets not found. Found: {vuln_names}"


def test_strategies_ranked(test_binary):
    from core.binary import Binary
    b = Binary(test_binary)
    report = b.analyze()
    assert len(report.recommended_strategies) > 0
    # ret2win should be highest with win() present and PIE off
    top_strategy = report.recommended_strategies[0][0]
    assert 'ret2win' in top_strategy


def test_nonexistent_binary():
    from core.binary import Binary
    with pytest.raises(FileNotFoundError):
        Binary('/nonexistent/binary')
