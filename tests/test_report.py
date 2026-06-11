"""
Tests for core/report.py — PDF generation.
"""
import pytest
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))


class MockBinaryReport:
    path = '/tmp/test_binary'
    arch = 'amd64'
    bits = 64
    protections = {
        'NX': True, 'Canary': False, 'PIE': False,
        'ASLR': True, 'RELRO': 'Partial', 'FORTIFY': False,
    }
    vuln_functions = []
    win_functions = [('win', 0x401196)]
    interesting_strings = ['/bin/sh', 'flag{test}']
    recommended_strategies = [('ret2win', 95), ('ret2libc', 72)]
    total_score = 10
    checksec_raw = ""


class MockExploitResult:
    success = True
    flag = 'flag{test_report_generation}'
    strategy_used = 'ret2win'
    offset = 72
    payload = b'A' * 72 + b'\x96\x11\x40\x00\x00\x00\x00\x00'
    output = b'flag{test_report_generation}\n'
    duration = 1.23
    error_msg = ''
    libc_base = 0
    mode = 'local'
    remote_host = ''
    remote_port = 0


def test_text_report_generation():
    from core.report import ReportGenerator
    gen = ReportGenerator(output_dir='/tmp')
    text = gen.generate_text_report(MockBinaryReport(), MockExploitResult())
    assert 'PENTEROUS' in text
    assert 'flag{test_report_generation}' in text
    assert 'ret2win' in text
    assert 'PWNED' in text


def test_pdf_generation():
    try:
        import reportlab
        has_reportlab = True
    except ImportError:
        has_reportlab = False

    if not has_reportlab:
        pytest.skip("reportlab not installed")

    from core.report import ReportGenerator
    with tempfile.TemporaryDirectory() as tmpdir:
        gen = ReportGenerator(output_dir=tmpdir)
        path = gen.generate(MockBinaryReport(), MockExploitResult())
        if path:
            assert os.path.exists(path)
            assert os.path.getsize(path) > 1000  # non-trivial PDF


def test_report_dir_created():
    from core.report import ReportGenerator
    with tempfile.TemporaryDirectory() as tmpdir:
        subdir = os.path.join(tmpdir, 'reports', 'nested')
        gen = ReportGenerator(output_dir=subdir)
        assert os.path.exists(subdir)
