"""
Tests for core/rop_builder.py
"""
import pytest
import os
import sys
import struct

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))


class MockBinary:
    def __init__(self, bits=64, arch='amd64'):
        self.bits = bits
        self.arch = arch
        self.elf = None
        self.libc = None
        self.protections = {}
        self.vuln_functions = []
        self.win_functions = []


def test_p64_packing():
    from core.rop_builder import ROPBuilder
    assert ROPBuilder._p64(0xdeadbeef) == struct.pack('<Q', 0xdeadbeef)


def test_p32_packing():
    from core.rop_builder import ROPBuilder
    assert ROPBuilder._p32(0xdeadbeef) == struct.pack('<I', 0xdeadbeef)


def test_ret2win_payload_64():
    from core.rop_builder import ROPBuilder
    b = MockBinary(bits=64)
    rop = ROPBuilder(b)
    win_addr = 0x401196
    payload = rop.build_ret2win(48, win_addr)
    assert len(payload) >= 48
    assert struct.pack('<Q', win_addr) in payload


def test_ret2win_payload_32():
    from core.rop_builder import ROPBuilder
    b = MockBinary(bits=32, arch='i386')
    rop = ROPBuilder(b)
    win_addr = 0x080484b6
    payload = rop.build_ret2win(40, win_addr)
    assert len(payload) >= 40
    assert struct.pack('<I', win_addr) in payload


def test_format_string_leak():
    from core.rop_builder import ROPBuilder
    b = MockBinary(bits=64)
    rop = ROPBuilder(b)
    for i in range(1, 10):
        p = rop.build_format_string_leak(i)
        assert p == f'%{i}$p'.encode()
