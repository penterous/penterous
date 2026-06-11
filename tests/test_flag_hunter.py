"""
Tests for core/flag_hunter.py
"""
import pytest
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from core.flag_hunter import FlagHunter


@pytest.fixture
def hunter():
    return FlagHunter()


def test_flag_lowercase(hunter):
    output = b"Congratulations! flag{y0u_g0t_m3_42} here you go"
    result = hunter.hunt(output, quiet=True)
    assert result == "flag{y0u_g0t_m3_42}"


def test_flag_uppercase(hunter):
    output = b"WIN! FLAG{BINARY_PWNED_2025}"
    result = hunter.hunt(output, quiet=True)
    assert result == "FLAG{BINARY_PWNED_2025}"


def test_flag_htb(hunter):
    output = b"HTB{r0p_is_fun_and_powerful}"
    result = hunter.hunt(output, quiet=True)
    assert result == "HTB{r0p_is_fun_and_powerful}"


def test_flag_pico(hunter):
    output = b"picoCTF{0verfl0w_b4sics}"
    result = hunter.hunt(output, quiet=True)
    assert result == "picoCTF{0verfl0w_b4sics}"


def test_no_flag(hunter):
    result = hunter.hunt(b"no flag here just noise", quiet=True)
    assert result is None


def test_hunt_all_multiple(hunter):
    output = b"flag{first} then FLAG{second}"
    flags = hunter.hunt_all(output)
    assert len(flags) == 2
    assert "flag{first}" in flags
    assert "FLAG{second}" in flags


def test_shell_detection(hunter):
    assert hunter.detect_shell(b"$ cat flag") is True
    assert hunter.detect_shell(b"# id") is True
    assert hunter.detect_shell(b"no shell here") is False


def test_md5_detection(hunter):
    output = b"Here is your hash: d41d8cd98f00b204e9800998ecf8427e"
    result = hunter.hunt(output, quiet=True)
    assert result is not None


def test_empty_output(hunter):
    assert hunter.hunt(b"", quiet=True) is None


def test_binary_output(hunter):
    output = b"\x00\x01\x02flag{binary_flag_123}\x00\xff"
    result = hunter.hunt(output, quiet=True)
    assert result == "flag{binary_flag_123}"
