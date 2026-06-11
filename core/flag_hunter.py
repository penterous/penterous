"""
Penterous — Flag Hunter: detects and extracts CTF flags from process output.
"""
import re
from typing import Optional, List
from utils.logger import flag_captured, warning, success, info

# Universal flag pattern: matches ANY CTF format — picoCTF{}, HTB{}, PTR{}, FLAG{}, flag{}, etc.
# No need to add new prefixes. Works for every competition automatically.
#
#   (?<![A-Za-z0-9])  — not preceded by an alphanumeric (word boundary)
#   [A-Za-z][A-Za-z0-9_]{0,19}  — prefix: 1-20 chars  (flag, CTF, picoCTF, HTB, PTR …)
#   \{[^}]{3,}\}      — brace-wrapped content, at least 3 chars
#
FLAG_PATTERNS = [
    # ── Priority 1: universal WORD{...} flag detector ─────────────────────
    (r'(?<![A-Za-z0-9])[A-Za-z][A-Za-z0-9_]{0,19}\{[^}]{3,}\}', 'flag'),
    # ── Priority 2: raw hashes (no braces) ────────────────────────────────
    (r'[0-9a-f]{64}(?![0-9a-f])', 'SHA256'),
    (r'[0-9a-f]{40}(?![0-9a-f])', 'SHA1'),
    (r'[0-9a-f]{32}(?![0-9a-f])', 'MD5'),
    # ── Priority 3: Base64 blobs (entropy-checked) ────────────────────────
    (r'[A-Za-z0-9+/]{32,}={0,2}', 'Base64'),
]

SHELL_INDICATORS = [
    b'$ ', b'# ', b'sh-', b'bash-', b'root@', b'uid=0',
    b'whoami', b'/bin/sh', b'sh\n', b'bash\n',
]


class FlagHunter:
    def __init__(self):
        self._found_flags: List[str] = []

    @staticmethod
    def _has_entropy(s: str, min_distinct: int = 5) -> bool:
        """Reject low-entropy strings (e.g. all-A padding bytes)."""
        return len(set(s)) >= min_distinct

    def hunt(self, output: bytes, quiet: bool = False) -> Optional[str]:
        """Scan process output for flags. Returns the first match found."""
        text = output.decode('utf-8', errors='replace')

        for pattern, desc in FLAG_PATTERNS:
            for match in re.finditer(pattern, text):
                candidate = match.group(0)
                # Base64/hash candidates must have sufficient entropy
                if desc in ('Base64 candidate', 'MD5 hash', 'SHA1 hash', 'SHA256 hash'):
                    if not self._has_entropy(candidate):
                        continue
                self._found_flags.append(candidate)
                if not quiet:
                    flag_captured(candidate)
                return candidate

        return None

    def hunt_all(self, output: bytes) -> List[str]:
        """Scan for all flags in output."""
        text = output.decode('utf-8', errors='replace')
        flags = []
        for pattern, desc in FLAG_PATTERNS:
            for match in re.finditer(pattern, text):
                candidate = match.group(0)
                if candidate not in flags:
                    flags.append(candidate)
        return flags

    def detect_shell(self, output: bytes) -> bool:
        """Check if we got a shell (interactive prompt)."""
        for indicator in SHELL_INDICATORS:
            if indicator in output:
                return True
        return False

    def interactive_flag_capture(self, process_obj) -> Optional[str]:
        """
        For interactive shells: send cat flag commands and hunt for flag.
        """
        commands = [
            b'cat flag\n',
            b'cat flag.txt\n',
            b'cat /flag\n',
            b'cat /flag.txt\n',
            b'cat ~/flag\n',
            b'find / -name "flag*" 2>/dev/null | head -5\n',
            b'ls\n',
        ]
        for cmd in commands:
            try:
                process_obj.sendline(cmd.strip())
                output = b''
                try:
                    output = process_obj.recvall(timeout=2)
                except Exception:
                    try:
                        output = process_obj.recv(timeout=2)
                    except Exception:
                        pass
                flag = self.hunt(output, quiet=True)
                if flag:
                    flag_captured(flag)
                    return flag
            except Exception:
                continue
        return None

    @property
    def found_flags(self) -> List[str]:
        return self._found_flags
