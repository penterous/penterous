#!/usr/bin/env bash
# Penterous — Quick installer script
# Run: bash install.sh

set -e

echo "=============================================="
echo " Penterous — Binary Exploitation Framework"
echo " Quick Installer"
echo "=============================================="
echo ""

# Check Python version
python3 --version >/dev/null 2>&1 || { echo "ERROR: python3 not found"; exit 1; }
PY_VER=$(python3 -c 'import sys; print(sys.version_info.minor)')
if [ "$PY_VER" -lt 11 ]; then
    echo "WARNING: Python 3.11+ recommended (you have 3.$PY_VER)"
fi

echo "[*] Installing Python dependencies..."
pip3 install -r requirements.txt

echo ""
echo "[*] Checking system tools..."

# GDB
if command -v gdb >/dev/null 2>&1; then
    echo "[+] GDB: found ($(gdb --version | head -1))"
else
    echo "[!] GDB: NOT found — install with: sudo apt install gdb"
fi

# checksec
if command -v checksec >/dev/null 2>&1; then
    echo "[+] checksec: found"
else
    echo "[!] checksec: NOT found — install with: sudo apt install checksec"
fi

# ROPgadget
if command -v ROPgadget >/dev/null 2>&1; then
    echo "[+] ROPgadget: found"
elif python3 -c 'import ropgadget' 2>/dev/null; then
    echo "[+] ROPgadget: found (python module)"
else
    echo "[!] ROPgadget: NOT found — install with: pip install ropgadget"
fi

# one_gadget (optional)
if command -v one_gadget >/dev/null 2>&1; then
    echo "[+] one_gadget: found"
else
    echo "[?] one_gadget: optional — install with: gem install one_gadget (requires Ruby)"
fi

echo ""
echo "=============================================="
echo " Installation complete!"
echo "=============================================="
echo ""
echo " Usage:"
echo "   python3 penterous.py auto ./binary"
echo "   python3 penterous.py auto ./binary --libc ./libc.so.6"
echo "   python3 penterous.py auto ./binary --remote 10.0.0.1:9001"
echo "   python3 penterous.py analyze ./binary"
echo "   python3 penterous.py exploit ./binary --strategy ret2win"
echo ""
echo " Run tests:"
echo "   pytest tests/ -v"
echo ""
