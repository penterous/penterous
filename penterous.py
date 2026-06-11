#!/usr/bin/env python3
"""
Penterous — Automated CTF Binary Exploitation Framework
by p3nt2r0us | Educational use only
"""
import sys
import os
import hashlib
import json
import argparse
import json

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from utils.logger import (
    print_banner, info, success, warning, error, phase, console
)
from utils.pwntools_wrap import PWNTOOLS_AVAILABLE, set_arch
from utils.gdb_helper import check_gdb_available, check_checksec_available
from core.binary import Binary
from core.fuzzer import AutoFuzzer
from core.exploit_engine import ExploitEngine
from core.report import ReportGenerator


_EPILOG = """
Penterous — Automated CTF Binary Exploitation Framework
by p3nt2r0us | Educational use only

Usage:
  python penterous.py auto    ./binary [options]
  python penterous.py analyze ./binary [options]
  python penterous.py exploit ./binary --strategy ret2win [options]
  python penterous.py fuzz    ./binary [options]
  python penterous.py report  ./binary --results last [options]

Remote options:
  --remote HOST:PORT
        Run exploit locally first, then auto-escalate to the remote target.
        The remote flag replaces the local flag in the terminal and PDF report.
        Accepts IP address or hostname.
        Example: python penterous.py auto ./vuln --remote 10.0.0.1:9001

  --remote-only HOST:PORT
        Skip local exploitation entirely.
        Penterous performs static analysis on the local binary,
        then attacks the remote server directly — no local process spawned.
        Pair with --offset N to skip fuzzing as well.
        Accepts IP address or hostname.
        Example: python penterous.py auto ./vuln --remote-only 10.0.0.1:9001 --offset 44

Common options:
  --offset N          Manual offset in bytes (skip fuzzing)
  --libc PATH         Path to target libc
  --strategy NAME     Force a specific strategy  (exploit command only)
  --timeout N         Timeout per step in seconds (default: 30)
  --no-pdf            Skip PDF report generation
  --verbose / -v      Verbose output
  --quiet  / -q       Only output the captured flag
  --debug             Full traceback on errors
  --output-dir DIR    Directory for reports/results (default: ./reports)
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog='penterous',
        description='Penterous — Automated CTF Binary Exploitation Framework',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=_EPILOG,
    )

    sub = parser.add_subparsers(dest='command', required=True)

    auto_p = sub.add_parser('auto', help='Full auto pipeline: analyze → fuzz → exploit → report')
    auto_p.add_argument('binary', help='Path to ELF binary')
    _add_common(auto_p)

    analyze_p = sub.add_parser('analyze', help='Static analysis only (no exploitation)')
    analyze_p.add_argument('binary', help='Path to ELF binary')
    analyze_p.add_argument('--json', action='store_true', help='Output in JSON format')
    _add_common(analyze_p)

    fuzz_p = sub.add_parser('fuzz', help='Dynamic fuzzing — find crash offset')
    fuzz_p.add_argument('binary', help='Path to ELF binary')
    fuzz_p.add_argument('--max-size', type=int, default=4096, metavar='N')
    _add_common(fuzz_p)

    exploit_p = sub.add_parser('exploit', help='Targeted exploitation')
    exploit_p.add_argument('binary', help='Path to ELF binary')
    exploit_p.add_argument('--strategy', '-s', required=True,
                           choices=['ret2win', 'ret2shellcode', 'ret2libc', 'leak_ret2libc',
                                    'rop_chain', 'rop', 'format_string', 'fmt',
                                    'heap_uaf', 'uaf', 'srop'])
    _add_common(exploit_p)

    report_p = sub.add_parser('report', help='Generate report from saved results')
    report_p.add_argument('binary', help='Path to ELF binary (for context)')
    report_p.add_argument('--results', default='last')
    _add_common(report_p)

    return parser


def _add_common(p: argparse.ArgumentParser):
    p.add_argument('--libc', metavar='PATH')
    p.add_argument('--remote', metavar='IP:PORT',
                   help='After local success, auto-escalate to remote target')
    p.add_argument('--remote-only', metavar='IP:PORT', dest='remote_only',
                   help='Skip local exploitation — attack remote directly')
    p.add_argument('--offset', type=int, metavar='N')
    p.add_argument('--timeout', type=int, default=30, metavar='N')
    p.add_argument('--no-pdf', action='store_true')
    p.add_argument('--verbose', '-v', action='store_true')
    p.add_argument('--quiet', '-q', action='store_true')
    p.add_argument('--debug', action='store_true')
    p.add_argument('--output-dir', default='./reports', metavar='DIR')


def check_environment(verbose: bool = False):
    if verbose:
        console.print("\n[bold cyan]Environment Check:[/]")
        console.print(f"  pwntools : {'[green]OK[/]' if PWNTOOLS_AVAILABLE else '[red]MISSING[/]'}")
        console.print(f"  GDB      : {'[green]OK[/]' if check_gdb_available() else '[yellow]NOT FOUND[/]'}")
        console.print(f"  checksec : {'[green]OK[/]' if check_checksec_available() else '[yellow]NOT FOUND[/]'}")
        console.print()


def parse_remote(remote_str: str):
    if ':' not in remote_str:
        raise ValueError(f"Invalid remote format '{remote_str}' — expected HOST:PORT")
    host, port_str = remote_str.rsplit(':', 1)
    return host.strip(), int(port_str.strip())


# ── Remote escalation prompt — PDF généré UNE SEULE FOIS à la fin ────────────

def _prompt_and_escalate(engine: ExploitEngine, result, gen: ReportGenerator,
                          bin_report, args) -> bool:
    """
    Demande si l'utilisateur veut escalader vers un serveur remote.
    Le PDF n'est PAS encore généré quand cette fonction est appelée.

    Flux :
      - Utilisateur dit Non / Ctrl+C  → PDF local généré ici, return False
      - Tentative remote RÉUSSIE      → PDF remote généré ici, return True
      - Tentative remote ÉCHOUÉE      → PDF local généré ici, return False
    """
    console.print()
    console.print("[bold bright_cyan]" + "─" * 60 + "[/]")
    console.print("[bold bright_cyan]  ■■  LOCAL EXPLOIT SUCCEEDED  ■■[/]")
    console.print("[bold bright_cyan]" + "─" * 60 + "[/]")
    console.print()

    try:
        answer = console.input("[bold]Escalate to remote server? [y/N]: [/]").strip().lower()
        if answer not in ('y', 'yes'):
            # Pas de remote → PDF local maintenant
            if not args.no_pdf:
                phase("REPORT — LOCAL")
                gen.generate(bin_report, result)
            return False

        host_port = console.input(
            "[bold]Target [HOST:PORT]: [/]"
        ).strip()
        if ':' not in host_port:
            error("Format invalide. Utilise HOST:PORT")
            if not args.no_pdf:
                phase("REPORT — LOCAL")
                gen.generate(bin_report, result)
            return False

        host, port_str = host_port.rsplit(':', 1)
        port = int(port_str.strip())

        libc_input = console.input(
            "[bold]Remote libc path (leave blank to skip): [/]"
        ).strip()

        if libc_input:
            if os.path.exists(libc_input):
                from utils.pwntools_wrap import load_elf
                engine.binary.libc = load_elf(libc_input)
                engine.rop.libc = engine.binary.libc
                info(f"Remote libc loaded: {libc_input}")
            else:
                warning("libc file not found — using local libc")

        # ── Tentative remote ──────────────────────────────────────────────────
        remote_result = engine.run_remote_escalation(
            result.strategy_used, result, host, port
        )

        if remote_result.success and remote_result.flag:
            # Merge remote flag
            result.remote_flag = remote_result.flag
            result.flag        = remote_result.flag
            result.mode        = 'local+remote'
            result.remote_host = host
            result.remote_port = port
            result.exploit_script = engine._generate_exploit_script(
                result.strategy_used, result, host, port
            )
            _print_remote_flag_banner(remote_result.flag)
            # PDF final — remote flag
            if not args.no_pdf:
                phase("REPORT — REMOTE FLAG")
                gen.generate(bin_report, result)
            return True

        else:
            warning("Remote exploit failed — génération du PDF local.")
            if not args.no_pdf:
                phase("REPORT — LOCAL")
                gen.generate(bin_report, result)
            return False

    except (KeyboardInterrupt, EOFError):
        console.print()
        info("Remote escalation annulée — génération du PDF local.")
        if not args.no_pdf:
            phase("REPORT — LOCAL")
            gen.generate(bin_report, result)
        return False


def _print_remote_flag_banner(flag: str):
    console.print()
    console.print("[bold bright_yellow]" + "─" * 60 + "[/]")
    console.print("[bold bright_yellow]   ■■  REMOTE FLAG CAPTURED  ■■[/]")
    console.print("[bold bright_yellow]" + "─" * 60 + "[/]")
    console.print(f"[bold bright_yellow]   {flag}[/]")
    console.print("[bold bright_yellow]" + "─" * 60 + "[/]")
    console.print()


# ── Command handlers ──────────────────────────────────────────────────────────

def cmd_analyze(args):
    binary = Binary(args.binary, libc_path=getattr(args, 'libc', None))
    report = binary.analyze()
    report.display()
    if getattr(args, 'json', False):
        out = {
            'path': report.path,
            'arch': report.arch,
            'bits': report.bits,
            'protections': {k: str(v) for k, v in report.protections.items()},
            'vuln_functions': [str(vf) for vf in report.vuln_functions],
            'win_functions': [(n, hex(a)) for n, a in (report.win_functions or [])],
        }
        print(json.dumps(out, indent=2))


def cmd_fuzz(args):
    binary = Binary(args.binary, libc_path=getattr(args, 'libc', None))
    binary.analyze()
    phase("DYNAMIC FUZZING")
    fuzzer = AutoFuzzer(binary, timeout=args.timeout, verbose=args.verbose)
    offset = fuzzer.find_offset(max_size=getattr(args, 'max_size', 4096))
    if offset > 0:
        success(f"Offset found: {offset} bytes")
    else:
        error("Offset not found — try increasing --max-size")


def cmd_exploit(args):
    binary = Binary(args.binary, libc_path=getattr(args, 'libc', None))
    report = binary.analyze()

    remote_host, remote_port, remote_only = None, None, False
    if getattr(args, 'remote_only', None):
        remote_host, remote_port = parse_remote(args.remote_only)
        remote_only = True
    elif getattr(args, 'remote', None):
        remote_host, remote_port = parse_remote(args.remote)

    offset = getattr(args, 'offset', None)
    if offset is None and not remote_only:
        # ── Offset cache ──────────────────────────────────────────────────
        cache_dir = os.path.expanduser("~/.cache/penterous")
        os.makedirs(cache_dir, exist_ok=True)
        try:
            with open(binary.path, 'rb') as _f:
                _sha = hashlib.sha256(_f.read()).hexdigest()[:16]
            cache_file = os.path.join(cache_dir, f"{os.path.basename(binary.path)}_{_sha}.json")
        except Exception:
            cache_file = None
        cached_offset = None
        if cache_file and os.path.exists(cache_file):
            try:
                with open(cache_file) as _cf:
                    cached_offset = json.load(_cf).get('offset')
            except Exception:
                cached_offset = None
        if cached_offset is not None and cached_offset >= 0:
            offset = cached_offset
            info(f"Offset loaded from cache: {offset} bytes")
        else:
            phase("DYNAMIC FUZZING")
            fuzzer = AutoFuzzer(binary, timeout=args.timeout, verbose=args.verbose)
            offset = fuzzer.find_offset()
            if offset < 0:
                error("Could not determine offset — use --offset N")
                sys.exit(1)
            elif cache_file:
                try:
                    with open(cache_file, 'w') as _cf:
                        json.dump({'offset': offset, 'binary': binary.path}, _cf)
                except Exception:
                    pass
    elif offset is None:
        offset = 0

    engine = ExploitEngine(binary, offset, report, timeout=args.timeout, verbose=args.verbose)
    result = engine.run(
        force_strategy=getattr(args, 'strategy', None),
        remote_host=remote_host, remote_port=remote_port,
        remote_only=remote_only,
    )

    _print_result_summary(result)

    gen = ReportGenerator(args.output_dir)

    if result.success and not remote_host and not remote_only and not args.quiet:
        # Succès local sans cible remote → prompt, PDF généré DANS _prompt_and_escalate
        _prompt_and_escalate(engine, result, gen, report, args)
    else:
        # --remote / --remote-only fourni, ou exploit raté → PDF direct maintenant
        if not args.no_pdf:
            phase("REPORT")
            gen.generate(report, result)

    _save_result_json(result, report, args.output_dir, args.binary)
    return result


def cmd_auto(args):
    """Full pipeline: analyze → fuzz → select strategy → exploit → report."""
    remote_host, remote_port, remote_only = None, None, False
    if getattr(args, 'remote_only', None):
        remote_host, remote_port = parse_remote(args.remote_only)
        remote_only = True
    elif getattr(args, 'remote', None):
        remote_host, remote_port = parse_remote(args.remote)

    # ── Phase 1: Static analysis ──────────────────────────────────────────────
    phase("PHASE 1: STATIC ANALYSIS")
    binary = Binary(args.binary, libc_path=getattr(args, 'libc', None))
    bin_report = binary.analyze()
    bin_report.display()

    # ── Phase 2: Fuzzing ──────────────────────────────────────────────────────
    offset = getattr(args, 'offset', None)
    if remote_only:
        offset = offset or 0
        info(f"Remote-only mode — skipping local fuzzing (offset={offset})")
    elif offset is None:
        # ── Pre-check: skip fuzzing for pure format-string binaries ────────
        # Only skip if: printf present AND no dangerous BOF function (gets/scanf/strcpy)
        # Binaries with both gets+printf still need fuzzing for the BOF offset.
        import re as _re
        _bof_funcs = {'gets', 'scanf', 'strcpy', 'sprintf', 'read', 'strcat'}
        _has_bof_func = any(vf.name in _bof_funcs for vf in binary.vuln_functions)
        _has_printf = any(vf.name in ('printf', 'fprintf') for vf in binary.vuln_functions)
        _has_menu = any(_re.search(r'\b[1-9]\s*[.)]\s*\w', s)
                        for s in getattr(binary, 'interesting_strings', []))
        if _has_printf and not _has_bof_func and not _has_menu:
            offset = 0
            info("Pure format-string binary (no BOF func) — skipping fuzzing")
        elif _has_menu and bool(binary.win_functions):
            offset = 0
            info("Menu binary with win function — skipping fuzzing (heap overwrite)")
        # Variable overwrite: 'You win!' string + gets() → BOF cache handles offset
        else:
            # ── Offset cache: skip fuzzing if binary hasn't changed ───────────
            cache_dir = os.path.expanduser("~/.cache/penterous")
            os.makedirs(cache_dir, exist_ok=True)
            try:
                with open(binary.path, 'rb') as _f:
                    _sha = hashlib.sha256(_f.read()).hexdigest()[:16]
                cache_file = os.path.join(cache_dir, f"{os.path.basename(binary.path)}_{_sha}.json")
            except Exception:
                cache_file = None
                _sha = None

            cached_offset = None
            if cache_file and os.path.exists(cache_file):
                try:
                    with open(cache_file) as _cf:
                        cached_offset = json.load(_cf).get('offset')
                except Exception:
                    cached_offset = None

            if cached_offset is not None and cached_offset >= 0:
                offset = cached_offset
                info(f"Offset loaded from cache: {offset} bytes (use --offset N to override)")
            else:
                phase("PHASE 2: DYNAMIC FUZZING")
                fuzzer = AutoFuzzer(binary, timeout=args.timeout, verbose=args.verbose)
                offset = fuzzer.find_offset()
                if offset < 0:
                    warning("Fuzzing failed — defaulting to offset=0 (use --offset N to override)")
                    offset = 0
                elif cache_file:
                    try:
                        with open(cache_file, 'w') as _cf:
                            json.dump({'offset': offset, 'binary': binary.path}, _cf)
                    except Exception:
                        pass
    else:
        info(f"Using manual offset: {offset} bytes")

    # ── Phase 3: Strategy selection ───────────────────────────────────────────
    phase("PHASE 3: STRATEGY SELECTION")
    engine = ExploitEngine(binary, offset, bin_report,
                           timeout=args.timeout, verbose=args.verbose)
    strategy = engine.select_strategy()
    info(f"Auto-selected strategy: [bold cyan]{strategy}[/]")

    # ── Phase 4/5: Exploitation ───────────────────────────────────────────────
    result = engine.run(
        force_strategy=strategy,
        remote_host=remote_host, remote_port=remote_port,
        remote_only=remote_only,
    )

    # ── Phase 6: Report ───────────────────────────────────────────────────────
    phase("PHASE 6: REPORT")
    _print_result_summary(result)

    gen = ReportGenerator(args.output_dir)

    if result.success and not remote_host and not remote_only and not args.quiet:
        # Succès local sans cible remote connue → prompt, PDF généré DANS _prompt_and_escalate
        _prompt_and_escalate(engine, result, gen, bin_report, args)
    else:
        # --remote / --remote-only fourni, ou exploit raté → PDF direct maintenant
        if not args.no_pdf:
            gen.generate(bin_report, result)
        else:
            print(gen.generate_text_report(bin_report, result))

    _save_result_json(result, bin_report, args.output_dir, args.binary)

    if args.quiet and result.flag:
        import sys
        sys.stdout = sys.__stdout__  # restore for flag output
        print(result.flag)

    return result


def cmd_report(args):
    import glob
    binary = Binary(args.binary, libc_path=getattr(args, 'libc', None))
    bin_report = binary.analyze()

    results_glob = os.path.join(args.output_dir,
                                f"{os.path.basename(args.binary)}_*.json")
    files = sorted(glob.glob(results_glob))
    if not files:
        error(f"No result files found in {args.output_dir}")
        sys.exit(1)

    result_file = files[-1]
    info(f"Loading results from: {result_file}")

    with open(result_file) as f:
        data = json.load(f)

    from strategies.base import ExploitResult
    result = ExploitResult(
        success=data.get('success', False),
        flag=data.get('flag'),
        strategy_used=data.get('strategy', 'unknown'),
        offset=data.get('offset', 0),
        payload=bytes.fromhex(data.get('payload_hex', '')),
        output=bytes.fromhex(data.get('output_hex', '')),
        duration=data.get('duration', 0),
        libc_base=data.get('libc_base', 0),
        mode=data.get('mode', 'local'),
        remote_host=data.get('remote_host', ''),
        remote_port=data.get('remote_port', 0),
        remote_flag=data.get('remote_flag'),
        exploit_script=data.get('exploit_script', ''),
    )

    gen = ReportGenerator(args.output_dir)
    gen.generate(bin_report, result)


def _print_result_summary(result):
    from utils.logger import flag_captured
    console.print()

    display_flag = result.remote_flag or result.flag

    if result.success and display_flag:
        if result.remote_flag:
            _print_remote_flag_banner(result.remote_flag)
        else:
            flag_captured(display_flag)
    elif result.success:
        success("Exploit succeeded — shell obtained but no flag pattern detected")
        success("Try: cat flag | cat flag.txt | find / -name flag*")
    else:
        error(f"Exploit failed: {result.error_msg or 'unknown error'}")
        warning("Suggestions:")
        warning("  — Try a different strategy: --strategy <name>")
        warning("  — Provide libc: --libc ./libc.so.6")
        warning("  — Specify offset: --offset N")

    mode_display = result.mode.upper()
    if result.remote_host:
        mode_display += f" → {result.remote_host}:{result.remote_port}"
    console.print(f"[dim]  Duration: {result.duration:.2f}s | Mode: {mode_display}[/]")


def _save_result_json(result, bin_report, output_dir: str, binary_path: str):
    import datetime
    os.makedirs(output_dir, exist_ok=True)
    date_str = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    name = os.path.basename(binary_path)
    path = os.path.join(output_dir, f"{name}_{date_str}.json")
    data = {
        'binary': binary_path,
        'arch': bin_report.arch,
        'bits': bin_report.bits,
        'success': result.success,
        'flag': result.flag,
        'remote_flag': result.remote_flag,
        'strategy': result.strategy_used,
        'offset': result.offset,
        'payload_hex': result.payload.hex() if result.payload else '',
        'output_hex': result.output.hex() if result.output else '',
        'duration': result.duration,
        'libc_base': result.libc_base,
        'mode': result.mode,
        'remote_host': result.remote_host,
        'remote_port': result.remote_port,
        'exploit_script': result.exploit_script,
        'protections': {k: str(v) for k, v in bin_report.protections.items()},
    }
    try:
        with open(path, 'w') as f:
            json.dump(data, f, indent=2)
        info(f"Results saved: {path}")
    except Exception as e:
        warning(f"Could not save JSON results: {e}")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    # Banner toujours affiché en premier, même en mode quiet
    print_banner()

    parser = build_parser()
    args = parser.parse_args()

    if args.quiet:
        import io
        from utils.logger import set_quiet
        set_quiet(True)
        sys.stdout = open('/dev/null', 'w')
        sys._quiet_mode = True

    if args.verbose:
        check_environment(verbose=True)

    if args.debug:
        import traceback
        def debug_hook(t, v, tb):
            traceback.print_exception(t, v, tb)
            sys.exit(1)
        sys.excepthook = debug_hook

    try:
        if args.command == 'auto':
            cmd_auto(args)
        elif args.command == 'analyze':
            cmd_analyze(args)
        elif args.command == 'fuzz':
            cmd_fuzz(args)
        elif args.command == 'exploit':
            cmd_exploit(args)
        elif args.command == 'report':
            cmd_report(args)
    except FileNotFoundError as e:
        error(str(e))
        sys.exit(1)
    except KeyboardInterrupt:
        console.print("\n[yellow][[!]] Interrupted by user[/]")
        sys.exit(0)
    except Exception as e:
        if args.debug:
            import traceback
            traceback.print_exc()
        else:
            error(f"Unexpected error: {e}")
            error("Run with --debug for full traceback")
        sys.exit(1)


if __name__ == '__main__':
    main()
