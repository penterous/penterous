"""
Penterous — Colored terminal logger using rich.
"""
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.theme import Theme
from rich import box
import time

# Mode quiet: désactivé par défaut, activé via set_quiet(True)
_QUIET = False

def set_quiet(val: bool):
    global _QUIET
    _QUIET = val
    if val:
        import io
        console._file = io.StringIO()  # redirect all console output to void

THEME = Theme({
    "info":    "cyan",
    "success": "bold green",
    "warning": "bold yellow",
    "error":   "bold red",
    "phase":   "bold magenta",
    "flag":    "bold bright_green",
    "dim":     "dim white",
})

console = Console(theme=THEME)

BANNER = (
    "\n"
    "██████╗ ███████╗███╗   ██╗████████╗███████╗██████╗  ██████╗ ██╗   ██╗███████╗\n"
    "██╔══██╗██╔════╝████╗  ██║╚══██╔══╝██╔════╝██╔══██╗██╔═══██╗██║   ██║██╔════╝\n"
    "██████╔╝█████╗  ██╔██╗ ██║   ██║   █████╗  ██████╔╝██║   ██║██║   ██║███████╗\n"
    "██╔═══╝ ██╔══╝  ██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗██║   ██║██║   ██║╚════██║\n"
    "██║     ███████╗██║ ╚████║   ██║   ███████╗██║  ██║╚██████╔╝╚██████╔╝███████║\n"
    "╚═╝     ╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚══════╝\n"
    "\n"
    "  by p3nt2r0us  |  Binary Exploitation Framework  |  CTF Training Tool\n\n"
     "  Github: https:kf\n"
    "\n"
)
def print_banner():
    console.print(f"[bold cyan]{BANNER}[/]")

def info(msg: str):
    if _QUIET: return
    console.print(f"[info]\\[*][/] {msg}")

def success(msg: str):
    console.print(f"[success]\\[+][/] {msg}")

def warning(msg: str):
    if _QUIET: return
    console.print(f"[warning]\\[!][/] {msg}")

def error(msg: str):
    if _QUIET: return
    console.print(f"[error]\\[✗][/] {msg}")

def phase(title: str):
    if _QUIET: return
    console.print()
    console.rule(f"[phase]■■ {title} ■■[/]", style="magenta")

def flag_captured(flag: str):
    console.print()
    console.print(Panel(
        f"[flag]■  FLAG CAPTURED  ■\n\n  {flag}[/]",
        border_style="bright_green",
        expand=False,
        padding=(1, 4),
    ))
    console.print()

def print_protection_table(protections: dict):
    table = Table(title="Binary Protections", box=box.ROUNDED, border_style="cyan")
    table.add_column("Protection", style="bold white")
    table.add_column("Status", justify="center")
    table.add_column("Impact")
    rows = [
        ("NX / DEP",      protections.get("NX",     False), "Shellcode impossible → ROP required"),
        ("Stack Canary",  protections.get("Canary",  False), "BOF direct blocked → leak needed"),
        ("ASLR",          protections.get("ASLR",    False), "libc addresses randomized → leak needed"),
        ("PIE",           protections.get("PIE",     False), "Binary addresses randomized → partial overwrite / leak"),
        ("Full RELRO",    protections.get("RELRO",   False) == "Full", "GOT overwrite impossible"),
        ("FORTIFY",       protections.get("FORTIFY", False), "Dangerous functions limited"),
    ]
    for name, enabled, impact in rows:
        status = "[bold green]ENABLED[/]" if enabled else "[bold red]DISABLED[/]"
        table.add_row(name, status, impact)
    console.print(table)

def print_strategy_table(strategies: list):
    table = Table(title="Recommended Strategies", box=box.ROUNDED, border_style="magenta")
    table.add_column("#", justify="right", style="dim")
    table.add_column("Strategy", style="bold white")
    table.add_column("Confidence", justify="right")
    table.add_column("Selected")
    for i, (name, confidence) in enumerate(strategies, 1):
        selected = "[bold bright_green]← AUTO-SELECTED[/]" if i == 1 else ""
        conf_color = "green" if confidence >= 80 else "yellow" if confidence >= 50 else "red"
        table.add_row(str(i), name, f"[{conf_color}]{confidence}%[/]", selected)
    console.print(table)

def spinner(msg: str):
    return Progress(SpinnerColumn(), TextColumn(msg), transient=True)
