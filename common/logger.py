"""
Readable, coloured console output for the live demo.
The assignment asks for visible logs: device IDs, hashes, roots, decisions.
"""
from __future__ import annotations

import os
import sys
from datetime import datetime

if os.name == "nt":
    os.system("")  # enables ANSI colours in the Windows terminal

_COLOURS = {
    "reset": "\033[0m",
    "dim": "\033[2m",
    "bold": "\033[1m",
    "red": "\033[91m",
    "green": "\033[92m",
    "yellow": "\033[93m",
    "blue": "\033[94m",
    "cyan": "\033[96m",
    "magenta": "\033[95m",
}


_QUIET = False


def set_quiet(quiet: bool) -> None:
    """Silence per event logs (used by benchmarks so printing does not distort timings)."""
    global _QUIET
    _QUIET = quiet


def _c(name: str, text: str) -> str:
    return f"{_COLOURS[name]}{text}{_COLOURS['reset']}"


def _now() -> str:
    return datetime.now().strftime("%I:%M:%S %p")


def _emit(tag: str, colour: str, source: str, msg: str) -> None:
    if _QUIET:
        return
    print(f"{_c('dim', _now())} {_c(colour, tag.ljust(6))} {_c('bold', source.ljust(10))} {msg}", flush=True)


def info(source: str, msg: str) -> None:
    _emit("INFO", "blue", source, msg)


def ok(source: str, msg: str) -> None:
    _emit("OK", "green", source, msg)


def fail(source: str, msg: str) -> None:
    _emit("FAIL", "red", source, msg)


def warn(source: str, msg: str) -> None:
    _emit("WARN", "yellow", source, msg)


def step(title: str) -> None:
    line = "=" * 70
    print(f"\n{_c('cyan', line)}\n{_c('cyan', '  ' + title)}\n{_c('cyan', line)}", flush=True)


def short(h: str, n: int = 12) -> str:
    """Shorten a long hex string for display."""
    return h if len(h) <= 2 * n else f"{h[:n]}...{h[-4:]}"


if __name__ == "__main__":
    step("Logger self test")
    info("fog", "information line")
    ok("fog", "success line")
    warn("fog", "warning line")
    fail("fog", "failure line")
    sys.exit(0)