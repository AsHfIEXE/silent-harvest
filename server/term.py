"""Terminal helpers for silent-harvest operator tools.

Zero-dependency ANSI color + VT handling that works on Windows 10+
(conhost/Windows Terminal) and POSIX. Respects NO_COLOR and non-tty
(robots get plain text automatically).

Usage:
    import term
    term.init()                      # once: enables VT on Windows consoles
    term.cprint("green", term.GREEN, "LOOT %s" % vid)

    for line in term.table(["ID", "PARTS", "SIZE"], rows): print(line)
"""
import os
import sys

# ---------------------------------------------------------------- ansi codes
class C:
    RESET = "\x1b[0m"
    BOLD = "\x1b[1m"
    DIM = "\x1b[2m"
    UNDERLINE = "\x1b[4m"
    REVERSE = "\x1b[7m"
    RED = "\x1b[31m"
    GREEN = "\x1b[32m"
    YELLOW = "\x1b[33m"
    BLUE = "\x1b[34m"
    MAGENTA = "\x1b[35m"
    CYAN = "\x1b[36m"
    WHITE = "\x1b[37m"
    GREY = "\x1b[90m"
    BG_RED = "\x1b[41m"
    BG_GREEN = "\x1b[42m"
    BG_BLUE = "\x1b[44m"
    BG_GREY = "\x1b[100m"
    GREEN_BG = "\x1b[42m\x1b[30m"   # keep flake8-quiet aliases
    RED_BG = "\x1b[41m\x1b[30m"


_ENABLEED = {"vt": False, "color": False}


def init(stream=None):
    """Enable VT processing on Windows and decide whether color is used."""
    stream = stream or sys.stdout
    vt = False
    if os.name == "nt":
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            handle = kernel32.GetStdHandle(-11 if stream is sys.stdout else -12)
            mode = ctypes.c_uint32()
            if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
                new = mode.value | 0x0004  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
                vt = bool(kernel32.SetConsoleMode(handle, new))
        except Exception:
            vt = False
    else:
        vt = True
    _ENABLEED["vt"] = vt
    _ENABLEED["color"] = (
        vt
        and hasattr(stream, "isatty") and stream.isatty()
        and os.environ.get("NO_COLOR", "") == ""
        and os.environ.get("TERM", "") != "dumb"
    )
    return _ENABLEED["color"]


def color_on():
    return _ENABLEED["color"]


def s(text, *codes):
    """Wrap text in codes (no-op when color is off)."""
    if not _ENABLEED["color"] or not codes:
        return str(text)
    return "".join(codes) + str(text) + C.RESET


def cprint(text, *codes, **kw):
    print(s(text, *codes), **kw)


def human_size(n):
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024 or unit == "TB":
            return ("%d %s" % (n, unit)) if unit == "B" else ("%.1f %s" % (n, unit))
        n /= 1024.0


def _visible_width(cell):
    # strip ANSI for width math
    import re
    return len(re.sub(r"\x1b\[[0-9;]*m", "", str(cell)))


def table(headers, rows, colors=None, indent=1, sep="  "):
    """Render an aligned table. `colors` optionally maps row-index -> code
    prefix (e.g. C.GREY). Returns a list of lines."""
    widths = [_visible_width(h) for h in headers]
    norm_rows = []
    for r in rows:
        r = [str(c) for c in r]
        for i, cell in enumerate(r):
            widths[i] = max(widths[i], _visible_width(cell))
        norm_rows.append(r)

    def fmt(cells):
        return sep.join(
            cell + " " * (widths[i] - _visible_width(cell))
            for i, cell in enumerate(cells))

    out = []
    out.append(" " * indent + s(fmt(headers), C.BOLD, C.UNDERLINE))
    for idx, r in enumerate(norm_rows):
        line = " " * indent + fmt(r)
        if colors and idx in colors:
            line = s(line, colors[idx])
        out.append(line)
    return out


def hr(width=64, char="─", code=(C.DIM,)):
    return s(char * width, *code)


def box(lines, title="", width=62):
    """Simple drawn box around lines, top row may carry a title."""
    out = ["┌─ %s %s" % (title, "─" * max(0, width - 4 - len(title))) + "┐"]
    for ln in lines:
        ln = ln.rstrip()
        vis = _visible_width(ln)
        out.append("│ " + ln + " " * max(0, width - 2 - vis) + "│")
    out.append("└" + "─" * width + "┘")
    return out
