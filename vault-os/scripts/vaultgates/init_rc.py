"""Android init .rc files, read the way init reads them (system/core/init of the Lineage
22.2 / 24.0 trees), not with line greps.

tokenizer.cpp: backslash-newline continues a line (leading blanks of the next line are
dropped), double quotes group, '#' at the start of a token comments out the rest of the line,
\\n \\r \\t \\\\ are escapes. parser.cpp: `on`, `service` and `import` open a section at any
indentation.
"""

import re

SECTION_KEYWORDS = ("on", "service", "import")
# Builtins that start a service (builtins.cpp): `enable` starts a disabled service whose
# class is already started, `exec_start` runs it to completion.
START_KEYWORDS = ("start", "restart", "enable", "exec_start")
EXEC_KEYWORDS = ("exec", "exec_background")
ADBD_PATH = re.compile(r"(^|/)adbd$")
# The adbd FunctionFS endpoint (mkdir/mount/write/symlink of functions/ffs.adb).
ADB_ENDPOINT = re.compile(r"functions/ffs\.adb|/dev/usb-ffs/adb|functionfs\s+adb")
DEBUGGABLE_TRIGGER = "property:ro.debuggable=1"

_ESCAPES = {"n": "\n", "r": "\r", "t": "\t", "\\": "\\"}
_CONTINUATION = re.compile(r"\\\r?\n[ \t]*")


def init_lines(text):
    """Yield (line_number, args, raw) for every logical init line.

    line_number is the physical line the logical line starts on; raw is the source text of
    the logical line, continuations included (see display()). An unterminated quote ends
    the file, as in init."""
    data = text + "\n"
    n = len(data)
    pos = 0
    line = 1
    start_line = 1
    args = []
    line_start = 0
    while pos < n:
        c = data[pos]
        if c == "\n":
            if args:
                yield start_line, args, data[line_start:pos]
            pos += 1
            line += 1
            start_line = line
            args = []
            line_start = pos
            continue
        if c in " \t\r":
            pos += 1
            continue
        if c == "#":
            while pos < n and data[pos] != "\n":
                pos += 1
            continue
        token = []
        while pos < n:
            c = data[pos]
            if c in " \t\r":
                pos += 1
                break
            if c == "\n":
                break
            if c == '"':
                pos += 1
                while pos < n and data[pos] != '"':
                    if data[pos] == "\n":
                        line += 1
                    token.append(data[pos])
                    pos += 1
                if pos >= n:
                    return
                pos += 1
                continue
            if c == "\\":
                pos += 1
                if pos >= n:
                    break
                escaped = data[pos]
                if escaped in "nrt\\":
                    token.append(_ESCAPES[escaped])
                    pos += 1
                elif escaped == "\r" and data[pos + 1: pos + 2] != "\n":
                    pos += 1
                elif escaped in "\r\n":
                    pos += 2 if escaped == "\r" else 1
                    line += 1
                    while pos < n and data[pos] in " \t":
                        pos += 1
                else:
                    token.append(escaped)
                    pos += 1
                continue
            token.append(c)
            pos += 1
        args.append("".join(token))


def display(raw):
    """A logical line for messages: each continuation becomes one space."""
    return _CONTINUATION.sub(" ", raw)
