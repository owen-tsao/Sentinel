"""Windows recursive-delete recognizer.

bashlex cannot see `rd /s /q`, `Remove-Item -Recurse`, or `robocopy /MIR`,
and every 2026 drive-root wipe was one of them. This is a tiny explicit
recognizer that judges the resolved path. Path semantics are untested on a
Windows host; it exists so the shape is caught, not to claim Windows support.
"""

from __future__ import annotations

import re

WIN_DELETE = re.compile(
    r"(?i)\b(?:rd|rmdir)\s+(?:/s\s+/q|/q\s+/s|/s)\b|"
    r"\bdel\s+(?:/[fsq]\s+)*|"
    r"\bRemove-Item\b(?=.*-Recurse)|"
    r"\brobocopy\b(?=.*/MIR)"
)
WIN_DRIVE_ROOT = re.compile(r"(?i)^(?:[a-z]:\\?|\\)$")
WIN_PROFILE = re.compile(r"(?i)^[a-z]:\\users\\?[^\\]*\\?$|^%userprofile%\\?$|^\$env:userprofile\\?$|^\$home\\?$|^~\\?$")
# A PowerShell/cmd variable in a recursive-delete target that this text never
# assigns. Judged as the shell would when the variable is empty.
WIN_UNRESOLVED_VAR = re.compile(r"(?i)^(?:\$(?!env:)[a-z_][a-z0-9_]*|%[a-z_][a-z0-9_]*%)(?:[\\/]\*?)?$")
NESTED_CMD = re.compile(r'cmd(?:\.exe)?\s+/c\s+"', re.I)


def resolved_windows_target(command: str) -> str | None:
    """The path argument of a Windows recursive delete, or None if the command has none.

    Applies the quote collapse that caused the incidents: `cmd /c "rd /s /q \\"X\\""`
    becomes `rd /s /q ""` once cmd re-parses, so an inner `\\"` pair with
    nothing left is treated as empty, which is the drive root (`\\`).
    """
    m = WIN_DELETE.search(command)
    if not m:
        return None
    rest = command[m.end():].strip()
    while True:
        pm = re.match(r"(?i)^-(?:literal)?path\s+", rest)
        if pm:
            rest = rest[pm.end():]
            break
        fm = re.match(r"^-[A-Za-z]+(?::\$?\w+)?\s*", rest)
        if fm and not re.match(r"^-[A-Za-z]+[\\/]", rest):
            rest = rest[fm.end():]
            continue
        break
    if re.match(r'^\\"\s*\\"', rest) or rest in {'""', "''", ""} or re.match(r'^\\"\\"', rest):
        return "\\"
    tok = re.match(r'^(?:"([^"]*)"|\'([^\']*)\'|(\S+))', rest)
    if not tok:
        return "\\"
    path = next(g for g in tok.groups() if g is not None)
    path = re.sub(r"[\\/]?\*+$", "", path)
    if re.match(r"(?i)^[a-z]:$", path):
        path += "\\"
    return path or "\\"


def variable_assigned(command: str, target: str) -> bool:
    """True if the command text assigns the variable named in `target` (`$x = ...`)."""
    name = re.escape(target.strip("$%\\/*"))
    return re.search(r"(?i)\$" + name + r"\s*=", command) is not None


def under_cwd(target: str, cwd: str) -> bool:
    """Case-insensitive, separator-insensitive prefix check for a Windows path against `cwd`."""
    return target.lower().replace("/", "\\").startswith(cwd.lower().replace("/", "\\"))
