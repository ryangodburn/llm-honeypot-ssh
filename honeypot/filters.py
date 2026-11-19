# Native Filters
# grep, wc, sort, head and the rest, run on the real bytes the store produced
# ls -la /etc | grep ssh | wc -l is answered from the database without the model
# file operands are read through the store, so grep root /etc/passwd works the same way
# an unimplemented flag declines and the stage goes to the model with the upstream output

# Imports
from __future__ import annotations

import fnmatch
import re
from typing import Callable, NamedTuple, Optional

from .vfs import FSError


# Raised when this filter cannot handle the arguments
class Declined(Exception):
    pass


# Separate flags from operands
# raises Declined on anything not listed
def _split(args: list[str], allowed: str, valued: tuple[str, ...] = ()):
    flags: dict[str, Optional[str]] = {}
    operands: list[str] = []
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--":
            operands.extend(args[i + 1:])
            break
        if a.startswith("--"):
            raise Declined(a)
        if a.startswith("-") and len(a) > 1:
            j = 1
            while j < len(a):
                c = a[j]
                if c in valued:
                    val = a[j + 1:]
                    if not val:
                        i += 1
                        if i >= len(args):
                            raise Declined(a)
                        val = args[i]
                    flags[c] = val
                    break
                if c not in allowed:
                    raise Declined(a)
                flags[c] = None
                j += 1
        else:
            operands.append(a)
        i += 1
    return flags, operands


def _lines(text: str) -> list[str]:
    out = text.split("\n")
    if out and out[-1] == "":
        out.pop()
    return out


# Individual Filters

# Filter output with optional stderr text and exit status
# grep needs both
class FilterResult(NamedTuple):
    stdout: str
    stderr: str = ""
    status: int = 0


_POSIX_CLASSES = {"alpha": "a-zA-Z", "digit": "0-9", "alnum": "a-zA-Z0-9", "upper": "A-Z",
                  "lower": "a-z", "space": r" \t\n\r\f\v", "blank": r" \t", "xdigit": "0-9A-Fa-f",
                  "punct": r"!-/:-@\[-`{-~", "print": r" -~", "graph": r"!-~", "cntrl": r"\x00-\x1f\x7f"}
_GREP_FLAGS = {"--ignore-case": "i", "--invert-match": "v", "--count": "c", "--line-number": "n",
               "--word-regexp": "w", "--line-regexp": "x", "--extended-regexp": "E",
               "--fixed-strings": "F", "--basic-regexp": "G", "--perl-regexp": "P", "--quiet": "q",
               "--silent": "q", "--files-with-matches": "l", "--files-without-match": "L",
               "--no-messages": "s", "--no-filename": "h", "--with-filename": "H",
               "--only-matching": "o", "--recursive": "r", "--dereference-recursive": "R",
               "--text": "a"}
_GREP_VALUED = {"--regexp": "e", "--max-count": "m", "--after-context": "A",
                "--before-context": "B", "--context": "C", "--include": "include",
                "--exclude": "exclude", "--exclude-dir": "exclude-dir"}
_SGR = {"ms": "\x1b[01;31m\x1b[K", "fn": "\x1b[35m\x1b[K", "ln": "\x1b[32m\x1b[K",
        "se": "\x1b[36m\x1b[K", "end": "\x1b[m\x1b[K"}


def _bracket(pattern: str, i: int):
    j, out = i + 1, ["["]
    if j < len(pattern) and pattern[j] in "^!":
        out.append("^")
        j += 1
    if j < len(pattern) and pattern[j] == "]":
        out.append(r"\]")
        j += 1
    while j < len(pattern) and pattern[j] != "]":
        if pattern.startswith("[:", j):
            close = pattern.find(":]", j + 2)
            if close != -1 and pattern[j + 2:close] in _POSIX_CLASSES:
                out.append(_POSIX_CLASSES[pattern[j + 2:close]])
                j = close + 2
                continue
        out.append("\\" + pattern[j] if pattern[j] in "\\[" else pattern[j])
        j += 1
    if j >= len(pattern):
        raise Declined("unmatched [")
    out.append("]")
    return "".join(out), j + 1


# Convert a POSIX BRE or ERE (GNU flavour) to a Python regex
def _posix_regex(pattern: str, extended: bool) -> str:
    out, i, n = [], 0, len(pattern)
    special = "|+?(){}"
    while i < n:
        c = pattern[i]
        if c == "\\" and i + 1 < n:
            d = pattern[i + 1]
            if d in special:
                out.append(("\\" + d) if extended else d)
            elif d == "<":
                out.append(r"\b(?=\w)")
            elif d == ">":
                out.append(r"\b(?<=\w)")
            elif d in "wWsSbB" or d.isdigit():
                out.append("\\" + d)
            else:
                out.append(re.escape(d))
            i += 2
            continue
        if c == "[":
            cls, i = _bracket(pattern, i)
            out.append(cls)
            continue
        if c in special:
            out.append(c if extended else "\\" + c)
            i += 1
            continue
        if c == "*" and (not out or out[-1] in ("^", "(", "|")):
            out.append(r"\*")
            i += 1
            continue
        out.append(c)
        i += 1
    return "".join(out)


def _grep_options(args):
    flags, patterns, opts, operands = set(), [], {}, []
    globs = {"include": [], "exclude": [], "exclude-dir": []}
    i = 0
    while i < len(args):
        a = args[i]
        i += 1
        if a == "--":
            operands.extend(args[i:])
            break
        if a.startswith("--"):
            name, eq, value = a.partition("=")
            if name in ("--color", "--colour"):
                opts["color"] = value if eq else "auto"
                continue
            if name in _GREP_FLAGS and not eq:
                flags.add(_GREP_FLAGS[name])
                continue
            if name == "--binary-files" and value in ("without-match", "text", "binary"):
                flags.add({"without-match": "I", "text": "a", "binary": ""}[value])
                continue
            if name in _GREP_VALUED:
                if not eq:
                    if i >= len(args):
                        raise Declined(a)
                    value = args[i]
                    i += 1
                key = _GREP_VALUED[name]
                if key == "e":
                    patterns.append(value)
                elif key in globs:
                    globs[key].append(value)
                else:
                    try:
                        opts[key] = int(value)
                    except ValueError:
                        raise Declined(a)
                continue
            raise Declined(a)
        if a.startswith("-") and len(a) > 1:
            if a[1:].isdigit():
                opts["C"] = int(a[1:])
                continue
            j = 1
            while j < len(a):
                c = a[j]
                if c in "emABC":
                    value = a[j + 1:]
                    if not value:
                        if i >= len(args):
                            raise Declined(a)
                        value = args[i]
                        i += 1
                    if c == "e":
                        patterns.append(value)
                    else:
                        try:
                            opts[c] = int(value)
                        except ValueError:
                            raise Declined(a)
                    break
                if c not in "ivcnwxEFGPqlLshHorRaI":
                    raise Declined(a)
                flags.add(c)
                j += 1
            continue
        operands.append(a)
    if not patterns:
        if not operands:
            raise Declined("grep needs a pattern")
        patterns = [operands.pop(0)]
    return flags, patterns, opts, operands, globs


def f_grep(args, stdin, read, *, mode=""):
    flags, patterns, opts, files, globs = _grep_options(args)
    if mode:
        flags.add(mode)
    pieces = []
    for pattern in patterns:
        for part in pattern.split("\n"):
            if "F" in flags:
                pieces.append(re.escape(part))
            elif "P" in flags:
                pieces.append(part)
            else:
                pieces.append(_posix_regex(part, "E" in flags))
    body = "|".join(f"(?:{p})" for p in pieces)
    if "w" in flags:
        body = rf"(?<!\w)(?:{body})(?!\w)"
    if "x" in flags:
        body = rf"^(?:{body})$"
    try:
        rx = re.compile(body, re.I if "i" in flags else 0)
    except re.error:
        raise Declined("bad regex")

    tty = getattr(read, "tty", False)
    colour = opts.get("color", "never")
    colour = colour in ("always", "yes", "force") or (colour in ("auto", "tty", "if-tty") and tty)
    recursive = bool(flags & {"r", "R"})
    errors: list[str] = []
    sources: list[tuple[str, Optional[bytes]]] = []
    reader = getattr(read, "bytes", None)
    walker = getattr(read, "walk", None)

    def complain(message):
        if "s" not in flags:
            errors.append(message)

    if recursive and walker is None:
        raise Declined("recursive grep needs the store")
    targets = files or (["."] if recursive else [])
    for target in targets:
        if target == "-":
            sources.append(("(standard input)", (stdin or "").encode()))
        elif recursive:
            for name, data, problem in walker(target, follow="R" in flags, include=globs["include"],
                                              exclude=globs["exclude"], exclude_dir=globs["exclude-dir"],
                                              strip_dot=not files):
                if problem:
                    complain(f"grep: {name}: {problem}")
                else:
                    sources.append((name, data))
        else:
            if globs["include"] and not any(fnmatch.fnmatch(target.rsplit("/", 1)[-1], g) for g in globs["include"]):
                continue
            try:
                data = reader(target) if reader else read(target).encode()
            except FSError as exc:
                message = exc.message
                if message.startswith(target + ": "):
                    message = message[len(target) + 2:]
                if exc.errno_name == "EISDIR" or message == "Is a directory":
                    complain(f"grep: {target}: Is a directory")
                else:
                    complain(f"grep: {target}: {message}")
                continue
            sources.append((target, data))
    if not targets:
        if stdin is None:
            raise Declined("grep with no input")
        sources.append(("(standard input)", stdin.encode()))

    show_name = ("H" in flags or len(sources) > 1 or recursive or len(files) > 1) and "h" not in flags
    after = opts.get("A", opts.get("C", 0))
    before = opts.get("B", opts.get("C", 0))
    max_count = opts.get("m")
    invert = "v" in flags

    def paint(code, text):
        return _SGR[code] + text + _SGR["end"] if colour and text else text

    def prefix(name, number, sep):
        out = ""
        if show_name:
            out += paint("fn", name) + paint("se", sep)
        if "n" in flags:
            out += paint("ln", str(number)) + paint("se", sep)
        return out

    def highlight(line):
        if not colour or invert:
            return line
        return rx.sub(lambda m: paint("ms", m.group(0)) if m.group(0) else "", line)

    out, any_selected, listed = [], False, []
    printed_group = False
    for name, data in sources:
        binary = b"\0" in data and "a" not in flags
        if binary and "I" in flags:
            continue
        text = data.decode("utf-8", "replace")
        lines = text.split("\n")
        if lines and lines[-1] == "":
            lines.pop()
        selected = [i for i, line in enumerate(lines) if bool(rx.search(line)) != invert]
        if max_count is not None:
            selected = selected[:max_count]
        if selected:
            any_selected = True
        if "q" in flags:
            continue
        if "l" in flags or "L" in flags:
            if bool(selected) == ("l" in flags):
                listed.append(paint("fn", name))
            continue
        if "c" in flags:
            out.append((paint("fn", name) + paint("se", ":") if show_name else "") + str(len(selected)))
            continue
        if binary:
            if selected:
                complain(f"grep: {name}: binary file matches")
            continue
        if "o" in flags and not invert:
            for i in selected:
                for m in rx.finditer(lines[i]):
                    if m.group(0):
                        out.append(prefix(name, i + 1, ":") + paint("ms", m.group(0)))
            continue
        if not (before or after):
            out.extend(prefix(name, i + 1, ":") + highlight(lines[i]) for i in selected)
            continue
        chosen = set(selected)
        shown = sorted({k for i in selected for k in range(max(0, i - before), min(len(lines), i + after + 1))})
        previous = None
        for k in shown:
            if previous is not None and k != previous + 1 or (previous is None and printed_group):
                out.append(paint("se", "--"))
            sep = ":" if k in chosen else "-"
            out.append(prefix(name, k + 1, sep) + (highlight(lines[k]) if k in chosen else lines[k]))
            previous = k
        printed_group = printed_group or bool(shown)
    if "l" in flags or "L" in flags:
        out = listed
    status = 0 if any_selected else 1
    if errors and not ("q" in flags and any_selected):
        status = 2
    return FilterResult("\n".join(out) if "q" not in flags else "", "\n".join(errors), status)


def f_wc(args, stdin, read):
    flags, operands = _split(args, "lwcm", ())
    texts: list[tuple[str, str]] = []
    if operands:
        for f in operands:
            texts.append((f, read(f)))
    else:
        if stdin is None:
            raise Declined("wc with no input")
        texts.append(("", stdin))

    out, totals = [], [0, 0, 0]
    for name, text in texts:
        # Lines are counted, not newline characters
        # a stage's output carries no trailing newline, so counting "\n" would lose the last line
        # byte counts add the newline each line really ends with, so wc -c matches the real tool
        rows = _lines(text)
        nl = len(rows)
        words = len(text.split())
        nbytes = sum(len(r.encode()) + 1 for r in rows)
        totals = [totals[0] + nl, totals[1] + words, totals[2] + nbytes]
        cols = []
        if not flags or "l" in flags:
            cols.append(nl)
        if not flags or "w" in flags:
            cols.append(words)
        if not flags or "c" in flags or "m" in flags:
            cols.append(nbytes)
        # With a single count and stdin, GNU wc prints just the number
        if len(cols) == 1 and not name:
            out.append(str(cols[0]))
        else:
            out.append(" ".join(f"{c:>7}" for c in cols) + (f" {name}" if name else ""))
    if len(texts) > 1:
        out.append(" ".join(f"{c:>7}" for c in totals) + " total")
    return "\n".join(out)


def f_head(args, stdin, read):
    return _head_tail(args, stdin, read, head=True)


def f_tail(args, stdin, read):
    return _head_tail(args, stdin, read, head=False)


def _head_tail(args, stdin, read, *, head):
    count, byte_count = 10, None
    rest = []
    i = 0
    while i < len(args):
        a = args[i]
        if a in ("-n", "-c") and i + 1 < len(args):
            i += 1
            try:
                value = int(args[i].lstrip("+-"))
            except ValueError:
                raise Declined(a)
            if a == "-c":
                byte_count = value
            else:
                count = value
        elif re.fullmatch(r"-[nc]\d+", a):
            value = int(a[2:])
            if a[1] == "c":
                byte_count = value
            else:
                count = value
        elif re.fullmatch(r"-\d+", a):
            count = int(a[1:])
        elif a.startswith("-") and a != "-":
            raise Declined(a)
        else:
            rest.append(a)
        i += 1
    text = read(rest[0]) if rest else stdin
    if text is None:
        raise Declined("no input")
    if byte_count is not None:
        # -c slices bytes, not lines, and prints no trailing newline
        raw = text if text.endswith("\n") else text + "\n"
        data = raw.encode()
        chunk = data[:byte_count] if head else data[-byte_count:]
        return chunk.decode("utf-8", "replace").rstrip("\n")
    lines = _lines(text)
    return "\n".join(lines[:count] if head else lines[-count:])


def f_sort(args, stdin, read):
    flags, operands = _split(args, "runfb", ())
    text = read(operands[0]) if operands else stdin
    if text is None:
        raise Declined("no input")
    lines = _lines(text)
    if "n" in flags:
        def key(s):
            m = re.match(r"\s*(-?\d+)", s)
            return (int(m.group(1)) if m else 0, s)
    elif "f" in flags:
        key = str.lower
    else:
        key = lambda s: s
    lines.sort(key=key, reverse="r" in flags)
    if "u" in flags:
        seen, uniq = set(), []
        for line in lines:
            if line not in seen:
                seen.add(line)
                uniq.append(line)
        lines = uniq
    return "\n".join(lines)


def f_uniq(args, stdin, read):
    flags, operands = _split(args, "cdu", ())
    text = read(operands[0]) if operands else stdin
    if text is None:
        raise Declined("no input")
    out, prev, run = [], None, 0
    def emit():
        if prev is None or run == 0:
            return
        if "d" in flags and run < 2:
            return
        if "u" in flags and run > 1:
            return
        out.append(f"{run:>7} {prev}" if "c" in flags else prev)
    for line in _lines(text):
        if line == prev:
            run += 1
        else:
            emit()
            prev, run = line, 1
    emit()
    return "\n".join(out)


def f_cut(args, stdin, read):
    flags, operands = _split(args, "s", ("d", "f", "c"))
    text = read(operands[0]) if operands else stdin
    if text is None:
        raise Declined("no input")
    delim = flags.get("d", "\t")
    spec = flags.get("f") or flags.get("c")
    if not spec:
        raise Declined("cut needs -f or -c")
    idx: list[int] = []
    for part in spec.split(","):
        if "-" in part:
            a, _, b = part.partition("-")
            start = int(a) if a else 1
            end = int(b) if b else 64
            idx.extend(range(start, end + 1))
        else:
            idx.append(int(part))
    out = []
    for line in _lines(text):
        fields = list(line) if "c" in flags else line.split(delim)
        if "c" not in flags and "s" in flags and delim not in line:
            continue
        picked = [fields[i - 1] for i in idx if 0 < i <= len(fields)]
        out.append(("" if "c" in flags else delim).join(picked))
    return "\n".join(out)


def f_nl(args, stdin, read):
    _split(args, "", ())
    text = stdin if stdin is not None else None
    if text is None:
        raise Declined("no input")
    return "\n".join(f"{i:6}\t{line}" for i, line in enumerate(_lines(text), 1))


def f_tac(args, stdin, read):
    _split(args, "", ())
    text = stdin if stdin is not None else None
    if text is None:
        raise Declined("no input")
    return "\n".join(reversed(_lines(text)))


def f_tee(args, stdin, read):
    # The caller applies the write itself - tee just passes the input through
    if stdin is None:
        raise Declined("no input")
    return stdin


def f_cat_stdin(args, stdin, read):
    if args or stdin is None:
        raise Declined("cat with operands is the store's job")
    return stdin


FILTERS: dict[str, Callable] = {
    "grep": f_grep, "egrep": lambda a, s, r: f_grep(a, s, r, mode="E"),
    "fgrep": lambda a, s, r: f_grep(a, s, r, mode="F"),
    "wc": f_wc, "head": f_head, "tail": f_tail, "sort": f_sort,
    "uniq": f_uniq, "cut": f_cut, "nl": f_nl, "tac": f_tac,
    "tee": f_tee, "cat": f_cat_stdin,
}

# Filters that can start a pipeline because they read files themselves
SOURCE_CAPABLE = {"grep", "egrep", "fgrep", "wc", "head", "tail", "sort",
                  "uniq", "cut"}


# Run one filter stage
# returns None when no native filter applies
def run(argv: list[str], stdin: Optional[str], read) -> Optional[str]:
    if not argv:
        return None
    name = argv[0].rsplit("/", 1)[-1]
    fn = FILTERS.get(name)
    if fn is None:
        return None
    if stdin is None and name not in SOURCE_CAPABLE:
        return None
    try:
        return fn(argv[1:], stdin, read)
    except Declined:
        return None
    except FSError as exc:
        return f"{name}: {exc.message}"
    except Exception:
        return None
