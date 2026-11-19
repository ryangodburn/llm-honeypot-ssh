# Extra Filters
# sed, awk, cut, tr, rev, base64 and digests, registered into filters.FILTERS
# same contract as filters.py - fn(args, stdin, read) returns text with no trailing newline
# anything outside the implemented subset raises Declined
# covers recon idioms whose answers are fully set by bytes the store already has
# for example awk -F: '{print $1}' /etc/passwd, md5sum /tmp/payload.sh and base64 -d
# sed here is read-only, in-place edits belong to the effects layer

# Imports
from __future__ import annotations

import hashlib
import re
from typing import Optional

from .filters import Declined, FILTERS, SOURCE_CAPABLE, _lines, _split


# File operands if present, otherwise stdin
def _gather(operands, stdin, read, util: str) -> str:
    if not operands:
        if stdin is None:
            raise Declined(f"{util} needs input")
        return stdin
    chunks = []
    for path in operands:
        if path == "-":
            chunks.append(stdin or "")
            continue
        chunks.append(read(path))
    return "\n".join(c.rstrip("\n") for c in chunks)


# The sed Filter

_SUB = re.compile(r"^(?P<addr>/(?:[^/\\]|\\.)*/|\d+|\$)?s(?P<d>[/|,#])"
                  r"(?P<pat>(?:[^\\]|\\.)*?)(?P=d)"
                  r"(?P<rep>(?:[^\\]|\\.)*?)(?P=d)(?P<f>[gip]*)$")
_DEL = re.compile(r"^(?P<addr>/(?:[^/\\]|\\.)*/|\d+|\$)d$")
_PRT = re.compile(r"^(?P<addr>/(?:[^/\\]|\\.)*/|\d+|\$)p$")


def _addr_hit(addr: Optional[str], i: int, line: str, total: int) -> bool:
    if not addr:
        return True
    if addr == "$":
        return i == total
    if addr.isdigit():
        return i == int(addr)
    try:
        return re.search(addr[1:-1], line) is not None
    except re.error:
        raise Declined("bad address")


# Apply one sed expression to text
# declines anything outside s///, Nd and /re/p
def apply_script(script: str, text: str, *, quiet: bool = False) -> str:
    lines = _lines(text)
    total = len(lines)
    script = script.strip()

    m = _SUB.match(script)
    if m:
        try:
            rx = re.compile(m.group("pat"),
                            re.I if "i" in (m.group("f") or "") else 0)
        except re.error:
            raise Declined("bad regex")
        count = 0 if "g" in (m.group("f") or "") else 1
        rep = m.group("rep").replace("&", r"\g<0>")
        out = []
        for i, line in enumerate(lines, 1):
            if _addr_hit(m.group("addr"), i, line, total):
                try:
                    line = rx.sub(rep, line, count=count)
                except re.error:
                    raise Declined("bad replacement")
            out.append(line)
        return "\n".join(out)

    m = _DEL.match(script)
    if m:
        return "\n".join(l for i, l in enumerate(lines, 1)
                         if not _addr_hit(m.group("addr"), i, l, total))

    m = _PRT.match(script)
    if m:
        hits = [l for i, l in enumerate(lines, 1)
                if _addr_hit(m.group("addr"), i, l, total)]
        # Without -n every line prints, and matches print twice
        if quiet:
            return "\n".join(hits)
        out = []
        for i, line in enumerate(lines, 1):
            out.append(line)
            if _addr_hit(m.group("addr"), i, line, total):
                out.append(line)
        return "\n".join(out)

    raise Declined("sed script outside the implemented subset")


def f_sed(args, stdin, read):
    # -i is left out of the allowed flags on purpose
    # so sed -i declines here and reaches the effects layer, which changes the store
    flags, operands = _split(args, "nrE", ("e",))
    script = flags.get("e") or (operands.pop(0) if operands else None)
    if not script:
        raise Declined("sed needs a script")
    text = _gather(operands, stdin, read, "sed")
    return apply_script(script, text, quiet="n" in flags)


# The awk Filter

_PRINT = re.compile(r"^\{\s*print\s*(?P<what>[^}]*)\}$")


def f_awk(args, stdin, read):
    flags, operands = _split(args, "", ("F", "v"))
    if not operands:
        raise Declined("awk needs a program")
    script = operands.pop(0)
    sep = flags.get("F")
    if sep in ("\\t", "\t"):
        sep = "\t"
    m = _PRINT.match(script.strip())
    if not m:
        raise Declined("only {print ...} is implemented")
    what = m.group("what").strip()
    text = _gather(operands, stdin, read, "awk")

    out = []
    for line in _lines(text):
        parts = line.split(sep) if sep else line.split()
        if not what or what == "$0":
            out.append(line)
            continue
        cells = []
        for token in what.replace(",", " ").split():
            if token == "NF":
                cells.append(str(len(parts)))
            elif token.startswith("$"):
                try:
                    n = int(token[1:])
                except ValueError:
                    raise Declined("computed field references")
                cells.append(parts[n - 1] if 0 < n <= len(parts) else "")
            elif token.startswith('"') and token.endswith('"'):
                cells.append(token[1:-1])
            else:
                raise Declined("expressions in print")
        out.append(" ".join(cells))
    return "\n".join(out)


# The tr and rev Filters

def _expand(spec: str) -> str:
    spec = (spec.replace("[:lower:]", "abcdefghijklmnopqrstuvwxyz")
                .replace("[:upper:]", "ABCDEFGHIJKLMNOPQRSTUVWXYZ")
                .replace("[:digit:]", "0123456789")
                .replace("[:alpha:]", "abcdefghijklmnopqrstuvwxyz"
                                      "ABCDEFGHIJKLMNOPQRSTUVWXYZ")
                .replace("[:space:]", " \t\n"))
    out, i = "", 0
    while i < len(spec):
        if i + 2 < len(spec) and spec[i + 1] == "-":
            out += "".join(chr(c) for c in range(ord(spec[i]), ord(spec[i + 2]) + 1))
            i += 3
        else:
            out += spec[i]
            i += 1
    return out


def f_tr(args, stdin, read):
    flags, operands = _split(args, "dsc", ())
    if stdin is None:
        raise Declined("tr only reads stdin")
    if "d" in flags:
        if not operands:
            raise Declined("tr -d needs a set")
        drop = set(_expand(operands[0]))
        return "\n".join("".join(c for c in line if c not in drop)
                         for line in _lines(stdin))
    if len(operands) < 2:
        raise Declined("tr needs two sets")
    src, dst = _expand(operands[0]), _expand(operands[1])
    if not dst:
        raise Declined("empty replacement set")
    dst = dst + dst[-1] * (len(src) - len(dst))
    return stdin.translate(str.maketrans(src, dst[:len(src)]))


def f_rev(args, stdin, read):
    _flags, operands = _split(args, "", ())
    text = _gather(operands, stdin, read, "rev")
    return "\n".join(line[::-1] for line in _lines(text))


# Digest Filters

_ALGOS = {"md5sum": "md5", "sha1sum": "sha1", "sha224sum": "sha224",
          "sha256sum": "sha256", "sha384sum": "sha384", "sha512sum": "sha512"}


def _hash_factory(util: str):
    algo = _ALGOS[util]

    def handler(args, stdin, read):
        _flags, operands = _split(args, "b", ())
        rows = []
        for path in operands or [None]:
            if path is None:
                if stdin is None:
                    raise Declined("no input")
                data, label = stdin.encode(), "-"
            else:
                # The trailing newline the store strips is part of the file
                # put it back before hashing or every digest is wrong
                text = read(path)
                data = text.encode() if text.endswith("\n") else (text + "\n").encode()
                label = path
            rows.append(f"{hashlib.new(algo, data).hexdigest()}  {label}")
        return "\n".join(rows)

    return handler


# The base64 Filter

def f_base64(args, stdin, read):
    import base64 as b64
    flags, operands = _split(args, "diw", ())
    text = _gather(operands, stdin, read, "base64")
    if "d" in flags:
        try:
            return b64.b64decode(re.sub(r"\s", "", text).encode(),
                                 validate=True).decode("utf-8", "replace")
        except Exception:
            return "base64: invalid input"
    enc = b64.b64encode(text.encode()).decode()
    return "\n".join(enc[i:i + 76] for i in range(0, len(enc), 76))


# Registration

def install() -> None:
    FILTERS.update({
        "sed": f_sed, "awk": f_awk, "gawk": f_awk, "mawk": f_awk,
        "tr": f_tr, "rev": f_rev, "base64": f_base64,
    })
    for util in _ALGOS:
        FILTERS[util] = _hash_factory(util)
    # Filters that can start a pipeline because they take file operands
    SOURCE_CAPABLE.update({"sed", "awk", "gawk", "mawk", "rev", "base64",
                           *_ALGOS})


install()
