# Write-Back Effects
# applies the filesystem effects of a model-answered command to the store
# so wget -O /tmp/x.sh followed by ls /tmp shows the file in the same session
# effects come from the command itself, never from the model's output
# nothing is applied when the output looks like a failure
# sizes come from the path, so a file's size does not change between two ls calls

# Imports
from __future__ import annotations

import hashlib
import posixpath
import re
from dataclasses import dataclass
from typing import Optional

from .vfs import VFS, FSError, normpath

_FAILED = re.compile(
    r"(No such file or directory|Permission denied|command not found|"
    r"Operation not permitted|cannot create|failed to|unable to|"
    r"Connection refused|could not resolve|Name or service not known|"
    r"Read-only file system|Is a directory|Not a directory|No space left)",
    re.I)

_ARCHIVE_SUFFIXES = (".tar.gz", ".tar.xz", ".tar.bz2", ".tgz", ".tar", ".zip")


@dataclass
class Effect:
    path: str
    # "file" or "dir"
    kind: str = "file"
    mode: int = 0o644
    size: Optional[int] = None
    note: str = ""


_SIZE_HINT = (
    re.compile(r"\bLength:\s*(\d{1,10})\b"),
    re.compile(r"saved\s*\[(\d{1,10})"),
    re.compile(r"\[(\d{1,10})/\1\]"),
    re.compile(r"\b(\d{1,10}) bytes\b"),
)
_MAX_REPORTED_SIZE = 1 << 30


# The byte count a transfer reported, if it gave one
# the file was already chosen from the command, so the worst case is a wrong number
# this keeps wget followed by ls -l consistent, and it is capped because the URL is the attacker's
def size_from_output(output: str) -> Optional[int]:
    for rx in _SIZE_HINT:
        m = rx.search(output or "")
        if m:
            val = int(m.group(1))
            if 0 < val <= _MAX_REPORTED_SIZE:
                return val
    return None


def _synthetic_size(path: str, lo: int = 400, hi: int = 60_000) -> int:
    h = int(hashlib.sha256(path.encode()).hexdigest()[:8], 16)
    return lo + h % (hi - lo)


def _basename_from_url(url: str) -> Optional[str]:
    tail = url.split("?", 1)[0].rstrip("/").rsplit("/", 1)[-1]
    return tail or None


# Filesystem effects implied by a command line, from the command alone
def infer(argv: list[str], cwd: str, home: str) -> list[Effect]:
    if not argv:
        return []
    cmd = argv[0].rsplit("/", 1)[-1]
    args = argv[1:]
    out: list[Effect] = []

    def P(p: str) -> str:
        return normpath(cwd, p, home)

    def flag_value(*names: str) -> Optional[str]:
        for i, a in enumerate(args):
            if a in names and i + 1 < len(args):
                return args[i + 1]
            for n in names:
                if len(n) == 2 and a.startswith(n) and len(a) > 2:
                    return a[2:]
        return None

    if cmd == "wget":
        target = flag_value("-O", "-o", "--output", "--output-document")
        urls = [a for a in args if re.match(r"\w+://", a)]
        if target and target != "-":
            out.append(Effect(P(target), mode=0o644,
                              size=_synthetic_size(target), note=cmd))
        elif urls:
            name = _basename_from_url(urls[0])
            if name:
                out.append(Effect(P(name), mode=0o644,
                                  size=_synthetic_size(name), note=cmd))

    elif cmd == "tee":
        for a in args:
            if not a.startswith("-"):
                out.append(Effect(P(a), note="tee"))

    elif cmd == "dd":
        for a in args:
            if a.startswith("of="):
                out.append(Effect(P(a[3:]), size=_synthetic_size(a),
                                  note="dd"))

    elif cmd in ("tar",) and any(f in "".join(args) for f in ("x",)):
        src = flag_value("-f", "--file") or next(
            (a for a in args if a.endswith(_ARCHIVE_SUFFIXES)), None)
        target_dir = flag_value("-C", "--directory") or "."
        if src:
            name = posixpath.basename(src)
            for suf in _ARCHIVE_SUFFIXES:
                if name.endswith(suf):
                    name = name[: -len(suf)]
                    break
            out.append(Effect(P(posixpath.join(target_dir, name)), kind="dir",
                              mode=0o755, note="tar -x"))

    elif cmd == "unzip":
        src = next((a for a in args if a.endswith(".zip")), None)
        target_dir = flag_value("-d") or "."
        if src:
            name = posixpath.basename(src)[:-4]
            out.append(Effect(P(posixpath.join(target_dir, name)), kind="dir",
                              mode=0o755, note="unzip"))

    elif cmd == "git" and args[:1] == ["clone"]:
        rest = [a for a in args[1:] if not a.startswith("-")]
        if rest:
            name = rest[1] if len(rest) > 1 else _basename_from_url(rest[0])
            if name:
                name = name[:-4] if name.endswith(".git") else name
                out.append(Effect(P(name), kind="dir", mode=0o755,
                                  note="git clone"))

    elif cmd in ("gcc", "cc", "g++", "clang"):
        target = flag_value("-o")
        if target:
            out.append(Effect(P(target), mode=0o755,
                              size=_synthetic_size(target, 8_000, 90_000),
                              note=cmd))

    elif cmd == "ssh-keygen":
        target = flag_value("-f")
        if target:
            out.append(Effect(P(target), mode=0o600, size=2602,
                              note="ssh-keygen"))
            out.append(Effect(P(target + ".pub"), mode=0o644, size=568,
                              note="ssh-keygen"))

    elif cmd == "openssl":
        target = flag_value("-out")
        if target:
            out.append(Effect(P(target), size=_synthetic_size(target),
                              note="openssl"))

    elif cmd in ("python", "python3") and "-m" in args:
        i = args.index("-m")
        if i + 1 < len(args) and args[i + 1] == "venv" and i + 2 < len(args):
            out.append(Effect(P(args[i + 2]), kind="dir", mode=0o755,
                              note="venv"))

    elif cmd == "base64":
        target = flag_value("-o", "--output")
        if target:
            out.append(Effect(P(target), size=_synthetic_size(target),
                              note="base64"))

    return out


def looks_failed(output: str) -> bool:
    return bool(_FAILED.search(output or ""))


# Apply the inferred effects and return notes for the log
# may_write(session, path) is the same permission check the store applies to a typed command
# without it wget -O /etc/backdoor as a normal user would create a file rm then refuses to delete
def apply(vfs: VFS, session, argv: list[str], output: str,
          *, ident, may_write=None) -> list[str]:
    if looks_failed(output):
        return []
    home = "/root" if session.username == "root" else f"/home/{session.username}"
    notes: list[str] = []
    reported = size_from_output(output)
    for eff in infer(argv, session.cwd, home):
        if may_write is not None and not may_write(session, eff.path):
            continue
        if (reported is not None and eff.kind == "file"
                and eff.note in ("wget", "curl", "dd", "base64")):
            eff.size = reported
        try:
            if vfs.exists(eff.path) and eff.kind == "dir":
                continue
            if eff.kind == "dir":
                parts, cur = [p for p in eff.path.split("/") if p], ""
                for part in parts:
                    cur += "/" + part
                    if not vfs.exists(cur):
                        vfs.mkdir(cur, uid=ident.uid, gid=ident.gid,
                                  uname=ident.uname, gname=ident.gname,
                                  mode=eff.mode)
            else:
                size = eff.size if eff.size is not None else 0
                # Metadata only - the bytes a download would have produced are unknown
                # inventing content that later cat calls must repeat is a hallucination with extra steps
                vfs.write_file(eff.path, b"", uid=ident.uid, gid=ident.gid,
                               uname=ident.uname, gname=ident.gname,
                               mode=eff.mode, store_content=False)
                vfs._x("UPDATE nodes SET size=? WHERE realm=? AND path=?",
                       (size, vfs.realm, eff.path))
            notes.append(f"{eff.note}:{eff.path}")
        except FSError:
            continue
    return notes
