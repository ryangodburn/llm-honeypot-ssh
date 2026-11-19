# Verification
# compares each model-produced stage with the filesystem store and logs disagreements as flags
# it detects and never repairs, so the hallucination rate stays a real measurement
# checks for invented paths, false "No such file or directory" and listings that disagree

# Imports
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

from .vfs import VFS, FSError, normpath

# Absolute paths in the output
# deliberately conservative - two components minimum, no trailing punctuation, prose false positives left out
_ABS_PATH = re.compile(r"(?<![\w/])(/(?:[\w.+-]+/)+[\w.+-]+)")
_NOT_FOUND = re.compile(
    r"([^\s:]+): (?:No such file or directory|not found)", re.I)
_IGNORE_PREFIXES = ("/proc/", "/sys/", "/dev/", "/run/")
_LISTING_CMDS = {"ls", "dir", "find", "tree"}


@dataclass
class Verdict:
    flags: list[str] = field(default_factory=list)
    details: list[str] = field(default_factory=list)
    checked: int = 0


def _resolvable(vfs: VFS, session, raw: str) -> Optional[bool]:
    home = "/root" if session.username == "root" else f"/home/{session.username}"
    try:
        path = normpath(session.cwd, raw, home)
    except Exception:
        return None
    if path.startswith(_IGNORE_PREFIXES):
        return None
    try:
        return vfs.resolve(path, follow=False) is not None
    except FSError:
        return None


def check(vfs: VFS, session, argv: list[str], output: str,
          *, max_paths: int = 25) -> Verdict:
    v = Verdict()
    if not output:
        return v

    cmd = argv[0].rsplit("/", 1)[-1] if argv else ""

    # 1. Invented paths
    invented: list[str] = []
    for m in list(_ABS_PATH.finditer(output))[:max_paths]:
        raw = m.group(1)
        exists = _resolvable(vfs, session, raw)
        if exists is None:
            continue
        v.checked += 1
        if not exists:
            invented.append(raw)
    if invented:
        v.flags.append("invented_path")
        v.details.append("not in store: " + ", ".join(sorted(set(invented))[:6]))

    # 2. Missing-file errors for paths that do exist
    denied: list[str] = []
    for m in _NOT_FOUND.finditer(output):
        raw = m.group(1)
        exists = _resolvable(vfs, session, raw)
        if exists is None:
            continue
        v.checked += 1
        if exists:
            denied.append(raw)
    if denied:
        v.flags.append("denied_existing_path")
        v.details.append("exists but reported missing: " + ", ".join(denied[:6]))

    # 3. A listing that disagrees with the store
    if cmd in _LISTING_CMDS:
        target = next((a for a in argv[1:] if not a.startswith("-")),
                      session.cwd)
        home = ("/root" if session.username == "root"
                else f"/home/{session.username}")
        try:
            entries = {n.name for n in vfs.listdir(
                normpath(session.cwd, target, home))}
        except FSError:
            entries = set()
        if entries:
            named = set()
            for line in output.split("\n"):
                token = line.strip().split()[-1] if line.strip() else ""
                if token and "/" not in token and not token.startswith("total"):
                    named.add(token)
            ghosts = {n for n in named if n not in entries
                      and n not in (".", "..")}
            missing = {n for n in entries if not n.startswith(".")} - named
            v.checked += len(named)
            if ghosts:
                v.flags.append("listing_has_ghosts")
                v.details.append("listed but absent: "
                                 + ", ".join(sorted(ghosts)[:6]))
            if missing and len(missing) > len(entries) * 0.5:
                v.flags.append("listing_incomplete")
                v.details.append(f"omitted {len(missing)} of {len(entries)}")

    return v
