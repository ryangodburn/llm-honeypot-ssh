# Listing Formats
# ls, stat and du output in GNU's exact layout
# per-listing column widths, a total in 1 KiB blocks and the six-month date switch
# plus the colour codes Ubuntu's ls alias prints on a tty

# Imports
from __future__ import annotations

import math
import re
import stat as statmod
import time
from typing import Optional, Sequence

from .vfs import Node

# GNU ls six months - 6 * 30 * 24 * 3600 seconds
SIX_MONTHS = 15_552_000

_KIND_CHAR = {"dir": "d", "file": "-", "link": "l", "chr": "c", "blk": "b",
              "fifo": "p", "sock": "s"}

# The part of Ubuntu's default LS_COLORS that shows up in listings
_C_RESET = "\x1b[0m"
_C_DIR = "01;34"
_C_LINK = "01;36"
_C_EXEC = "01;32"
_C_ARCHIVE = "01;31"
_C_SETUID = "37;41"
_C_SETGID = "30;43"
_C_STICKY = "37;44"
_C_FIFO = "40;33"
_C_SOCK = "01;35"
_C_DEV = "40;33;01"

_ARCHIVE_EXT = (".tar", ".tgz", ".gz", ".bz2", ".xz", ".zip", ".rpm", ".deb",
                ".7z", ".rar", ".zst", ".lz4", ".tbz2", ".jar")


# Mode string such as drwxr-xr-x
# includes the s and t bits in their shared positions
def mode_string(node: Node) -> str:
    m = node.mode
    out = [_KIND_CHAR.get(node.kind, "-")]
    for shift, (r, w, x) in ((6, ("r", "w", "x")), (3, ("r", "w", "x")),
                             (0, ("r", "w", "x"))):
        bits = (m >> shift) & 0o7
        out.append(r if bits & 4 else "-")
        out.append(w if bits & 2 else "-")
        out.append(x if bits & 1 else "-")
    if m & statmod.S_ISUID:
        out[3] = "s" if out[3] == "x" else "S"
    if m & statmod.S_ISGID:
        out[6] = "s" if out[6] == "x" else "S"
    if m & statmod.S_ISVTX:
        out[9] = "t" if out[9] == "x" else "T"
    return "".join(out)


def colour_for(node: Node) -> Optional[str]:
    if node.kind == "dir":
        if node.mode & statmod.S_ISVTX:
            return _C_STICKY
        return _C_DIR
    if node.kind == "link":
        return _C_LINK
    if node.kind in ("chr", "blk"):
        return _C_DEV
    if node.kind == "fifo":
        return _C_FIFO
    if node.kind == "sock":
        return _C_SOCK
    if node.mode & statmod.S_ISUID:
        return _C_SETUID
    if node.mode & statmod.S_ISGID:
        return _C_SETGID
    if node.mode & 0o111:
        return _C_EXEC
    if node.name.lower().endswith(_ARCHIVE_EXT):
        return _C_ARCHIVE
    return None


def paint(node: Node, text: Optional[str] = None, *, colour: bool = True) -> str:
    label = node.name if text is None else text
    if not colour:
        return label
    c = colour_for(node)
    return f"\x1b[{c}m{label}{_C_RESET}" if c else label


def ls_date(mtime: float, now: Optional[float] = None) -> str:
    now = time.time() if now is None else now
    # The host clock is UTC, like a cloud image
    tm = time.gmtime(mtime)
    if abs(now - mtime) > SIX_MONTHS:
        return time.strftime("%b %e  %Y", tm)
    return time.strftime("%b %e %H:%M", tm)


# Human-readable sizes with ls -h and du -h rounding
# one decimal below 10, none at or above
def human_size(n: int) -> str:
    if n < 1024:
        return str(n)
    val = float(n)
    for unit in ("K", "M", "G", "T", "P"):
        val /= 1024.0
        if val < 1024:
            rounded = math.ceil(val * 10) / 10
            if rounded < 10:
                return f"{rounded:.1f}{unit}"
            return f"{math.ceil(val):.0f}{unit}"
    return f"{val:.0f}E"


# Block count (st_blocks) in 1 KiB units as total reports it, for a 4 KiB ext4 block size
def blocks_1k(node: Node) -> int:
    if node.kind in ("chr", "blk", "fifo", "sock"):
        return 0
    if node.kind == "link":
        return 0
    if node.kind == "dir":
        return 4
    return int(math.ceil(node.size / 4096.0) * 4)


# Long listing as ls -l prints it
# column widths are computed across this listing only
def format_long(nodes: Sequence[Node], *, colour: bool = True,
                human: bool = False, show_total: bool = True,
                now: Optional[float] = None,
                prefix: str = "") -> list[str]:
    if not nodes:
        return ["total 0"] if show_total else []

    sizes = [human_size(n.size) if human else str(n.size) for n in nodes]
    w_link = max(len(str(n.nlink)) for n in nodes)
    w_user = max(len(n.uname) for n in nodes)
    w_group = max(len(n.gname) for n in nodes)
    w_size = max(len(s) for s in sizes)

    lines: list[str] = []
    if show_total:
        lines.append(f"total {sum(blocks_1k(n) for n in nodes)}")
    for node, size in zip(nodes, sizes):
        name = paint(node, prefix + node.name, colour=colour)
        if node.kind == "link" and node.target:
            name += f" -> {node.target}"
        lines.append(
            f"{mode_string(node)} {str(node.nlink):>{w_link}} "
            f"{node.uname:<{w_user}} {node.gname:<{w_group}} "
            f"{size:>{w_size}} {ls_date(node.mtime, now)} {name}"
        )
    return lines


# Short listing as ls prints it without -l
# down-then-across columns with two spaces between
def format_columns(nodes: Sequence[Node], *, width: int = 80,
                   colour: bool = True) -> list[str]:
    names = [n.name for n in nodes]
    if not names:
        return []
    longest = max(len(n) for n in names) + 2
    cols = max(1, width // longest)
    if cols == 1:
        return [paint(n, colour=colour) for n in nodes]
    rows = math.ceil(len(names) / cols)
    out: list[str] = []
    for r in range(rows):
        cells = []
        for c in range(cols):
            i = c * rows + r
            if i >= len(nodes):
                continue
            pad = longest - len(names[i]) if c * rows + rows + r < len(nodes) else 0
            cells.append(paint(nodes[i], colour=colour) + " " * pad)
        out.append("".join(cells).rstrip())
    return out


# Decline unsupported conversions rather than invent missing metadata
def stat_format_supported(pattern: str) -> bool:
    return '%' not in re.sub(r'%[nsaAuUgGhFfYy%]', '', pattern)


def format_stat_fields(node: Node, pattern: str, operand: str) -> str:
    kind = {"dir": "directory", "file": "regular file", "link": "symbolic link",
            "chr": "character special file", "blk": "block special file",
            "fifo": "fifo", "sock": "socket"}[node.kind]
    if node.kind == 'file' and node.size == 0:
        kind = 'regular empty file'
    fields = {'n': operand, 's': str(node.size), 'a': format(node.mode & 0o7777, 'o'),
              'A': mode_string(node), 'u': str(node.uid), 'U': node.uname,
              'g': str(node.gid), 'G': node.gname, 'h': str(node.nlink),
              'F': kind, 'f': format(node.st_mode, 'x'), 'Y': str(int(node.mtime)),
              'y': time.strftime('%Y-%m-%d %H:%M:%S.000000000 +0000', time.gmtime(node.mtime)),
              '%': '%'}
    return re.sub(r'%([nsaAuUgGhFfYy%])', lambda match: fields[match[1]], pattern)


# Full stat output, including the three timestamps and the device line
def format_stat(node: Node, *, fs_blocks: int = 4096) -> str:
    kind = {"dir": "directory", "file": "regular file", "link": "symbolic link",
            "chr": "character special file", "blk": "block special file",
            "fifo": "fifo", "sock": "socket"}.get(node.kind, "regular file")
    if node.kind == "file" and node.size == 0:
        kind = "regular empty file"
    name = (f"'{node.name}' -> '{node.target}'" if node.kind == "link"
            else f"'{node.path}'")
    ts = time.strftime("%Y-%m-%d %H:%M:%S.000000000 +0000",
                       time.gmtime(node.mtime))
    return "\n".join([
        f"  File: {name}",
        f"  Size: {node.size:<14} Blocks: {blocks_1k(node) * 2:<10} "
        f"IO Block: {fs_blocks} {kind}",
        f"Device: 253,0\tInode: {_fake_inode(node.path):<11} Links: {node.nlink}",
        f"Access: ({node.mode & 0o7777:04o}/{mode_string(node)})  "
        f"Uid: ({node.uid:5d}/{node.uname:>8})   "
        f"Gid: ({node.gid:5d}/{node.gname:>8})",
        f"Access: {ts}",
        f"Modify: {ts}",
        f"Change: {ts}",
        " Birth: -",
    ])


# Synthetic inode that never changes for a path within a deployment
def _fake_inode(path: str) -> int:
    h = 2166136261
    for ch in path.encode():
        h = ((h ^ ch) * 16777619) & 0xFFFFFFFF
    return 100_000 + (h % 8_000_000)


def format_df(*, human: bool = False, total_kb: int = 40_470_704,
              used_kb: int = 16_672_312) -> str:
    avail = total_kb - used_kb - 1_200_000
    pct = round(used_kb / (used_kb + avail) * 100)

    def f(kb: int) -> str:
        return human_size(kb * 1024) if human else str(kb)

    rows = [
        ("tmpfs", 401_684, 1_064, 400_620, "/run"),
        ("/dev/root", total_kb, used_kb, avail, "/"),
        ("tmpfs", 2_008_412, 0, 2_008_412, "/dev/shm"),
        ("tmpfs", 5_120, 0, 5_120, "/run/lock"),
        ("/dev/sda15", 106_858, 6_182, 100_677, "/boot/efi"),
        ("tmpfs", 401_680, 4, 401_676, "/run/user/1000"),
    ]
    head = (f"{'Filesystem':<15} {'Size':>5} {'Used':>5} {'Avail':>5} Use% "
            "Mounted on" if human else
            f"{'Filesystem':<15} {'1K-blocks':>10} {'Used':>9} {'Available':>9} "
            "Use% Mounted on")
    lines = [head]
    for fs, size, used, av, mount in rows:
        use = round(used / (used + av) * 100) if (used + av) else 0
        if human:
            lines.append(f"{fs:<15} {f(size):>5} {f(used):>5} {f(av):>5} "
                         f"{use:>3}% {mount}")
        else:
            lines.append(f"{fs:<15} {size:>10} {used:>9} {av:>9} "
                         f"{use:>3}% {mount}")
    _ = pct
    return "\n".join(lines)
