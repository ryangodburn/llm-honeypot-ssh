# Filesystem Commands
# ls, cat, cd, stat, find, chmod and the other file commands, answered from the store
# handle() returns the rendered text, or None so the controller sends the command elsewhere
# an unimplemented flag combination declines rather than approximating
# error messages are exact - ls, cat and cd each word a missing path differently
# permissions come from the image's own /etc/passwd and /etc/group, so they match id
# redirects write to the store and print nothing, which is what cross-session persistence needs

# Imports
from __future__ import annotations

import hashlib
import posixpath
import re
import shlex
import stat as statmod
import time
from dataclasses import dataclass, field, replace
from typing import Callable, Optional

from . import fsformat as fmt
from .vfs import VFS, FSError, Node, _sortkey, normpath

# Commands handled here outright - anything else goes elsewhere
_REDIRECT = re.compile(r"\s(?P<op>2?>>?|>)\s*(?P<path>[^\s>|&;]+)\s*$")
# Constructs that are not approximated
# && and ; are split first, so only a bare & (background) reaches this check
_UNSUPPORTED = ("|", "`", "$(", "<")
_BARE_AMP = re.compile(r"&(?!&)|(?<!&)&")


@dataclass
class Identity:
    uid: int
    gid: int
    uname: str
    gname: str
    groups: set[int] = field(default_factory=set)
    home: str = "/root"

    @property
    def is_root(self) -> bool:
        return self.uid == 0


# Ubuntu's pam_umask with USERGROUPS_ENAB
# 0002 for a user whose primary group is their own private group, 0022 otherwise and for root
# umask reports the same value, so created modes and umask agree
def session_umask(session, vfs) -> int:
    value = getattr(session, "shell_umask", None)
    if value is not None:
        return value
    entry = vfs.passwd_users().get(session.username)
    if not entry or entry[0] == 0:
        return 0o022
    return 0o002 if vfs.group_names().get(entry[1]) == session.username else 0o022


# Parse touch -t [[CC]YY]MMDDhhmm[.ss], or a practical subset of -d strings, in UTC
def parse_touch_time(value: str, *, stamp: bool = False) -> Optional[float]:
    import calendar
    now = time.time()
    if stamp:
        m = re.fullmatch(r"(\d{2,4})?(\d{2})(\d{2})(\d{2})(\d{2})(?:\.(\d{2}))?", value)
        if not m or (m.group(1) and len(m.group(1)) == 3):
            return None
        year = m.group(1)
        if year is None:
            year = time.gmtime(now).tm_year
        elif len(year) == 2:
            year = int(year) + (1900 if int(year) >= 69 else 2000)
        try:
            return float(calendar.timegm((int(year), int(m.group(2)), int(m.group(3)), int(m.group(4)),
                                          int(m.group(5)), int(m.group(6) or 0), 0, 0, 0)))
        except (ValueError, OverflowError):
            return None
    text = value.strip()
    if text.startswith("@") and re.fullmatch(r"@-?\d+(\.\d+)?", text):
        return float(text[1:])
    relative = {"now": 0, "today": 0, "yesterday": -86400, "tomorrow": 86400}
    if text.lower() in relative:
        return now + relative[text.lower()]
    m = re.fullmatch(r"(\d+)\s+(second|minute|hour|day|week|month|year)s?\s+ago", text.lower())
    if m:
        unit = {"second": 1, "minute": 60, "hour": 3600, "day": 86400, "week": 604800,
                "month": 2592000, "year": 31536000}[m.group(2)]
        return now - int(m.group(1)) * unit
    m = re.fullmatch(r"(\d{4})-(\d{1,2})-(\d{1,2})(?:[ T](\d{1,2}):(\d{2})(?::(\d{2}))?)?(?:\s*(?:UTC|Z))?", text)
    if m:
        try:
            return float(calendar.timegm((int(m.group(1)), int(m.group(2)), int(m.group(3)),
                                          int(m.group(4) or 0), int(m.group(5) or 0), int(m.group(6) or 0), 0, 0, 0)))
        except (ValueError, OverflowError):
            return None
    return None


# GNU cat -v byte rendering (^X, ^? and M-x)
def show_nonprinting(data: bytes, *, tabs: bool) -> str:
    out = []
    for byte in data:
        if byte == 10:
            out.append("\n")
        elif byte == 9 and not tabs:
            out.append("\t")
        elif byte >= 128:
            low = byte - 128
            out.append("M-" + ("^?" if low == 127 else "^" + chr(low + 64) if low < 32 else chr(low)))
        elif byte == 127:
            out.append("^?")
        elif byte < 32:
            out.append("^" + chr(byte + 64))
        else:
            out.append(chr(byte))
    return "".join(out)


# Bash's error prefix
# -bash for SSH login shells, bash: line 1 for exec requests
def shell_prefix(session) -> str:
    return "-bash: " if getattr(session, "interactive", True) else "bash: line 1: "


# The filesystem store side of the controller
# implements the controller's store protocol
class FilesystemCommands:
    def __init__(self, vfs: VFS, *, colour: bool = True,
                 max_cat_bytes: int = 256_000,
                 synthesize_binaries: bool = True) -> None:
        self.vfs = vfs
        self.colour = colour
        self.max_cat_bytes = max_cat_bytes
        self.synthesize_binaries = synthesize_binaries
        self.last_flags: list[str] = []
        self.last_store_ms: float = 0.0
        self._table: dict[str, Callable] = {
            "ls": self._ls, "dir": self._ls,
            "cat": self._cat, "pwd": self._pwd, "cd": self._cd,
            "mkdir": self._mkdir, "rmdir": self._rmdir, "touch": self._touch,
            "rm": self._rm, "cp": self._cp, "mv": self._mv,
            "stat": self._stat, "head": self._head, "tail": self._tail,
            "wc": self._wc, "file": self._file, "du": self._du, "df": self._df,
            "find": self._find, "chmod": self._chmod, "chown": self._chown,
            "ln": self._ln, "readlink": self._readlink, "echo": self._echo,
            "which": self._which, "basename": self._basename,
            "dirname": self._dirname, "realpath": self._realpath,
            "mountpoint": None, "true": None,
        }

    # Identity

    def names(self) -> list[str]:
        return sorted(name for name, handler in self._table.items() if handler)

    def identity(self, session) -> Identity:
        # Account and group files can change in each realm
        # recompute rather than keep permissions after a usermod, a file edit or a realm change
        users = self.vfs.passwd_users()
        groups = self.vfs.group_names()
        if session.username in users:
            uid, gid, home, _shell = users[session.username]
        elif session.username == "root":
            uid, gid, home = 0, 0, "/root"
        else:
            uid, gid, home = 1000, 1000, f"/home/{session.username}"
        member_gids = {gid}
        for line in (self.vfs.read("/etc/group") or b"").decode("utf-8", "replace").splitlines():
            fields = line.split(":")
            if len(fields) == 4 and fields[2].isdigit() and session.username in fields[3].split(","):
                member_gids.add(int(fields[2]))
        ident = Identity(uid=uid, gid=gid, uname=session.username,
                         gname=groups.get(gid, session.username),
                         groups=member_gids,
                         home=home)
        session._identity = ident
        return ident

    def _can(self, node: Node, want: str, ident: Identity) -> bool:
        if ident.is_root:
            # Root still needs one execute bit somewhere to traverse
            return want != "x" or bool(node.mode & 0o111) or node.is_dir
        if node.uid == ident.uid:
            bits = (node.mode >> 6) & 7
        elif node.gid in ident.groups or node.gid == ident.gid:
            bits = (node.mode >> 3) & 7
        else:
            bits = node.mode & 7
        return bool(bits & {"r": 4, "w": 2, "x": 1}[want])

    # Entry Point

    # Run a command against the store, or return None to decline
    # the overlay realm is set from the session on entry
    # safe because the method never awaits, so no other session can interleave
    def handle(self, session, command: str) -> Optional[str]:
        self.last_flags = []
        self.vfs.realm = getattr(session, "realm", "") or "unknown"
        t0 = self.vfs.stats.seconds
        try:
            return self._handle(session, command)
        finally:
            self.last_store_ms = round(
                (self.vfs.stats.seconds - t0) * 1000, 4)

    def _handle(self, session, command: str) -> Optional[str]:
        line = command.strip()
        if not line:
            return None

        segments = [s.strip() for s in re.split(r"&&|;", line) if s.strip()]
        if not segments:
            return None
        for seg in segments:
            if any(tok in seg for tok in _UNSUPPORTED) or "&" in seg:
                return None

        # All or nothing - if any segment is not handled here the whole line goes to the model
        # so it never sees a half-applied state
        parsed = []
        for seg in segments:
            p = self._parse(seg)
            if p is None:
                return None
            parsed.append(p)

        out: list[str] = []
        for argv, redirect in parsed:
            try:
                text = self._dispatch(session, argv)
            except FSError as exc:
                text = f"{argv[0]}: {exc.message}"
                self.last_flags.append("fs_error")
            if text is None:
                return None
            if redirect is not None:
                op, path = redirect
                try:
                    self._write_redirect(session, path, text,
                                         append=(op == ">>"))
                    self.last_flags.append("fs_redirect")
                except FSError as exc:
                    # Redirection is the shell's job, so the shell reports it
                    out.append(f"{shell_prefix(session)}{path}: {exc.message}")
                    self.last_flags.append("fs_error")
            elif text:
                out.append(text)
        return "\n".join(out)

    # Split one segment into argv plus an optional trailing redirect
    def _parse(self, segment: str):
        redirect = None
        m = _REDIRECT.search(segment)
        if m:
            if m.group("op").startswith("2"):
                # Stderr redirection changes the meaning - decline
                return None
            redirect = (m.group("op"), m.group("path"))
            segment = segment[: m.start()].strip()
            if not segment:
                segment = "true"
        try:
            argv = shlex.split(segment)
        except ValueError:
            return None
        if not argv:
            return None
        base = argv[0].rsplit("/", 1)[-1]
        if base == "sudo":
            # Privilege changes belong to the process layer
            return None
        if base not in self._table or self._table[base] is None:
            if base == "true":
                return (["true"], redirect)
            return None
        argv[0] = base
        return (argv, redirect)

    # Run one already-parsed stage for the pipeline executor
    # unlike handle() it does not parse, chain or redirect, the pipeline owns all three
    # piped is true when stdout goes to another stage or a file instead of the terminal
    # real coreutils change on isatty() - ls prints one entry per line and stops colouring
    # ignoring that would answer ls /etc | wc -l with the column count, a one-command giveaway
    def run_argv(self, session, argv: list[str], *,
                 piped: bool = False) -> Optional[str]:
        self.last_flags = []
        self._piped = piped
        self.vfs.realm = getattr(session, "realm", "") or "unknown"
        t0 = self.vfs.stats.seconds
        try:
            if not argv:
                return None
            base = argv[0].rsplit("/", 1)[-1]
            if base == "sudo" or base not in self._table or self._table[base] is None:
                return None
            try:
                return self._dispatch(session, [base] + argv[1:])
            except FSError as exc:
                self.last_flags.append("fs_error")
                return f"{base}: {exc.message}"
        finally:
            self.last_store_ms = round((self.vfs.stats.seconds - t0) * 1000, 4)

    # Read a file through the store for native filters with operands
    def read_for_filter(self, session, path: str) -> str:
        self.vfs.realm = getattr(session, "realm", "") or "unknown"
        text = self._read_text(session, self._abs(session, path), "grep")
        if text is None:
            raise FSError(f"{path}: No such file or directory")
        return text

    def _dispatch(self, session, argv: list[str]) -> Optional[str]:
        if argv[0] == "true":
            return ""
        return self._table[argv[0]](session, argv[1:])

    def _write_redirect(self, session, raw_path: str, text: str,
                        *, append: bool) -> None:
        ident = self.identity(session)
        path = normpath(session.cwd, raw_path, ident.home)
        if not self.vfs.exists(path):
            self._require_write(session, path)
        else:
            node = self.vfs.resolve(path)
            if node is not None and not self._can(node, "w", ident):
                raise FSError("Permission denied", "EACCES")
        data = (text + "\n").encode() if text else b""
        existing = self.vfs.resolve(path)
        self.vfs.write_file(path, data, uid=ident.uid, gid=ident.gid,
                            uname=ident.uname, gname=ident.gname,
                            mode=existing.mode if existing is not None else 0o666 & ~session_umask(session, self.vfs),
                            append=append)

    # Helpers

    def _abs(self, session, path: str) -> str:
        return normpath(session.cwd, path, self.identity(session).home)

    # Creating or deleting a name needs write and execute on its directory
    # checked here because the store knows nothing about identity
    # a normal user deleting /etc/passwd would end the engagement
    def _require_write(self, session, path: str) -> None:
        ident = self.identity(session)
        if ident.is_root:
            return
        parent = posixpath.dirname(path) or "/"
        node = self.vfs.resolve(parent)
        if node is None:
            # The ENOENT path prints its own message
            return
        if not (self._can(node, "w", ident) and self._can(node, "x", ident)):
            raise FSError("Permission denied", "EACCES")
        # Sticky directories such as /tmp only let you remove what you own
        victim = self.vfs.resolve(path, follow=False)
        if (node.mode & statmod.S_ISVTX and victim is not None
                and victim.uid != ident.uid):
            raise FSError("Operation not permitted", "EPERM")

    def _require_owner(self, session, path: str) -> None:
        ident = self.identity(session)
        if ident.is_root:
            return
        node = self.vfs.resolve(path)
        if node is not None and node.uid != ident.uid:
            raise FSError("Operation not permitted", "EPERM")

    # Never in any command's allowed flags
    # so set(flags) - set(allowed) is never empty and the command declines
    # dropping an unknown option would answer a different command from the one typed
    UNKNOWN = "\x00"

    _LONG = {"--all": "a", "--long": "l", "--recursive": "R",
             "--human-readable": "h", "--almost-all": "A", "--directory": "d",
             "--reverse": "r", "--parents": "p", "--force": "f",
             "--summarize": "s", "--verbose": "v", "--numeric-sort": "n",
             "--no-clobber": "n", "--symbolic": "s", "--lines": "l",
             "--bytes": "c", "--words": "w"}

    @classmethod
    def _split_flags(cls, args: list[str]) -> tuple[str, list[str]]:
        flags, operands = "", []
        for a in args:
            if a == "--":
                continue
            if a.startswith("--"):
                name = a.split("=", 1)[0]
                if name == "--color" or a == "--color":
                    # Accept ls --color[=when] - colour is applied anyway
                    continue
                flags += cls._LONG.get(name, cls.UNKNOWN)
            elif a.startswith("-") and len(a) > 1:
                flags += a[1:]
            else:
                operands.append(a)
        return flags, operands

    # Whether this session could create or remove the path
    def may_write(self, session, path: str) -> bool:
        try:
            self._require_write(session, self._abs(session, path))
            return True
        except FSError:
            return False

    def _read_text(self, session, path: str, util: str) -> Optional[str]:
        from .tools import VFSTools
        try:
            node = VFSTools(self, session).resolve(path, want="r")
        except FSError as exc:
            raise FSError(f"{path}: {exc.message}", exc.errno_name) from exc
        if node.is_dir:
            raise FSError(f"{path}: Is a directory")
        ident = self.identity(session)
        if not self._can(node, "r", ident):
            raise FSError(f"{path}: Permission denied", "EACCES")
        data = self.vfs.read(path, self.max_cat_bytes)
        if data is None:
            data = self._synthesize(node)
            if data is None:
                return None
            self.last_flags.append("content_synthesized")
        return data.decode("utf-8", "replace")

    # Content for a node whose bytes were not imported
    # only for obvious binaries - an ELF header plus filler that is the same on every read
    # text files decline instead, so the command goes to the model and is logged as a fall-through
    def _synthesize(self, node: Node) -> Optional[bytes]:
        if not self.synthesize_binaries:
            return None
        looks_binary = bool(node.mode & 0o111) or node.path.startswith(
            ("/usr/lib", "/usr/bin", "/bin", "/sbin", "/usr/sbin", "/lib"))
        if not looks_binary or node.size == 0:
            return None
        head = bytes([0x7F]) + b"ELF\x02\x01\x01\x00" + b"\x00" * 8
        seed = hashlib.sha256(node.path.encode()).digest()
        body = (seed * ((min(node.size, 4096) // len(seed)) + 1))[:max(0, min(node.size, 4096) - len(head))]
        return head + body

    # Commands

    def _ls(self, session, args):
        flags, operands = self._split_flags(args)
        # -C (Ubuntu's l alias) is the tty default
        if set(flags) - set("laAhR1dtSrFiC"):
            return None
        ident = self.identity(session)
        targets = operands or ["."]
        piped = getattr(self, "_piped", False)
        width = getattr(session, "term_width", 80) or 80
        # Exec requests have no tty either
        tty = getattr(session, "has_pty", True) and not piped
        colour = self.colour and tty
        if not tty and "C" not in flags:
            # Not a tty - one name per line, as GNU ls does
            flags += "1"

        blocks: list[str] = []
        errors: list[str] = []
        dirs: list[tuple[str, list[Node]]] = []
        loose: list[Node] = []

        for t in targets:
            p = self._abs(session, t)
            try:
                node = self.vfs.resolve(p, follow=False)
                # A symlink named on the command line is shown as a link
                # except when it points at a directory, which ls descends into
                if node is not None and node.is_link and "d" not in flags:
                    target = self.vfs.resolve(p)
                    if target is not None and target.is_dir:
                        node = target
            except FSError as exc:
                errors.append(f"ls: cannot access '{t}': {exc.message}")
                continue
            if node is None:
                errors.append(f"ls: cannot access '{t}': No such file or directory")
                continue
            if node.is_dir and "d" not in flags:
                if not self._can(node, "r", ident):
                    errors.append(f"ls: cannot open directory '{t}': Permission denied")
                    continue
                dirs.append((t, self.vfs.listdir(p)))
            else:
                # GNU ls shows a file operand exactly as it was typed
                loose.append(replace(node, name=t))

        def render(nodes: list[Node], header: Optional[str] = None,
                   dirpath: Optional[str] = None, total: bool = True) -> str:
            entries = list(nodes)
            if "a" in flags and dirpath:
                # GNU ls -a lists . and .. and -A does not
                # they are made up on the fly, storing every directory's dot entries would double the table
                here = self.vfs.resolve(dirpath)
                up = self.vfs.resolve(posixpath.dirname(dirpath) or "/")
                for label, n in ((".", here), ("..", up or here)):
                    if n is not None:
                        entries.append(replace(n, name=label))
            elif "a" not in flags and "A" not in flags and dirpath:
                entries = [n for n in entries if not n.name.startswith(".")]
            entries.sort(key=lambda n: (n.name not in (".", ".."),
                                        _sortkey(n.name)))
            if "t" in flags:
                entries.sort(key=lambda n: -n.mtime)
            elif "S" in flags:
                entries.sort(key=lambda n: -n.size)
            if "r" in flags:
                entries.reverse()
            lines = []
            if header:
                lines.append(f"{header}:")
            if "l" in flags:
                lines += fmt.format_long(entries, colour=colour,
                                         human="h" in flags, show_total=total)
            elif "1" in flags:
                lines += [fmt.paint(n, colour=colour) for n in entries]
            else:
                lines += fmt.format_columns(entries, width=width, colour=colour)
            return "\n".join(lines)

        if loose:
            blocks.append(render(loose, total=False))
        multi = len(dirs) > 1 or (dirs and loose) or "R" in flags
        budget = [20000]

        def recurse(shown: str, real: str, entries: list[Node], depth: int) -> None:
            # Full depth-first recursion in listing order, as GNU ls -R does
            children = [n for n in entries if n.is_dir and n.name not in (".", "..")
                        and ("a" in flags or "A" in flags or not n.name.startswith("."))]
            if "r" in flags:
                children.reverse()
            for child in sorted(children, key=lambda n: _sortkey(n.name), reverse="r" in flags):
                if budget[0] <= 0 or depth > 64:
                    return
                budget[0] -= 1
                child_shown = posixpath.join(shown, child.name)
                if not (self._can(child, "r", ident) and self._can(child, "x", ident)):
                    errors_inline.append((len(blocks), f"ls: cannot open directory '{child_shown}': Permission denied"))
                    continue
                listing = self.vfs.listdir(child.path)
                blocks.append(render(listing, header=child_shown, dirpath=child.path))
                recurse(child_shown, child.path, listing, depth + 1)

        errors_inline: list[tuple[int, str]] = []
        for name, entries in dirs:
            p = self._abs(session, name)
            blocks.append(render(entries, header=name if multi else None,
                                 dirpath=p))
            if "R" in flags:
                recurse(name, p, entries, 0)
        for position, message in reversed(errors_inline):
            blocks.insert(position, message)
        joiner = "\n\n" if multi and "R" in flags else "\n"
        body = joiner.join(b for b in blocks if b)
        return "\n".join(errors + ([body] if body else []))

    _CAT_LONG = {"--show-all": "A", "--number-nonblank": "b", "--show-ends": "E", "--number": "n",
                 "--squeeze-blank": "s", "--show-tabs": "T", "--show-nonprinting": "v"}

    def _cat(self, session, args):
        args = [("-" + self._CAT_LONG[a]) if a in self._CAT_LONG else a for a in args]
        flags, operands = self._split_flags(args)
        # -v and the flags that imply it (-A, -e, -t) stay on the grounded model path
        # the tool-evidence validation is built around cat -v
        if set(flags) - set("nbsETu") or not operands:
            return None
        flags = set(flags)
        out, n = [], 0
        for t in operands:
            try:
                text = self._read_text(session, self._abs(session, t), "cat")
            except FSError as exc:
                out.append(f"cat: {exc.message.replace(self._abs(session, t), t, 1)}")
                self.last_flags.append("fs_error")
                continue
            if text is None:
                return None
            if not flags & {"n", "b", "s", "v", "E", "T"}:
                out.append(text.rstrip("\n"))
                continue
            data = self.vfs.read(self._abs(session, t), self.max_cat_bytes)
            if data is not None and "v" in flags:
                text = show_nonprinting(data, tabs="T" in flags)
            elif "T" in flags:
                text = text.replace("\t", "^I")
            lines = text.split("\n")
            if lines and lines[-1] == "":
                lines.pop()
            previous_blank = False
            for line in lines:
                blank = line == ""
                if "s" in flags and blank and previous_blank:
                    continue
                previous_blank = blank
                if "E" in flags:
                    line += "$"
                if "b" in flags:
                    if not blank:
                        n += 1
                        line = f"{n:6}\t{line}"
                elif "n" in flags:
                    n += 1
                    line = f"{n:6}\t{line}"
                out.append(line)
        return "\n".join(out)

    def _pwd(self, session, args):
        return session.cwd

    def _cd(self, session, args):
        ident = self.identity(session)
        if len(args) > 1:
            return f"{shell_prefix(session)}cd: too many arguments"
        dash = args[:1] == ["-"]
        target = args[0] if args else "~"
        if dash:
            if not getattr(session, "shell_cd_count", 1):
                return f"{shell_prefix(session)}cd: OLDPWD not set"
            target = getattr(session, "oldpwd", session.cwd)
        p = self._abs(session, target)
        try:
            node = self.vfs.resolve(p)
        except FSError as exc:
            return f"{shell_prefix(session)}cd: {target}: {exc.message}"
        if node is None:
            return f"{shell_prefix(session)}cd: {target}: No such file or directory"
        if not node.is_dir:
            return f"{shell_prefix(session)}cd: {target}: Not a directory"
        if not self._can(node, "x", ident):
            return f"{shell_prefix(session)}cd: {target}: Permission denied"
        session.oldpwd = session.cwd
        session.cwd = node.path
        # Bash prints the new directory for cd -
        return node.path if dash else ""

    def _mkdir(self, session, args):
        mode_spec, rest, index = None, [], 0
        while index < len(args):
            arg = args[index]
            if arg == "-m" and index + 1 < len(args):
                mode_spec, index = args[index + 1], index + 2
                continue
            if arg.startswith("--mode="):
                mode_spec, index = arg[7:], index + 1
                continue
            match = re.fullmatch(r"-([pv]*)m(.+)", arg)
            if match:
                mode_spec = match.group(2)
                if match.group(1):
                    rest.append("-" + match.group(1))
                index += 1
                continue
            rest.append(arg)
            index += 1
        flags, operands = self._split_flags(rest)
        if set(flags) - set("pv") or not operands:
            return None
        umask = session_umask(session, self.vfs)
        default_mode = 0o777 & ~umask
        if mode_spec is None:
            final_mode = default_mode
        elif re.fullmatch(r"[0-7]{1,4}", mode_spec):
            final_mode = int(mode_spec, 8)
        elif _SYMBOLIC.fullmatch(mode_spec):
            final_mode = apply_symbolic(0o777 | statmod.S_IFDIR, mode_spec) & 0o7777
        else:
            return f"mkdir: invalid mode '{mode_spec}'"
        ident = self.identity(session)
        out = []
        for t in operands:
            p = self._abs(session, t)
            if "p" in flags:
                parts, cur = [x for x in p.split("/") if x], ""
                for part in parts:
                    cur += "/" + part
                    if not self.vfs.exists(cur):
                        self.vfs.mkdir(cur, uid=ident.uid, gid=ident.gid,
                                       uname=ident.uname, gname=ident.gname,
                                       mode=final_mode if cur == p else default_mode | 0o300)
                        if "v" in flags:
                            out.append(f"mkdir: created directory '{t}'")
                continue
            try:
                self._require_write(session, p)
                self.vfs.mkdir(p, uid=ident.uid, gid=ident.gid,
                               uname=ident.uname, gname=ident.gname, mode=final_mode)
                if "v" in flags:
                    out.append(f"mkdir: created directory '{t}'")
            except FSError as exc:
                out.append(f"mkdir: cannot create directory '{t}': {exc.message}")
                self.last_flags.append("fs_error")
        return "\n".join(out)

    def _rmdir(self, session, args):
        flags, operands = self._split_flags(args)
        if set(flags) - set("p") or not operands:
            return None
        out = []
        for t in operands:
            try:
                self._require_write(session, self._abs(session, t))
                self.vfs.rmdir(self._abs(session, t))
            except FSError as exc:
                out.append(f"rmdir: failed to remove '{t}': {exc.message}")
                self.last_flags.append("fs_error")
        return "\n".join(out)

    def _touch(self, session, args):
        when, rest, index = None, [], 0
        while index < len(args):
            arg = args[index]
            option, value = None, None
            if arg in ("-r", "-d", "-t") and index + 1 < len(args):
                option, value, index = arg[1], args[index + 1], index + 2
            elif arg.startswith(("--reference=", "--date=")):
                option, value, index = ("r" if arg.startswith("--r") else "d"), arg.split("=", 1)[1], index + 1
            elif re.fullmatch(r"-[acmfh]*[rdt].+", arg):
                letters = re.match(r"-([acmfh]*)([rdt])(.+)", arg)
                if letters.group(1):
                    rest.append("-" + letters.group(1))
                option, value, index = letters.group(2), letters.group(3), index + 1
            else:
                rest.append(arg)
                index += 1
                continue
            if option == "r":
                try:
                    from .tools import VFSTools
                    when = VFSTools(self, session).resolve(value).mtime
                except FSError as exc:
                    return f"touch: failed to get attributes of '{value}': {exc.message}"
            else:
                when = parse_touch_time(value, stamp=option == "t")
                if when is None:
                    if option == "t":
                        return f"touch: invalid date format '{value}'"
                    # An unusual -d string - let the grounded model answer
                    return None
        flags, operands = self._split_flags(rest)
        if set(flags) - set("acmfh") or not operands:
            return None
        ident = self.identity(session)
        out = []
        for t in operands:
            p = self._abs(session, t)
            try:
                if self.vfs.exists(p):
                    self._require_owner(session, p)
                    self.vfs.utime(p, when)
                elif "c" not in flags:
                    self._require_write(session, p)
                    self.vfs.write_file(p, b"", uid=ident.uid, gid=ident.gid,
                                        uname=ident.uname, gname=ident.gname,
                                        mode=0o666 & ~session_umask(session, self.vfs))
                    if when is not None:
                        self.vfs.utime(p, when)
            except FSError as exc:
                out.append(f"touch: cannot touch '{t}': {exc.message}")
                self.last_flags.append("fs_error")
        return "\n".join(out)

    def _rm(self, session, args):
        flags, operands = self._split_flags(args)
        if set(flags) - set("rRfvi") or not operands:
            return None
        out = []
        for t in operands:
            p = self._abs(session, t)
            try:
                self._require_write(session, p)
                self.vfs.remove(p, recursive=bool({"r", "R"} & set(flags)))
                if "v" in flags:
                    out.append(f"removed '{t}'")
            except FSError as exc:
                if "f" in flags and exc.errno_name == "ENOENT":
                    continue
                out.append(f"rm: cannot remove '{t}': {exc.message}")
                self.last_flags.append("fs_error")
        return "\n".join(out)

    _CP_LONG = {"--no-clobber": "n", "--update": "u", "--preserve": "p", "--archive": "a",
                "--recursive": "r", "--force": "f", "--verbose": "v", "--dereference": "L",
                "--no-dereference": "P"}

    def _cp(self, session, args):
        args = [("-" + self._CP_LONG[a.split("=", 1)[0]]) if a.split("=", 1)[0] in self._CP_LONG else a
                for a in args]
        flags, operands = self._split_flags(args)
        if set(flags) - set("rRafvpnuLPd") or len(operands) < 2:
            return None
        ident = self.identity(session)
        umask = session_umask(session, self.vfs)
        *srcs, dst = operands
        out = []
        for s in srcs:
            try:
                source = self.vfs.resolve(self._abs(session, s))
                target = self._abs(session, dst)
                existing = self.vfs.resolve(target)
                if existing is not None and existing.is_dir and source is not None:
                    target = posixpath.join(target, source.name)
                    existing = self.vfs.resolve(target)
                if existing is not None and source is not None and not source.is_dir:
                    if "n" in flags:
                        continue
                    if "u" in flags and existing.mtime >= source.mtime:
                        continue
                self._require_write(session, self._abs(session, dst))
                self.vfs.copy(self._abs(session, s), self._abs(session, dst),
                              uid=ident.uid, gid=ident.gid, uname=ident.uname,
                              gname=ident.gname,
                              recursive=bool({"r", "R", "a"} & set(flags)))
                if source is not None and not source.is_dir and self.vfs.exists(target):
                    if {"p", "a"} & set(flags):
                        self.vfs.chmod(target, source.mode & 0o7777)
                        self.vfs.utime(target, source.mtime)
                    elif existing is None:
                        self.vfs.chmod(target, source.mode & 0o777 & ~umask)
                if "v" in flags:
                    into_dir = source is not None and target != self._abs(session, dst)
                    out.append(f"'{s}' -> '{dst.rstrip('/') + '/' + source.name if into_dir else dst}'")
            except FSError as exc:
                verb = "stat" if exc.errno_name == "ENOENT" else "copy"
                out.append(f"cp: cannot {verb} '{s}': {exc.message}")
                self.last_flags.append("fs_error")
        return "\n".join(out)

    def _mv(self, session, args):
        flags, operands = self._split_flags(args)
        if set(flags) - set("fvn") or len(operands) < 2:
            return None
        ident = self.identity(session)
        *srcs, dst = operands
        out = []
        for s in srcs:
            try:
                self._require_write(session, self._abs(session, dst))
                self._require_write(session, self._abs(session, s))
                self.vfs.move(self._abs(session, s), self._abs(session, dst),
                              uid=ident.uid, gid=ident.gid, uname=ident.uname,
                              gname=ident.gname)
            except FSError as exc:
                out.append(f"mv: cannot stat '{s}': {exc.message}")
                self.last_flags.append("fs_error")
        return "\n".join(out)

    def _stat(self, session, args):
        from .tools import VFSTools
        operands, pattern, follow = [], None, False
        i = 0
        while i < len(args):
            arg = args[i]
            if arg == '--':
                operands.extend(args[i + 1:])
                break
            if arg in ('-L', '--dereference'):
                follow = True
            elif arg in ('-c', '--format'):
                i += 1
                if i == len(args):
                    return None
                pattern = args[i]
            elif arg.startswith('--format='):
                pattern = arg.split('=', 1)[1]
            elif arg.startswith('-c'):
                pattern = arg[2:]
            elif arg.startswith('-') and arg != '-':
                return None
            else:
                operands.append(arg)
            i += 1
        if not operands or (pattern is not None and not fmt.stat_format_supported(pattern)):
            return None
        out = []
        access = VFSTools(self, session)
        for t in operands:
            try:
                # The stat command needs search permission on the parents, not read permission on the file
                # symlinks are resolved before .. is handled
                node = access.resolve(t, follow=follow)
            except FSError as exc:
                out.append(f"stat: cannot statx '{t}': {exc.message}")
                self.last_flags.append("fs_error")
                continue
            out.append(fmt.format_stat(node) if pattern is None
                       else fmt.format_stat_fields(node, pattern, t))
        return "\n".join(out)

    def _head(self, session, args):
        return self._head_tail(session, args, head=True)

    def _tail(self, session, args):
        return self._head_tail(session, args, head=False)

    def _head_tail(self, session, args, *, head: bool):
        util = "head" if head else "tail"
        count, operands, i = 10, [], 0
        while i < len(args):
            a = args[i]
            if a == "-n" and i + 1 < len(args):
                i += 1
                try:
                    count = int(args[i].lstrip("+-"))
                except ValueError:
                    return None
            elif re.fullmatch(r"-\d+", a):
                count = int(a[1:])
            elif a.startswith("-") and a != "-":
                return None
            else:
                operands.append(a)
            i += 1
        if not operands:
            return None
        out = []
        show_names = len(operands) > 1
        for t in operands:
            try:
                text = self._read_text(session, self._abs(session, t), util)
            except FSError as exc:
                msg = exc.message.replace(self._abs(session, t), t, 1)
                if exc.errno_name in ("ENOENT", "EACCES"):
                    msg = f"cannot open '{t}' for reading: {msg.split(': ',1)[-1]}"
                out.append(f"{util}: {msg}")
                self.last_flags.append("fs_error")
                continue
            if text is None:
                return None
            lines = text.split("\n")
            if lines and lines[-1] == "":
                lines.pop()
            chunk = lines[:count] if head else lines[-count:]
            if show_names:
                out.append(f"==> {t} <==")
            out.append("\n".join(chunk))
        return "\n".join(out)

    def _wc(self, session, args):
        flags, operands = self._split_flags(args)
        if set(flags) - set("lcwm") or not operands:
            return None
        out, totals = [], [0, 0, 0]
        for t in operands:
            try:
                text = self._read_text(session, self._abs(session, t), "wc")
            except FSError as exc:
                out.append(f"wc: {exc.message.replace(self._abs(session, t), t, 1)}")
                self.last_flags.append("fs_error")
                continue
            if text is None:
                return None
            nl = text.count("\n")
            words = len(text.split())
            nbytes = len(text.encode())
            totals = [totals[0] + nl, totals[1] + words, totals[2] + nbytes]
            cols = []
            if not flags or "l" in flags:
                cols.append(str(nl))
            if not flags or "w" in flags:
                cols.append(str(words))
            if not flags or {"c", "m"} & set(flags):
                cols.append(str(nbytes))
            out.append(" ".join(f"{c:>7}" for c in cols) + f" {t}")
        if len(operands) > 1:
            out.append(" ".join(f"{c:>7}" for c in map(str, totals)) + " total")
        return "\n".join(out)

    def _file(self, session, args):
        flags, operands = self._split_flags(args)
        if flags or not operands:
            return None
        out = []
        for t in operands:
            node = self.vfs.resolve(self._abs(session, t), follow=False)
            if node is None:
                out.append(f"{t}: cannot open `{t}' (No such file or directory)")
                continue
            if node.is_dir:
                desc = "directory"
            elif node.is_link:
                desc = f"symbolic link to {node.target}"
            elif node.mode & 0o111 and not node.has_content:
                desc = ("ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), "
                        "dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, "
                        "BuildID[sha1]=" + hashlib.sha1(node.path.encode()).hexdigest()[:40] +
                        ", for GNU/Linux 3.2.0, stripped")
            elif node.size == 0:
                desc = "empty"
            else:
                from .vfsio import read_bytes
                try:
                    data = read_bytes(self, session, t, 4096)
                except FSError as exc:
                    out.append(f"{t}: cannot read ({exc.message})")
                    self.last_flags.append("fs_error")
                    continue
                if data.startswith(b"\x7fELF"):
                    bits = "64-bit" if data[4:5] == b"\x02" else "32-bit"
                    desc = f"ELF {bits} executable"
                elif data.startswith(b"PK\x03\x04"):
                    desc = "Zip archive data"
                elif data.startswith(b"\x1f\x8b"):
                    desc = "gzip compressed data"
                elif data.startswith(b"\x89PNG\r\n\x1a\n"):
                    desc = "PNG image data"
                elif data.startswith(b"#!"):
                    desc = "script, ASCII text" if _is_text(data) else "script, text"
                else:
                    desc = "ASCII text" if _is_text(data) else "data"
            out.append(f"{t}: {desc}")
        return "\n".join(out)

    def _du(self, session, args):
        flags, operands = self._split_flags(args)
        if set(flags) - set("sha") or not operands:
            operands = operands or ["."]
        if set(flags) - set("sha"):
            return None
        out = []
        for t in operands:
            p = self._abs(session, t)
            try:
                nodes = list(self.vfs.walk(p))
            except FSError as exc:
                out.append(f"du: cannot access '{t}': {exc.message}")
                self.last_flags.append("fs_error")
                continue
            if "s" in flags:
                total = sum(fmt.blocks_1k(n) for n in nodes)
                out.append(f"{fmt.human_size(total * 1024) if 'h' in flags else total}\t{t}")
            else:
                per: dict[str, int] = {}
                for n in nodes:
                    d = n.path if n.is_dir else posixpath.dirname(n.path)
                    per[d] = per.get(d, 0) + fmt.blocks_1k(n)
                for d in sorted(per, reverse=True):
                    rel = t if d == p else posixpath.join(t, d[len(p):].lstrip("/"))
                    size = fmt.human_size(per[d] * 1024) if "h" in flags else per[d]
                    out.append(f"{size}\t{rel}")
        return "\n".join(out)

    def _df(self, session, args):
        flags, operands = self._split_flags(args)
        if set(flags) - set("h") or operands:
            return None
        return fmt.format_df(human="h" in flags)

    def _find(self, session, args):
        paths, name_pat, kind, maxdepth = [], None, None, None
        permission, owner, group, writable = None, None, None, False
        fold_case = False
        i = 0
        while i < len(args):
            a = args[i]
            if a in ("-name", "-iname") and i + 1 < len(args):
                name_pat, fold_case = args[i + 1], a == "-iname"
                i += 2; continue
            if a == "-type" and i + 1 < len(args):
                kind = {"f": "file", "d": "dir", "l": "link"}.get(args[i + 1])
                if kind is None:
                    # Types b, c, p, s and lists - let the grounded path answer
                    return None
                i += 2; continue
            if a == "-maxdepth" and i + 1 < len(args):
                try:
                    maxdepth = int(args[i + 1])
                except ValueError:
                    return None
                i += 2; continue
            if a == "-perm" and i + 1 < len(args):
                # Octal (-perm -4000) or symbolic (-perm -u=s, /u=s,g=s, -o+w), as GNU find accepts
                # a symbolic mode is applied to 000 to get the bits to test
                spec = args[i + 1]
                op = spec[0] if spec[:1] in ("-", "/") else "="
                body = spec[1:] if op != "=" else spec
                if re.fullmatch(r"[0-7]{1,4}", body):
                    bits = int(body, 8)
                elif body and _SYMBOLIC.fullmatch(body):
                    bits = apply_symbolic(0, body)
                else:
                    return None
                permission = (op, bits)
                i += 2; continue
            if a in ("-user", "-group") and i + 1 < len(args):
                if a == "-user":
                    owner = args[i + 1]
                else:
                    group = args[i + 1]
                i += 2; continue
            if a == "-writable":
                writable = True
                i += 1; continue
            if a == "-print":
                i += 1; continue
            if a.startswith("-"):
                # -exec, expressions, -mtime and similar need the fallback
                return None
            paths.append(a); i += 1
        if not paths:
            paths = ["."]

        import fnmatch
        from .tools import VFSTools
        access = VFSTools(self, session)
        ident = access.ident
        out, errors = [], []
        for t in paths:
            p = self._abs(session, t)
            try:
                top = access.resolve(t, follow=False)
            except FSError as exc:
                errors.append(f"find: '{t}': {exc.message}")
                continue
            pending = [(top, 0)]
            while pending:
                n, depth = pending.pop()
                rel = t if n.path == p else posixpath.join(
                    t, n.path[len(p):].lstrip("/"))
                if n.is_dir and (maxdepth is None or depth < maxdepth):
                    if all(self._can(n, bit, ident) for bit in "rx"):
                        pending.extend((child, depth + 1) for child in reversed(self.vfs.listdir(n.path)))
                    else:
                        errors.append(f"find: '{rel}': Permission denied")
                        self.last_flags.append("fs_error")
                if kind and n.kind != kind:
                    continue
                if name_pat and not (fnmatch.fnmatchcase(n.name.lower(), name_pat.lower()) if fold_case
                                     else fnmatch.fnmatchcase(n.name, name_pat)):
                    continue
                if owner is not None and owner not in (n.uname, str(n.uid)):
                    continue
                if group is not None and group not in (n.gname, str(n.gid)):
                    continue
                if writable and not self._can(n, "w", ident):
                    continue
                if permission:
                    op, bits = permission
                    mode = n.mode & 0o7777
                    if (op == "=" and mode != bits) or (op == "-" and mode & bits != bits) or (op == "/" and bits and not mode & bits):
                        continue
                out.append(rel)
        return "\n".join(errors + sorted(out))

    def _chmod(self, session, args):
        flags, operands = self._split_flags(args)
        if set(flags) - set("Rv") or len(operands) < 2:
            return None
        spec, targets = operands[0], operands[1:]
        numeric = re.fullmatch(r"[0-7]{3,4}", spec)
        if not numeric and not _SYMBOLIC.fullmatch(spec):
            return None
        out = []
        for t in targets:
            p = self._abs(session, t)
            try:
                self._require_owner(session, p)
                victims = ([n.path for n in self.vfs.walk(p)]
                           if "R" in flags else [p])
                for v in victims:
                    if numeric:
                        mode = int(spec, 8)
                    else:
                        node = self.vfs.resolve(v)
                        if node is None:
                            raise FSError("No such file or directory")
                        mode = apply_symbolic(node.mode, spec)
                    self.vfs.chmod(v, mode)
                if "v" in flags:
                    out.append(f"mode of '{t}' changed to {spec} "
                               f"({fmt.mode_string(self.vfs.resolve(p))[1:]})")
            except FSError as exc:
                verb = ("changing permissions of" if exc.errno_name == "EPERM"
                        else "cannot access")
                out.append(f"chmod: {verb} '{t}': {exc.message}")
                self.last_flags.append("fs_error")
        return "\n".join(out)

    def _chown(self, session, args):
        flags, operands = self._split_flags(args)
        if set(flags) - set("Rv") or len(operands) < 2:
            return None
        spec, targets = operands[0], operands[1:]
        users = self.vfs.passwd_users()
        groups = {v: k for k, v in self.vfs.group_names().items()}
        uname, _, gname = spec.partition(":")
        uid = users.get(uname, (None,))[0] if uname else None
        gid = groups.get(gname) if gname else None
        if uname and uid is None:
            return f"chown: invalid user: '{spec}'"
        out = []
        for t in targets:
            try:
                if not self.identity(session).is_root:
                    raise FSError("Operation not permitted", "EPERM")
                self.vfs.chown(self._abs(session, t), uid, gid,
                               uname or None, gname or None)
            except FSError as exc:
                verb = ("changing ownership of" if exc.errno_name == "EPERM"
                        else "cannot access")
                out.append(f"chown: {verb} '{t}': {exc.message}")
                self.last_flags.append("fs_error")
        return "\n".join(out)

    def _ln(self, session, args):
        flags, operands = self._split_flags(args)
        if "s" not in flags or len(operands) != 2:
            return None
        ident = self.identity(session)
        target, link = operands
        try:
            self._require_write(session, self._abs(session, link))
            self.vfs.symlink(self._abs(session, link), target, uid=ident.uid,
                             gid=ident.gid, uname=ident.uname, gname=ident.gname)
        except FSError as exc:
            self.last_flags.append("fs_error")
            return f"ln: failed to create symbolic link '{link}': {exc.message}"
        return ""

    def _readlink(self, session, args):
        flags, operands = self._split_flags(args)
        if set(flags) - set("f") or not operands:
            return None
        out = []
        for t in operands:
            node = self.vfs.resolve(self._abs(session, t), follow=False)
            if node is None:
                continue
            if "f" in flags:
                out.append(self.vfs.resolve(self._abs(session, t)).path
                           if self.vfs.resolve(self._abs(session, t)) else "")
            elif node.is_link:
                out.append(node.target or "")
        return "\n".join(out)

    def _echo(self, session, args):
        flags, operands = self._split_flags(args)
        if set(flags) - set("ne"):
            # -not-a-flag is just text to echo
            operands = args
            flags = ""
        return " ".join(operands)

    def _which(self, session, args):
        flags, operands = self._split_flags(args)
        if flags or not operands:
            return None
        path_dirs = ("/usr/local/sbin", "/usr/local/bin", "/usr/sbin",
                     "/usr/bin", "/sbin", "/bin", "/snap/bin")
        out = []
        for name in operands:
            for d in path_dirs:
                node = self.vfs.resolve(posixpath.join(d, name), follow=False)
                if node is not None and not node.is_dir:
                    out.append(posixpath.join(d, name))
                    break
        return "\n".join(out)

    def _basename(self, session, args):
        flags, operands = self._split_flags(args)
        if flags or not operands:
            return None
        return posixpath.basename(operands[0].rstrip("/")) or "/"

    def _dirname(self, session, args):
        flags, operands = self._split_flags(args)
        if flags or not operands:
            return None
        return posixpath.dirname(operands[0].rstrip("/")) or "."

    def _realpath(self, session, args):
        flags, operands = self._split_flags(args)
        if flags or not operands:
            return None
        out = []
        for t in operands:
            node = self.vfs.resolve(self._abs(session, t))
            if node is None:
                out.append(f"realpath: {t}: No such file or directory")
                self.last_flags.append("fs_error")
            else:
                out.append(node.path)
        return "\n".join(out)


_SYMBOLIC = re.compile(r"[ugoa]*(?:[-+=][rwxXst]*)(?:,[ugoa]*[-+=][rwxXst]*)*")


# Apply chmod modes such as +x, u+rw, go-w, a=rx and comma-separated lists
# chmod +x payload is one of the most common things an attacker types
# sending it to the model would print success while the execute bit never changes
def apply_symbolic(mode: int, spec: str) -> int:
    bits = {"r": 4, "w": 2, "x": 1}
    for clause in spec.split(","):
        m = re.fullmatch(r"([ugoa]*)([-+=])([rwxXst]*)", clause)
        if not m:
            continue
        who, op, perms = m.group(1) or "a", m.group(2), m.group(3)
        value = sum(bits[c] for c in perms if c in bits)
        if "X" in perms and mode & 0o111:
            # -X only sets x where some x bit already exists
            value |= 1
        shifts = []
        if "u" in who or "a" in who:
            shifts.append(6)
        if "g" in who or "a" in who:
            shifts.append(3)
        if "o" in who or "a" in who:
            shifts.append(0)
        for sh in shifts:
            if op == "+":
                mode |= value << sh
            elif op == "-":
                mode &= ~(value << sh)
            else:
                mode = (mode & ~(0o7 << sh)) | (value << sh)
        if "s" in perms:
            if op == "-":
                mode &= ~(statmod.S_ISUID | statmod.S_ISGID)
            else:
                if "u" in who or "a" in who:
                    mode |= statmod.S_ISUID
                if "g" in who or "a" in who:
                    mode |= statmod.S_ISGID
        if "t" in perms:
            mode = (mode & ~statmod.S_ISVTX) if op == "-" else (mode | statmod.S_ISVTX)
    return mode & 0o7777


def _is_text(data: bytes) -> bool:
    if b"\x00" in data:
        return False
    try:
        data.decode("utf-8")
        return True
    except UnicodeDecodeError:
        return False
