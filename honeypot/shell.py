# Bash Session
# variables, word expansion, builtins and command lookup, all deterministic
# reads the same SQLite realm as the rest of the system and never reaches Qwen
# PATH comes from /etc/environment, shell and home from /etc/passwd
# aliases from ~/.bashrc and history from ~/.bash_history
# a login shell is -bash, so its messages read -bash: cd: /nope: No such file or directory
# ssh host 'cmd' runs bash -c, which says bash: line 1, skips the aliases and keeps no history

# Imports
from __future__ import annotations

import fnmatch
import posixpath
import random
import re
import shlex
import stat as statmod
import time
from dataclasses import dataclass
from typing import Optional

from .cmdline import PARAM_FORM
from .vfs import FSError

BASH_VERSION = "5.1.16(1)-release"
DEFAULT_PATH = ("/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:"
                "/usr/games:/usr/local/games:/snap/bin")
UBUNTU_PS1 = (r"\[\e]0;\u@\h: \w\a\]${debian_chroot:+($debian_chroot)}"
              r"\[\033[01;32m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ ")

KEYWORDS = {"if", "then", "else", "elif", "fi", "case", "esac", "for", "select", "while",
            "until", "do", "done", "in", "function", "time", "{", "}", "!", "[[", "]]", "coproc"}
BUILTINS = {".", ":", "[", "alias", "bg", "bind", "break", "builtin", "caller", "cd", "command",
            "compgen", "complete", "compopt", "continue", "declare", "dirs", "disown", "echo",
            "enable", "eval", "exec", "exit", "export", "false", "fc", "fg", "getopts", "hash",
            "help", "history", "jobs", "kill", "let", "local", "logout", "mapfile", "popd",
            "printf", "pushd", "pwd", "read", "readarray", "readonly", "return", "set", "shift",
            "shopt", "source", "suspend", "test", "times", "trap", "true", "type", "typeset",
            "ulimit", "umask", "unalias", "unset", "wait"}
# Builtins this module answers itself
# cd and pwd stay in the store, kill, jobs and wait in the process manager, exit in the controller
HANDLED = {"echo", "printf", "export", "unset", "set", "alias", "unalias", "type", "command",
           "hash", "umask", "true", "false", ":", "test", "[", "history", "printenv", "env",
           "source", ".", "shopt", "ulimit"}
READONLY = {"UID", "EUID", "PPID", "BASHOPTS", "SHELLOPTS", "BASH_VERSINFO", "GROUPS"}
RC_FILES = {".bashrc", ".profile", ".bash_profile", ".bash_login", "profile", "bash.bashrc",
            "environment"}

# Install suggestions from command-not-found for common attacker tools, worded as on Ubuntu 22.04
# only single-package commands are listed, anything else gets the plain message
CNF_PACKAGES = {
    "ifconfig": "net-tools", "netstat": "net-tools", "route": "net-tools", "arp": "net-tools",
    "nmap": "nmap", "gcc": "gcc", "g++": "g++", "pip": "python3-pip", "pip3": "python3-pip",
    "socat": "socat", "ncat": "ncat", "zip": "zip", "unzip": "unzip", "whois": "whois",
    "john": "john", "hydra": "hydra", "masscan": "masscan", "sshpass": "sshpass",
    "gdb": "gdb", "ltrace": "ltrace", "jq": "jq", "tree": "tree", "nikto": "nikto",
    "sqlmap": "sqlmap", "hping3": "hping3", "proxychains4": "proxychains4", "tor": "tor",
    "python2": "python2", "node": "nodejs", "ruby": "ruby", "lynx": "lynx", "nasm": "nasm",
}
CNF_DID_YOU_MEAN = {
    "python": [("python3", "python3"), ("python", "python-is-python3")],
}
SET_OPTIONS = ["allexport", "braceexpand", "emacs", "errexit", "errtrace", "functrace", "hashall",
               "histexpand", "history", "ignoreeof", "interactive-comments", "keyword", "monitor",
               "noclobber", "noexec", "noglob", "nolog", "notify", "nounset", "onecmd", "physical",
               "pipefail", "posix", "privileged", "verbose", "vi", "xtrace"]
DEFAULT_ON = {"braceexpand", "emacs", "hashall", "histexpand", "history", "interactive-comments",
              "monitor"}
_MARK = re.compile("\x00([LVT])([^\x00]*)\x00")
_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_GLOB_CHARS = set("*?[")


class ShellError(Exception):
    def __init__(self, message: str, status: int = 1) -> None:
        super().__init__(message)
        self.message, self.status = message, status


@dataclass
class ShellResult:
    stdout: bytes = b""
    stderr: str = ""
    status: int = 0
    # Run this argv as the command instead
    delegate: Optional[list[str]] = None


# Bash's own error prefix for this session - -bash or bash: line 1
def shell_prefix(session) -> str:
    return "-bash: " if getattr(session, "interactive", True) else "bash: line 1: "


def is_special_device(path: str) -> bool:
    return path in ("/dev/null", "/dev/zero", "/dev/full", "/dev/random", "/dev/urandom",
                    "/dev/stdout", "/dev/stderr", "/dev/tty", "/dev/fd/1", "/dev/fd/2")


def single_quote(value: str) -> str:
    return "'" + value.replace("'", "'\\''") + "'"


# Backslash escapes for echo -e (echo=True) and printf
# returns (text, stop)
def _escape_text(text: str, *, echo: bool) -> tuple[str, bool]:
    out, i, n = [], 0, len(text)
    simple = {"a": "\a", "b": "\b", "e": "\x1b", "E": "\x1b", "f": "\f", "n": "\n",
              "r": "\r", "t": "\t", "v": "\v", "\\": "\\", '"': '"', "'": "'"}
    while i < n:
        c = text[i]
        if c != "\\" or i + 1 >= n:
            out.append(c)
            i += 1
            continue
        d = text[i + 1]
        if d == "c" and echo:
            return "".join(out), True
        if d in simple and not (echo and d in "\"'"):
            out.append(simple[d])
            i += 2
        elif d == "0" and echo or (d in "01234567" and not echo):
            j = i + 2 if echo else i + 1
            digits = re.match(r"[0-7]{0,3}", text[j:]).group(0)
            out.append(chr(int(digits or "0", 8) & 0xFF))
            i = j + len(digits)
        elif d == "x":
            digits = re.match(r"[0-9A-Fa-f]{1,2}", text[i + 2:])
            if digits:
                out.append(chr(int(digits.group(0), 16)))
                i += 2 + len(digits.group(0))
            else:
                out.append("\\x")
                i += 2
        elif d in "uU":
            digits = re.match(r"[0-9A-Fa-f]{1,%d}" % (4 if d == "u" else 8), text[i + 2:])
            if digits:
                out.append(chr(int(digits.group(0), 16)))
                i += 2 + len(digits.group(0))
            else:
                out.append("\\" + d)
                i += 2
        else:
            out.append("\\" + d)
            i += 2
    return "".join(out), False


# Escapes such as \xff are bytes, not code points, and everything else is UTF-8
def _latin(text: str) -> bytes:
    out = bytearray()
    for ch in text:
        out.extend(bytes([ord(ch)]) if 0x80 <= ord(ch) <= 0xFF else ch.encode("utf-8"))
    return bytes(out)


class Shell:
    def __init__(self, filesystem=None, processes=None) -> None:
        self.filesystem = filesystem
        self.processes = processes

    # State

    def _view(self, session):
        if self.filesystem is None:
            return None
        return self.filesystem.vfs.for_realm(getattr(session, "realm", "") or "unknown")

    def _access(self, session):
        from .tools import VFSTools
        return VFSTools(self.filesystem, session) if self.filesystem is not None else None

    def _read(self, session, path: str) -> str:
        view = self._view(session)
        if view is None:
            return ""
        try:
            data = view.read(path)
        except FSError:
            return ""
        return (data or b"").decode("utf-8", "replace")

    def _passwd(self, session, username: str):
        view = self._view(session)
        return view.passwd_users().get(username) if view is not None else None

    def home(self, session, username: Optional[str] = None) -> Optional[str]:
        username = username or getattr(session, "username", "root")
        entry = self._passwd(session, username)
        if entry:
            return entry[2]
        if username != getattr(session, "username", "root"):
            return None
        return "/root" if username == "root" else f"/home/{username}"

    def uid(self, session) -> int:
        username = getattr(session, "username", "root")
        entry = self._passwd(session, username)
        return entry[0] if entry else (0 if username == "root" else 1000)

    def ensure(self, session) -> None:
        if getattr(session, "shell_env", None) is not None:
            return
        interactive = getattr(session, "interactive", True)
        has_pty = getattr(session, "has_pty", True)
        username = getattr(session, "username", "root")
        entry = self._passwd(session, username)
        uid = entry[0] if entry else (0 if username == "root" else 1000)
        home = self.home(session) or "/"
        login_shell = (entry[3] if entry and entry[3] else "/bin/bash")
        path = DEFAULT_PATH
        for line in self._read(session, "/etc/environment").splitlines():
            if line.startswith("PATH="):
                path = line[5:].strip().strip('"') or DEFAULT_PATH
        lang = "C.UTF-8"
        for line in self._read(session, "/etc/default/locale").splitlines():
            if line.startswith("LANG="):
                lang = line[5:].strip().strip('"') or lang
        peer_ip = getattr(session, "peer_ip", "10.0.0.5")
        peer_port = getattr(session, "peer_port", 54321)
        server_ip = (self.filesystem.vfs.meta("server_ip", "10.0.12.31")
                     if self.filesystem is not None else "10.0.12.31")
        sid = getattr(session, "session_id", "0") or "0"
        session_number = int(re.sub("[^0-9a-f]", "", sid)[:4] or "0", 16) % 40 + 1
        term = getattr(session, "term_type", None) or ("xterm-256color" if has_pty else None)
        env: dict[str, str] = {}
        env["SHELL"] = login_shell
        env["PWD"] = getattr(session, "cwd", home)
        env["LOGNAME"] = getattr(session, "username", "root")
        if has_pty:
            env["XDG_SESSION_TYPE"] = "tty"
            env["MOTD_SHOWN"] = "pam"
        env["HOME"] = home
        env["LANG"] = lang
        env["SSH_CONNECTION"] = f"{peer_ip} {peer_port} {server_ip} 22"
        env["LESSCLOSE"] = "/usr/bin/lesspipe %s %s"
        env["XDG_SESSION_CLASS"] = "user"
        if term:
            env["TERM"] = term
        env["LESSOPEN"] = "| /usr/bin/lesspipe %s"
        env["USER"] = getattr(session, "username", "root")
        env["SHLVL"] = "1"
        env["XDG_SESSION_ID"] = str(session_number)
        env["XDG_RUNTIME_DIR"] = f"/run/user/{uid}"
        env["SSH_CLIENT"] = f"{peer_ip} {peer_port} 22"
        env["XDG_DATA_DIRS"] = "/usr/local/share:/usr/share:/var/lib/snapd/desktop"
        env["PATH"] = path
        env["DBUS_SESSION_BUS_ADDRESS"] = f"unix:path=/run/user/{uid}/bus"
        if has_pty:
            env["SSH_TTY"] = "/dev/pts/0"
        session.shell_env = env
        session.shell_vars = {}
        session.shell_unset = set()
        session.shell_aliases = self._bashrc_aliases(session, home) if interactive else {}
        session.shell_options = set(DEFAULT_ON) if interactive else {"braceexpand", "hashall"}
        session.shell_hash = {}
        session.shell_umask = None
        session.shell_started = time.monotonic()
        session.shell_cd_count = 0
        if interactive:
            session.shell_vars.update({"HISTCONTROL": "ignoreboth", "HISTSIZE": "1000",
                                       "HISTFILESIZE": "2000", "PS1": UBUNTU_PS1})
            past = [line for line in self._read(session, home + "/.bash_history").splitlines() if line]
            session.shell_history = past[-1000:]
        else:
            session.shell_history = []

    def _bashrc_aliases(self, session, home: str) -> dict[str, str]:
        aliases: dict[str, str] = {}
        for line in self._read(session, home.rstrip("/") + "/.bashrc").splitlines():
            stripped = line.strip()
            if not stripped.startswith("alias "):
                continue
            try:
                words = shlex.split(stripped, comments=False)
            except ValueError:
                continue
            for word in words[1:]:
                name, sep, value = word.partition("=")
                if sep and _IDENT.fullmatch(name.replace("-", "_")):
                    aliases[name] = value
        return aliases

    def record_history(self, session, line: str) -> None:
        self.ensure(session)
        if not getattr(session, "interactive", True) or "history" not in session.shell_options:
            return
        control = self.get_var(session, "HISTCONTROL") or ""
        if ("ignorespace" in control or "ignoreboth" in control) and line[:1] == " ":
            return
        if (("ignoredups" in control or "ignoreboth" in control) and session.shell_history
                and session.shell_history[-1] == line):
            return
        session.shell_history.append(line)
        session.shell_history = session.shell_history[-1000:]

    # Variables

    def get_var(self, session, name: str) -> Optional[str]:
        self.ensure(session)
        interactive = getattr(session, "interactive", True)
        if name == "?":
            return str(getattr(session, "last_exit_status", 0) or 0)
        if name == "$" or name == "BASHPID":
            return str(getattr(session, "shell_pid", None) or self._fallback_pid(session))
        if name == "!":
            value = getattr(session, "last_background_pid", None)
            return str(value) if value else ""
        if name == "0":
            return "-bash" if interactive else "bash"
        if name.isdigit():
            return None
        if name == "#":
            return "0"
        if name in ("@", "*"):
            return ""
        if name == "-":
            return "himBHs" if interactive else "hBc"
        if name in session.shell_unset:
            return None
        if name == "PWD":
            return getattr(session, "cwd", "/")
        if name == "OLDPWD":
            return getattr(session, "oldpwd", None) if session.shell_cd_count else None
        if name in session.shell_vars:
            return session.shell_vars[name]
        if name in session.shell_env:
            return session.shell_env[name]
        return self._dynamic(session, name)

    def _fallback_pid(self, session) -> int:
        sid = getattr(session, "session_id", "0") or "0"
        return 1000 + int(re.sub("[^0-9a-f]", "", sid)[:5] or "0", 16) % 30000

    def _dynamic(self, session, name: str) -> Optional[str]:
        if name == "RANDOM":
            return str(random.randint(0, 32767))
        if name == "SECONDS":
            return str(int(time.monotonic() - session.shell_started))
        if name in ("EPOCHSECONDS", "EPOCHREALTIME"):
            return str(int(time.time())) if name == "EPOCHSECONDS" else f"{time.time():.6f}"
        if name in ("UID", "EUID"):
            return str(self.uid(session))
        if name == "GROUPS":
            entry = self._passwd(session, session.username)
            return str(entry[1]) if entry else str(self.uid(session))
        if name == "PPID":
            pid = int(self.get_var(session, "$") or 1000)
            return str(getattr(session, "shell_ppid", None) or max(2, pid - 1))
        if name == "HOSTNAME":
            text = self._read(session, "/etc/hostname").strip()
            return text or (self.filesystem.vfs.meta("hostname", "localhost")
                            if self.filesystem is not None else "localhost")
        return {
            "BASH": "/bin/bash", "BASH_VERSION": BASH_VERSION, "HOSTTYPE": "x86_64",
            "OSTYPE": "linux-gnu", "MACHTYPE": "x86_64-pc-linux-gnu", "IFS": " \t\n",
            "LINENO": "1", "PS2": "> ", "PS4": "+ ", "OPTIND": "1", "OPTERR": "1",
            "HISTFILE": (self.home(session) or "/") .rstrip("/") + "/.bash_history",
            "BASH_ARGV0": "-bash" if getattr(session, "interactive", True) else "bash",
            "COLUMNS": str(getattr(session, "term_width", 80) or 80) if getattr(session, "has_pty", True) else None,
            "SHELLOPTS": ":".join(sorted(session.shell_options & {"braceexpand", "emacs", "hashall", "histexpand",
                                                                "history", "interactive-comments", "monitor"})),
        }.get(name)

    def set_var(self, session, name: str, value: str, *, export: bool = False) -> None:
        self.ensure(session)
        if name in READONLY:
            raise ShellError(f"{shell_prefix(session)}{name}: readonly variable", 1)
        session.shell_unset.discard(name)
        if name in ("PWD", "OLDPWD"):
            session.shell_vars.pop(name, None)
        if export or name in session.shell_env:
            session.shell_vars.pop(name, None)
            session.shell_env[name] = value
        else:
            session.shell_vars[name] = value
        if name == "PATH":
            session.shell_hash = {}

    def environment(self, session) -> dict[str, str]:
        self.ensure(session)
        env = {k: v for k, v in session.shell_env.items() if k not in session.shell_unset}
        if "PWD" in env:
            env["PWD"] = getattr(session, "cwd", "/")
        if session.shell_cd_count and "OLDPWD" not in session.shell_unset:
            env["OLDPWD"] = getattr(session, "oldpwd", "") or ""
        return env

    # Expansion

    def parameter(self, session, expr: str) -> str:
        match = PARAM_FORM.fullmatch(expr)
        if not match:
            return ""
        length, name, op, word = match.groups()
        value = self.get_var(session, name)
        if length:
            return str(len(value or ""))
        if op:
            word = re.sub(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?",
                          lambda m: self.get_var(session, m.group(1)) or "", word or "")
            null = value is None or (op.startswith(":") and value == "")
            kind = op[-1]
            if kind == "-":
                return word if null else value
            if kind == "=":
                if null:
                    self.set_var(session, name, word)
                    return word
                return value
            if kind == "+":
                return "" if null else word
            if kind == "?" and null:
                raise ShellError(f"{shell_prefix(session)}{name}: {word or 'parameter null or not set'}", 1)
        return value or ""

    def tilde(self, session, spec: str) -> str:
        if spec == "":
            return self.get_var(session, "HOME") or self.home(session) or "~"
        if spec == "+":
            return session.cwd
        if spec == "-":
            return self.get_var(session, "OLDPWD") or "~-"
        return self.home(session, spec) or "~" + spec

    def expand_words(self, session, words: list[str], *, glob: bool = True) -> list[str]:
        self.ensure(session)
        result: list[str] = []
        noglob = "noglob" in session.shell_options
        for word in words:
            if word == "":
                result.append("")
                continue
            fields: list[list[tuple[str, bool]]] = [[]]
            keep = [False]
            pos = 0
            pieces = []
            for m in _MARK.finditer(word):
                if m.start() > pos:
                    pieces.append(("lit", word[pos:m.start()]))
                pieces.append((m.group(1), m.group(2)))
                pos = m.end()
            if pos < len(word):
                pieces.append(("lit", word[pos:]))
            for kind, body in pieces:
                if kind == "lit":
                    fields[-1].append((body, True))
                elif kind == "L":
                    fields[-1].append((body, False))
                    keep[-1] = True
                elif kind == "T":
                    fields[-1].append((self.tilde(session, body), False))
                    keep[-1] = True
                elif body[:1] == "Q":
                    fields[-1].append((self.parameter(session, body[1:]), False))
                    keep[-1] = True
                else:
                    value = self.parameter(session, body[1:])
                    for index, part in enumerate(re.split(r"[ \t\n]+", value)):
                        if index and (fields[-1] or keep[-1]):
                            fields.append([])
                            keep.append(False)
                        if part:
                            fields[-1].append((part, True))
            for segments, kept in zip(fields, keep):
                if not segments and not kept:
                    continue
                text = "".join(s for s, _ in segments)
                if (glob and not noglob and
                        any(active and _GLOB_CHARS & set(s) for s, active in segments)):
                    pattern = "".join(s.replace("[^", "[!") if active else
                                      re.sub(r"([*?\[])", r"[\1]", s) for s, active in segments)
                    matches = self.glob(session, pattern)
                    if matches:
                        result.extend(matches)
                        continue
                result.append(text)
        return result

    # Expand a redirect target as one word with no field splitting, as bash does
    def expand_one(self, session, word: str) -> str:
        words = self.expand_words(session, [word], glob=True)
        if len(words) != 1:
            raise ShellError(f"{shell_prefix(session)}{word.replace(chr(0), '')}: ambiguous redirect", 1)
        return words[0]

    # Pathname expansion against the session's realm with bash's rules
    # hidden names need a literal leading dot and unreadable directories match nothing
    # results are sorted, and no match leaves the word unchanged
    def glob(self, session, pattern: str, limit: int = 10000) -> list[str]:
        access = self._access(session)
        if access is None:
            return []
        absolute = pattern.startswith("/")
        trailing = pattern.endswith("/") and len(pattern) > 1
        parts = [p for p in pattern.split("/") if p]
        if not parts:
            return []

        def magic(part: str) -> bool:
            return bool(_GLOB_CHARS & set(re.sub(r"\[[*?\[]\]", "", part)))

        def join(shown: str, name: str) -> str:
            return name if shown == "" else ("/" + name if shown == "/" else shown + "/" + name)

        candidates = [("/" if absolute else "", "/" if absolute else session.cwd)]
        for index, part in enumerate(parts):
            last = index == len(parts) - 1
            nxt: list[tuple[str, str]] = []
            for shown, real in candidates:
                if not magic(part):
                    literal = re.sub(r"\[([*?\[])\]", r"\1", part)
                    path = posixpath.join(real, literal)
                    try:
                        node = access.resolve(path, follow=not last or trailing)
                    except FSError:
                        continue
                    if (not last or trailing) and not node.is_dir:
                        continue
                    nxt.append((join(shown, literal), path))
                    continue
                try:
                    directory = access.resolve(real, want="rx")
                except FSError:
                    continue
                if not directory.is_dir:
                    continue
                regex = re.compile(fnmatch.translate(part))
                for child in access.vfs.listdir(directory.path):
                    if child.name in (".", "..") or (child.name.startswith(".") and not part.startswith(".")):
                        continue
                    if not regex.match(child.name):
                        continue
                    child_path = posixpath.join(real, child.name)
                    if not last or trailing:
                        try:
                            if not access.resolve(child_path).is_dir:
                                continue
                        except FSError:
                            continue
                    nxt.append((join(shown, child.name), child_path))
                    if len(nxt) > limit:
                        return []
            candidates = nxt
            if not candidates:
                return []
        if not any(magic(p) for p in parts):
            return []
        return sorted(shown + ("/" if trailing else "") for shown, _ in candidates)

    # Commands

    def path_dirs(self, session) -> list[str]:
        value = self.get_var(session, "PATH")
        if value is None:
            return []
        return [d or session.cwd for d in value.split(":")]

    # First executable regular file with this name on PATH, as bash finds it
    def lookup(self, session, name: str) -> Optional[str]:
        access = self._access(session)
        if access is None or not name or "/" in name:
            return None
        for directory in self.path_dirs(session):
            candidate = posixpath.join(directory, name)
            try:
                node = access.resolve(candidate)
            except FSError:
                continue
            if node.is_file and access.fs._can(node, "x", access.ident):
                return candidate
        return None

    def note_command(self, session, name: str) -> None:
        if not name or "/" in name or name in BUILTINS or name in KEYWORDS:
            return
        self.ensure(session)
        if "hashall" not in session.shell_options:
            return
        path = self.lookup(session, name)
        if path:
            hits, _ = session.shell_hash.get(name, (0, path))
            session.shell_hash[name] = (hits + 1, path)

    def _has_programs(self, session) -> bool:
        cached = getattr(session, "_shell_has_programs", None)
        if cached is None:
            cached = any(self.lookup(session, name) for name in ("sh", "ls", "cat", "bash"))
            session._shell_has_programs = cached
        return cached

    def command_not_found_installed(self, session) -> bool:
        access = self._access(session)
        if access is None:
            return False
        for path in ("/usr/lib/command-not-found", "/usr/share/command-not-found/command-not-found"):
            try:
                node = access.resolve(path)
            except FSError:
                continue
            if node.is_file:
                return True
        return False

    def can_sudo(self, session) -> bool:
        for line in self._read(session, "/etc/group").splitlines():
            fields = line.split(":")
            if len(fields) == 4 and fields[0] in ("sudo", "admin") and session.username in fields[3].split(","):
                return True
        return False

    # Bash's answer when argv[0] cannot be executed, or None if it can
    def not_found(self, session, argv: list[str]) -> Optional[tuple[str, int]]:
        if not argv or self.filesystem is None:
            return None
        name = argv[0]
        prefix = shell_prefix(session)
        if "/" in name:
            access = self._access(session)
            try:
                node = access.resolve(name)
            except FSError as exc:
                if exc.errno_name == "EACCES":
                    return f"{prefix}{name}: Permission denied\n", 126
                if exc.errno_name == "ENOTDIR":
                    return f"{prefix}{name}: Not a directory\n", 126
                if not self._has_programs(session):
                    # A store without executables cannot vouch that a command is missing
                    return None
                return f"{prefix}{name}: No such file or directory\n", 127
            if node.is_dir:
                return f"{prefix}{name}: Is a directory\n", 126
            if not access.fs._can(node, "x", access.ident):
                return f"{prefix}{name}: Permission denied\n", 126
            return None
        if name in BUILTINS or name in KEYWORDS or self.lookup(session, name):
            return None
        if not self._has_programs(session):
            # A store without executables cannot vouch that a command is missing
            return None
        if getattr(session, "interactive", True) and self.command_not_found_installed(session):
            root = self.uid(session) == 0
            if name in CNF_DID_YOU_MEAN:
                lines = [f"Command '{name}' not found, did you mean:", ""]
                lines += [f"  command '{cmd}' from deb {pkg}" for cmd, pkg in CNF_DID_YOU_MEAN[name]]
                install = "apt install <deb name>" if root else (
                    "sudo apt install <deb name>" if self.can_sudo(session) else "apt install <deb name>")
                lines += ["", "Try: " + install, ""]
                return "\n".join(lines) + "\n", 127
            if name in CNF_PACKAGES:
                package = CNF_PACKAGES[name]
                if root:
                    tail = [f"apt install {package}", ""]
                elif self.can_sudo(session):
                    tail = [f"sudo apt install {package}", ""]
                else:
                    tail = [f"apt install {package}", "Please ask your administrator."]
                return "\n".join([f"Command '{name}' not found, but can be installed with:", ""] + tail) + "\n", 127
            return f"{name}: command not found\n", 127
        return f"{prefix}{name}: command not found\n", 127

    # Interactive alias expansion of the first word
    # repeats when the value ends in a space
    def expand_alias(self, session, argv: list[str], quoted_head: bool = False) -> list[str]:
        self.ensure(session)
        if not argv or quoted_head or not getattr(session, "interactive", True):
            return argv
        seen = set()
        while argv and argv[0] in session.shell_aliases and argv[0] not in seen:
            seen.add(argv[0])
            value = session.shell_aliases[argv[0]]
            try:
                replacement = shlex.split(value)
            except ValueError:
                return argv
            argv = replacement + argv[1:]
        return argv

    # Builtins

    def run(self, session, argv: list[str], stdin: Optional[str] = None,
            stdin_bytes: Optional[bytes] = None) -> Optional[ShellResult]:
        if not argv or argv[0] not in HANDLED:
            return None
        self.ensure(session)
        try:
            return getattr(self, "_b_" + {"[": "test", ":": "true", ".": "source"}.get(argv[0], argv[0]))(
                session, argv, stdin, stdin_bytes)
        except ShellError as exc:
            return ShellResult(stderr=exc.message + "\n", status=exc.status)

    def _out(self, text: str, status: int = 0, stderr: str = "") -> ShellResult:
        return ShellResult(stdout=_latin(text), stderr=stderr, status=status)

    def _b_true(self, session, argv, stdin, stdin_bytes):
        return ShellResult()

    def _b_false(self, session, argv, stdin, stdin_bytes):
        return ShellResult(status=1)

    def _b_echo(self, session, argv, stdin, stdin_bytes):
        args, newline, escapes = argv[1:], True, False
        while args and re.fullmatch(r"-[neE]+", args[0]):
            for flag in args[0][1:]:
                newline = newline and flag != "n"
                escapes = True if flag == "e" else False if flag == "E" else escapes
            args = args[1:]
        text = " ".join(args)
        stop = False
        if escapes:
            text, stop = _escape_text(text, echo=True)
        return self._out(text + ("\n" if newline and not stop else ""))

    def _b_printf(self, session, argv, stdin, stdin_bytes):
        args = argv[1:]
        target = None
        if args[:1] == ["-v"] and len(args) > 1:
            target, args = args[1], args[2:]
        if args[:1] == ["--"]:
            args = args[1:]
        if not args:
            raise ShellError(f"{shell_prefix(session)}printf: usage: printf [-v var] format [arguments]", 2)
        fmt, values = args[0], args[1:]
        out, errors, index = [], [], 0
        spec = re.compile(r"%([-+ #0]*)(\*|\d+)?(?:\.(\*|\d*))?([diouxXeEfFgGcsbq%])")

        def take():
            nonlocal index
            if index < len(values):
                index += 1
                return values[index - 1]
            return None

        def number(raw, kind):
            if raw is None or raw == "":
                return 0
            if raw[:1] in "'\"" and len(raw) > 1:
                return ord(raw[1])
            try:
                return float(raw) if kind == "f" else int(raw, 0) if not re.fullmatch(r"[-+]?0\d+", raw) else int(raw, 8)
            except ValueError:
                errors.append(f"{shell_prefix(session)}printf: {raw}: invalid number")
                return 0
        while True:
            start = index
            pos = 0
            for m in spec.finditer(fmt):
                out.append(_escape_text(fmt[pos:m.start()], echo=False)[0])
                pos = m.end()
                flags, width, precision, conv = m.groups()
                if conv == "%":
                    out.append("%")
                    continue
                if width == "*":
                    width = str(int(number(take(), "d")))
                if precision == "*":
                    precision = str(int(number(take(), "d")))
                # Bash would print gigabytes for %999999999s, the honeypot must not
                if width and abs(int(width)) > 8192:
                    width = "8192" if int(width) > 0 else "-8192"
                if precision and int(precision) > 8192:
                    precision = "8192"
                raw = take()
                pyspec = "%" + flags + (width or "") + ("." + precision if precision is not None else "")
                if conv in "diouxX":
                    value = int(number(raw, "d"))
                    text = (pyspec + ("d" if conv in "diu" else conv)) % value
                elif conv in "eEfFgG":
                    text = (pyspec + conv) % float(number(raw, "f"))
                elif conv == "c":
                    text = (pyspec + "s") % ((raw or "")[:1])
                elif conv == "b":
                    expanded, stop = _escape_text(raw or "", echo=True)
                    text = (pyspec + "s") % expanded
                    if stop:
                        out.append(text)
                        return self._finish_printf(session, target, out, errors)
                elif conv == "q":
                    text = (pyspec + "s") % (re.sub(r"([^A-Za-z0-9_./=:,@%+-])", r"\\\1", raw or "") or "''")
                else:
                    text = (pyspec + "s") % (raw or "")
                out.append(text)
            out.append(_escape_text(fmt[pos:], echo=False)[0])
            if index >= len(values) or index == start:
                break
        return self._finish_printf(session, target, out, errors)

    def _finish_printf(self, session, target, out, errors):
        text = "".join(out)
        if target:
            self.set_var(session, target, text)
            text = ""
        return self._out(text, 1 if errors else 0, "".join(e + "\n" for e in errors))

    def _b_export(self, session, argv, stdin, stdin_bytes):
        args = argv[1:]
        unexport = False
        while args and args[0].startswith("-") and args[0] != "-":
            if args[0] == "--":
                args = args[1:]
                break
            if set(args[0][1:]) - set("fnp"):
                raise ShellError(f"{shell_prefix(session)}export: {args[0][:2]}: invalid option\n"
                                 "export: usage: export [-fn] [name[=value] ...] or export -p", 2)
            unexport = unexport or "n" in args[0]
            args = args[1:]
        if not args:
            env = self.environment(session)
            lines = [f'declare -x {k}="{v}"' if v is not None else f"declare -x {k}"
                     for k, v in sorted(env.items())]
            return self._out("".join(line + "\n" for line in lines))
        errors = []
        for arg in args:
            name, sep, value = arg.partition("=")
            if not _IDENT.fullmatch(name):
                errors.append(f"{shell_prefix(session)}export: `{arg}': not a valid identifier")
                continue
            if unexport:
                if name in session.shell_env:
                    session.shell_vars[name] = session.shell_env.pop(name)
                continue
            if sep:
                self.set_var(session, name, value, export=True)
            else:
                current = session.shell_vars.pop(name, None)
                if current is not None or name not in session.shell_env:
                    session.shell_env[name] = current if current is not None else (self.get_var(session, name) or "")
                session.shell_unset.discard(name)
        return ShellResult(stderr="".join(e + "\n" for e in errors), status=1 if errors else 0)

    def _b_unset(self, session, argv, stdin, stdin_bytes):
        errors = []
        for name in argv[1:]:
            if name in ("-v", "-f", "-n"):
                continue
            if not _IDENT.fullmatch(name):
                errors.append(f"{shell_prefix(session)}unset: `{name}': not a valid identifier")
                continue
            if name in READONLY:
                errors.append(f"{shell_prefix(session)}unset: {name}: cannot unset: readonly variable")
                continue
            session.shell_vars.pop(name, None)
            session.shell_env.pop(name, None)
            session.shell_unset.add(name)
            if name == "PATH":
                session.shell_hash = {}
        return ShellResult(stderr="".join(e + "\n" for e in errors), status=1 if errors else 0)

    def _b_set(self, session, argv, stdin, stdin_bytes):
        args = argv[1:]
        if not args:
            names = set(session.shell_vars) | set(self.environment(session)) | {
                "BASH", "BASH_VERSION", "HISTFILE", "HOSTNAME", "HOSTTYPE", "IFS", "MACHTYPE",
                "OPTERR", "OPTIND", "OSTYPE", "PPID", "PS2", "PS4", "SHELLOPTS", "UID", "EUID"}
            rows = []
            for name in sorted(names):
                value = self.get_var(session, name)
                if value is None:
                    continue
                shown = value if re.fullmatch(r"[A-Za-z0-9_./:,@%+=-]*", value) and value else single_quote(value)
                if name == "IFS":
                    shown = "$' \\t\\n'"
                rows.append(f"{name}={shown}")
            return self._out("".join(r + "\n" for r in rows))
        index = 0
        while index < len(args):
            arg = args[index]
            if arg in ("-o", "+o"):
                if index + 1 >= len(args):
                    rows = ([f"{o:<15}\t{'on' if o in session.shell_options else 'off'}" for o in SET_OPTIONS]
                            if arg == "-o" else
                            [f"set {'-' if o in session.shell_options else '+'}o {o}" for o in SET_OPTIONS])
                    return self._out("".join(r + "\n" for r in rows))
                option = args[index + 1]
                if option not in SET_OPTIONS:
                    raise ShellError(f"{shell_prefix(session)}set: {option}: invalid option name", 1)
                (session.shell_options.add if arg == "-o" else session.shell_options.discard)(option)
                index += 2
                continue
            if arg == "--":
                break
            if re.fullmatch(r"[-+][abefhkmnptuvxBCHP]+", arg):
                letters = {"f": "noglob", "u": "nounset", "x": "xtrace", "e": "errexit", "v": "verbose",
                           "C": "noclobber", "H": "histexpand", "h": "hashall", "m": "monitor",
                           "a": "allexport", "B": "braceexpand", "n": "noexec", "b": "notify",
                           "k": "keyword", "p": "privileged", "t": "onecmd", "P": "physical", "T": "functrace",
                           "E": "errtrace"}
                for letter in arg[1:]:
                    option = letters.get(letter)
                    if option:
                        (session.shell_options.add if arg[0] == "-" else session.shell_options.discard)(option)
                index += 1
                continue
            if arg.startswith(("-", "+")):
                raise ShellError(f"{shell_prefix(session)}set: {arg[:2]}: invalid option\n"
                                 "set: usage: set [-abefhkmnptuvxBCHP] [-o option-name] [--] [arg ...]", 2)
            break
        return ShellResult()

    def _b_shopt(self, session, argv, stdin, stdin_bytes):
        return ShellResult() if len(argv) > 2 and argv[1] in ("-s", "-u", "-q") else None

    def _b_ulimit(self, session, argv, stdin, stdin_bytes):
        if argv[1:] in ([], ["-f"]):
            return self._out("unlimited\n")
        if argv[1:] == ["-n"]:
            return self._out("1024\n")
        return None

    def _b_alias(self, session, argv, stdin, stdin_bytes):
        args = [a for a in argv[1:] if a != "-p"]
        if not args:
            return self._out("".join(f"alias {k}={single_quote(v)}\n"
                                     for k, v in sorted(session.shell_aliases.items())))
        out, errors = [], []
        for arg in args:
            name, sep, value = arg.partition("=")
            if sep:
                session.shell_aliases[name] = value
            elif name in session.shell_aliases:
                out.append(f"alias {name}={single_quote(session.shell_aliases[name])}\n")
            else:
                errors.append(f"{shell_prefix(session)}alias: {name}: not found\n")
        return self._out("".join(out), 1 if errors else 0, "".join(errors))

    def _b_unalias(self, session, argv, stdin, stdin_bytes):
        if argv[1:] == ["-a"]:
            session.shell_aliases.clear()
            return ShellResult()
        if not argv[1:]:
            raise ShellError(f"{shell_prefix(session)}unalias: usage: unalias [-a] name [name ...]", 2)
        errors = []
        for name in argv[1:]:
            if session.shell_aliases.pop(name, None) is None:
                errors.append(f"{shell_prefix(session)}unalias: {name}: not found\n")
        return ShellResult(stderr="".join(errors), status=1 if errors else 0)

    # [(kind, detail)] for type and command - alias, keyword, builtin, hashed or file
    def describe(self, session, name: str, *, all_matches=False) -> list[tuple[str, str]]:
        found = []
        if name in session.shell_aliases and getattr(session, "interactive", True):
            found.append(("alias", session.shell_aliases[name]))
        if name in KEYWORDS:
            found.append(("keyword", name))
        if name in BUILTINS:
            found.append(("builtin", name))
        if not all_matches and found:
            return found[:1]
        if name in session.shell_hash and not all_matches:
            return found + [("hashed", session.shell_hash[name][1])]
        access = self._access(session)
        if access is None:
            return found
        if "/" in name:
            try:
                node = access.resolve(name)
                if node.is_file and access.fs._can(node, "x", access.ident):
                    found.append(("file", name))
            except FSError:
                pass
            return found
        for directory in self.path_dirs(session):
            candidate = posixpath.join(directory, name)
            try:
                node = access.resolve(candidate)
            except FSError:
                continue
            if node.is_file and access.fs._can(node, "x", access.ident):
                found.append(("file", candidate))
                if not all_matches:
                    break
        return found

    def _b_type(self, session, argv, stdin, stdin_bytes):
        args = argv[1:]
        flags = set()
        while args and args[0].startswith("-") and len(args[0]) > 1:
            flags |= set(args[0][1:])
            args = args[1:]
        out, errors = [], []
        for name in args:
            found = self.describe(session, name, all_matches="a" in flags)
            if not found:
                if "t" not in flags and "p" not in flags and "P" not in flags:
                    errors.append(f"{shell_prefix(session)}type: {name}: not found\n")
                else:
                    errors.append("")
                continue
            for kind, detail in found:
                if "t" in flags:
                    out.append(("file" if kind == "hashed" else kind) + "\n")
                elif "p" in flags or "P" in flags:
                    if kind in ("file", "hashed"):
                        out.append(detail + "\n")
                elif kind == "alias":
                    out.append(f"{name} is aliased to `{detail}'\n")
                elif kind == "keyword":
                    out.append(f"{name} is a shell keyword\n")
                elif kind == "builtin":
                    out.append(f"{name} is a shell builtin\n")
                elif kind == "hashed":
                    out.append(f"{name} is hashed ({detail})\n")
                else:
                    out.append(f"{name} is {detail}\n")
                if "t" in flags and "a" not in flags:
                    break
        return self._out("".join(out), 1 if errors else 0, "".join(errors))

    def _b_command(self, session, argv, stdin, stdin_bytes):
        args = argv[1:]
        if not args:
            return ShellResult()
        if args[0] in ("-v", "-V"):
            verbose = args[0] == "-V"
            out, failed = [], False
            for name in args[1:]:
                found = self.describe(session, name)
                if not found:
                    failed = True
                    if verbose:
                        return ShellResult(stderr=f"{shell_prefix(session)}command: {name}: not found\n", status=1)
                    continue
                kind, detail = found[0]
                if verbose:
                    out.append(self._b_type(session, ["type", name], None, None).stdout.decode())
                elif kind == "alias":
                    out.append(f"alias {name}={single_quote(detail)}\n")
                elif kind in ("keyword", "builtin"):
                    out.append(name + "\n")
                else:
                    out.append(detail + "\n")
            return self._out("".join(out), 1 if failed else 0)
        if args[0] == "-p":
            args = args[1:]
        return ShellResult(delegate=args) if args else ShellResult()

    def _b_hash(self, session, argv, stdin, stdin_bytes):
        args = argv[1:]
        if args == ["-r"]:
            session.shell_hash = {}
            return ShellResult()
        if args:
            errors = []
            for name in args:
                path = self.lookup(session, name)
                if path:
                    session.shell_hash[name] = (0, path)
                else:
                    errors.append(f"{shell_prefix(session)}hash: {name}: not found\n")
            return ShellResult(stderr="".join(errors), status=1 if errors else 0)
        if not session.shell_hash:
            return self._out("hash: hash table empty\n")
        rows = ["hits\tcommand"] + [f"{hits:4d}\t{path}" for name, (hits, path) in session.shell_hash.items()]
        return self._out("".join(r + "\n" for r in rows))

    def _b_umask(self, session, argv, stdin, stdin_bytes):
        if session.shell_umask is None:
            from .fscommands import session_umask
            session.shell_umask = session_umask(session, self._view(session))
        args = argv[1:]
        if not args or args == ["-p"]:
            return self._out(("umask " if args else "") + f"{session.shell_umask:04o}\n")
        if args == ["-S"]:
            allowed = ~session.shell_umask & 0o777
            parts = []
            for who, shift in (("u", 6), ("g", 3), ("o", 0)):
                bits = (allowed >> shift) & 7
                parts.append(who + "=" + "".join(c for c, b in (("r", 4), ("w", 2), ("x", 1)) if bits & b))
            return self._out(",".join(parts) + "\n")
        if re.fullmatch(r"[0-7]{1,4}", args[0]):
            session.shell_umask = int(args[0], 8) & 0o777
            return ShellResult()
        return None

    def _b_printenv(self, session, argv, stdin, stdin_bytes):
        env = self.environment(session)
        env["_"] = "/usr/bin/printenv"
        names = [a for a in argv[1:] if not a.startswith("-")]
        if any(a.startswith("-") for a in argv[1:]):
            return None
        if not names:
            return self._out("".join(f"{k}={v}\n" for k, v in env.items()))
        values = [env[n] for n in names if n in env]
        return self._out("".join(v + "\n" for v in values), 0 if len(values) == len(names) else 1)

    def _b_env(self, session, argv, stdin, stdin_bytes):
        args = argv[1:]
        if not args:
            env = self.environment(session)
            env["_"] = "/usr/bin/env"
            return self._out("".join(f"{k}={v}\n" for k, v in env.items()))
        if args[0].startswith("-"):
            return None
        while args and "=" in args[0] and _IDENT.fullmatch(args[0].split("=", 1)[0]):
            args = args[1:]
        if not args:
            env = self.environment(session)
            for assignment in argv[1:]:
                name, _, value = assignment.partition("=")
                env[name] = value
            env["_"] = "/usr/bin/env"
            return self._out("".join(f"{k}={v}\n" for k, v in env.items()))
        return ShellResult(delegate=args)

    def _b_source(self, session, argv, stdin, stdin_bytes):
        if len(argv) < 2:
            raise ShellError(f"{shell_prefix(session)}{argv[0]}: filename argument required\n"
                             f"{argv[0]}: usage: {argv[0]} filename [arguments]", 2)
        access = self._access(session)
        if access is None:
            return None
        try:
            node = access.resolve(argv[1], want="r")
        except FSError as exc:
            return ShellResult(stderr=f"{shell_prefix(session)}{argv[1]}: {exc.message}\n", status=1)
        if node.is_dir:
            return ShellResult(stderr=f"{shell_prefix(session)}{argv[1]}: is a directory\n", status=1)
        # Startup files only set variables and aliases, so their effect is silence
        return ShellResult() if posixpath.basename(node.path) in RC_FILES else None

    def _b_history(self, session, argv, stdin, stdin_bytes):
        args = argv[1:]
        if not getattr(session, "interactive", True):
            return ShellResult()
        if args == ["-c"]:
            session.shell_history = []
            return ShellResult()
        if args and args[0] in ("-w", "-a", "-r", "-n"):
            return ShellResult()
        if len(args) == 2 and args[0] == "-d" and args[1].lstrip("-").isdigit():
            index = int(args[1])
            if not 1 <= index <= len(session.shell_history):
                return ShellResult(stderr=f"{shell_prefix(session)}history: {args[1]}: history position out of range\n", status=1)
            del session.shell_history[index - 1]
            return ShellResult()
        if len(args) > 1 or (args and not args[0].isdigit()):
            return None
        lines = session.shell_history
        count = int(args[0]) if args else len(lines)
        start = max(0, len(lines) - count)
        return self._out("".join(f"{i + 1:5d}  {line}\n" for i, line in enumerate(lines) if i >= start))

    def _b_test(self, session, argv, stdin, stdin_bytes):
        args = argv[1:]
        name = argv[0]
        if name == "[":
            if not args or args[-1] != "]":
                return ShellResult(stderr=f"{shell_prefix(session)}[: missing `]'\n", status=2)
            args = args[:-1]
        try:
            return ShellResult(status=0 if self._test(session, args) else 1)
        except ShellError as exc:
            return ShellResult(stderr=exc.message.replace("{name}", name) + "\n", status=2)

    def _test(self, session, args: list[str]) -> bool:
        if not args:
            return False
        if args[0] == "!":
            return not self._test(session, args[1:])
        for joiner in ("-o", "-a"):
            if joiner in args[1:-1]:
                index = args.index(joiner, 1)
                left, right = self._test(session, args[:index]), self._test(session, args[index + 1:])
                return (left or right) if joiner == "-o" else (left and right)
        if len(args) == 1:
            return args[0] != ""
        if len(args) == 2:
            op, operand = args
            if op == "-z":
                return operand == ""
            if op == "-n":
                return operand != ""
            if op in ("-e", "-a", "-f", "-d", "-r", "-w", "-x", "-s", "-L", "-h", "-p", "-S", "-b", "-c", "-u", "-g", "-k", "-O", "-G"):
                return self._file_test(session, op, operand)
            raise ShellError(f"{shell_prefix(session)}{{name}}: {op}: unary operator expected")
        if len(args) == 3:
            a, op, b = args
            if op in ("=", "=="):
                return a == b
            if op == "!=":
                return a != b
            if op in ("<", ">"):
                return a < b if op == "<" else a > b
            if op in ("-eq", "-ne", "-lt", "-le", "-gt", "-ge"):
                values = []
                for value in (a, b):
                    if not re.fullmatch(r"\s*[-+]?\d+\s*", value):
                        raise ShellError(f"{shell_prefix(session)}{{name}}: {value}: integer expression expected")
                    values.append(int(value))
                x, y = values
                return {"-eq": x == y, "-ne": x != y, "-lt": x < y, "-le": x <= y, "-gt": x > y, "-ge": x >= y}[op]
            if op in ("-nt", "-ot", "-ef"):
                return False
            raise ShellError(f"{shell_prefix(session)}{{name}}: {op}: binary operator expected")
        raise ShellError(f"{shell_prefix(session)}{{name}}: too many arguments")

    def _file_test(self, session, op: str, path: str) -> bool:
        access = self._access(session)
        if access is None or not path:
            return False
        try:
            node = access.resolve(path, follow=op not in ("-L", "-h"))
        except FSError:
            return False
        if op in ("-e", "-a"):
            return True
        if op == "-f":
            return node.is_file
        if op == "-d":
            return node.is_dir
        if op in ("-L", "-h"):
            return node.is_link
        if op == "-s":
            return node.size > 0
        if op in ("-r", "-w", "-x"):
            return access.fs._can(node, op[1], access.ident)
        if op == "-u":
            return bool(node.mode & statmod.S_ISUID)
        if op == "-g":
            return bool(node.mode & statmod.S_ISGID)
        if op == "-k":
            return bool(node.mode & statmod.S_ISVTX)
        if op == "-O":
            return node.uid == access.ident.uid
        if op == "-G":
            return node.gid == access.ident.gid
        return False


# Completion
# readline-style Tab completion for interactive sessions
# one Tab completes a unique match or the longest common prefix, otherwise rings the bell
# a second Tab at the same place lists the candidates, as bash does
# command words complete builtins, keywords, aliases and programs on PATH
# other words complete paths the user may list, with the same permission checks as ls

_WORD_BREAKS = re.compile(r"[^\s;|&<>()]*$")
_ESCAPE = re.compile(r"([\s\\'\"$`!&|;()<>*?\[\]{}#])")
MAX_LISTED = 100


def _escape_completion(text: str) -> str:
    return _ESCAPE.sub(r"\\\1", text)


# Complete the word at pos
# returns ("insert", new_line, new_pos), ("list", [candidates]) or ("bell",)
def _complete(self, session, line: str, pos: int):
    self.ensure(session)
    before = line[:pos]
    word = _WORD_BREAKS.search(before).group(0)
    start = pos - len(word)
    if word[:1] in ("'", '"') or "$" in word:
        return ("bell",)
    typed = re.sub(r"\\(.)", r"\1", word)
    head = before[:start].rstrip()
    command_word = (not head or head.endswith((";", "|", "&", "(")) or
                    re.search(r"(^|[;&|(])\s*(sudo|time|nohup|command|exec|env)$", head) is not None)
    access = self._access(session)
    # (name, is_directory) pairs
    candidates: list[tuple[str, bool]] = []
    if command_word and "/" not in typed:
        names = set(BUILTINS) | set(KEYWORDS) | set(session.shell_aliases)
        if access is not None:
            for directory in self.path_dirs(session):
                try:
                    node = access.resolve(directory, want="rx")
                except FSError:
                    continue
                if not node.is_dir:
                    continue
                for child in access.vfs.listdir(node.path):
                    if child.name.startswith(typed) and not child.is_dir and (
                            child.is_link or access.fs._can(child, "x", access.ident)):
                        names.add(child.name)
        candidates = [(n, False) for n in names if n.startswith(typed)]
        base = typed
    else:
        if access is None:
            return ("bell",)
        directory, _, base = typed.rpartition("/")
        lookup = directory if "/" in typed else "."
        if typed.startswith("/") and not directory:
            lookup = "/"
        if lookup.startswith("~"):
            user, _, rest = lookup[1:].partition("/")
            home = self.home(session, user or None)
            if home is None:
                return ("bell",)
            lookup = home + ("/" + rest if rest else "")
        try:
            node = access.resolve(lookup, want="rx")
        except FSError:
            return ("bell",)
        if not node.is_dir:
            return ("bell",)
        for child in access.vfs.listdir(node.path):
            if child.name in (".", "..") or not child.name.startswith(base):
                continue
            if child.name.startswith(".") and not base.startswith("."):
                continue
            is_dir = child.is_dir
            if child.is_link:
                try:
                    is_dir = access.resolve(posixpath.join(node.path, child.name)).is_dir
                except FSError:
                    is_dir = False
            candidates.append((child.name, is_dir))
    candidates.sort()
    if not candidates:
        return ("bell",)
    if len(candidates) == 1:
        name, is_dir = candidates[0]
        insert = _escape_completion(name[len(base):]) + ("/" if is_dir else " ")
        return ("insert", line[:pos] + insert + line[pos:], pos + len(insert))
    common = posixpath.commonprefix([name for name, _ in candidates])
    if len(common) > len(base):
        insert = _escape_completion(common[len(base):])
        return ("insert", line[:pos] + insert + line[pos:], pos + len(insert))
    if len(candidates) > MAX_LISTED:
        return ("bell",)
    return ("list", [name + ("/" if is_dir else "") for name, is_dir in candidates])


# Readline's column layout, sorted and filled down the columns
def format_completions(names: list[str], width: int) -> str:
    if not names:
        return ""
    column = max(len(n) for n in names) + 2
    columns = max(1, (width or 80) // column)
    rows = -(-len(names) // columns)
    lines = []
    for row in range(rows):
        cells = [names[row + col * rows] for col in range(columns) if row + col * rows < len(names)]
        lines.append("".join(cell.ljust(column) for cell in cells).rstrip())
    return "\n".join(lines)


Shell.complete = _complete
