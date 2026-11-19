# Account Commands
# useradd, usermod, passwd and the other account tools, run against the virtual filesystem
# each command edits the real identity files, so id, groups, su and /etc/passwd all agree
# returns one string with no trailing newline, or None to decline

# Imports
from __future__ import annotations

import hashlib
import posixpath
import time
from typing import Callable, Optional

from .vfs import VFS, FSError

# Groups adduser gives a new interactive user on Ubuntu
_ADMIN_GROUPS = ("adm", "dialout", "cdrom", "floppy", "sudo", "audio", "dip",
                 "video", "plugdev", "netdev", "lxd")


# Split clustered short flags so -aG parses as -a -G
# usermod -aG sudo is how people actually type it
def _expand_clusters(args: list[str], valued: str) -> list[str]:
    out: list[str] = []
    for a in args:
        if a.startswith("--") or not a.startswith("-") or len(a) <= 2:
            out.append(a)
            continue
        letters = a[1:]
        if not letters.isalpha():
            out.append(a)
            continue
        for i, ch in enumerate(letters):
            out.append("-" + ch)
            if ch in valued and i < len(letters) - 1:
                # Value attached to the last flag
                out.append(letters[i + 1:])
                break
    return out


class AccountCommands:
    def __init__(self, vfs: VFS) -> None:
        self.vfs = vfs
        self.last_flags: list[str] = []
        self.last_exit_code = 0
        self._table: dict[str, Callable] = {
            "useradd": self._useradd, "adduser": self._useradd,
            "userdel": self._userdel, "deluser": self._userdel,
            "usermod": self._usermod,
            "groupadd": self._groupadd, "addgroup": self._groupadd,
            "groupdel": self._groupdel,
            "passwd": self._passwd, "chpasswd": self._chpasswd,
        }

    def names(self) -> list[str]:
        return sorted(self._table)

    def run_argv(self, session, argv: list[str],
                 stdin: Optional[str] = None) -> Optional[str]:
        if not argv:
            return None
        self.last_flags = []
        self.last_exit_code = 0
        self.vfs.realm = getattr(session, "realm", "") or "unknown"
        fn = self._table.get(argv[0].rsplit("/", 1)[-1])
        if fn is None:
            return None
        ident = getattr(session, "_identity", None)
        is_root = session.username == "root" or (ident and ident.uid == 0)
        try:
            result = fn(session, argv[1:], stdin, bool(is_root))
            # Only a recorded change counts as success
            # diagnostic text without a change is a failure
            if result is not None and result and not self.last_flags:
                self.last_exit_code = 1
            return result
        except FSError as exc:
            self.last_exit_code = 1
            return f"{argv[0]}: {exc.message}"

    # Identity File Access

    def _read(self, path: str) -> str:
        try:
            data = self.vfs.read(path)
        except FSError:
            return ""
        return data.decode("utf-8", "replace") if data else ""

    def _write_passwd(self, text: str) -> None:
        self.vfs.write_file("/etc/passwd", text.encode(), uid=0, gid=0,
                            uname="root", gname="root", mode=0o644)

    def _write_group(self, text: str) -> None:
        self.vfs.write_file("/etc/group", text.encode(), uid=0, gid=0,
                            uname="root", gname="root", mode=0o644)

    def _write_shadow(self, text: str) -> None:
        self.vfs.write_file("/etc/shadow", text.encode(), uid=0, gid=42,
                            uname="root", gname="shadow", mode=0o640)

    @staticmethod
    def _rows(text: str) -> list[list[str]]:
        return [l.split(":") for l in text.splitlines() if l.strip()]

    def _next_id(self, text: str, field: int = 2) -> int:
        ids = []
        for row in self._rows(text):
            if len(row) > field and row[field].isdigit():
                ids.append(int(row[field]))
        return max([i for i in ids if 1000 <= i < 60000] or [999]) + 1

    def _has(self, text: str, name: str) -> bool:
        return any(row and row[0] == name for row in self._rows(text))

    # Users

    def _useradd(self, session, args, stdin, is_root) -> Optional[str]:
        name = args[0].rsplit("/", 1)[-1] if args else "useradd"
        util = "adduser" if "adduser" in (name,) else "useradd"
        args = _expand_clusters(args, "sdugGcp")
        make_home, shell, home, system = False, "/bin/sh", None, False
        names, i = [], 0
        while i < len(args):
            a = args[i]
            if a in ("-m", "--create-home"):
                make_home = True
            elif a in ("-M", "--no-create-home"):
                make_home = False
            elif a in ("-r", "--system"):
                system = True
            elif a in ("-s", "--shell") and i + 1 < len(args):
                shell = args[i + 1]; i += 2; continue
            elif a in ("-d", "--home", "--home-dir") and i + 1 < len(args):
                home = args[i + 1]; i += 2; continue
            elif a in ("-u", "-g", "-G", "-c", "-p", "--gecos", "--uid",
                       "--gid", "--groups", "--password") and i + 1 < len(args):
                i += 2; continue
            elif a.startswith("-"):
                # Unknown flag - decline rather than guess
                return None
            else:
                names.append(a)
            i += 1
        if len(names) != 1:
            return None
        user = names[0]
        if not is_root:
            return (f"{util}: Permission denied.\n"
                    f"{util}: cannot lock /etc/passwd; try again later.")

        passwd = self._read("/etc/passwd")
        if self._has(passwd, user):
            return f"{util}: user '{user}' already exists"

        uid = self._next_id(passwd) if not system else 999
        home = home or f"/home/{user}"
        self._write_passwd(passwd.rstrip("\n") +
                           f"\n{user}:x:{uid}:{uid}::{home}:{shell}\n")

        group = self._read("/etc/group")
        if not self._has(group, user):
            self._write_group(group.rstrip("\n") + f"\n{user}:x:{uid}:\n")

        shadow = self._read("/etc/shadow")
        days = int(time.time() // 86400)
        self._write_shadow(shadow.rstrip("\n") +
                           f"\n{user}:!:{days}:0:99999:7:::\n")

        if make_home:
            try:
                if not self.vfs.exists(home):
                    self.vfs.mkdir(home, uid=uid, gid=uid, uname=user,
                                   gname=user, mode=0o750)
                for skel in self.vfs.listdir("/etc/skel"):
                    if skel.is_file:
                        self.vfs.write_file(
                            posixpath.join(home, skel.name),
                            self.vfs.read(skel.path) or b"", uid=uid, gid=uid,
                            uname=user, gname=user, mode=skel.mode)
            except FSError:
                pass

        self.last_flags.append("account_added")
        # Silent for useradd, while adduser narrates each step
        if util == "useradd":
            return ""
        return "\n".join([
            f"Adding user `{user}' ...",
            f"Adding new group `{user}' ({uid}) ...",
            f"Adding new user `{user}' ({uid}) with group `{user}' ...",
            f"Creating home directory `{home}' ..." if make_home else
            f"Not creating home directory `{home}'.",
            "Copying files from `/etc/skel' ..." if make_home else "",
        ]).replace("\n\n", "\n").rstrip()

    def _userdel(self, session, args, stdin, is_root) -> Optional[str]:
        remove_home = "-r" in args or "--remove" in args
        names = [a for a in args if not a.startswith("-")]
        if len(names) != 1:
            return None
        user = names[0]
        if not is_root:
            return "userdel: Permission denied."
        passwd = self._read("/etc/passwd")
        if not self._has(passwd, user):
            return f"userdel: user '{user}' does not exist"
        home = next((r[5] for r in self._rows(passwd)
                     if r[0] == user and len(r) > 5), f"/home/{user}")

        self._write_passwd("\n".join(
            l for l in passwd.splitlines() if not l.startswith(user + ":")) + "\n")
        group = self._read("/etc/group")
        kept = []
        for line in group.splitlines():
            if line.startswith(user + ":"):
                continue
            f = line.split(":")
            if len(f) == 4 and user in f[3].split(","):
                f[3] = ",".join(m for m in f[3].split(",") if m and m != user)
                line = ":".join(f)
            kept.append(line)
        self._write_group("\n".join(kept) + "\n")
        shadow = self._read("/etc/shadow")
        self._write_shadow("\n".join(
            l for l in shadow.splitlines() if not l.startswith(user + ":")) + "\n")

        if remove_home:
            try:
                self.vfs.remove(home, recursive=True)
            except FSError:
                pass
        self.last_flags.append("account_removed")
        return ""

    def _usermod(self, session, args, stdin, is_root) -> Optional[str]:
        args = _expand_clusters(args, "Gsd")
        add_groups, shell, new_home = [], None, None
        append_groups, groups_supplied = False, False
        names, i = [], 0
        while i < len(args):
            a = args[i]
            if a in ("-a", "--append"):
                append_groups = True
            elif a in ("-G", "--groups") and i + 1 < len(args):
                groups_supplied = True
                add_groups = [g for g in args[i + 1].split(",") if g]
                i += 2; continue
            elif a in ("-s", "--shell") and i + 1 < len(args):
                shell = args[i + 1]; i += 2; continue
            elif a in ("-d", "--home") and i + 1 < len(args):
                new_home = args[i + 1]; i += 2; continue
            elif a in ("-L", "-U"):
                pass
            elif a.startswith("-"):
                return None
            else:
                names.append(a)
            i += 1
        if len(names) != 1:
            return None
        user = names[0]
        if not is_root:
            return "usermod: Permission denied."
        passwd = self._read("/etc/passwd")
        if not self._has(passwd, user):
            return f"usermod: user '{user}' does not exist"

        group = self._read("/etc/group")
        known = {f[0] for f in self._rows(group) if len(f) == 4}
        missing = [g for g in add_groups if g not in known]
        if missing:
            return f"usermod: group '{missing[0]}' does not exist"
        if shell or new_home:
            rows = []
            for line in passwd.splitlines():
                f = line.split(":")
                if f and f[0] == user and len(f) >= 7:
                    if new_home:
                        f[5] = new_home
                    if shell:
                        f[6] = shell
                    line = ":".join(f)
                rows.append(line)
            self._write_passwd("\n".join(rows) + "\n")

        if groups_supplied:
            rows, known = [], set()
            for line in group.splitlines():
                f = line.split(":")
                if len(f) == 4:
                    known.add(f[0])
                    if f[0] in add_groups:
                        members = [m for m in f[3].split(",") if m]
                        if user not in members:
                            members.append(user)
                        f[3] = ",".join(members)
                        line = ":".join(f)
                    elif not append_groups:
                        f[3] = ','.join(m for m in f[3].split(',') if m and m != user)
                        line = ':'.join(f)
                rows.append(line)
            self._write_group("\n".join(rows) + "\n")
        self.last_flags.append("account_modified")
        return ""

    # Groups

    def _groupadd(self, session, args, stdin, is_root) -> Optional[str]:
        names = [a for a in args if not a.startswith("-")]
        if len(names) != 1:
            return None
        if not is_root:
            return "groupadd: Permission denied."
        group = self._read("/etc/group")
        if self._has(group, names[0]):
            return f"groupadd: group '{names[0]}' already exists"
        gid = self._next_id(group)
        self._write_group(group.rstrip("\n") + f"\n{names[0]}:x:{gid}:\n")
        self.last_flags.append("group_added")
        return ""

    def _groupdel(self, session, args, stdin, is_root) -> Optional[str]:
        names = [a for a in args if not a.startswith("-")]
        if len(names) != 1:
            return None
        if not is_root:
            return "groupdel: Permission denied."
        group = self._read("/etc/group")
        if not self._has(group, names[0]):
            return f"groupdel: group '{names[0]}' does not exist"
        self._write_group("\n".join(
            l for l in group.splitlines()
            if not l.startswith(names[0] + ":")) + "\n")
        return ""

    # Passwords

    # Yescrypt-shaped digest for /etc/shadow
    # stable for a user and day, so two reads never disagree
    @staticmethod
    def _hash(user: str, days: int) -> str:
        raw = hashlib.sha256(f"{user}:{days}".encode()).hexdigest()
        return "$y$j9T$" + raw[:22] + "$" + raw[22:65]

    def _set_password(self, user: str) -> bool:
        shadow = self._read("/etc/shadow")
        days = int(time.time() // 86400)
        rows, found = [], False
        for line in shadow.splitlines():
            f = line.split(":")
            if f and f[0] == user and len(f) >= 3:
                f[1] = self._hash(user, days)
                f[2] = str(days)
                line = ":".join(f)
                found = True
            rows.append(line)
        if found:
            self._write_shadow("\n".join(rows) + "\n")
        return found

    def _passwd(self, session, args, stdin, is_root) -> Optional[str]:
        flags = [a for a in args if a.startswith("-")]
        names = [a for a in args if not a.startswith("-")]
        if flags and set("".join(flags).replace("-", "")) - set("ldeS"):
            return None
        target = names[0] if names else session.username
        if target != session.username and not is_root:
            return (f"passwd: You may not view or modify password information "
                    f"for {target}.")
        if not self._has(self._read("/etc/passwd"), target):
            return f"passwd: user '{target}' does not exist"
        if not self._set_password(target):
            return f"passwd: user '{target}' does not exist"
        self.last_flags.append("password_changed")
        # Without a tty passwd cannot prompt
        # this is what the prompts and the result look like on the wire
        return ("New password: \nRetype new password: \n"
                "passwd: password updated successfully")

    def _chpasswd(self, session, args, stdin, is_root) -> Optional[str]:
        if stdin is None:
            return None
        if not is_root:
            return "chpasswd: cannot lock /etc/passwd; try again later."
        for line in stdin.splitlines():
            user, sep, _pw = line.partition(":")
            if sep and self._has(self._read("/etc/passwd"), user):
                self._set_password(user)
        self.last_flags.append("password_changed")
        return ""
