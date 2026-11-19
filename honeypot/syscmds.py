# System Commands
# id, whoami, uname, hostname, free and the rest, computed from files in the store
# /etc/passwd, /etc/group, /etc/hostname, /proc/version, /proc/meminfo and /proc/cpuinfo
# if an attacker edits /etc/hostname, hostname changes, and a user added to /etc/passwd resolves
# the commands are a view over the database, so the two can never disagree

# Imports
from __future__ import annotations

import re
import time
from typing import Callable, Optional

from .vfs import VFS, FSError

Result = tuple[str, str, int]


class SystemCommands:
    def __init__(self, vfs: VFS, *, boot_epoch: Optional[float] = None) -> None:
        self.vfs = vfs
        # A fixed boot time, so uptime advances steadily instead of being made up on each call
        self.boot = boot_epoch or (time.time() - 184_726)
        self._table: dict[str, Callable] = {
            "whoami": self._whoami, "id": self._id, "groups": self._groups,
            "hostname": self._hostname, "uname": self._uname,
            "uptime": self._uptime, "date": self._date, "arch": self._arch,
            "nproc": self._nproc, "free": self._free, "env": self._env,
            "printenv": self._env, "lscpu": self._lscpu,
            "lsb_release": self._lsb_release, "who": self._who, "w": self._w,
            "tty": self._tty, "sleep": self._sleep, "true": self._true,
            "false": self._false, "logname": self._whoami,
            "getent": self._getent,
        }

    def names(self) -> list[str]:
        return sorted(self._table)

    def run(self, session, argv: list[str], stdin: Optional[str]) -> Optional[Result]:
        fn = self._table.get(argv[0].rsplit("/", 1)[-1])
        return fn(session, argv[1:]) if fn else None

    # Run one stage with the engine contract
    # one string with no trailing newline, or None, like the store and the filters
    def run_argv(self, session, argv: list[str],
                 stdin: Optional[str] = None) -> Optional[str]:
        if not argv:
            return None
        res = self.run(session, argv, stdin)
        if res is None:
            return None
        stdout, stderr, _status = res
        return (stdout + stderr).rstrip("\n")

    # Helpers

    def _read(self, path: str) -> str:
        try:
            data = self.vfs.read(path)
        except FSError:
            return ""
        return data.decode("utf-8", "replace") if data else ""

    def _passwd(self) -> dict[str, tuple[int, int, str, str]]:
        return self.vfs.passwd_users()

    def _groups_for(self, username: str, gid: int) -> list[tuple[int, str]]:
        out: list[tuple[int, str]] = []
        for line in self._read("/etc/group").splitlines():
            f = line.split(":")
            if len(f) < 4:
                continue
            try:
                g = int(f[2])
            except ValueError:
                continue
            members = [m for m in f[3].split(",") if m]
            if g == gid or username in members:
                out.append((g, f[0]))
        return sorted(out, key=lambda x: (x[0] != gid, x[0]))

    def hostname_value(self) -> str:
        return (self._read("/etc/hostname").strip()
                or self.vfs.meta("hostname", "ubuntu"))

    def kernel_value(self) -> str:
        m = re.search(r"Linux version (\S+)", self._read("/proc/version"))
        return m.group(1) if m else self.vfs.meta("kernel", "5.15.0-58-generic")

    # Commands

    def _whoami(self, session, args) -> Result:
        if args:
            return ("", "whoami: extra operand\n", 1)
        return (session.username + "\n", "", 0)

    def _id(self, session, args) -> Optional[Result]:
        flags = [a for a in args if a.startswith("-")]
        operands = [a for a in args if not a.startswith("-")]
        if set("".join(flags).replace("-", "")) - set("ugnr"):
            return None
        who = operands[0] if operands else session.username
        users = self._passwd()
        if who not in users:
            if operands:
                return ("", f"id: '{who}': no such user\n", 1)
            uid, gid = 1000, 1000
        else:
            uid, gid = users[who][0], users[who][1]
        groups = self._groups_for(who, gid)
        gname = next((n for g, n in groups if g == gid), who)

        joined = "".join(flags).replace("-", "")
        if "u" in joined:
            return (f"{who}\n" if "n" in joined else f"{uid}\n", "", 0)
        if "g" in joined:
            return (f"{gname}\n" if "n" in joined else f"{gid}\n", "", 0)
        extra = "".join(f",{g}({n})" for g, n in groups if g != gid)
        return (f"uid={uid}({who}) gid={gid}({gname}) "
                f"groups={gid}({gname}){extra}\n", "", 0)

    def _groups(self, session, args) -> Result:
        who = args[0] if args else session.username
        users = self._passwd()
        gid = users.get(who, (1000, 1000, "", ""))[1]
        return (" ".join(n for _, n in self._groups_for(who, gid)) + "\n", "", 0)

    def _hostname(self, session, args) -> Optional[Result]:
        if not args:
            return (self.hostname_value() + "\n", "", 0)
        if args[0] in ("-f", "--fqdn", "-A"):
            return (self.hostname_value() + "\n", "", 0)
        if args[0] in ("-I", "--all-ip-addresses"):
            return (self.vfs.meta("server_ip", "10.0.12.31") + " \n", "", 0)
        if args[0] in ("-i",):
            return (self.vfs.meta("server_ip", "10.0.12.31") + "\n", "", 0)
        return None

    def _uname(self, session, args) -> Optional[Result]:
        joined = "".join(a[1:] for a in args if a.startswith("-") and
                         not a.startswith("--"))
        for long, short in (("--all", "a"), ("--kernel-name", "s"),
                            ("--nodename", "n"), ("--kernel-release", "r"),
                            ("--kernel-version", "v"), ("--machine", "m"),
                            ("--operating-system", "o"),
                            ("--processor", "p"), ("--hardware-platform", "i")):
            if long in args:
                joined += short
        if set(joined) - set("asnrvmpio"):
            return None
        kernel = self.kernel_value()
        host = self.hostname_value()
        version = "#64-Ubuntu SMP Thu Jan  5 11:43:14 UTC 2023"
        m = re.search(r"\) (#\d+[^\n]*)$", self._read("/proc/version").strip())
        if m:
            version = m.group(1)
        if not joined or joined == "s":
            return ("Linux\n", "", 0)
        if "a" in joined:
            return (f"Linux {host} {kernel} {version} x86_64 x86_64 x86_64 "
                    f"GNU/Linux\n", "", 0)
        parts = []
        for ch in "snrvmpio":
            if ch not in joined:
                continue
            parts.append({"s": "Linux", "n": host, "r": kernel, "v": version,
                          "m": "x86_64", "p": "x86_64", "i": "x86_64",
                          "o": "GNU/Linux"}[ch])
        return (" ".join(parts) + "\n", "", 0)

    def _uptime(self, session, args) -> Optional[Result]:
        if args and args[0] not in ("-p", "-s"):
            return None
        up = time.time() - self.boot
        days, rem = divmod(int(up), 86400)
        hours, rem = divmod(rem, 3600)
        mins = rem // 60
        if args and args[0] == "-s":
            return (time.strftime("%Y-%m-%d %H:%M:%S",
                                  time.gmtime(self.boot)) + "\n", "", 0)
        if args and args[0] == "-p":
            bits = ([f"{days} days"] if days else []) + \
                   ([f"{hours} hours"] if hours else []) + [f"{mins} minutes"]
            return ("up " + ", ".join(bits) + "\n", "", 0)
        pretty = (f"{days} days, {hours:2d}:{mins:02d}" if days
                  else f"{hours:2d}:{mins:02d}")
        return (f" {time.strftime('%H:%M:%S', time.gmtime())} up {pretty},  1 user,  "
                f"load average: 0.08, 0.03, 0.01\n", "", 0)

    def _date(self, session, args) -> Optional[Result]:
        # The host clock is UTC, so -u changes nothing
        # +FORMAT, -R and -I are rendered here, anything else (-d, -s, -r FILE) goes to the model
        fmt = None
        for arg in args:
            if arg in ("-u", "--utc", "--universal"):
                continue
            if arg.startswith("+") and fmt is None:
                fmt = arg[1:]
            elif arg in ("-R", "--rfc-email"):
                fmt = "%a, %d %b %Y %H:%M:%S +0000"
            elif arg in ("-I", "-Idate", "--iso-8601", "--iso-8601=date"):
                fmt = "%Y-%m-%d"
            elif arg in ("-Iseconds", "--iso-8601=seconds"):
                fmt = "%Y-%m-%dT%H:%M:%S+00:00"
            else:
                return None
        now_ns = time.time_ns()
        now = time.gmtime(now_ns // 1_000_000_000)
        if fmt is None:
            return (time.strftime("%a %b %e %H:%M:%S UTC %Y", now) + "\n", "", 0)
        # GNU-only conversions strftime(3) lacks or would render in local time
        special = {"s": str(now_ns // 1_000_000_000), "N": f"{now_ns % 1_000_000_000:09d}",
                   "Z": "UTC", "z": "+0000", ":z": "+00:00", "P": time.strftime("%p", now).lower()}
        out, i = [], 0
        while i < len(fmt):
            if fmt[i] == "%" and i + 1 < len(fmt):
                key = ":z" if fmt[i + 1:i + 3] == ":z" else fmt[i + 1]
                if key == "%":
                    out.append("%%")
                elif key in special:
                    out.append(special[key].replace("%", "%%"))
                else:
                    out.append(fmt[i:i + 2])
                i += 1 + len(key)
                continue
            out.append(fmt[i])
            i += 1
        try:
            return (time.strftime("".join(out), now) + "\n", "", 0)
        except ValueError:
            return None

    def _arch(self, session, args) -> Result:
        return ("x86_64\n", "", 0)

    def _nproc(self, session, args) -> Result:
        n = self._read("/proc/cpuinfo").count("processor\t:") or 2
        return (f"{n}\n", "", 0)

    def _free(self, session, args) -> Optional[Result]:
        joined = "".join(a[1:] for a in args if a.startswith("-"))
        if set(joined) - set("hmgtk"):
            return None
        info = {}
        for line in self._read("/proc/meminfo").splitlines():
            k, _, v = line.partition(":")
            m = re.match(r"\s*(\d+)", v)
            if m:
                info[k] = int(m.group(1))
        total = info.get("MemTotal", 4_016_824)
        free = info.get("MemFree", 2_418_112)
        avail = info.get("MemAvailable", 3_341_208)
        buff = info.get("Buffers", 88_204) + info.get("Cached", 1_012_456)
        used = total - free - buff
        shared = info.get("Shmem", 1_024)

        def f(kb: int) -> str:
            if "h" in joined:
                from .fsformat import human_size
                return human_size(kb * 1024) + "i"
            div = {"m": 1024, "g": 1024 * 1024}.get(
                next((c for c in joined if c in "mg"), ""), 1)
            return str(kb // div)

        head = (f"{'':<15}{'total':>11}{'used':>11}{'free':>11}"
                f"{'shared':>11}{'buff/cache':>11}{'available':>11}")
        mem = (f"{'Mem:':<15}{f(total):>11}{f(used):>11}{f(free):>11}"
               f"{f(shared):>11}{f(buff):>11}{f(avail):>11}")
        swap = f"{'Swap:':<15}{f(0):>11}{f(0):>11}{f(0):>11}"
        return (f"{head}\n{mem}\n{swap}\n", "", 0)

    def _env(self, session, args) -> Optional[Result]:
        if args:
            return None
        home = ("/root" if session.username == "root"
                else f"/home/{session.username}")
        env = {
            "SHELL": "/bin/bash", "PWD": session.cwd, "LOGNAME": session.username,
            "HOME": home, "LANG": "C.UTF-8", "USER": session.username,
            "SSH_CLIENT": f"{getattr(session, 'peer_ip', '10.0.0.5')} "
                          f"{getattr(session, 'peer_port', 54321)} 22",
            "SSH_CONNECTION": f"{getattr(session, 'peer_ip', '10.0.0.5')} "
                              f"{getattr(session, 'peer_port', 54321)} "
                              f"{self.vfs.meta('server_ip', '10.0.12.31')} 22",
            "TERM": "xterm-256color",
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:"
                    "/sbin:/bin:/snap/bin",
            "_": "/usr/bin/env",
        }
        return ("\n".join(f"{k}={v}" for k, v in env.items()) + "\n", "", 0)

    def _lscpu(self, session, args) -> Optional[Result]:
        if args:
            return None
        n = self._read("/proc/cpuinfo").count("processor\t:") or 2
        model = "Intel(R) Xeon(R) Platinum 8259CL CPU @ 2.50GHz"
        m = re.search(r"model name\t: (.+)", self._read("/proc/cpuinfo"))
        if m:
            model = m.group(1).strip()
        rows = [("Architecture", "x86_64"),
                ("CPU op-mode(s)", "32-bit, 64-bit"),
                ("Byte Order", "Little Endian"),
                ("Address sizes", "46 bits physical, 48 bits virtual"),
                ("CPU(s)", str(n)),
                ("On-line CPU(s) list", f"0-{n - 1}" if n > 1 else "0"),
                ("Vendor ID", "GenuineIntel"),
                ("Model name", model),
                ("CPU family", "6"), ("Model", "85"),
                ("Thread(s) per core", "2"), ("Core(s) per socket", "1"),
                ("Socket(s)", "1"), ("Stepping", "7"),
                ("BogoMIPS", "5000.00"),
                ("Hypervisor vendor", "KVM"),
                ("Virtualization type", "full"),
                ("L1d cache", "32 KiB"), ("L1i cache", "32 KiB"),
                ("L2 cache", "1 MiB"), ("L3 cache", "35.8 MiB")]
        width = max(len(k) for k, _ in rows) + 2
        return ("\n".join(f"{k + ':':<{width}}{v}" for k, v in rows) + "\n",
                "", 0)

    def _lsb_release(self, session, args) -> Optional[Result]:
        rel = self._read("/etc/os-release")
        def field(key: str, default: str) -> str:
            m = re.search(rf'^{key}="?([^"\n]+)"?', rel, re.M)
            return m.group(1) if m else default
        desc = field("PRETTY_NAME", self.vfs.meta("distro", "Ubuntu 22.04 LTS"))
        ver = field("VERSION_ID", "22.04")
        code = field("VERSION_CODENAME", "jammy")
        joined = "".join(a[1:] for a in args if a.startswith("-"))
        if set(joined) - set("adrcis"):
            return None
        rows = [("Distributor ID", "Ubuntu"), ("Description", desc),
                ("Release", ver), ("Codename", code)]
        if "a" in joined or not joined:
            return ("No LSB modules are available.\n"
                    + "".join(f"{k}:\t{v}\n" for k, v in rows), "", 0)
        pick = {"i": 0, "d": 1, "r": 2, "c": 3}
        out = [f"{rows[pick[c]][0]}:\t{rows[pick[c]][1]}"
               for c in joined if c in pick]
        return ("\n".join(out) + "\n", "", 0)

    def _who(self, session, args) -> Optional[Result]:
        if args:
            return None
        when = time.strftime("%Y-%m-%d %H:%M",
                             time.gmtime(time.time() - 600))
        return (f"{session.username:<8} pts/0        {when} "
                f"({getattr(session, 'peer_ip', '10.0.0.5')})\n", "", 0)

    def _w(self, session, args) -> Optional[Result]:
        if args:
            return None
        up = self._uptime(session, [])[0].rstrip("\n")
        head = (f"{'USER':<8} {'TTY':<8} {'FROM':<15} {'LOGIN@':<7} "
                f"{'IDLE':<6} {'JCPU':<6} {'PCPU':<6} WHAT")
        row = (f"{session.username:<8} {'pts/0':<8} "
               f"{getattr(session, 'peer_ip', '10.0.0.5'):<15} "
               f"{time.strftime('%H:%M', time.gmtime(time.time() - 600)):<7} "
               f"{'0.00s':<6} {'0.04s':<6} {'0.00s':<6} -bash")
        return (f"{up}\n{head}\n{row}\n", "", 0)

    def _tty(self, session, args) -> Result:
        return ("/dev/pts/0\n" if getattr(session, "has_pty", True)
                else "not a tty\n", "", 0 if getattr(session, "has_pty", True) else 1)

    def _sleep(self, session, args) -> Optional[Result]:
        # Answered at once - a real sleep would block the session
        # short sleeps are hidden by SSH latency, and long ones would only tie up the honeypot
        if len(args) != 1:
            return None
        try:
            float(args[0].rstrip("smhd"))
        except ValueError:
            return None
        return ("", "", 0)

    # Answer getent from the same identity files everything else reads
    def _getent(self, session, args) -> Optional[Result]:
        if not args:
            return None
        db = args[0]
        path = {"passwd": "/etc/passwd", "group": "/etc/group",
                "shadow": "/etc/shadow", "hosts": "/etc/hosts"}.get(db)
        if path is None:
            return ("", f"Unknown database: {db}\n", 2)
        if db == "shadow" and session.username != "root":
            return ("", "", 2)
        text = self._read(path)
        keys = args[1:]
        if not keys:
            return (text if text.endswith("\n") else text + "\n", "", 0)
        rows = []
        for key in keys:
            for line in text.splitlines():
                f = line.split(":")
                if not f:
                    continue
                if f[0] == key or (db != "hosts" and len(f) > 2 and f[2] == key) \
                        or (db == "hosts" and key in line.split()):
                    rows.append(line)
                    break
        if not rows:
            return ("", "", 2)
        return ("\n".join(rows) + "\n", "", 0)

    def _true(self, session, args) -> Result:
        return ("", "", 0)

    def _false(self, session, args) -> Result:
        return ("", "", 1)
