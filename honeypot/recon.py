# Reconnaissance Views
# bounded, read-only answers for ps, ss, sudo -l, crontab and similar over the current realm
# no subprocesses, sockets, client SQL or host file reads
# unsupported syntax declines instead of guessing

# Imports
from __future__ import annotations

import fnmatch
import re
import struct
import time
from .vfs import FSError


# Small lookup hints for Qwen when native coverage runs out
def extra_paths(argv):
    if not argv:
        return []
    name = argv[0].rsplit("/", 1)[-1]
    return {"sudo": ["/etc/sudoers", "/etc/sudoers.d"],
            "systemctl": ["/etc/systemd/system"],
            "service": ["/etc/systemd/system"],
            "ps": ["/proc"], "pgrep": ["/proc"],
            "ss": ["/proc/net/tcp", "/proc/net/tcp6"],
            "netstat": ["/proc/net/tcp", "/proc/net/route"],
            "ip": ["/proc/net/route", "/etc/hosts"],
            "dpkg": ["/var/lib/dpkg/status"],
            "dpkg-query": ["/var/lib/dpkg/status"],
            "apt": ["/var/lib/dpkg/status", "/etc/apt/sources.list"],
            "journalctl": ["/var/log/syslog"],
            "ufw": ["/etc/ufw/ufw.conf"],
            "crontab": ["/etc/crontab", "/etc/cron.d"],
            "nginx": ["/etc/nginx/nginx.conf", "/etc/nginx/sites-enabled"],
            "docker": ["/var/lib/dpkg/status", "/run/docker.sock"]}.get(name, [])


# Recognise the scenario's NOPASSWD ALL rule from the live files
# not a general sudoers parser - unknown policies never imply elevation
# used only for simulated sudo, no OS privilege changes
def sudo_policy(filesystem, session):
    v = filesystem.vfs.for_realm(session.realm or "unknown")
    if session.username == "root":
        return True
    try:
        policy = (v.read("/etc/sudoers") or b"").decode()
        if "@includedir /etc/sudoers.d" in policy or "#includedir /etc/sudoers.d" in policy:
            for node in v.listdir("/etc/sudoers.d"):
                if node.is_file and "." not in node.name and not node.name.endswith("~"):
                    policy += "\n" + (v.read(node.path) or b"").decode()
    except (FSError, UnicodeError):
        return False
    user = re.escape(session.username)
    return bool(re.search(rf"(?m)^\s*{user}\s+ALL\s*=\s*\(ALL(?::ALL)?\)\s+NOPASSWD:\s*ALL\s*(?:#.*)?$", policy))


class ReconCommands:
    def __init__(self, filesystem):
        self.filesystem = filesystem

    def run(self, session, argv, stdin=None):
        if not argv or stdin is not None:
            return None
        from .tools import VFSTools
        access = VFSTools(self.filesystem, session)
        self.v, self.access, self.session = access.vfs, access, session
        if not self.v.meta("attacker_profile"):
            return None
        name = argv[0].rsplit("/", 1)[-1]
        fn = {"ps": self.ps, "pgrep": self.pgrep, "ss": self.ss,
              "ip": self.ip, "dpkg-query": self.packages, "dpkg": self.packages,
              "systemctl": self.systemctl, "crontab": self.crontab,
              "history": self.history, "sudo": self.sudo, "ufw": self.ufw}.get(name)
        if fn is None:
            return None
        try:
            result = fn(argv[1:], name)
            if result is None:
                return None
            if isinstance(result, tuple):
                return result
            return result.rstrip("\n"), 0
        except FSError as exc:
            return f"{name}: {exc.message}", 1

    def read(self, path):
        node = self.access.resolve(path, want="r")
        if not node.is_file:
            raise FSError("Is a directory", "EISDIR")
        data = self.v.read(node.path)
        if data is None and node.size:
            raise FSError("Input/output error", "EIO")
        return (data or b"").decode("utf-8", "replace")

    def processes(self):
        users = {uid: name for name, (uid, _, _, _) in self.v.passwd_users().items()}
        rows = []
        for node in self.v.listdir("/proc"):
            if not node.is_dir or not node.name.isdigit():
                continue
            try:
                status = dict(line.split(":", 1) for line in self.read(node.path + "/status").splitlines() if ":" in line)
                uid = int(status["Uid"].split()[0])
                rows.append({"pid": int(node.name), "ppid": int(status["PPid"].strip()),
                             "name": status["Name"].strip(), "uid": uid,
                             "user": users.get(uid, str(uid)),
                             "start": time.strftime("%b%d", time.gmtime(self.v.get(node.path + "/status").mtime)),
                             "vsz": int(status.get("VmSize", "0").split()[0]),
                             "rss": int(status.get("VmRSS", "0").split()[0]),
                             "cmd": self.read(node.path + "/cmdline").replace("\0", " ").rstrip()})
            except (FSError, KeyError, ValueError):
                continue
        return sorted(rows, key=lambda r: r["pid"])

    def ps(self, args, name):
        if args not in (["aux"], ["-aux"], ["-ef"], ["-e"], []):
            return None
        rows = self.processes()
        if not args:
            # By default ps shows the current terminal, and service processes have none
            return "    PID TTY          TIME CMD"
        if args == ["-e"]:
            return "    PID TTY          TIME CMD\n" + "\n".join(f"{r['pid']:7d} ?        00:00:00 {r['name']}" for r in rows)
        if args == ["-ef"]:
            return "UID          PID    PPID  C STIME TTY          TIME CMD\n" + "\n".join(f"{r['user']:<8} {r['pid']:7d} {r['ppid']:7d}  0 {r['start']} ?        00:00:00 {r['cmd']}" for r in rows)
        return "USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n" + "\n".join(f"{r['user']:<8} {r['pid']:7d}  0.0  0.1 {r['vsz']:6d} {r['rss']:5d} ?        S    {r['start']}   0:00 {r['cmd']}" for r in rows)

    def pgrep(self, args, name):
        full, show = False, False
        patterns = []
        for arg in args:
            if arg.startswith("-") and set(arg[1:]) <= set("fal"):
                full |= "f" in arg
                show |= "a" in arg or "l" in arg
            elif arg.startswith("-"):
                return None
            else:
                patterns.append(arg)
        if len(patterns) != 1:
            return None
        try:
            # Keep regex simple - a literal substring or a simple anchored literal
            # complex patterns go to the model
            pattern = patterns[0]
            if re.search(r"[^\w./ :^$-]", pattern):
                return None
            rows = [r for r in self.processes() if re.search(pattern, r["cmd"] if full else r["name"])]
        except re.error:
            return "pgrep: invalid regular expression", 2
        return "\n".join(str(r["pid"]) + (" " + (r["cmd"] if "-a" in args or "-af" in args else r["name"]) if show else "") for r in rows), 0 if rows else 1

    @staticmethod
    def address(value):
        address, port = value.split(":")
        ip = ".".join(str(x) for x in struct.pack("<I", int(address, 16)))
        return ip + ":" + str(int(port, 16))

    def ss(self, args, name):
        flags = "".join(a[1:] for a in args if a.startswith("-") and not a.startswith("--"))
        # Accept ss -u and the usual -tulpn and -tunlp spellings
        # with the Netid column ss prints when more than one socket table is selected
        if (not args or len([a for a in args if a.startswith("-")]) != len(args)
                or set(flags) - set("lntupH4") or not all(c in flags for c in "ln")
                or not ({"t", "u"} & set(flags))):
            return None
        tables = [t for t in ("tcp", "udp") if t[0] in flags]
        netid = len(tables) > 1
        rows = [] if "H" in flags else [("Netid " if netid else "") + "State  Recv-Q Send-Q Local Address:Port Peer Address:Port" + (" Process" if "p" in flags else "")]
        processes = self.processes()
        for table in tables:
            listening = "0A" if table == "tcp" else "07"
            try:
                table_text = self.read(f"/proc/net/{table}")
            except FSError:
                # This host has no sockets of that kind
                table_text = ""
            for line in table_text.splitlines()[1:]:
                fields = line.split()
                if len(fields) < 10 or fields[3] != listening:
                    continue
                pid = None
                for proc in processes:
                    try:
                        inode_match = any(n.is_link and n.target == f"socket:[{fields[9]}]" for n in self.v.listdir(f"/proc/{proc['pid']}/fd"))
                    except FSError:
                        inode_match = False
                    if inode_match:
                        pid = proc
                        break
                # Owner details are only visible to root or the socket owner
                owner = ""
                if "p" in flags and pid and (self.access.ident.uid == 0 or self.access.ident.uid == pid["uid"]):
                    owner = f' users:(("{pid["name"]}",pid={pid["pid"]},fd=3))'
                state = "LISTEN" if table == "tcp" else "UNCONN"
                queue = "128   " if table == "tcp" else "0     "
                rows.append((f"{table:<5} " if netid else "") + f"{state:<6} 0      {queue} {self.address(fields[1]):<22} 0.0.0.0:*{owner}")
        return "\n".join(rows)

    def ip(self, args, name):
        if args in (["route"], ["route", "show"], ["r"]):
            rows = []
            for line in self.read("/proc/net/route").splitlines()[1:]:
                f = line.split()
                if len(f) < 8:
                    continue
                addr = self.address(f[1] + ":0000").split(":")[0]
                gateway = self.address(f[2] + ":0000").split(":")[0]
                if addr == "0.0.0.0":
                    rows.append(f"default via {gateway} dev {f[0]} proto static metric {f[6]}")
                else:
                    prefix = int(f[7], 16).bit_count()
                    rows.append(f"{addr}/{prefix} dev {f[0]} proto kernel scope link src {self.v.meta('server_ip')} metric {f[6]}")
            return "\n".join(rows)
        if args in (["addr"], ["a"], ["address", "show"], ["addr", "show"]):
            mac = self.read("/sys/class/net/eth0/address").strip()
            ip = self.v.meta("server_ip")
            return f"1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000\n    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n    inet 127.0.0.1/8 scope host lo\n2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000\n    link/ether {mac} brd ff:ff:ff:ff:ff:ff\n    inet {ip}/24 brd 10.0.12.255 scope global eth0"
        return None

    def packages(self, args, name):
        if not args or args[0] not in ("-l", "-W", "--show"):
            return None
        fmt = None
        patterns = []
        for arg in args[1:]:
            if arg.startswith(("-f=", "--showformat=")):
                fmt = arg.split("=", 1)[1].replace("\\n", "\n").replace("\\t", "\t")
            elif arg.startswith("-"):
                return None
            else:
                patterns.append(arg)
        if fmt and re.search(r"\$\{(?!Package\}|Version\}|Architecture\}|db:Status-Abbrev\})", fmt):
            return None
        packages = []
        for block in self.read("/var/lib/dpkg/status").split("\n\n"):
            fields = dict(line.split(": ", 1) for line in block.splitlines() if ": " in line and not line.startswith(" "))
            if fields.get("Status") == "install ok installed" and (not patterns or any(fnmatch.fnmatchcase(fields.get("Package", ""), p) for p in patterns)):
                packages.append(fields)
        if not packages:
            return f"{name}: no packages found matching " + " ".join(patterns), 1
        if args[0] == "-l":
            return "Desired=Unknown/Install/Remove/Purge/Hold\n| Status=Not/Inst/Conf-files/Unpacked/halF-conf/Half-inst/trig-aWait/Trig-pend\n|/ Err?=(none)/Reinst-required (Status,Err: uppercase=bad)\n||/ Name                         Version                      Architecture Description\n+++============================-============================-============-=================================\n" + "\n".join(f"ii  {p['Package']:<28} {p.get('Version',''):<28} {p.get('Architecture','amd64'):<12} {p.get('Description','')}" for p in packages)
        fmt = fmt if fmt is not None else "${Package}\t${Version}\n"
        output = []
        for p in packages:
            item = fmt
            for field in ("Package", "Version", "Architecture"):
                item = item.replace("${" + field + "}", p.get(field, ""))
            output.append(item.replace("${db:Status-Abbrev}", "ii "))
        return "".join(output)

    def systemctl(self, args, name):
        args = [a for a in args if a not in ("--no-pager", "--full")]
        if not args:
            return None
        action = args[0]
        if action == "list-units" and all(a in ("--type=service", "--all") for a in args[1:]):
            lines = ["UNIT                           LOAD   ACTIVE SUB     DESCRIPTION"]
            for node in self.v.listdir("/etc/systemd/system"):
                if node.is_file and node.name.endswith(".service"):
                    service = node.name[:-8]
                    unit = self.read(node.path)
                    description = re.search(r"(?m)^Description=(.*)$", unit)
                    active = self._service_pid(service)
                    lines.append(f"{node.name:<30} loaded {'active' if active else 'inactive':<6} {'running' if active else 'dead':<7} {description[1] if description else service}")
            return "\n".join(lines)
        if len(args) != 2 or action not in ("status", "cat", "is-active", "is-enabled", "show"):
            return None
        service = args[1].removesuffix(".service")
        if not re.fullmatch(r"[\w@.-]+", service):
            return None
        path = f"/etc/systemd/system/{service}.service"
        if not self.v.exists(path):
            return f"Unit {service}.service could not be found.", 4
        unit = self.read(path)
        if action == "cat":
            return "# " + path + "\n" + unit
        pid = self._service_pid(service)
        enabled = self.v.exists(f"/etc/systemd/system/multi-user.target.wants/{service}.service")
        if action == "is-active":
            return ("active", 0) if pid else ("inactive", 3)
        if action == "is-enabled":
            return ("enabled", 0) if enabled else ("disabled", 1)
        description = re.search(r"(?m)^Description=(.*)$", unit)
        desc = description[1] if description else service
        if action == "show":
            return f"Id={service}.service\nDescription={desc}\nLoadState=loaded\nActiveState={'active' if pid else 'inactive'}\nSubState={'running' if pid else 'dead'}\nMainPID={pid}\nFragmentPath={path}\nUnitFileState={'enabled' if enabled else 'disabled'}"
        return f"{'●' if pid else '○'} {service}.service - {desc}\n     Loaded: loaded ({path}; {'enabled' if enabled else 'disabled'}; vendor preset: enabled)\n     Active: {'active (running)' if pid else 'inactive (dead)'}\n   Main PID: {pid}" , 0 if pid else 3

    def _service_pid(self, service):
        try:
            pid = int(self.read(f"/run/{service}.pid").strip())
            return pid if self.v.exists(f"/proc/{pid}/status") else 0
        except (FSError, ValueError):
            return 0

    def crontab(self, args, name):
        if args != ["-l"]:
            return None
        path = "/var/spool/cron/crontabs/" + self.session.username
        # The crontab command reads this one caller-owned spool file with privilege
        # a direct cat still checks the unsearchable spool directory
        node = self.v.get(path)
        if node is None:
            return f"no crontab for {self.session.username}", 1
        if node.uid != self.access.ident.uid:
            return "crontab: permission denied", 1
        return (self.v.read(path) or b"").decode()

    def history(self, args, name):
        if len(args) > 1 or (args and not args[0].isdigit()):
            return None
        lines = self.read(self.access.ident.home + "/.bash_history").splitlines()
        lines += getattr(self.session, "command_history", [])
        count = int(args[0]) if args else len(lines)
        start = max(0, len(lines) - count)
        return "\n".join(f"{i+1:5d}  {line}" for i, line in enumerate(lines) if i >= start)

    def sudo(self, args, name):
        if args not in (["-l"], ["-n", "-l"], ["-ln"]):
            return None
        host = self.v.meta("hostname")
        from .privilege_profile import granted, HIGH_USER, REVIEW_PATH
        if granted(self.filesystem, self.session):
            return f"Matching Defaults entries for {self.session.username} on {host}:\n    env_reset\n\nUser {self.session.username} may run the following commands on {host}:\n    ({HIGH_USER}) NOPASSWD: /usr/bin/find {REVIEW_PATH} *", 0
        if not sudo_policy(self.filesystem, self.session):
            return "sudo: a password is required", 1
        return f"Matching Defaults entries for {self.session.username} on {host}:\n    env_reset, mail_badpass\n\nUser {self.session.username} may run the following commands on {host}:\n    (ALL) NOPASSWD: ALL"

    def ufw(self, args, name):
        if args not in (["status"], ["status", "verbose"]):
            return None
        if self.access.ident.uid != 0:
            return "ERROR: You need to be root to run this script", 1
        if "ENABLED=no" in self.read("/etc/ufw/ufw.conf"):
            return "Status: inactive"
        return None
