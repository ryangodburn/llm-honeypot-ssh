# Virtual Processes
# a persistent process table for ps, kill, jobs and systemctl that never touches host processes
# one SQLite transaction commits the state with its /proc, /run and socket views
# a realm owns its PIDs and a channel owns its shell jobs
# completion and restart deadlines use the wall clock, so they survive reconnects

# Imports
from __future__ import annotations

import asyncio
from contextlib import contextmanager
from copy import copy, deepcopy
from dataclasses import dataclass
import fnmatch
import json
import math
import posixpath
import re
import shlex
import threading
import time
import uuid
from types import SimpleNamespace

from .tools import VFSTools
from .vfs import FSError

# Linux signal numbers, whatever the operator's own OS is
SIGNALS = {name: n for n, name in enumerate(("0", "HUP", "INT", "QUIT", "ILL", "TRAP", "ABRT", "BUS", "FPE", "KILL", "USR1", "SEGV", "USR2", "PIPE", "ALRM", "TERM", "STKFLT", "CHLD", "CONT", "STOP", "TSTP", "TTIN", "TTOU", "URG", "XCPU", "XFSZ", "VTALRM", "PROF", "WINCH", "IO", "PWR", "SYS"))}
ACTIVE = {"R", "S", "T"}
COMMANDS = {"ps", "pgrep", "pidof", "top", "kill", "pkill", "killall", "jobs", "bg", "fg", "wait", "disown", "nohup", "nice", "renice", "sleep", "systemctl", "service", "journalctl"}


@dataclass
class ProcessResult:
    output: str = ""
    exit_code: int = 0
    wait_pids: tuple[int, ...] = ()
    wait_any: bool = False
    wait_all: bool = False


class ProcessError(Exception):
    def __init__(self, message, code=1):
        self.code = code
        super().__init__(message)


def signal_number(value):
    text = str(value).upper().removeprefix("SIG")
    if text in SIGNALS:
        return SIGNALS[text]
    if text.isdigit() and 0 <= int(text) <= 64:
        return int(text)
    raise ProcessError(f"invalid signal specification: {value}", 2)


class ProcessManager:
    def __init__(self, filesystem, *, clock=None, max_processes=512):
        epoch, monotonic = time.time(), time.monotonic()
        self.fs, self.clock, self.max_processes = filesystem, clock or (lambda: epoch + time.monotonic()-monotonic), max_processes
        # Every view of this database connection shares the lock
        if not hasattr(filesystem.vfs, "_process_lock"):
            filesystem.vfs._process_lock = threading.RLock()
        self.lock = filesystem.vfs._process_lock
        filesystem.vfs.db.execute("CREATE TABLE IF NOT EXISTS process_lifecycle (realm TEXT PRIMARY KEY, data TEXT NOT NULL)")

    @contextmanager
    def transaction(self, session):
        with self.lock:
            self.v = self.fs.vfs.for_realm(getattr(session, "realm", "") or "unknown")
            self.session = session
            self.v.db.execute("BEGIN IMMEDIATE")
            try:
                row = self.v.db.execute("SELECT data FROM process_lifecycle WHERE realm=?", (self.v.realm,)).fetchone()
                self.d = json.loads(row[0]) if row else self._bootstrap()
                self._tick()
                yield
                self._sockets()
                self.v.db.execute("INSERT INTO process_lifecycle VALUES (?,?) ON CONFLICT(realm) DO UPDATE SET data=excluded.data", (self.v.realm, json.dumps(self.d, separators=(",", ":"))))
                self.v.db.execute("COMMIT")
            except BaseException:
                self.v.db.execute("ROLLBACK")
                raise

    def _read(self, path):
        try:
            return (self.v.read(path) or b"").decode("utf-8", "replace")
        except FSError:
            return ""

    def _put(self, path, data=b"", *, kind="file", mode=0o444, uid=0, gid=0, target=None):
        if isinstance(data, str):
            data = data.encode()
        parent = posixpath.dirname(path)
        if parent and parent != path and not self.v.exists(parent):
            self._put(parent, kind="dir", mode=0o755)
        users = {v[0]: k for k, v in self.v.passwd_users().items()}
        groups = self.v.group_names()
        self.v._put(path, kind=kind, mode=mode, uid=uid, gid=gid,
                    uname=users.get(uid, str(uid)), gname=groups.get(gid, str(gid)),
                    content=data if kind == "file" else None, size=len(data) if kind == "file" else 4096 if kind == "dir" else len(target or ""), target=target)

    def _remove(self, path):
        if self.v.get(path):
            self.v.remove(path, recursive=True)

    def _bootstrap(self):
        d = {"version": 1, "boot_time": self.clock()-float((self._read("/proc/uptime").split() or ["0"])[0]), "next_pid": 2000, "next_inode": 40000, "processes": {}, "services": {}, "sessions": {}, "events": [], "socket_inodes": []}
        self.d = d
        sockets = {}
        for line in self._read("/proc/net/tcp").splitlines()[1:]:
            fields = line.split()
            if len(fields) >= 10:
                sockets[fields[9]] = line
        if not self.v.exists("/proc"):
            self._put("/proc", kind="dir", mode=0o555)
        for node in self.v.listdir("/proc"):
            if not node.name.isdigit() or not node.is_dir:
                continue
            try:
                status = dict(line.split(":", 1) for line in self._read(node.path + "/status").splitlines() if ":" in line)
                pid, uid, gid = int(node.name), int(status["Uid"].split()[0]), int(status["Gid"].split()[0])
                command = self._read(node.path + "/cmdline").strip("\0").split("\0")
                p = self._record(pid, int(status["PPid"]), uid, gid, command, "/", name=status["Name"].strip())
                p["started"] = node.mtime
                p["state"] = status.get("State", "S").strip()[0]
                p["env"] = self._read(node.path + "/environ")
                p["sockets"] = []
                if self.v.exists(node.path + "/fd"):
                    for fd in self.v.listdir(node.path + "/fd"):
                        match = re.fullmatch(r"socket:\[(\d+)\]", fd.target or "")
                        if match and match[1] in sockets:
                            p["sockets"].append(sockets[match[1]])
                            d["socket_inodes"].append(match[1])
                d["processes"][str(pid)] = p
                d["next_pid"] = max(d["next_pid"], pid + 1)
            except (KeyError, ValueError):
                continue
        if "1" not in d["processes"]:
            d["processes"]["1"] = self._record(1, 0, 0, 0, ["/sbin/init"], "/", name="systemd")
            self._project(d["processes"]["1"])
        if self.v.exists("/run"):
            for node in self.v.listdir("/run"):
                if node.name.endswith(".pid"):
                    try:
                        pid = int(self._read(node.path).strip())
                        if str(pid) in d["processes"]:
                            self._service(node.name[:-4], seed_pid=pid)
                    except (ValueError, ProcessError):
                        pass
        return d

    def _record(self, pid, ppid, uid, gid, argv, cwd, *, name=None):
        return dict(pid=pid, ppid=ppid, pgid=pid, sid=ppid, uid=uid, gid=gid,
                    argv=argv, name=name or posixpath.basename(argv[0])[:15], cwd=cwd,
                    state="S", started=self.clock(), deadline=None, remaining=None,
                    ended=None, exit_code=None, nice=0, owner="", job=0, nohup=False,
                    disowned=False, service="", env="", sockets=[])

    def _event(self, action, p=None, **details):
        self.d["events"].append(dict(time=self.clock(), action=action, pid=p["pid"] if p else None,
                                     service=p["service"] if p else details.pop("service", ""), **details))
        self.d["events"] = self.d["events"][-2048:]

    def _project(self, p):
        path = f"/proc/{p['pid']}"
        if p["state"] == "X":
            self._remove(path)
            return
        uid, gid = p["uid"], p["gid"]
        self._put(path, kind="dir", mode=0o555, uid=uid, gid=gid)
        state = {"R": "running", "S": "sleeping", "T": "stopped", "Z": "zombie"}[p["state"]]
        status = f"Name:\t{p['name']}\nUmask:\t0022\nState:\t{p['state']} ({state})\nTgid:\t{p['pid']}\nPid:\t{p['pid']}\nPPid:\t{p['ppid']}\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\nGid:\t{gid}\t{gid}\t{gid}\t{gid}\nVmSize:\t16384 kB\nVmRSS:\t4096 kB\nThreads:\t1\n"
        self._put(path + "/status", status)
        self._put(path + "/cmdline", "\0".join(p["argv"]) + "\0" if p["state"] != "Z" else "")
        self._put(path + "/environ", p["env"], uid=uid, gid=gid, mode=0o400)
        # Linux /proc/PID/stat fields up to exit_code, with stable start ticks
        fields = [p["state"], p["ppid"], p["pgid"], p["sid"], 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 20+p["nice"], p["nice"], 1, 0, max(0,int((p["started"]-self.d["boot_time"])*100)), 16777216, 1024] + [0]*27 + [(p["exit_code"] or 0) << 8]
        self._put(path + "/stat", f"{p['pid']} ({p['name']}) " + " ".join(map(str, fields)) + "\n")
        self._put(path + "/cwd", kind="link", mode=0o700, uid=uid, gid=gid, target=p["cwd"])
        self._put(path + "/exe", kind="link", mode=0o700, uid=uid, gid=gid, target=p["argv"][0])
        self._put(path + "/fd", kind="dir", mode=0o500, uid=uid, gid=gid)
        for i, line in enumerate(p["sockets"] if p["state"] in ACTIVE else []):
            self._put(path + f"/fd/{i+3}", kind="link", mode=0o700, uid=uid, gid=gid, target=f"socket:[{line.split()[9]}]")

    def _sockets(self):
        path = "/proc/net/tcp"
        current = self._read(path)
        lines = current.splitlines()
        header = lines[0] if lines else "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode"
        owned = set(self.d["socket_inodes"])
        rows = [s for s in lines[1:] if len(s.split()) >= 10 and s.split()[9] not in owned]
        for p in self.d["processes"].values():
            if p["state"] in ACTIVE:
                rows.extend(p["sockets"])
        new = header + "\n" + "".join(s + "\n" for s in rows)
        if new != current:
            self._put(path, new)
        self.d["socket_inodes"] = list({line.split()[9] for p in self.d["processes"].values() for line in p["sockets"] if p["state"] in ACTIVE})

    def _alloc(self):
        if sum(p["state"] != "X" for p in self.d["processes"].values()) >= self.max_processes:
            raise ProcessError("fork: Resource temporarily unavailable")
        pid = self.d["next_pid"]
        if pid >= 4194304:
            raise ProcessError("PID space exhausted")
        self.d["next_pid"] += 1
        # Keep a bounded exit history, but never drop a child that was not reaped
        old = [k for k, p in self.d["processes"].items() if p["state"] == "X"]
        for k in old[:-256]:
            del self.d["processes"][k]
        return pid

    def _identity(self, session=None):
        return VFSTools(self.fs, session or self.session).ident

    def _shell(self, argv=None):
        key = getattr(self.session, "_process_session", None)
        if key is None:
            key = uuid.uuid4().hex
            self.session._process_session = key
        saved = self.d["sessions"].get(key)
        if saved and self.d["processes"].get(str(saved["pid"]), {}).get("state") in ACTIVE:
            self.session.shell_pid = saved["pid"]
            return saved
        ident = self._identity()
        pid = self._alloc()
        p = self._record(pid, 1, ident.uid, ident.gid, argv or ["/bin/bash"], self.session.cwd)
        p["sid"] = pid
        p["owner"] = key
        self.d["processes"][str(pid)] = p
        self.d["sessions"][key] = saved = dict(pid=pid, next_job=1)
        self.session.shell_pid = pid
        self._project(p)
        self._event("shell-open", p)
        return saved

    def refresh(self, session):
        with self.transaction(session):
            self._shell()

    def snapshot(self, session):
        with self.transaction(session):
            return deepcopy(self.d)

    def _tick(self):
        now = self.clock()
        for p in list(self.d["processes"].values()):
            if p["state"] in ("R", "S") and p["deadline"] is not None and p["deadline"] <= now:
                self._finish(p, 0)
            elif p["state"] in ACTIVE and not self.v.exists(f"/proc/{p['pid']}/status"):
                # Removing it from the filesystem is a clean exit, not a restart
                self._finish(p, 0)
        for service in list(self.d["services"].values()):
            if service.get("restart_at") is not None and service["restart_at"] <= now:
                service["restart_at"] = None
                self._start_checked(service)

    def _finish(self, p, code, *, manual=False):
        if p["state"] not in ACTIVE:
            return
        p.update(state="Z" if p["owner"] in self.d["sessions"] and p["job"] and not p["disowned"] else "X", exit_code=code, ended=self.clock(), deadline=None)
        self._event("exit", p, exit_code=code)
        for child in self.d["processes"].values():
            if child["ppid"] == p["pid"] and child["state"] != "X":
                child["ppid"] = 1
                if child["state"] == "Z":
                    child["state"] = "X"
                self._project(child)
        self._remove(f"/proc/{p['pid']}/fd")
        self._project(p)
        service = self.d["services"].get(p["service"])
        if service and service["pid"] == p["pid"]:
            service.update(pid=0, state="inactive" if code == 0 or code in (129,130,143) else "failed", result="success" if code == 0 else f"exit-code={code}", restart_at=None)
            self._remove(f"/run/{service['name']}.pid")
            for child in list(self.d["processes"].values()):
                if child["service"] == service["name"] and child["state"] in ACTIVE:
                    self._finish(child, code, manual=True)
            policy = service["config"].get("Restart", "no")
            failed = service["state"] == "failed"
            if not manual and (policy == "always" or policy == "on-failure" and failed):
                delay = self._duration(service["config"].get("RestartSec", "0.1"))
                service.update(state="activating", restart_at=self.clock()+max(.05, delay))
                self._event("service-restart-scheduled", service=service["name"])

    def _reap(self, p):
        code = p["exit_code"] or 0
        p["state"] = "X"
        p["job"] = 0
        self._project(p)
        self._event("reap", p, exit_code=code)
        return code

    @staticmethod
    def _duration(value):
        total = 0.0
        for text in str(value).split():
            match = re.fullmatch(r"(\d+(?:\.\d*)?|\.\d+)(ms|s|m|h|d)?", text)
            if not match:
                raise ProcessError(f"invalid time interval: {value}", 2)
            total += float(match[1]) * {None:1,"ms":.001,"s":1,"m":60,"h":3600,"d":86400}[match[2]]
        if not math.isfinite(total) or total > 31536000:
            raise ProcessError("time interval exceeds one year", 2)
        return total

    def _signal(self, p, sig, *, privileged=False, manual=False):
        if p["state"] == "X":
            raise ProcessError(f"({p['pid']}) - No such process")
        uid = self._identity().uid
        if not privileged and uid not in (0, p["uid"]):
            raise ProcessError(f"({p['pid']}) - Operation not permitted")
        if p["pid"] == 1 and sig:
            raise ProcessError("(1) - Operation not permitted")
        if sig == 0 or p["state"] == "Z":
            return
        self._event("signal", p, signal=sig)
        if sig in (19,20,21,22):
            if p["state"] != "T":
                # Linux sleep deadlines keep running while the task is stopped
                p["state"] = "T"
        elif sig == 18:
            if p["state"] == "T":
                p["state"] = "S"
        elif sig in (17,23,28) or sig == 1 and p["nohup"]:
            return
        elif sig == 1 and p["service"] and self.d["services"][p["service"]]["config"].get("ExecReload"):
            self._event("service-reload", p)
            return
        else:
            self._finish(p, 128+sig, manual=manual)
        self._project(p)

    def open_subshell(self, session, parent_pid, *, argv=None):
        with self.transaction(session):
            saved = self._shell(argv)
            p = self.d['processes'][str(saved['pid'])]
            parent = self.d['processes'].get(str(parent_pid), {})
            p.update(ppid=parent_pid, sid=parent.get('sid', parent_pid))
            self._project(p)

    def close_session(self, session, *, include_parents=True):
        if not getattr(session, "_process_session", None):
            return
        with self.transaction(session):
            key = session._process_session
            saved = self.d["sessions"].get(key)
            if not saved:
                return
            for p in list(self.d["processes"].values()):
                if p["owner"] == key and p["pid"] != saved["pid"]:
                    if p["state"] in ACTIVE and not p["nohup"] and not p["disowned"]:
                        self._signal(p, 1, privileged=True)
                    if p["state"] == "Z":
                        self._reap(p)
                    elif p["state"] in ACTIVE:
                        p.update(ppid=1, owner="", job=0)
                        self._project(p)
            self._finish(self.d["processes"][str(saved["pid"])], 0, manual=True)
            del self.d["sessions"][key]
        parent = getattr(session, '_privilege_parent', None)
        if include_parents and parent:
            original = copy(session)
            original._privilege_parent = None
            for field, value in parent.items():
                if value is not None: setattr(original, field, value)
                else: original.__dict__.pop(field, None)
            self.close_session(original)

    def _unit_path(self, name):
        for directory in ("/etc/systemd/system", "/run/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system"):
            path = f"{directory}/{name}.service"
            if self.v.get(path):
                return path
        raise ProcessError(f"Unit {name}.service could not be found.", 4)

    def _unit_config(self, name):
        path = self._unit_path(name)
        node = self.v.get(path)
        if node.is_link and node.target == "/dev/null":
            return path, {"Masked": "yes"}
        config, section = {}, ""
        for line in self._read(path).splitlines():
            line = line.strip()
            if line.startswith("["):
                section = line.strip("[]")
            elif line and not line.startswith(("#", ";")) and "=" in line:
                key, value = line.split("=", 1)
                if section in ("Unit", "Service", "Install"):
                    config[key.strip()] = value.strip()
        return path, config

    def _service(self, name, seed_pid=0):
        name = name.removesuffix(".service")
        if name == "sshd" and not self.v.exists("/etc/systemd/system/sshd.service"):
            name = "ssh"
        if not re.fullmatch(r"[\w@.-]+", name):
            raise ProcessError("Invalid unit name", 2)
        if name in self.d["services"]:
            return self.d["services"][name]
        path, config = self._unit_config(name)
        service = dict(name=name, path=path, config=config, pid=seed_pid, state="active" if seed_pid else "inactive",
                       result="success", restart_at=None, restarts=0, templates=[], masked=config.get("Masked") == "yes")
        self.d["services"][name] = service
        if seed_pid:
            members = [seed_pid]
            for _ in range(16):
                children = [p["pid"] for p in self.d["processes"].values() if p["ppid"] in members and p["pid"] not in members]
                if not children:
                    break
                members.extend(children)
            for pid in members:
                p = self.d["processes"][str(pid)]
                p["service"] = name
                service["templates"].append(deepcopy(p))
        return service

    def _executable(self, argv, session):
        if not argv:
            raise ProcessError("missing command", 2)
        access = VFSTools(self.fs, session)
        candidates = [argv[0]] if "/" in argv[0] else [d+"/"+argv[0] for d in ("/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin")]
        denied = False
        for path in candidates:
            try:
                node = access.resolve(path, want="x")
                if not node.is_file or not node.mode & 0o111:
                    denied = True
                    continue
                return node.path
            except FSError as exc:
                denied |= exc.errno_name == "EACCES"
        raise ProcessError(f"{argv[0]}: {'Permission denied' if denied else 'command not found'}", 126 if denied else 127)

    # A failed start leaves no partial processes but keeps the failed unit state
    def _start_checked(self, service):
        name = service["name"]
        saved = deepcopy(self.d)
        self.v.db.execute("SAVEPOINT process_start")
        try:
            self._start(service)
        except (ProcessError, FSError, ValueError) as exc:
            self.v.db.execute("ROLLBACK TO process_start")
            self.v.db.execute("RELEASE process_start")
            self.d = saved
            service.clear()
            # The caller keeps its service object - restore it from the saved unit
            service.update(saved["services"][name])
            self.d["services"][name] = service
            service.update(pid=0, state="failed", result=str(exc), restart_at=None)
            self._remove(f"/run/{name}.pid")
            self._event("service-start-failed", service=name, error=str(exc))
            return ProcessResult("systemctl: " + str(exc), getattr(exc,"code",1))
        self.v.db.execute("RELEASE process_start")
        return None

    def _start(self, service):
        if service["state"] == "active":
            return
        if service["masked"]:
            raise ProcessError(f"Unit {service['name']}.service is masked.")
        config = service["config"]
        if config.get("Type", "simple") not in ("simple", "exec", "forking", "oneshot"):
            raise ProcessError("Unsupported service Type", 2)
        if any(config.get(k) for k in ("ExecStartPre", "ExecStartPost", "ExecStop", "ExecStopPost")):
            raise ProcessError("Service lifecycle hooks are not supported", 2)
        if config.get("KillMode", "control-group") != "control-group":
            raise ProcessError("Unsupported KillMode", 2)
        if config.get("Restart", "no") not in ("no", "always", "on-failure"):
            raise ProcessError("Unsupported Restart policy", 2)
        interval = self._duration(config.get("StartLimitIntervalSec", "10"))
        burst = max(1,min(100,int(config.get("StartLimitBurst", "5"))))
        starts = [t for t in service.get("starts", []) if self.clock()-t < interval]
        if interval and len(starts) >= burst:
            raise ProcessError("Start request repeated too quickly (start-limit-hit)")
        service["starts"] = starts + [self.clock()]
        argv = shlex.split(config.get("ExecStart", ""))
        run_as = copy(self.session)
        run_as.username, run_as._identity = config.get("User", "root"), None
        users = self.v.passwd_users()
        if run_as.username not in users:
            raise ProcessError(f"Failed to determine user: {run_as.username}")
        ident = self._identity(run_as)
        group = config.get("Group")
        gid = ident.gid
        if group:
            found = [g for g, name in self.v.group_names().items() if name == group]
            if not found:
                raise ProcessError(f"Failed to determine group: {group}")
            gid = found[0]
        executable = self._executable(argv, run_as)
        cwd = config.get("WorkingDirectory", "/")
        access = VFSTools(self.fs, run_as)
        if not access.resolve(cwd, want="x").is_dir:
            raise ProcessError("WorkingDirectory is not a directory")
        env = "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\0"
        envfile = config.get("EnvironmentFile")
        if envfile:
            # The service manager reads these as root, while /proc environ stays private
            optional = envfile.startswith("-")
            path = envfile.lstrip("-")
            if not self.v.exists(path) and not optional:
                raise ProcessError(f"Environment file {path}: No such file or directory")
            env += "\0".join(line for line in self._read(path).splitlines() if "=" in line and not line.startswith("#")) + "\0"
        templates = service["templates"]
        needed = max(1, len(templates))
        if sum(p["state"] != "X" for p in self.d["processes"].values()) + needed > self.max_processes:
            raise ProcessError("fork: Resource temporarily unavailable")
        duration = self._duration(" ".join(argv[1:])) if posixpath.basename(argv[0]) == "sleep" else None
        if config.get("Type") == "oneshot" and posixpath.basename(argv[0]) not in ("true", "false"):
            raise ProcessError("Only true/false oneshot commands are supported", 2)
        mapping = {}
        members = templates or [None]
        for i, template in enumerate(members):
            pid = self._alloc()
            if template:
                mapping[template["pid"]] = pid
            p = self._record(pid, 1 if not i else mapping.get(template["ppid"], service["pid"]),
                             ident.uid if not i else template["uid"], gid if not i else template["gid"],
                             [executable]+argv[1:] if not i else template["argv"], cwd,
                             name=template["name"] if template else None)
            p.update(service=service["name"], env=env, pgid=pid if not i else service["pid"])
            if duration is not None:
                p["deadline"] = self.clock()+duration
            if not i:
                service["pid"] = pid
            for line in template["sockets"] if template else []:
                fields = line.split()
                inode = str(self.d["next_inode"])
                self.d["next_inode"] += 1
                fields[9], fields[7] = inode, str(p["uid"])
                p["sockets"].append(" ".join(fields))
                self.d["socket_inodes"].append(inode)
            self.d["processes"][str(pid)] = p
            self._project(p)
            self._event("spawn", p)
        service.update(state="active", result="success", restart_at=None, restarts=service["restarts"]+1)
        self._put(f"/run/{service['name']}.pid", str(service["pid"])+"\n", mode=0o644)
        self._event("service-start", service=service["name"])
        if config.get("Type") == "oneshot":
            command = posixpath.basename(argv[0])
            if command not in ("true", "false"):
                # Refuse unsupported execution before committing anything
                raise ProcessError("Only true/false oneshot commands are supported", 2)
            self._finish(self.d["processes"][str(service["pid"])], int(command == "false"), manual=True)
            if command == "true" and config.get("RemainAfterExit", "no") == "yes":
                service["state"] = "active"

    def _stop(self, service):
        service["restart_at"] = None
        for p in list(self.d["processes"].values()):
            if p["service"] == service["name"] and p["state"] in ACTIVE:
                self._finish(p, 143, manual=True)
        service.update(pid=0, state="inactive", result="success", restart_at=None)
        self._remove(f"/run/{service['name']}.pid")
        self._event("service-stop", service=service["name"])

    def _systemctl(self, args):
        value_only = "--value" in args
        now = "--now" in args
        properties, clean = [], []
        i = 0
        sig = 15
        while i < len(args):
            arg = args[i]
            if arg in ("--no-pager", "--full", "--all", "--plain", "--value", "--now", "--type=service"):
                pass
            elif arg in ("-p", "--property", "--signal", "-s"):
                i += 1
                if i == len(args):
                    raise ProcessError("missing option value", 2)
                if arg in ("-p", "--property"):
                    properties.extend(args[i].split(","))
                else:
                    sig = signal_number(args[i])
            elif arg.startswith("--property="):
                properties.extend(arg.split("=",1)[1].split(","))
            elif arg.startswith("--signal="):
                sig = signal_number(arg.split("=",1)[1])
            elif arg.startswith("-"):
                raise ProcessError(f"unrecognized option: {arg}", 2)
            else:
                clean.append(arg)
            i += 1
        action = clean[0] if clean else "list-units"
        names = clean[1:]
        mutating = {"start", "stop", "restart", "try-restart", "reload", "reload-or-restart", "enable", "disable", "mask", "unmask", "daemon-reload", "reset-failed", "kill"}
        if action in mutating and self._identity().uid != 0:
            raise ProcessError("Interactive authentication required.")
        if action == "daemon-reload":
            for s in self.d["services"].values():
                s["path"], s["config"] = self._unit_config(s["name"])
                s["masked"] = s["config"].get("Masked") == "yes"
            self._event("daemon-reload")
            return ProcessResult()
        if action in ("list-units", "list-unit-files"):
            output = ["UNIT                           LOAD   ACTIVE SUB     DESCRIPTION" if action == "list-units" else "UNIT FILE                      STATE"]
            directory = "/etc/systemd/system"
            if self.v.exists(directory):
                for node in self.v.listdir(directory):
                    if node.name.endswith(".service"):
                        self._service(node.name)
            for s in self.d["services"].values():
                if names and not any(fnmatch.fnmatch(s["name"]+".service", n) for n in names):
                    continue
                output.append(f"{s['name']+'.service':<30} " + (self._enabled(s) if action == "list-unit-files" else f"loaded {s['state']:<8} {self._substate(s):<9} {s['config'].get('Description', s['name'])}"))
            return ProcessResult("\n".join(output))
        if not names:
            raise ProcessError("Too few arguments.", 2)
        output, code = [], 0
        for name in names:
            s = self._service(name)
            config = s["config"]
            if action == "start":
                error = self._start_checked(s)
                if error: return error
            elif action in ("stop", "restart", "try-restart", "reload-or-restart"):
                if action == "try-restart" and s["state"] != "active":
                    continue
                if action == "reload-or-restart" and s["state"] == "active" and config.get("ExecReload"):
                    self._event("service-reload", service=s["name"])
                else:
                    self._stop(s)
                    if action != "stop":
                        error = self._start_checked(s)
                        if error: return error
            elif action == "reload":
                if s["state"] != "active" or not config.get("ExecReload"):
                    raise ProcessError(f"Job type reload is not applicable for unit {s['name']}.service.")
                self._event("service-reload", service=s["name"])
            elif action in ("enable", "disable"):
                link = f"/etc/systemd/system/multi-user.target.wants/{s['name']}.service"
                if action == "enable":
                    self._put(link, kind="link", mode=0o777, target=s["path"])
                else:
                    self._remove(link)
                if now:
                    if action == "enable":
                        error = self._start_checked(s)
                        if error: return error
                    else:
                        self._stop(s)
                self._event("service-"+action, service=s["name"])
            elif action in ("mask", "unmask"):
                path = f"/etc/systemd/system/{s['name']}.service"
                if action == "mask" and not s["masked"]:
                    node = self.v.get(path)
                    s["unmasked"] = {"text":self._read(path), "target":node.target if node else None, "exists":bool(node)}
                    self._put(path, kind="link", mode=0o777, target="/dev/null")
                elif action == "unmask" and s["masked"]:
                    original = s.pop("unmasked", {"exists":False})
                    self._remove(path)
                    if original["exists"]:
                        self._put(path, original["text"], kind="link" if original["target"] else "file", mode=0o777 if original["target"] else 0o644, target=original["target"])
                    s["path"], s["config"] = self._unit_config(s["name"])
                s["masked"] = action == "mask"
                if now and s["masked"]:
                    self._stop(s)
                self._event("service-"+action, service=s["name"])
            elif action == "reset-failed":
                if s["state"] == "failed":
                    s.update(state="inactive", result="success", starts=[])
            elif action == "kill":
                for p in list(self.d["processes"].values()):
                    if p["service"] == s["name"] and p["state"] in ACTIVE:
                        self._signal(p, sig, privileged=True)
            elif action == "is-active":
                output.append(s["state"])
                code = max(code, 0 if s["state"] == "active" else 3)
            elif action == "is-enabled":
                output.append(self._enabled(s))
                code = max(code, int(self._enabled(s) != "enabled"))
            elif action == "cat":
                output.append("# " + s["path"] + "\n" + self._read(s["path"]).rstrip())
            elif action == "show":
                fields = dict(Id=s["name"]+".service", Description=config.get("Description", s["name"]), LoadState="masked" if s["masked"] else "loaded", ActiveState=s["state"], SubState=self._substate(s), MainPID=s["pid"], FragmentPath=s["path"], UnitFileState=self._enabled(s), Result=s["result"], NRestarts=max(0,s["restarts"]-1))
                for key in properties or fields:
                    if key not in fields:
                        raise ProcessError(f"Unsupported property: {key}", 2)
                    output.append(str(fields[key]) if value_only else f"{key}={fields[key]}")
            elif action == "status":
                output.append(f"{'●' if s['state'] == 'active' else '○'} {s['name']}.service - {config.get('Description', s['name'])}\n     Loaded: {'masked' if s['masked'] else 'loaded'} ({s['path']}; {self._enabled(s)})\n     Active: {s['state']} ({self._substate(s)})\n   Main PID: {s['pid']}")
                code = max(code, 0 if s["state"] == "active" else 3)
            else:
                raise ProcessError(f"Unknown command verb {action}.", 2)
        return ProcessResult("\n".join(output), code)

    def _enabled(self, s):
        return "masked" if s["masked"] else "enabled" if self.v.exists(f"/etc/systemd/system/multi-user.target.wants/{s['name']}.service") else "disabled"

    @staticmethod
    def _substate(s):
        return {"active": "running" if s["pid"] else "exited", "inactive": "dead", "failed": "failed", "activating": "auto-restart"}.get(s["state"], "dead")

    def _spawn(self, argv, *, background=False):
        if argv and posixpath.basename(argv[0]) == "sudo":
            from .recon import sudo_policy
            if not sudo_policy(self.fs, self.session):
                raise ProcessError("sudo: a password is required")
            target, index = "root", 1
            while index < len(argv):
                if argv[index] == "-n": index += 1
                elif argv[index] == "-u" and index + 1 < len(argv):
                    target, index = argv[index+1], index+2
                elif argv[index] == "--": index += 1; break
                else: break
            if target not in self.v.passwd_users():
                raise ProcessError(f"sudo: unknown user {target}")
            if index >= len(argv) or argv[index].startswith("-"):
                raise ProcessError("sudo: unsupported syntax", 2)
            if posixpath.basename(argv[index]) == "sudo":
                raise ProcessError("sudo: nested background wrapper is unsupported", 2)
            original = self.session
            elevated = copy(original)
            elevated.username, elevated._identity = target, None
            self.session = elevated
            try:
                result = self._spawn(argv[index:], background=background)
                original.last_background_pid = getattr(elevated,"last_background_pid",None)
                return result
            finally:
                self.session = original
        shell = self._shell()
        argv = list(argv)
        nohup, nice = False, 0
        while argv and posixpath.basename(argv[0]) in ("nohup", "nice"):
            wrapper = posixpath.basename(argv.pop(0))
            if wrapper == "nohup":
                nohup = True
            else:
                nice = 10
                if argv and argv[0] == "-n":
                    if len(argv) < 3:
                        raise ProcessError("nice: option requires an argument", 2)
                    nice, argv = int(argv[1]), argv[2:]
        if not argv:
            raise ProcessError("missing command", 2)
        ident = self._identity()
        if nice < 0 and ident.uid != 0:
            raise ProcessError("nice: cannot set niceness: Permission denied")
        if not -20 <= nice <= 19:
            raise ProcessError("niceness must be in -20..19", 2)
        executable = self._executable(argv, self.session)
        name = posixpath.basename(argv[0])
        duration = None
        if name == "sleep":
            if len(argv) < 2:
                raise ProcessError("sleep: missing operand", 2)
            duration = self._duration(" ".join(argv[1:]))
        elif name in ("true", "false"):
            duration = 0
        elif not background:
            raise ProcessError(f"{name}: foreground program execution is not supported", 2)
        pid = self._alloc()
        p = self._record(pid, shell["pid"], ident.uid, ident.gid, [executable]+argv[1:], self.session.cwd)
        p.update(owner=self.session._process_session, sid=shell["pid"], nice=nice, nohup=nohup)
        p["env"] = f"HOME={ident.home}\0USER={self.session.username}\0PATH=/usr/local/bin:/usr/bin:/bin\0"
        if duration is not None:
            p["deadline"] = self.clock()+duration
        if background:
            p["job"] = shell["next_job"]
            shell["next_job"] += 1
        self.d["processes"][str(pid)] = p
        self._project(p)
        self._event("spawn", p, background=background)
        if name in ("true", "false"):
            self._finish(p, int(name == "false"))
        if background:
            self.session.last_background_pid = pid
            return ProcessResult(f"[{p['job']}] {pid}")
        return ProcessResult(wait_pids=(pid,))

    def _jobs(self):
        key = getattr(self.session, "_process_session", "")
        return [p for p in self.d["processes"].values() if p["owner"] == key and p["job"] and not p["disowned"] and p["state"] != "X"]

    def _job(self, spec):
        jobs = self._jobs()
        if spec in ("%", "%+", "%%"):
            found = jobs[-1:]
        elif spec == "%-":
            found = jobs[-2:-1]
        elif spec.startswith("%") and spec[1:].isdigit():
            found = [p for p in jobs if p["job"] == int(spec[1:])]
        elif spec.isdigit():
            found = [p for p in jobs if p["pid"] == int(spec)]
        else:
            raise ProcessError(f"{spec}: invalid job specification", 2)
        if not found:
            raise ProcessError(f"{spec}: no such job", 127)
        return found[0]

    def _targets(self, spec):
        if spec.startswith("%"):
            leader = self._job(spec)
            return [p for p in self.d["processes"].values() if p["pgid"] == leader["pgid"] and p["state"] != "X"]
        try:
            pid = int(spec)
        except ValueError:
            raise ProcessError(f"{spec}: arguments must be process or job IDs", 2)
        if pid > 0:
            p = self.d["processes"].get(str(pid))
            return [p] if p and p["state"] != "X" else []
        group = self.d["processes"][str(self._shell()["pid"])]["pgid"] if pid == 0 else -pid
        return [p for p in self.d["processes"].values() if p["state"] != "X" and p["pid"] > 1 and (pid == -1 or p["pgid"] == group)]

    def _kill(self, args):
        sig, i = 15, 0
        if args and args[0] in ("-l", "-L"):
            if len(args) == 1:
                return ProcessResult(" ".join(f"{v}) SIG{k}" for k,v in SIGNALS.items() if v))
            value = int(args[1])
            value = value-128 if value > 128 else value
            return ProcessResult(next((k for k,v in SIGNALS.items() if v == value), str(value)))
        if args and args[0] in ("-s", "--signal", "-n"):
            if len(args) < 3:
                raise ProcessError("kill: missing signal or process ID", 2)
            sig, i = signal_number(args[1]), 2
        elif args and args[0].startswith("-") and args[0] != "--":
            sig, i = signal_number(args[0][1:]), 1
        if i < len(args) and args[i] == "--":
            i += 1
        if i == len(args):
            raise ProcessError("kill: missing process ID", 2)
        errors = []
        for arg in args[i:]:
            targets = self._targets(arg)
            if not targets:
                errors.append(f"kill: ({arg}) - No such process")
            for p in targets:
                try:
                    self._signal(p, sig)
                except ProcessError as exc:
                    errors.append("kill: "+str(exc))
        return ProcessResult("\n".join(errors), int(bool(errors)))

    def _match(self, args, *, action="pgrep"):
        full, exact, show, sig = False, False, "", 15
        uid, parent = None, None
        patterns = []
        i = 0
        while i < len(args):
            arg = args[i]
            if arg in ("-u", "-U", "-P"):
                i += 1
                if i == len(args):
                    raise ProcessError("option requires an argument", 2)
                value = args[i]
                if arg == "-P":
                    parent = int(value)
                else:
                    uid = int(value) if value.isdigit() else self.v.passwd_users().get(value, (-1,))[0]
            elif arg in ("--signal", "-s") and action != "pgrep":
                i += 1
                if i == len(args):
                    raise ProcessError("missing signal", 2)
                sig = signal_number(args[i])
            elif arg.startswith("-") and len(arg)>1 and set(arg[1:]) <= set("flax"):
                full |= "f" in arg
                exact |= "x" in arg
                show = "cmd" if "a" in arg else "name" if "l" in arg else show
            elif arg.startswith("-") and action != "pgrep":
                sig = signal_number(arg[1:])
            elif arg.startswith("-"):
                raise ProcessError(f"unsupported option: {arg}", 2)
            else:
                patterns.append(arg)
            i += 1
        if len(patterns) != 1:
            raise ProcessError("exactly one pattern is required", 2)
        pattern = patterns[0]
        if len(pattern)>128 or re.search(r"[^\w ./^$*+-]", pattern):
            raise ProcessError("unsupported regular expression", 2)
        # Bounded subset - anchors, literal text and .* wildcards, no nested repetition
        if "*" in pattern.replace(".*", "") or "+" in pattern:
            raise ProcessError("unsupported regular expression", 2)
        try:
            matcher = re.compile(pattern)
        except re.error:
            raise ProcessError("invalid regular expression", 2)
        rows = []
        for p in self._rows():
            text = " ".join(p["argv"]) if full else p["name"]
            match = text == pattern if exact or action in ("killall", "pidof") else bool(matcher.search(text))
            if match and (uid is None or p["uid"] == uid) and (parent is None or p["ppid"] == parent):
                rows.append(p)
        if action in ("pkill", "killall"):
            errors, successes = [], 0
            for p in rows:
                try:
                    self._signal(p, sig)
                    successes += 1
                except ProcessError as exc:
                    errors.append(action+": "+str(exc))
            return ProcessResult("\n".join(errors), 0 if successes else 1)
        separator = " " if action == "pidof" else "\n"
        return ProcessResult(separator.join(str(p["pid"])+( " " + (" ".join(p["argv"]) if show == "cmd" else p["name"]) if show else "") for p in rows), 0 if rows else 1)

    def _rows(self):
        return sorted((p for p in self.d["processes"].values() if p["state"] != "X"), key=lambda p:p["pid"])

    def _ps(self, args):
        rows = self._rows()
        fields, headers, pid_filter, user_filter, all_rows = None, True, None, None, False
        style, sort_key = "short", "pid"
        i = 0
        while i < len(args):
            arg = args[i]
            if arg in ("aux", "-aux", "-ef", "-e", "-A", "-f", "-eo", "-axo"):
                all_rows = True
                style = "aux" if "aux" in arg else "full" if "f" in arg else style
                if arg.endswith("o"):
                    i += 1
                    fields = args[i].split(",")
            elif arg in ("-p", "--pid", "-o", "--format", "-u", "--user"):
                i += 1
                value = args[i]
                if arg in ("-p", "--pid"):
                    pid_filter = set(int(x) for x in value.replace(" ", ",").split(",") if x)
                elif arg in ("-u", "--user"):
                    user_filter = int(value) if value.isdigit() else self.v.passwd_users().get(value,(-1,))[0]
                else:
                    fields = value.split(",")
            elif arg in ("--no-headers", "--no-heading", "h"):
                headers = False
            elif arg.startswith("--sort="):
                sort_key = arg.split("=",1)[1]
            else:
                raise ProcessError(f"ps: unsupported option {arg}", 2)
            i += 1
        if pid_filter is not None:
            rows = [p for p in rows if p["pid"] in pid_filter]
        if user_filter is not None:
            rows = [p for p in rows if p["uid"] == user_filter]
        if not all_rows and pid_filter is None and user_filter is None:
            rows = [p for p in rows if p["owner"] == getattr(self.session,"_process_session", "")]
        if sort_key.lstrip("+-") not in ("pid", "ppid", "uid", "nice", "name"):
            raise ProcessError("ps: unsupported sort key", 2)
        rows.sort(key=lambda p:p[sort_key.lstrip("+-")], reverse=sort_key.startswith("-"))
        fields = fields or {"aux":["user","pid","%cpu","%mem","vsz","rss","tty","stat","start","time","args"], "full":["uid","pid","ppid","c","stime","tty","time","cmd"], "short":["pid","tty","time","ucmd"]}[style]
        names = {uid:name for name,(uid,*_) in self.v.passwd_users().items()}
        labels = {"user":"USER","uid":"UID","pid":"PID","ppid":"PPID","pgid":"PGID","sid":"SID","ni":"NI","nice":"NI","s":"S","state":"S","stat":"STAT","comm":"COMMAND","ucmd":"CMD","cmd":"CMD","args":"COMMAND","etime":"ELAPSED","etimes":"ELAPSED","start":"START","stime":"STIME","time":"TIME","tty":"TTY","c":"C","vsz":"VSZ","rss":"RSS","%cpu":"%CPU","%mem":"%MEM"}
        parsed = [f.partition("=") for f in fields]
        if any(k not in labels for k,sep,custom in parsed):
            raise ProcessError("ps: unknown output format", 2)
        out = []
        now = self.clock()
        # Column layout of procps-ng 3.3.17 as (width, right-aligned)
        # text columns such as COMMAND come last and unpadded, usernames over 8 become name+
        layout = {"user":(8,False),"uid":(8,False),"pid":(7,True),"ppid":(7,True),"pgid":(7,True),"sid":(7,True),
                  "ni":(3,True),"nice":(3,True),"s":(1,False),"state":(1,False),"stat":(4,False),"etime":(11,True),
                  "etimes":(7,True),"start":(5,True),"stime":(5,False),"time":(8,True),"tty":(8,False),"c":(2,True),
                  "vsz":(6,True),"rss":(5,True),"%cpu":(4,True),"%mem":(4,True)}
        def started(p):
            return time.strftime("%H:%M" if now - p["started"] < 86400 else "%b%d", time.gmtime(p["started"]))
        def cell(key, value, last):
            width, right = layout.get(key, (0, False))
            text = str(value)
            if key in ("user", "uid") and len(text) > 8:
                text = text[:7] + "+"
            if last and not right:
                return text
            return text.rjust(width) if right else text.ljust(width)
        aux_time = style == "aux"
        if aux_time:
            # BSD-style listings print M:SS cumulative time
            layout["time"] = (6, True)
        def render(values):
            cells = [cell(k, v, i == len(values) - 1) for i, (k, v) in enumerate(values)]
            return " ".join(cells).rstrip()
        if headers and any(not sep or custom for k,sep,custom in parsed):
            header = [(k, custom if sep else labels[k]) for k,sep,custom in parsed]
            out.append(render(header))
        for p in rows:
            name = names.get(p["uid"],str(p["uid"]))
            cpu_time = "0:00" if aux_time else "00:00:00"
            values = {**p,"user":name,"uid":name,"ni":p["nice"],"s":p["state"],"stat":p["state"],"comm":p["name"],"ucmd":p["name"],"cmd":" ".join(p["argv"]),"args":" ".join(p["argv"]),"etime":str(int(now-p["started"])),"etimes":str(int(now-p["started"])),"start":started(p),"stime":started(p),"time":cpu_time,"tty":"pts/0" if p["owner"] else "?","c":0,"vsz":16384,"rss":4096,"%cpu":"0.0","%mem":"0.1"}
            out.append(render([(k, values[k]) for k,sep,custom in parsed]))
        return ProcessResult("\n".join(out), 0 if rows else 1)

    def run_argv(self, session, argv, stdin=None, *, background=False):
        if not argv:
            return None
        name = posixpath.basename(argv[0])
        if not background and name not in COMMANDS:
            return None
        try:
            with self.transaction(session):
                self._shell()
                args = list(argv[1:])
                if background:
                    return self._spawn(argv, background=True)
                if name in ("sleep", "nohup", "nice"):
                    return self._spawn(argv)
                if name == "ps":
                    return self._ps(args)
                if name == "top":
                    if any(x not in ("-b", "-n", "1", "-bn1") for x in args):
                        raise ProcessError("top: supported mode is -b -n 1", 2)
                    rows = self._rows()
                    return ProcessResult(f"Tasks: {len(rows)} total, {sum(p['state']=='T' for p in rows)} stopped, {sum(p['state']=='Z' for p in rows)} zombie\n"+self._ps(["-e","-o","pid,user,ni,s,comm"]).output)
                if name == "kill":
                    return self._kill(args)
                if name in ("pgrep", "pkill", "pidof", "killall"):
                    return self._match(args, action=name)
                if name == "systemctl":
                    return self._systemctl(args)
                if name == "service":
                    if len(args) != 2:
                        raise ProcessError("Usage: service NAME ACTION", 2)
                    return self._systemctl([args[1],args[0]])
                if name == "renice":
                    args = [x for x in args if x not in ("-n", "-p")]
                    if len(args)<2:
                        raise ProcessError("renice: priority and PID required", 2)
                    nice = int(args[0])
                    if not -20 <= nice <= 19:
                        raise ProcessError("renice: priority out of range", 2)
                    output = []
                    for spec in args[1:]:
                        targets = self._targets(spec)
                        if not targets:
                            raise ProcessError("renice: No such process")
                        for p in targets:
                            self._signal(p, 0)
                            if nice < p["nice"] and self._identity().uid != 0:
                                raise ProcessError("renice: Permission denied")
                            old, p["nice"] = p["nice"], nice
                            self._project(p)
                            self._event("renice", p, nice=nice)
                            output.append(f"{p['pid']} (process ID) old priority {old}, new priority {nice}")
                    return ProcessResult("\n".join(output))
                if name == "journalctl":
                    service, count, i = None, 50, 0
                    while i < len(args):
                        if args[i] in ("-u", "--unit", "-n"):
                            opt = args[i]; i += 1
                            if opt == "-n": count = min(1000,max(0,int(args[i])))
                            else: service = args[i].removesuffix(".service")
                        elif args[i] not in ("--no-pager", "-b"):
                            raise ProcessError("journalctl: unsupported option", 2)
                        i += 1
                    events = [e for e in self.d["events"] if service is None or e["service"] == service]
                    return ProcessResult("\n".join(f"{time.strftime('%b %d %H:%M:%S',time.gmtime(e['time']))} systemd[1]: {e['service'] or 'session'}: {e['action']}" for e in (events[-count:] if count else [])))
                if name == "jobs":
                    if any(a not in ("-l", "-p", "-r", "-s") for a in args):
                        raise ProcessError("jobs: unsupported option", 2)
                    jobs = self._jobs()
                    if "-r" in args: jobs = [p for p in jobs if p["state"] in ("R","S")]
                    if "-s" in args: jobs = [p for p in jobs if p["state"] == "T"]
                    return ProcessResult("\n".join(str(p["pid"]) if "-p" in args else f"[{p['job']}] " + (str(p["pid"])+" " if "-l" in args else "") + ("Stopped" if p["state"] == "T" else "Done" if p["state"] == "Z" else "Running") + " " + shlex.join(p["argv"]) for p in jobs))
                if name in ("bg", "fg", "disown"):
                    no_hup = name == "disown" and "-h" in args
                    all_jobs = name == "disown" and "-a" in args
                    args = [a for a in args if a not in ("-h", "-a")]
                    jobs = self._jobs() if all_jobs else [self._job(a) for a in (args or ["%+"])]
                    output = []
                    for p in jobs:
                        if name == "disown":
                            p["nohup"] = True
                            if not no_hup:
                                p["disowned"] = True
                        else:
                            self._signal(p, 18)
                            output.append(f"[{p['job']}] " + shlex.join(p["argv"]))
                    return ProcessResult("\n".join(output), wait_pids=tuple(p["pid"] for p in jobs) if name == "fg" else ())
                if name == "wait":
                    any_job = "-n" in args
                    args = [a for a in args if a != "-n"]
                    jobs = [self._job(a) for a in args] if args else self._jobs()
                    if any_job and not jobs:
                        return ProcessResult(exit_code=127)
                    return ProcessResult(wait_pids=tuple(p["pid"] for p in jobs), wait_any=any_job, wait_all=not args and not any_job)
        except (ProcessError, FSError, ValueError, IndexError) as exc:
            return ProcessResult(f"{name}: {getattr(exc, 'message', str(exc))}", getattr(exc,"code",2 if isinstance(exc,(ValueError,IndexError)) else 1))
        return None

    async def wait_result(self, session, result):
        pending = list(result.wait_pids)
        if not pending:
            return result
        last_status = 0
        session._foreground_pids = tuple(pending)
        try:
            while pending:
                with self.transaction(session):
                    for pid in list(pending):
                        p = self.d["processes"].get(str(pid))
                        if p is None:
                            pending.remove(pid)
                            last_status = 127
                        elif p["state"] in ("Z", "X"):
                            last_status = self._reap(p)
                            pending.remove(pid)
                        elif p["state"] == "T":
                            last_status = 128+19
                            pending.remove(pid)
                        else:
                            continue
                        if result.wait_any:
                            pending.clear()
                            break
                if pending:
                    await asyncio.sleep(.025)
        except asyncio.CancelledError:
            with self.transaction(session):
                for pid in pending:
                    p = self.d["processes"].get(str(pid))
                    if p and p["state"] in ACTIVE:
                        self._signal(p, 2, privileged=True)
                    if p and p["state"] == "Z":
                        self._reap(p)
            raise
        finally:
            session._foreground_pids = ()
        return ProcessResult(result.output, 0 if result.wait_all else last_status)


    def signal_foreground(self, session, signal):
        targets = getattr(session, "_foreground_pids", ())
        if not targets:
            return False
        try:
            sig = signal_number(signal)
        except ProcessError:
            return False
        with self.transaction(session):
            for pid in targets:
                p = self.d["processes"].get(str(pid))
                if p and p["state"] in ACTIVE:
                    self._signal(p, sig, privileged=True)
                    if p["state"] == "T" and not p["job"]:
                        shell = self._shell()
                        p["job"] = shell["next_job"]
                        shell["next_job"] += 1
        return True

    # Operator startup and shutdown - hang up stale shells, keep detached work
    def recover_sessions(self):
        with self.lock:
            rows = self.fs.vfs.db.execute("SELECT realm,data FROM process_lifecycle").fetchall()
        for row in rows:
            for key in json.loads(row[1])["sessions"]:
                session = SimpleNamespace(realm=row[0],username="root",cwd="/",_process_session=key,_identity=None)
                self.close_session(session)

    # Reconcile timed processes and automatic restarts even when no commands arrive
    async def serve(self, interval=.1):
        while True:
            with self.lock:
                realms = [r[0] for r in self.fs.vfs.db.execute("SELECT realm FROM process_lifecycle")]
            for realm in realms:
                session = SimpleNamespace(realm=realm,username="root",cwd="/",_identity=None)
                with self.transaction(session):
                    pass
                await asyncio.sleep(0)
            await asyncio.sleep(interval)


    def session_exit_code(self, session):
        pid = getattr(session, "shell_pid", None)
        if pid is None:
            return None
        with self.transaction(session):
            p = self.d["processes"].get(str(pid))
            return p["exit_code"] if p and p["state"] in ("Z", "X") else None
