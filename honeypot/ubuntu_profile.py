# Ubuntu Profile
# the operator-only research scenario added on top of the imported Ubuntu image
# names, records and credentials are lab data, never installed in the host's SSH setup
# keys are generated for this image only, and SQLite holds every file an attacker can see

# Imports
from __future__ import annotations

from contextlib import closing
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import posixpath
import re
import secrets
import sqlite3
import time

from .vfs import SCHEMA
from .ubuntu_analysis import ANALYSIS_VERSION, NODE_FIELDS, analyze_import, node_fingerprint, save_analysis

PROFILE_VERSION = "ubuntu-web-1"
FACTS = {"hostname": "srv-web-03", "distro": "Ubuntu 22.04.3 LTS",
         "kernel": "5.15.0-58-generic", "server_ip": "10.0.12.31",
         "persona_user": "ubuntu"}
APP_ENV = "/opt/portal/.env"

EVIDENCE = [
    ("system discovery", ["/etc/os-release", "/proc/version", "/var/lib/dpkg/status"],
     ["T1082"], ["https://attack.mitre.org/techniques/T1082/"]),
    ("service and network discovery", ["/etc/nginx/sites-available/portal", "/proc/net/tcp", "/etc/hosts"],
     ["T1190", "T1049"], ["https://attack.mitre.org/techniques/T1190/", "https://attack.mitre.org/techniques/T1049/"]),
    ("credentials", [APP_ENV, "/home/deploy/.pgpass", "/home/ubuntu/.bash_history", "/home/ubuntu/.ssh/id_ed25519"],
     ["T1552.001", "T1552.003", "T1552.004"], ["https://attack.mitre.org/techniques/T1552/001/", "https://attack.mitre.org/techniques/T1552/003/", "https://attack.mitre.org/techniques/T1552/004/"]),
    ("privilege discovery", ["/etc/passwd", "/etc/group", "/etc/sudoers", "/etc/sudoers.d/90-cloud-init-users", "/usr/bin/sudo"],
     ["T1548.001", "T1548.003"], ["https://attack.mitre.org/techniques/T1548/001/", "https://attack.mitre.org/techniques/T1548/003/"]),
    ("persistence locations", ["/etc/crontab", "/etc/cron.d/portal-backup", "/etc/systemd/system/portal.service", "/home/ubuntu/.ssh/authorized_keys"],
     ["T1053.003", "T1543.002", "T1098.004"], ["https://attack.mitre.org/techniques/T1053/003/", "https://attack.mitre.org/techniques/T1543/002/", "https://attack.mitre.org/techniques/T1098/004/"]),
    ("data and operating history", ["/var/backups/portal/portal-latest.sql", "/srv/finance/invoices.csv", "/var/log/auth.log", "/var/log/nginx/access.log"],
     ["T1083"], ["https://attack.mitre.org/techniques/T1083/"]),
]


def _read_base(db, path):
    row = db.execute("SELECT content FROM nodes WHERE realm='' AND path=? AND deleted=0", (path,)).fetchone()
    return bytes(row[0]).decode("utf-8", "replace") if row and row[0] else ""


# Apply the base profile once, in one transaction, keeping every overlay row
# refuses conflicting accounts and other host identities, so scenarios never mix
# a backup is made before an existing database is changed
def _install_base_profile(db_path, *, create=False, analysis=None):
    path = Path(db_path)
    if not path.exists() and not create:
        raise ValueError("Database missing; use --create to build the focused scenario")
    path.parent.mkdir(parents=True, exist_ok=True)
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization

    with closing(sqlite3.connect(path, isolation_level=None)) as db:
        db.executescript(SCHEMA)
        found = db.execute("SELECT value FROM meta WHERE key='attacker_profile'").fetchone()
        if found:
            if found[0] != PROFILE_VERSION:
                raise ValueError("A different profile exists; an explicit migration is required")
            return {"action": "reused", "profile": PROFILE_VERSION,
                    "base_nodes": db.execute("SELECT count(*) FROM nodes WHERE realm='' AND deleted=0").fetchone()[0]}
        for key in ("hostname", "kernel", "server_ip"):
            row = db.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
            if row and row[0] != FACTS[key]:
                raise ValueError(f"Profile requires {key}={FACTS[key]}; existing database preserved")
        original_count = db.execute("SELECT count(*) FROM nodes WHERE realm=''").fetchone()[0]
        analysis = analysis or analyze_import(path, EVIDENCE)
        if APP_ENV in analysis.manifest:
            raise ValueError("Existing portal application data conflicts with the new profile; database unchanged")
        facts = dict(FACTS)
        kernels = analysis.report["kernel_candidates"]
        if kernels:
            facts["kernel"] = kernels[0]
        imported_release = _read_base(db, "/usr/lib/os-release")
        pretty = re.search(r'^PRETTY_NAME="(Ubuntu 22\.04[^"\n]*)"$', imported_release, re.M)
        if pretty:
            facts["distro"] = pretty[1]
        now = int(time.time())
        old = now - 30 * 86400
        recent = now - 86400
        stamp = datetime.fromtimestamp(recent, timezone.utc)
        day = stamp.strftime("%Y-%m-%d")
        sysday = stamp.strftime("%b %e")
        webday = stamp.strftime("%d/%b/%Y")
        nodes, plan, before_rows = {}, {}, {}
        merge_paths = {"/etc/passwd", "/etc/group", "/etc/shadow", "/etc/gshadow", "/var/lib/dpkg/status"}

        def policy_for(p):
            if p in merge_paths:
                return "merge"
            if p == "/etc/hostname":
                return "virtual_host_identity"
            if p == "/etc/hosts" or p.endswith(("/.bash_history", "/.ssh/authorized_keys", "/.ssh/known_hosts", "/.ssh/config")) or p.startswith("/var/log/"):
                return "append"
            if p == "/etc/machine-id":
                return "fill_empty"
            return "preserve"

        def add(p, content=b"", *, kind="file", mode=0o644, uid=0, gid=0,
                user="root", group="root", target=None, size=None, mtime=None):
            p = posixpath.normpath(p)
            policy = policy_for(p)
            existing_node = analysis.manifest.get(p)
            if existing_node and policy == "preserve":
                plan[p] = ("preserve", "Imported path already provides this file, binary, link or directory")
                return
            before = db.execute(f"SELECT {NODE_FIELDS} FROM nodes WHERE realm='' AND path=?", (p,)).fetchone() if existing_node else None
            if before and policy == "fill_empty" and before[14]:
                plan[p] = ("preserve", "Imported machine identity already exists")
                return
            parent = posixpath.dirname(p) or "/"
            if p != "/" and parent not in nodes:
                exists = db.execute("SELECT kind FROM nodes WHERE realm='' AND path=?", (parent,)).fetchone()
                if not exists:
                    add(parent, kind="dir", mode=0o755)
            if isinstance(content, str):
                content = content.encode()
            if before and policy in ("merge", "append", "fill_empty"):
                if before[4] != "file":
                    raise ValueError(f"Cannot merge profile data into non-file {p}; database unchanged")
                # Keep the imported permissions and owners
                # and every earlier byte when adding history or authorized_keys entries
                mode, uid, gid, user, group = before[5:10]
                if policy == "append" and before[14]:
                    original = bytes(before[14])
                    content = original + (b"" if original.endswith(b"\n") else b"\n") + (content or b"")
                size = len(content or b"")
            if kind == "dir":
                content, size = None, 4096
            elif kind == "link":
                content, size = None, len(target.encode())
            elif size is None:
                size = len(content or b"")
            nodes[p] = ("", p, parent, posixpath.basename(p) or "/", kind, mode,
                        uid, gid, user, group, size, mtime or old, target,
                        2 if kind == "dir" else 1, content, 0)
            before_rows[p] = before
            plan[p] = (policy if before else "add", "Merge analyzed identity/package data" if policy == "merge" else
                       "Append scenario activity without deleting imported data" if policy == "append" and before else
                       "Set the virtual host name consistently" if policy == "virtual_host_identity" and before else
                       "Add missing attacker-interest profile detail")

        add("/", kind="dir", mode=0o755)
        for p in ("/etc", "/usr/bin", "/usr/sbin", "/usr/lib", "/usr/local/bin", "/usr/local/sbin",
                  "/var/log", "/var/lib", "/var/backups", "/run", "/dev", "/home", "/opt", "/srv", "/boot"):
            add(p, kind="dir", mode=0o755)
        for p in ("/tmp", "/var/tmp", "/dev/shm"):
            add(p, kind="dir", mode=0o1777)
        for p in ("/proc", "/sys"):
            add(p, kind="dir", mode=0o555)
        for p, target in (("/bin", "usr/bin"), ("/sbin", "usr/sbin"), ("/lib", "usr/lib")):
            add(p, kind="link", mode=0o777, target=target)

        # Keep the other imported users, allocating daemon IDs if the image differs
        # interactive IDs must match this scenario's ownership
        passwd = _read_base(db, "/etc/passwd")
        existing = {r[0]: r for l in passwd.splitlines() if len(r := l.split(":")) == 7}
        imported_groups = {r[0]: r for l in _read_base(db, "/etc/group").splitlines() if len(r := l.split(":")) == 4}
        accounts = [
            ("root", 0, 0, "root", "/root", "/bin/bash"),
            ("daemon", 1, 1, "daemon", "/usr/sbin", "/usr/sbin/nologin"),
            ("bin", 2, 2, "bin", "/bin", "/usr/sbin/nologin"),
            ("sys", 3, 3, "sys", "/dev", "/usr/sbin/nologin"),
            ("sync", 4, 65534, "sync", "/bin", "/bin/sync"),
            ("games", 5, 60, "games", "/usr/games", "/usr/sbin/nologin"),
            ("man", 6, 12, "man", "/var/cache/man", "/usr/sbin/nologin"),
            ("lp", 7, 7, "lp", "/var/spool/lpd", "/usr/sbin/nologin"),
            ("mail", 8, 8, "mail", "/var/mail", "/usr/sbin/nologin"),
            ("news", 9, 9, "news", "/var/spool/news", "/usr/sbin/nologin"),
            ("backup", 34, 34, "backup", "/var/backups", "/usr/sbin/nologin"),
            ("www-data", 33, 33, "www-data", "/var/www", "/usr/sbin/nologin"),
            ("nobody", 65534, 65534, "nobody", "/nonexistent", "/usr/sbin/nologin"),
            ("syslog", 104, 110, "", "/home/syslog", "/usr/sbin/nologin"),
            ("sshd", 106, 65534, "", "/run/sshd", "/usr/sbin/nologin"),
            ("postgres", 114, 120, "PostgreSQL administrator", "/var/lib/postgresql", "/bin/bash"),
            ("ubuntu", 1000, 1000, "Ubuntu", "/home/ubuntu", "/bin/bash"),
            ("deploy", 1001, 1001, "Application deployment", "/home/deploy", "/bin/bash"),
        ]
        taken = {int(r[2]) for r in existing.values()}
        for name, uid, gid, gecos, home, shell in accounts:
            if name in existing:
                if name in ("root", "ubuntu", "deploy", "www-data") and (int(existing[name][2]), int(existing[name][3])) != (uid, gid):
                    raise ValueError(f"Account conflict for {name}; database unchanged")
                continue
            if uid in taken:
                if uid >= 1000 or name in ("root", "www-data"):
                    raise ValueError(f"UID {uid} already assigned; database unchanged")
                uid = next(x for x in range(110, 999) if x not in taken)
            if name == "postgres":
                used_gids = {int(g[2]) for g in imported_groups.values()}
                gid = int(imported_groups[name][2]) if name in imported_groups else next(x for x in range(120, 999) if x not in used_gids)
            existing[name] = [name, "x", str(uid), str(gid), gecos, home, shell]
            taken.add(uid)
        pguid, pggid = map(int, existing["postgres"][2:4])
        add("/etc/passwd", "\n".join(":".join(r) for r in existing.values()) + "\n")
        groups = imported_groups
        cron_gid = int(groups["crontab"][2]) if "crontab" in groups else next(x for x in range(101, 999) if x not in {int(g[2]) for g in groups.values()})
        for name, gid, members in (("root", 0, ""), ("adm", 4, "ubuntu"), ("sudo", 27, "ubuntu"),
                                   ("shadow", 42, ""), ("www-data", 33, "deploy"), ("crontab", cron_gid, ""),
                                   ("ubuntu", 1000, ""), ("deploy", 1001, ""), ("postgres", pggid, "")):
            if name in groups:
                if int(groups[name][2]) != gid:
                    raise ValueError(f"Group conflict for {name}; database unchanged")
                members = ",".join(dict.fromkeys(filter(None, (groups[name][3] + "," + members).split(","))))
            elif any(int(g[2]) == gid for g in groups.values()):
                raise ValueError(f"GID {gid} conflict; database unchanged")
            groups[name] = [name, "x", str(gid), members]
        for r in existing.values():
            if not any(g[2] == r[3] for g in groups.values()):
                groups[r[0]] = [r[0], "x", r[3], ""]
        add("/etc/group", "\n".join(":".join(g) for g in groups.values()) + "\n")
        shadow = _read_base(db, "/etc/shadow").splitlines()
        known = {s.split(":")[0] for s in shadow}
        shadow.extend(f"{u}:!:19600:0:99999:7:::" for u in existing if u not in known)
        add("/etc/shadow", "\n".join(shadow) + "\n", mode=0o640, gid=42, group="shadow")
        gshadow = {r[0]:r for line in _read_base(db, "/etc/gshadow").splitlines() if len(r := line.split(":")) == 4}
        for group_name, group_record in groups.items():
            entry = gshadow.setdefault(group_name, [group_name, "!", "", ""])
            entry[3] = ",".join(dict.fromkeys(filter(None, (entry[3] + "," + group_record[3]).split(","))))
        add("/etc/gshadow", "\n".join(":".join(r) for r in gshadow.values()) + "\n", mode=0o640, gid=42, group="shadow")
        add("/etc/nsswitch.conf", "passwd: files systemd\ngroup: files systemd\nshadow: files\nhosts: files dns\n")
        add("/etc/shells", "/bin/sh\n/bin/bash\n/usr/bin/bash\n/bin/dash\n")
        add("/etc/sudoers", 'Defaults env_reset\nDefaults mail_badpass\nDefaults secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin"\nroot ALL=(ALL:ALL) ALL\n%sudo ALL=(ALL:ALL) ALL\n@includedir /etc/sudoers.d\n', mode=0o440)
        add("/etc/sudoers.d", kind="dir", mode=0o755)
        add("/etc/sudoers.d/90-cloud-init-users", "ubuntu ALL=(ALL) NOPASSWD:ALL\n", mode=0o440)

        release = 'PRETTY_NAME="Ubuntu 22.04.3 LTS"\nNAME="Ubuntu"\nVERSION_ID="22.04"\nVERSION="22.04.3 LTS (Jammy Jellyfish)"\nVERSION_CODENAME=jammy\nID=ubuntu\nID_LIKE=debian\nHOME_URL="https://www.ubuntu.com/"\nSUPPORT_URL="https://help.ubuntu.com/"\nBUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"\nPRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"\nUBUNTU_CODENAME=jammy\n'
        if pretty:
            release = imported_release
        add("/usr/lib/os-release", release)
        add("/etc/os-release", kind="link", mode=0o777, target="../usr/lib/os-release")
        add("/etc/lsb-release", f'DISTRIB_ID=Ubuntu\nDISTRIB_RELEASE=22.04\nDISTRIB_CODENAME=jammy\nDISTRIB_DESCRIPTION="{facts["distro"]}"\n')
        add("/etc/issue", facts["distro"] + " \\n \\l\n\n")
        add("/etc/hostname", FACTS["hostname"] + "\n")
        add("/etc/machine-id", hashlib.md5(FACTS["hostname"].encode()).hexdigest() + "\n", mode=0o444)
        add("/etc/hosts", "127.0.0.1 localhost\n127.0.1.1 srv-web-03\n10.0.12.31 srv-web-03 portal.example.test\n10.0.12.20 git-01 git.internal.example.test\n10.0.12.44 backup-01\n::1 localhost ip6-localhost ip6-loopback\n")
        add("/etc/resolv.conf", "nameserver 127.0.0.53\noptions edns0 trust-ad\nsearch internal.example.test\n")
        add("/run/systemd/resolve/stub-resolv.conf", "nameserver 127.0.0.53\noptions edns0 trust-ad\nsearch internal.example.test\n")
        add("/etc/netplan/50-cloud-init.yaml", "network:\n  version: 2\n  ethernets:\n    eth0:\n      dhcp4: false\n      addresses: [10.0.12.31/24]\n      routes:\n        - to: default\n          via: 10.0.12.1\n      nameservers:\n        addresses: [10.0.12.2]\n", mode=0o600)
        add("/sys/class/net/eth0/address", "02:42:0a:00:0c:1f\n", mode=0o444)
        add("/sys/class/net/eth0/operstate", "up\n", mode=0o444)
        add("/proc/net/route", "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\neth0\t00000000\t010C000A\t0003\t0\t0\t100\t00000000\t0\t0\t0\neth0\t000C000A\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n", mode=0o444)
        from .rootfs import _cpuinfo, _meminfo
        add("/proc/cpuinfo", _cpuinfo(), mode=0o444)
        add("/proc/meminfo", _meminfo(), mode=0o444)
        add("/proc/version", f"Linux version {facts['kernel']} (buildd@ubuntu) #1 SMP Ubuntu\n", mode=0o444)
        add("/proc/uptime", "184726.41 1468291.07\n", mode=0o444)
        add("/proc/loadavg", "0.08 0.03 0.01 1/128 1924\n", mode=0o444)
        add("/proc/mounts", "/dev/root / ext4 rw,relatime,errors=remount-ro 0 0\nproc /proc proc rw,nosuid,nodev,noexec,relatime 0 0\nsysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0\ntmpfs /run tmpfs rw,nosuid,nodev,size=401684k,mode=755 0 0\n", mode=0o444)
        add("/etc/fstab", "LABEL=cloudimg-rootfs / ext4 defaults 0 1\n")
        add("/etc/ssh/sshd_config", "Include /etc/ssh/sshd_config.d/*.conf\nPort 22\nPermitRootLogin prohibit-password\nPubkeyAuthentication yes\nAuthorizedKeysFile .ssh/authorized_keys\nPasswordAuthentication yes\nKbdInteractiveAuthentication no\nUsePAM yes\nX11Forwarding no\nPrintMotd no\nAcceptEnv LANG LC_*\nSubsystem sftp /usr/lib/openssh/sftp-server\n")
        add("/etc/ssh/sshd_config.d", kind="dir", mode=0o755)
        add("/etc/ssh/sshd_config.d/50-cloud-init.conf", "PasswordAuthentication yes\n")

        dbpass = secrets.token_urlsafe(21)
        secret_key = secrets.token_hex(32)
        for user, uid, gid in (("ubuntu", 1000, 1000), ("deploy", 1001, 1001), ("root", 0, 0)):
            home = "/root" if user == "root" else "/home/" + user
            own = dict(uid=uid, gid=gid, user=user, group=user)
            add(home, kind="dir", mode=0o700 if user == "root" else 0o750, **own)
            add(home + "/.ssh", kind="dir", mode=0o700, **own)
            key = Ed25519PrivateKey.generate()
            private = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH, serialization.NoEncryption())
            public = key.public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode() + f" {user}@srv-web-03\n"
            private_path, public_path = home + "/.ssh/id_ed25519", home + "/.ssh/id_ed25519.pub"
            if private_path not in analysis.manifest and public_path not in analysis.manifest:
                add(private_path, private, mode=0o600, **own)
                add(public_path, public, **own)
            else:
                for key_path in (private_path, public_path):
                    plan[key_path] = ("preserve", "Existing key material is retained; no mismatched key pair is generated")
            login_key = Ed25519PrivateKey.generate().public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode()
            add(home + "/.ssh/authorized_keys", login_key + " ops@workstation\n", mode=0o600, **own)
            add(home + "/.ssh/config", "Host backup-01\n    HostName 10.0.12.44\n    User backup\n    IdentityFile ~/.ssh/id_ed25519\n\nHost git-01\n    HostName git.internal.example.test\n    User git\n", mode=0o600, **own)
            remote_key = Ed25519PrivateKey.generate().public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode()
            add(home + "/.ssh/known_hosts", "backup-01,10.0.12.44 " + remote_key + "\n", mode=0o600, **own)
            add(home + "/.bashrc", _read_base(db, "/etc/skel/.bashrc") or "# ~/.bashrc\n[ -z \"$PS1\" ] && return\nHISTCONTROL=ignoreboth\nHISTSIZE=1000\nHISTFILESIZE=2000\nshopt -s histappend\nalias ll='ls -alF'\nalias la='ls -A'\n", **own)
            add(home + "/.profile", _read_base(db, "/etc/skel/.profile") or 'if [ -n "$BASH_VERSION" ] && [ -f "$HOME/.bashrc" ]; then\n    . "$HOME/.bashrc"\nfi\n', **own)
            history = ["id", "uname -a", "df -h", "systemctl status nginx --no-pager", "cd /opt/portal", "git log -3 --oneline", "cat config/settings.py", "tail -n 20 /var/log/nginx/error.log", "ls -lh /var/backups/portal", "ssh backup-01", "exit"]
            if user == "deploy":
                history[6:6] = [f"PGPASSWORD={dbpass} psql -h 127.0.0.1 -U portal_app -d portal -c 'select count(*) from invoices;'", "python3 -m compileall app"]
            add(home + "/.bash_history", "\n".join(history) + "\n", mode=0o600, mtime=recent, **own)
        add("/home/deploy/.pgpass", f"127.0.0.1:5432:portal:portal_app:{dbpass}\n", mode=0o600, uid=1001, gid=1001, user="deploy", group="deploy")
        add("/home/ubuntu/.sudo_as_admin_successful", b"", uid=1000, gid=1000, user="ubuntu", group="ubuntu")
        add("/home/ubuntu/operations.txt", "Portal deployment\nApplication: /opt/portal\nService: portal.service\nDatabase: local PostgreSQL 14, database portal\nNightly backup: /var/backups/portal/portal-latest.sql\nBackup host: backup-01\nRelease approval: change CHG-1842\n", uid=1000, gid=1000, user="ubuntu", group="ubuntu")

        add("/opt/portal", kind="dir", mode=0o755, uid=1001, gid=33, user="deploy", group="www-data")
        appown = dict(uid=1001, gid=33, user="deploy", group="www-data")
        add(APP_ENV, f"APP_NAME=operations-portal\nAPP_ENV=production\nAPP_DEBUG=false\nAPP_URL=http://portal.example.test\nDATABASE_HOST=127.0.0.1\nDATABASE_PORT=5432\nDATABASE_NAME=portal\nDATABASE_USER=portal_app\nDATABASE_PASSWORD={dbpass}\nSECRET_KEY={secret_key}\nLOG_LEVEL=INFO\nBACKUP_PATH=/var/backups/portal\n", mode=0o640, **appown)
        add("/opt/portal/config/settings.py", 'import os\nDATABASE = {"host": os.environ["DATABASE_HOST"], "port": 5432,\n            "name": "portal", "user": "portal_app",\n            "password": os.environ["DATABASE_PASSWORD"]}\nSECRET_KEY = os.environ["SECRET_KEY"]\n', **appown)
        add("/opt/portal/app/__init__.py", 'from flask import Flask\napp = Flask(__name__)\n@app.get("/health")\ndef health():\n    return {"status": "ok", "service": "portal"}\n', **appown)
        add("/opt/portal/requirements.txt", "# Runtime dependencies are installed by apt\nFlask==2.0.1\ngunicorn==20.1.0\npsycopg2==2.9.2\n", **appown)
        add("/opt/portal/.git/config", '[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n[remote "origin"]\n\turl = git@git.internal.example.test:operations/portal.git\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n[branch "main"]\n\tremote = origin\n\tmerge = refs/heads/main\n', **appown)
        add("/opt/portal/.git/HEAD", "ref: refs/heads/main\n", **appown)
        add("/opt/portal/README.md", "# Operations portal\n\nNginx forwards requests to Gunicorn on 127.0.0.1:8000.\nPostgreSQL 14 runs locally. Environment is read from .env by systemd.\nDeploy as deploy; restart portal.service after checking /health.\nNightly database exports are retained under /var/backups/portal.\n", **appown)
        add("/var/www/html/index.html", "<!doctype html><html><head><title>Operations Portal</title></head><body><h1>Operations Portal</h1><p>Sign in to view invoices and service requests.</p></body></html>\n")
        add("/etc/nginx/nginx.conf", "user www-data;\nworker_processes auto;\npid /run/nginx.pid;\ninclude /etc/nginx/modules-enabled/*.conf;\nevents { worker_connections 768; }\nhttp {\n    include /etc/nginx/mime.types;\n    access_log /var/log/nginx/access.log;\n    error_log /var/log/nginx/error.log;\n    include /etc/nginx/sites-enabled/*;\n}\n")
        add("/etc/nginx/modules-enabled", kind="dir", mode=0o755)
        add("/etc/nginx/mime.types", "types { text/html html htm; text/css css; application/javascript js; application/json json; }\n")
        add("/etc/nginx/sites-available/portal", "server {\n    listen 80 default_server;\n    server_name portal.example.test srv-web-03;\n    root /var/www/html;\n    location / {\n        proxy_pass http://127.0.0.1:8000;\n        proxy_set_header Host $host;\n        proxy_set_header X-Real-IP $remote_addr;\n    }\n    location ~ /\\. { deny all; }\n}\n")
        add("/etc/nginx/sites-enabled/portal", kind="link", mode=0o777, target="/etc/nginx/sites-available/portal")
        add("/etc/postgresql/14/main/postgresql.conf", "data_directory = '/var/lib/postgresql/14/main'\nhba_file = '/etc/postgresql/14/main/pg_hba.conf'\nlisten_addresses = '127.0.0.1'\nport = 5432\nmax_connections = 100\nshared_buffers = 128MB\n", uid=pguid, gid=pggid, user="postgres", group="postgres")
        add("/etc/postgresql/14/main/pg_hba.conf", "local all postgres peer\nlocal all all peer\nhost portal portal_app 127.0.0.1/32 scram-sha-256\nhost all all ::1/128 scram-sha-256\n", mode=0o640, uid=pguid, gid=pggid, user="postgres", group="postgres")
        add("/var/lib/postgresql/14/main", kind="dir", mode=0o700, uid=pguid, gid=pggid, user="postgres", group="postgres")
        add("/var/lib/postgresql/14/main/PG_VERSION", "14\n", mode=0o600, uid=pguid, gid=pggid, user="postgres", group="postgres")
        add("/var/backups/portal", kind="dir", mode=0o750, gid=33, group="www-data")
        sql = "-- PostgreSQL database dump\nSET client_encoding = 'UTF8';\nCREATE TABLE public.invoices (invoice_id integer PRIMARY KEY, customer_name text, amount numeric(10,2), status text);\nINSERT INTO public.invoices VALUES (1842, 'Northfield Office Supplies', 1284.50, 'paid');\nINSERT INTO public.invoices VALUES (1843, 'Harbor Facilities', 3620.00, 'pending');\n-- PostgreSQL database dump complete\n"
        add("/var/backups/portal/portal-latest.sql", sql, mode=0o640, gid=33, group="www-data", mtime=recent)
        add("/srv/finance/invoices.csv", "invoice_id,customer_name,amount,status\n1842,Northfield Office Supplies,1284.50,paid\n1843,Harbor Facilities,3620.00,pending\n", mode=0o640, gid=33, group="www-data", mtime=recent)
        add("/usr/local/sbin/portal-backup", "#!/bin/sh\nset -eu\ninstall -d -m 0750 -o root -g www-data /var/backups/portal\nsu -s /bin/sh postgres -c 'pg_dump portal' > /var/backups/portal/portal-latest.sql\nchgrp www-data /var/backups/portal/portal-latest.sql\nchmod 0640 /var/backups/portal/portal-latest.sql\n", mode=0o750)
        add("/etc/crontab", "SHELL=/bin/sh\nPATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n17 * * * * root cd / && run-parts --report /etc/cron.hourly\n25 6 * * * root test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )\n")
        add("/etc/cron.d/portal-backup", "SHELL=/bin/sh\nPATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n15 2 * * * root /usr/local/sbin/portal-backup >> /var/log/portal-backup.log 2>&1\n")
        add("/var/spool/cron/crontabs", kind="dir", mode=0o1730, gid=cron_gid, group="crontab")
        for user, uid in (("root", 0), ("ubuntu", 1000), ("deploy", 1001)):
            add("/var/spool/cron/crontabs/" + user, "# m h dom mon dow command\n", mode=0o600, uid=uid, gid=cron_gid, user=user, group="crontab")
        add("/etc/apt/sources.list", "deb http://archive.ubuntu.com/ubuntu jammy main restricted universe multiverse\ndeb http://archive.ubuntu.com/ubuntu jammy-updates main restricted universe multiverse\ndeb http://security.ubuntu.com/ubuntu jammy-security main restricted universe multiverse\n")
        add("/etc/apt/apt.conf.d/20auto-upgrades", 'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\n')
        add("/etc/apt/apt.conf.d/50unattended-upgrades", 'Unattended-Upgrade::Allowed-Origins { "${distro_id}:${distro_codename}-security"; };\nUnattended-Upgrade::Automatic-Reboot "false";\n')
        add("/etc/ufw/ufw.conf", "ENABLED=no\nLOGLEVEL=low\n")
        add("/sys/module/apparmor/parameters/enabled", "Y\n", mode=0o444)
        add("/etc/apparmor.d/usr.sbin.tcpdump", '#include <tunables/global>\n/usr/bin/tcpdump {\n  #include <abstractions/base>\n  capability net_raw,\n  capability net_admin,\n  network raw,\n  network packet,\n}\n')

        packages = [("base-files", "12ubuntu4.4", "Debian base system miscellaneous files"),
                    ("bash", "5.1-6ubuntu1", "GNU Bourne Again SHell"), ("coreutils", "8.32-4.1ubuntu1", "GNU core utilities"),
                    ("openssh-server", "1:8.9p1-3ubuntu0.10", "secure shell server"), ("openssh-client", "1:8.9p1-3ubuntu0.10", "secure shell client"),
                    ("sudo", "1.9.9-1ubuntu2.4", "Provide limited super user privileges"), ("nginx", "1.18.0-6ubuntu14.4", "small powerful scalable web server"),
                    ("postgresql-14", "14.8-0ubuntu0.22.04.1", "object relational SQL database version 14 server"),
                    ("python3", "3.10.6-1~22.04", "interactive high level object oriented language"),
                    ("gunicorn", "20.1.0-2ubuntu1", "Event based HTTP WSGI server"), ("python3-flask", "2.0.1-2ubuntu1.1", "micro web framework based on Werkzeug and Jinja2"),
                    ("python3-psycopg2", "2.9.2-1build2", "Python module for PostgreSQL"),
                    ("cron", "3.0pl1-137ubuntu3", "process scheduling daemon"), ("systemd", "249.11-0ubuntu3.9", "system and service manager"),
                    ("iproute2", "5.15.0-1ubuntu2", "networking and traffic control tools"), ("procps", "2:3.3.17-6ubuntu2", "/proc file system utilities"),
                    ("curl", "7.81.0-1ubuntu1.13", "command line tool for transferring data with URL syntax"),
                    ("wget", "1.21.2-2ubuntu1", "retrieves files from the web"), ("git", "1:2.34.1-1ubuntu1.10", "fast scalable distributed revision control system"),
                    ("apparmor", "3.0.4-2ubuntu2.2", "user space parser utility for AppArmor"), ("ufw", "0.36.1-4ubuntu0.1", "program for managing a netfilter firewall"),
                    ("unattended-upgrades", "2.8ubuntu1", "automatic installation of security upgrades"),
                    ("linux-image-" + facts["kernel"], "5.15.0-58.64" if not kernels else facts["kernel"], "Signed kernel image generic")]
        # Keep every imported package record and version, adding only missing scenario records
        # this is not a host package installation
        pkg_records = {}
        for block in _read_base(db, "/var/lib/dpkg/status").split("\n\n"):
            if block.startswith("Package: "):
                pkg_records[block.splitlines()[0][9:]] = block.strip()
        for name, version, desc in packages:
            pkg_records.setdefault(name, f"Package: {name}\nStatus: install ok installed\nPriority: optional\nSection: admin\nInstalled-Size: 1024\nArchitecture: amd64\nVersion: {version}\nDescription: {desc}")
        add("/var/lib/dpkg/status", "\n\n".join(pkg_records[k] for k in sorted(pkg_records)) + "\n\n")
        ssh_pkg = re.search(r"(?m)^Version: (?:1:)?([^\n]+)", pkg_records["openssh-server"])[1]
        upstream, _, revision = ssh_pkg.partition("-")
        facts["ssh_server_version"] = f"OpenSSH_{upstream} Ubuntu-{revision}"
        # Original binaries keep their contents
        # only missing scenario programs get metadata placeholders, nothing runs on the host
        for name in "bash dash cat ls stat find grep head tail wc cut sort uniq tr sed awk echo printf pwd mkdir rmdir rm cp mv ln chmod chown readlink realpath dirname basename id whoami groups getent uname hostname date free uptime ps ss ip dpkg dpkg-query systemctl journalctl crontab curl wget git python3 gunicorn ssh scp tar gzip env which lscpu nproc touch tee sleep true false".split():
            if not db.execute("SELECT 1 FROM nodes WHERE realm='' AND path=?", ("/usr/bin/" + name,)).fetchone():
                add("/usr/bin/" + name, None, mode=0o755, size=40960 + int(hashlib.sha256(name.encode()).hexdigest()[:4], 16))
        for name in ("sudo", "su", "passwd", "chsh", "chfn", "newgrp", "gpasswd", "mount", "umount"):
            if not db.execute("SELECT 1 FROM nodes WHERE realm='' AND path=?", ("/usr/bin/" + name,)).fetchone():
                add("/usr/bin/" + name, None, mode=0o4755, size=65536)
        for name in ("sshd", "nginx", "cron", "ufw", "nologin"):
            add("/usr/sbin/" + name, None, mode=0o755, size=131072)
        add("/usr/bin/sh", kind="link", mode=0o777, target="dash")
        add("/usr/sbin/init", kind="link", mode=0o777, target="/usr/lib/systemd/systemd")
        add("/usr/lib/systemd/systemd", None, mode=0o755, size=1843200)
        add("/usr/lib/postgresql/14/bin/postgres", None, mode=0o755, size=8808032)
        add("/boot/vmlinuz-" + facts["kernel"], None, mode=0o600, size=11534336)

        # Stable processes and socket inode references visible through /proc
        process_specs = [
            (1, 0, 0, 0, "systemd", "/sbin/init"),
            (512, 1, 0, 0, "cron", "/usr/sbin/cron -f -P"),
            (722, 1, 0, 0, "sshd", "/usr/sbin/sshd -D"),
            (810, 1, 0, 0, "nginx", "nginx: master process /usr/sbin/nginx -g daemon on; master_process on;"),
            (811, 810, 33, 33, "nginx", "nginx: worker process"),
            (812, 810, 33, 33, "nginx", "nginx: worker process"),
            (932, 1, pguid, pggid, "postgres", "/usr/lib/postgresql/14/bin/postgres -D /var/lib/postgresql/14/main -c config_file=/etc/postgresql/14/main/postgresql.conf"),
            (1104, 1, 33, 33, "gunicorn", "/usr/bin/python3 /usr/bin/gunicorn --workers 2 --bind 127.0.0.1:8000 app:app"),
            (1105, 1104, 33, 33, "gunicorn", "/usr/bin/python3 /usr/bin/gunicorn --workers 2 --bind 127.0.0.1:8000 app:app"),
            (1106, 1104, 33, 33, "gunicorn", "/usr/bin/python3 /usr/bin/gunicorn --workers 2 --bind 127.0.0.1:8000 app:app"),
        ]
        uid_name = {int(r[2]): r[0] for r in existing.values()}
        for pid, ppid, uid, gid, name, cmd in process_specs:
            add(f"/proc/{pid}", kind="dir", mode=0o555, uid=uid, gid=gid, user=uid_name[uid], group=uid_name[uid])
            add(f"/proc/{pid}/status", f"Name:\t{name}\nUmask:\t0022\nState:\tS (sleeping)\nTgid:\t{pid}\nPid:\t{pid}\nPPid:\t{ppid}\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\nGid:\t{gid}\t{gid}\t{gid}\t{gid}\nVmSize:\t{16384 + pid * 8} kB\nVmRSS:\t{4096 + pid} kB\nThreads:\t1\n", mode=0o444, mtime=now-184726)
            add(f"/proc/{pid}/cmdline", cmd.replace(" ", "\0") + "\0", mode=0o444)
            add(f"/proc/{pid}/fd", kind="dir", mode=0o500, uid=uid, gid=gid, user=uid_name[uid], group=uid_name[uid])
        add("/proc/1104/environ", f"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin\0DATABASE_HOST=127.0.0.1\0DATABASE_NAME=portal\0DATABASE_USER=portal_app\0DATABASE_PASSWORD={dbpass}\0", mode=0o400, uid=33, gid=33, user="www-data", group="www-data")
        tcp = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
        for i, (pid, address, port, uid) in enumerate(((722, "00000000", 22, 0), (810, "00000000", 80, 0), (932, "0100007F", 5432, pguid), (1104, "0100007F", 8000, 33))):
            inode = 27000 + i
            tcp += f"{i:4d}: {address}:{port:04X} 00000000:0000 0A 00000000:00000000 00:00000000 00000000 {uid:5d} 0 {inode} 1 0000000000000000 100 0 0 10 0\n"
            add(f"/proc/{pid}/fd/3", kind="link", mode=0o700, uid=uid, user=uid_name[uid], target=f"socket:[{inode}]")
        add("/proc/net/tcp", tcp, mode=0o444)
        add("/proc/net/tcp6", tcp.splitlines()[0] + "\n", mode=0o444)
        for service, pid, desc, command in (("ssh", 722, "OpenBSD Secure Shell server", "/usr/sbin/sshd -D"),
                    ("nginx", 810, "A high performance web server and a reverse proxy server", "/usr/sbin/nginx -g 'daemon on; master_process on;'"),
                    ("cron", 512, "Regular background program processing daemon", "/usr/sbin/cron -f -P"),
                    ("postgresql@14-main", 932, "PostgreSQL Cluster 14-main", "/usr/lib/postgresql/14/bin/postgres -D /var/lib/postgresql/14/main"),
                    ("portal", 1104, "Operations portal application", "/usr/bin/gunicorn --workers 2 --bind 127.0.0.1:8000 app:app")):
            unit = f"[Unit]\nDescription={desc}\nAfter=network.target\n\n[Service]\nType=simple\nExecStart={command}\nRestart=on-failure\n"
            if service == "portal":
                unit += "User=www-data\nGroup=www-data\nWorkingDirectory=/opt/portal\nEnvironmentFile=/opt/portal/.env\n"
            elif service.startswith("postgresql"):
                unit += "User=postgres\nGroup=postgres\n"
            unit += "\n[Install]\nWantedBy=multi-user.target\n"
            add(f"/etc/systemd/system/{service}.service", unit)
            add(f"/etc/systemd/system/multi-user.target.wants/{service}.service", kind="link", mode=0o777, target=f"/etc/systemd/system/{service}.service")
            add(f"/run/{service}.pid", str(pid) + "\n")
        add("/var/log/auth.log", "".join(f"{sysday} {t} srv-web-03 {s}\n" for t,s in [
            ("08:42:01", "sshd[1680]: Accepted publickey for ubuntu from 192.0.2.24 port 52184 ssh2: ED25519"),
            ("08:42:01", "sshd[1680]: pam_unix(sshd:session): session opened for user ubuntu(uid=1000) by (uid=0)"),
            ("08:44:12", "sudo: ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/systemctl status portal"),
            ("09:02:33", "sshd[1762]: Failed password for invalid user admin from 198.51.100.73 port 46922 ssh2"),
            ("09:17:08", "sshd[1838]: Accepted publickey for deploy from 192.0.2.24 port 52901 ssh2: ED25519")]), mode=0o640, gid=4, group="adm", mtime=recent)
        add("/var/log/syslog", f"{sysday} 02:15:01 srv-web-03 CRON[1552]: (root) CMD (/usr/local/sbin/portal-backup >> /var/log/portal-backup.log 2>&1)\n{sysday} 08:41:02 srv-web-03 systemd[1]: Started Operations portal application.\n", mode=0o640, gid=4, group="adm", mtime=recent)
        add("/var/log/nginx/access.log", "".join(f'192.0.2.24 - - [{webday}:09:{minute:02d}:12 +0000] "GET {route} HTTP/1.1" {code} {size} "-" "Mozilla/5.0"\n' for minute,route,code,size in ((10,"/health",200,35),(11,"/",200,2138),(12,"/login",200,1893),(15,"/favicon.ico",404,153))), mode=0o640, uid=33, gid=4, user="www-data", group="adm", mtime=recent)
        add("/var/log/nginx/error.log", f"{day.replace('-', '/')} 08:41:01 [notice] 810#810: using the epoll event method\n", mode=0o640, uid=33, gid=4, user="www-data", group="adm", mtime=recent)
        add("/var/log/portal-backup.log", f"{day} 02:15:02 completed portal export\n", mode=0o640, gid=4, group="adm", mtime=recent)
        add("/var/log/apt/history.log", f"Start-Date: {day}  06:25:01\nCommandline: /usr/bin/unattended-upgrade\nEnd-Date: {day}  06:25:04\n", mtime=recent)

        db.execute("BEGIN IMMEDIATE")
        try:
            save_analysis(db, analysis)
            directory_before = {r[1]:r for r in db.execute(f"SELECT {NODE_FIELDS} FROM nodes WHERE realm='' AND kind='dir'")}
            db.executemany("INSERT OR REPLACE INTO nodes (realm,path,parent,name,kind,mode,uid,gid,uname,gname,size,mtime,target,nlink,content,deleted) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", nodes.values())
            from .rootfs import update_directory_links
            update_directory_links(db)
            for p, before in directory_before.items():
                after = db.execute(f"SELECT {NODE_FIELDS} FROM nodes WHERE realm='' AND path=?", (p,)).fetchone()
                if node_fingerprint(before) != node_fingerprint(after) and p not in before_rows:
                    before_rows[p] = before
                    plan[p] = ("directory_links", "Update directory link count after adding child directories")
            db.execute("CREATE TABLE IF NOT EXISTS profile_patch_plan (path TEXT PRIMARY KEY, action TEXT, reason TEXT)")
            db.executemany("INSERT OR REPLACE INTO profile_patch_plan VALUES (?,?,?)", [(p,*v) for p,v in plan.items()])
            db.execute("CREATE TABLE IF NOT EXISTS profile_changes (path TEXT PRIMARY KEY,action TEXT,reason TEXT,before_node TEXT,before_content BLOB,after_node_sha256 TEXT)")
            added = modified = 0
            for p, before in before_rows.items():
                after = db.execute(f"SELECT {NODE_FIELDS} FROM nodes WHERE realm='' AND path=?", (p,)).fetchone()
                after_hash = node_fingerprint(after)
                if before and node_fingerprint(before) == after_hash:
                    continue
                before_meta, before_content = None, None
                if before:
                    before_meta = list(before)
                    before_content, before_meta[14] = before_meta[14], None
                    before_meta = json.dumps(before_meta)
                    modified += 1
                else:
                    added += 1
                db.execute("INSERT OR REPLACE INTO profile_changes VALUES (?,?,?,?,?,?)",
                           (p,*plan[p],before_meta,before_content,after_hash))
            missing_sources = db.execute("SELECT count(*) FROM ubuntu_source_manifest s LEFT JOIN nodes n ON n.realm='' AND n.path=s.path WHERE n.path IS NULL OR n.deleted<>0").fetchone()[0]
            if missing_sources:
                raise ValueError("Profile would delete imported paths; transaction rolled back")
            patch_summary = {"added_paths": added, "modified_imported_paths": modified,
                             "unchanged_imported_paths": original_count-modified, "deleted_imported_paths": 0,
                             "analysis_version": ANALYSIS_VERSION}
            db.execute("CREATE TABLE IF NOT EXISTS profile_evidence (category TEXT PRIMARY KEY, paths TEXT, techniques TEXT, sources TEXT)")
            db.executemany("INSERT OR REPLACE INTO profile_evidence VALUES (?,?,?,?)", [(c,json.dumps(p),json.dumps(t),json.dumps(s)) for c,p,t,s in EVIDENCE])
            meta = {**facts, "attacker_profile": PROFILE_VERSION, "profile_created_at": datetime.now(timezone.utc).isoformat(),
                    "profile_kind": "focused-synthetic-scenario" if not original_count else "enriched-import",
                    "profile_analysis_version": ANALYSIS_VERSION,
                    "profile_patch_summary": json.dumps(patch_summary),
                    "profile_source_manifest_sha256": analysis.report["source_manifest_sha256"],
                    "kernel_source": "imported boot filename" if kernels else "simulated runtime; archive has no boot kernel",
                    "profile_notes": "Synthetic lab data only. Package versions are a historical scenario, not a patch or CVE assessment."}
            db.executemany("INSERT OR REPLACE INTO meta VALUES (?,?)", meta.items())
            db.execute("COMMIT")
        except Exception:
            db.execute("ROLLBACK")
            raise
        db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        db.execute("PRAGMA journal_mode=DELETE")
        return {"action": "installed", "profile": PROFILE_VERSION, "written_nodes": len(nodes),
                "base_nodes": db.execute("SELECT count(*) FROM nodes WHERE realm='' AND deleted=0").fetchone()[0],
                "kind": meta["profile_kind"], "patches": patch_summary,
                "analysis": analysis.report["inventory"]}


# Install or reuse the analysed base image, then apply the additive expansion
def install_profile(db_path, *, create=False, analysis=None):
    result = _install_base_profile(db_path, create=create, analysis=analysis)
    from .privilege_profile import install_expansion
    result['expansion'] = install_expansion(db_path)
    if result['action'] == 'reused' and result['expansion']['action'] in ('installed', 'upgraded'):
        result['action'] = 'expanded'
    return result
