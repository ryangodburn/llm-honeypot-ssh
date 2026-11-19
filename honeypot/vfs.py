# Virtual Filesystem
# SQLite with two layers and copy-on-write
# the base layer is the imported Ubuntu image, read-only and shared by every connection
# attacker writes land in an overlay keyed by realm, with tombstone rows for deletions
# lookups check the overlay first and fall through to the base
# the default realm is the attacker's IP address, so files survive a reconnect
# reset_realm() puts a realm back to the pristine image in one statement
# queries are indexed point lookups that run inline on the event loop, and VFS.stats counts them

# Imports
from __future__ import annotations

import posixpath
import sqlite3
import stat as statmod
import time
from dataclasses import dataclass
from typing import Iterable, Iterator, Optional

# Realm name of the shared read-only image
BASE = ""
# Linux's ELOOP threshold
MAX_SYMLINKS = 40

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;

CREATE TABLE IF NOT EXISTS nodes (
    realm   TEXT    NOT NULL,
    path    TEXT    NOT NULL,
    parent  TEXT    NOT NULL,
    name    TEXT    NOT NULL,
    kind    TEXT    NOT NULL,
    mode    INTEGER NOT NULL,
    uid     INTEGER NOT NULL DEFAULT 0,
    gid     INTEGER NOT NULL DEFAULT 0,
    uname   TEXT,
    gname   TEXT,
    size    INTEGER NOT NULL DEFAULT 0,
    mtime   REAL    NOT NULL,
    target  TEXT,
    nlink   INTEGER NOT NULL DEFAULT 1,
    content BLOB,
    deleted INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (realm, path)
) WITHOUT ROWID;

CREATE INDEX IF NOT EXISTS idx_children ON nodes(realm, parent);

CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
"""


# Carries the exact message a real utility would print
class FSError(Exception):
    def __init__(self, message: str, errno_name: str = "ENOENT") -> None:
        super().__init__(message)
        self.message = message
        self.errno_name = errno_name


@dataclass
class Node:
    path: str
    name: str
    # Node type - dir, file, link, chr, blk, fifo or sock
    kind: str
    mode: int
    uid: int
    gid: int
    uname: str
    gname: str
    size: int
    mtime: float
    target: Optional[str]
    nlink: int
    realm: str
    has_content: bool

    @property
    def is_dir(self) -> bool:
        return self.kind == "dir"

    @property
    def is_link(self) -> bool:
        return self.kind == "link"

    @property
    def is_file(self) -> bool:
        return self.kind == "file"

    @property
    def st_mode(self) -> int:
        bits = {"dir": statmod.S_IFDIR, "file": statmod.S_IFREG,
                "link": statmod.S_IFLNK, "chr": statmod.S_IFCHR,
                "blk": statmod.S_IFBLK, "fifo": statmod.S_IFIFO,
                "sock": statmod.S_IFSOCK}[self.kind]
        return bits | (self.mode & 0o7777)


@dataclass
class Stats:
    queries: int = 0
    seconds: float = 0.0

    def add(self, dt: float, n: int = 1) -> None:
        self.queries += n
        self.seconds += dt


_COLS = ("path,name,kind,mode,uid,gid,uname,gname,size,mtime,target,nlink,"
         "realm,content IS NOT NULL AS has_content")


def _row_to_node(row: sqlite3.Row) -> Node:
    return Node(
        path=row["path"], name=row["name"], kind=row["kind"], mode=row["mode"],
        uid=row["uid"], gid=row["gid"], uname=row["uname"] or "root",
        gname=row["gname"] or "root", size=row["size"], mtime=row["mtime"],
        target=row["target"], nlink=row["nlink"], realm=row["realm"],
        has_content=bool(row["has_content"]),
    )


# GNU ls sort key, ignoring a leading dot and punctuation
# so .bashrc sorts next to bashrc rather than ahead of everything
def _sortkey(name: str) -> str:
    return "".join(c for c in name.lower() if c.isalnum()) or name.lower()


# Resolve a user-supplied path to an absolute, normalised one without following symlinks
def normpath(cwd: str, path: str, home: str = "/root") -> str:
    if not path:
        return cwd
    if path == "~":
        path = home
    elif path.startswith("~/"):
        path = home + path[1:]
    if not path.startswith("/"):
        path = posixpath.join(cwd, path)
    out = posixpath.normpath(path)
    return out if out.startswith("/") else "/" + out


class VFS:
    def __init__(self, db_path: str, realm: str = BASE,
                 *, read_only: bool = False) -> None:
        uri = f"file:{db_path}" + ("?mode=ro" if read_only else "")
        self.db = sqlite3.connect(uri, uri=True, isolation_level=None,
                                  check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        if not read_only:
            self.db.executescript(SCHEMA)
        self.realm = realm
        self.stats = Stats()
        self._uid_names: Optional[dict[int, str]] = None
        self._gid_names: Optional[dict[int, str]] = None

    def close(self) -> None:
        self.db.close()

    # A view of the same database scoped to another overlay realm
    def for_realm(self, realm: str) -> "VFS":
        clone = object.__new__(VFS)
        clone.db = self.db
        clone.realm = realm
        clone.stats = Stats()
        clone._uid_names = self._uid_names
        clone._gid_names = self._gid_names
        return clone

    # Query Helpers

    def _q(self, sql: str, args: Iterable = ()) -> list[sqlite3.Row]:
        t0 = time.perf_counter()
        rows = self.db.execute(sql, tuple(args)).fetchall()
        self.stats.add(time.perf_counter() - t0)
        return rows

    def _x(self, sql: str, args: Iterable = ()) -> None:
        t0 = time.perf_counter()
        self.db.execute(sql, tuple(args))
        self.stats.add(time.perf_counter() - t0)

    # Reads

    def _lookup_base(self, path: str) -> Optional[Node]:
        rows = self._q(
            f"SELECT {_COLS} FROM nodes WHERE realm=? AND path=?", (BASE, path))
        return _row_to_node(rows[0]) if rows else None

    def get(self, path: str) -> Optional[Node]:
        if self.realm != BASE:
            rows = self._q(
                f"SELECT {_COLS}, deleted FROM nodes WHERE realm=? AND path=?",
                (self.realm, path))
            if rows:
                return None if rows[0]["deleted"] else _row_to_node(rows[0])
        return self._lookup_base(path)

    def exists(self, path: str) -> bool:
        return self.get(path) is not None

    # Walk a path, following symlinks on every component
    # returns None when any component is missing
    # raises FSError on ELOOP and on a file used as a directory, since attackers read those messages
    def resolve(self, path: str, *, follow: bool = True) -> Optional[Node]:
        parts = [p for p in path.split("/") if p]
        cur = "/"
        node = self.get("/")
        hops = 0
        for i, part in enumerate(parts):
            if node is None:
                return None
            if node.is_link:
                node, cur, hops = self._deref(node, cur, hops)
                if node is None:
                    return None
            if not node.is_dir:
                raise FSError("Not a directory", "ENOTDIR")
            cur = posixpath.join(cur, part)
            node = self.get(cur)
        if node is not None and node.is_link and follow:
            node, cur, hops = self._deref(node, cur, hops)
        return node

    def _deref(self, node: Node, cur: str, hops: int):
        while node is not None and node.is_link:
            hops += 1
            if hops > MAX_SYMLINKS:
                raise FSError("Too many levels of symbolic links", "ELOOP")
            target = node.target or ""
            cur = target if target.startswith("/") else posixpath.normpath(
                posixpath.join(posixpath.dirname(node.path), target))
            node = self.get(cur)
        return node, cur, hops

    # Children of a directory - overlay rows plus base rows that are not shadowed
    def listdir(self, path: str) -> list[Node]:
        node = self.resolve(path)
        if node is None:
            raise FSError("No such file or directory", "ENOENT")
        if not node.is_dir:
            raise FSError("Not a directory", "ENOTDIR")
        real = node.path

        if self.realm == BASE:
            rows = self._q(
                f"SELECT {_COLS} FROM nodes "
                f"WHERE realm=? AND parent=? AND deleted=0", (BASE, real))
        else:
            rows = self._q(
                f"SELECT {_COLS} FROM nodes "
                f"WHERE realm=? AND parent=? AND deleted=0 "
                f"UNION ALL "
                f"SELECT {_COLS} FROM nodes b "
                f"WHERE b.realm=? AND b.parent=? AND NOT EXISTS ("
                f"  SELECT 1 FROM nodes o WHERE o.realm=? AND o.path=b.path)",
                (self.realm, real, BASE, real, self.realm))
        return sorted((_row_to_node(r) for r in rows if r["path"] != real),
                      key=lambda n: _sortkey(n.name))

    # File contents, or None when the node exists but its bytes were not stored
    def read(self, path: str, limit: int = 1 << 20) -> Optional[bytes]:
        node = self.resolve(path)
        if node is None:
            raise FSError("No such file or directory", "ENOENT")
        if node.is_dir:
            raise FSError("Is a directory", "EISDIR")
        for realm in ((self.realm, BASE) if self.realm != BASE else (BASE,)):
            rows = self._q("SELECT content FROM nodes WHERE realm=? AND path=?",
                           (realm, node.path))
            if rows and rows[0]["content"] is not None:
                return bytes(rows[0]["content"])[:limit]
        return None

    # Pre-order traversal for find, du and rm -r
    def walk(self, top: str, *, max_nodes: int = 200_000) -> Iterator[Node]:
        start = self.resolve(top)
        if start is None:
            raise FSError("No such file or directory", "ENOENT")
        stack = [start]
        seen = 0
        while stack:
            node = stack.pop()
            yield node
            seen += 1
            if seen >= max_nodes:
                return
            if node.is_dir:
                try:
                    stack.extend(reversed(self.listdir(node.path)))
                except FSError:
                    pass

    # Writes

    def _parent_dir(self, path: str) -> Node:
        parent = posixpath.dirname(path) or "/"
        node = self.resolve(parent)
        if node is None:
            raise FSError("No such file or directory", "ENOENT")
        if not node.is_dir:
            raise FSError("Not a directory", "ENOTDIR")
        return node

    def _put(self, path: str, *, kind: str, mode: int, uid: int, gid: int,
             uname: str, gname: str, size: int = 0, target: Optional[str] = None,
             content: Optional[bytes] = None, mtime: Optional[float] = None,
             nlink: int = 1) -> None:
        if self.realm == BASE:
            raise FSError("Read-only file system", "EROFS")
        self._x(
            "INSERT INTO nodes (realm,path,parent,name,kind,mode,uid,gid,"
            "uname,gname,size,mtime,target,nlink,content,deleted) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,0) "
            "ON CONFLICT(realm,path) DO UPDATE SET "
            "kind=excluded.kind, mode=excluded.mode, uid=excluded.uid, "
            "gid=excluded.gid, uname=excluded.uname, gname=excluded.gname, "
            "size=excluded.size, mtime=excluded.mtime, target=excluded.target, "
            "nlink=excluded.nlink, content=excluded.content, deleted=0",
            (self.realm, path, posixpath.dirname(path) or "/",
             posixpath.basename(path) or "/", kind, mode, uid, gid, uname,
             gname, size, mtime if mtime is not None else time.time(),
             target, nlink, content))

    def mkdir(self, path: str, *, uid: int, gid: int, uname: str, gname: str,
              mode: int = 0o755) -> None:
        if self.exists(path):
            raise FSError("File exists", "EEXIST")
        self._parent_dir(path)
        self._put(path, kind="dir", mode=mode, uid=uid, gid=gid, uname=uname,
                  gname=gname, size=4096, nlink=2)
        self._touch_parent(path)

    def write_file(self, path: str, data: bytes, *, uid: int, gid: int,
                   uname: str, gname: str, mode: int = 0o644,
                   append: bool = False, store_content: bool = True) -> None:
        existing = self.get(path)
        if existing is not None and existing.is_dir:
            raise FSError("Is a directory", "EISDIR")
        self._parent_dir(path)
        if append and existing is not None:
            prev = self.read(path) or b""
            data = prev + data
            mode = existing.mode
        self._put(path, kind="file", mode=mode, uid=uid, gid=gid, uname=uname,
                  gname=gname, size=len(data),
                  content=data if store_content else None)
        if existing is None:
            self._touch_parent(path)

    def symlink(self, path: str, target: str, *, uid: int, gid: int,
                uname: str, gname: str) -> None:
        if self.exists(path):
            raise FSError("File exists", "EEXIST")
        self._parent_dir(path)
        self._put(path, kind="link", mode=0o777, uid=uid, gid=gid, uname=uname,
                  gname=gname, size=len(target), target=target)
        self._touch_parent(path)

    def remove(self, path: str, *, recursive: bool = False) -> None:
        node = self.resolve(path, follow=False)
        if node is None:
            raise FSError("No such file or directory", "ENOENT")
        if node.is_dir and not recursive:
            raise FSError("Is a directory", "EISDIR")
        victims = [node]
        if node.is_dir and recursive:
            victims = list(self.walk(node.path))
        for v in victims:
            if v.realm == self.realm:
                self._x("DELETE FROM nodes WHERE realm=? AND path=?",
                        (self.realm, v.path))
            if self._lookup_base(v.path) is not None:
                self._put_tombstone(v.path)
        self._touch_parent(path)

    def rmdir(self, path: str) -> None:
        node = self.resolve(path)
        if node is None:
            raise FSError("No such file or directory", "ENOENT")
        if not node.is_dir:
            raise FSError("Not a directory", "ENOTDIR")
        if self.listdir(path):
            raise FSError("Directory not empty", "ENOTEMPTY")
        self.remove(path, recursive=True)

    def _put_tombstone(self, path: str) -> None:
        self._x(
            "INSERT INTO nodes (realm,path,parent,name,kind,mode,mtime,deleted)"
            " VALUES (?,?,?,?,'file',0,?,1) "
            "ON CONFLICT(realm,path) DO UPDATE SET deleted=1, content=NULL",
            (self.realm, path, posixpath.dirname(path) or "/",
             posixpath.basename(path), time.time()))

    def copy(self, src: str, dst: str, *, uid: int, gid: int, uname: str,
             gname: str, recursive: bool = False) -> None:
        s = self.resolve(src)
        if s is None:
            raise FSError("No such file or directory", "ENOENT")
        d = self.get(dst)
        if d is not None and d.is_dir:
            dst = posixpath.join(dst, s.name)
        if s.is_dir:
            if not recursive:
                raise FSError("-r not specified; omitting directory", "EISDIR")
            base = s.path
            for n in self.walk(base):
                rel = n.path[len(base):].lstrip("/")
                target = posixpath.join(dst, rel) if rel else dst
                if n.is_dir:
                    if not self.exists(target):
                        self._put(target, kind="dir", mode=n.mode, uid=uid,
                                  gid=gid, uname=uname, gname=gname, size=4096,
                                  nlink=2)
                else:
                    self._put(target, kind=n.kind, mode=n.mode, uid=uid,
                              gid=gid, uname=uname, gname=gname, size=n.size,
                              target=n.target, content=self._raw_content(n.path))
        else:
            self._put(dst, kind=s.kind, mode=s.mode, uid=uid, gid=gid,
                      uname=uname, gname=gname, size=s.size, target=s.target,
                      content=self._raw_content(s.path))
        self._touch_parent(dst)

    def move(self, src: str, dst: str, *, uid: int, gid: int, uname: str,
             gname: str) -> None:
        s = self.resolve(src, follow=False)
        if s is None:
            raise FSError("No such file or directory", "ENOENT")
        d = self.get(dst)
        if d is not None and d.is_dir:
            dst = posixpath.join(dst, s.name)
        if s.is_link:
            # A rename(2) moves the link itself, never what it points to
            self._parent_dir(dst)
            self._put(dst, kind="link", mode=0o777, uid=s.uid, gid=s.gid, uname=s.uname,
                      gname=s.gname, size=len(s.target or ""), target=s.target, mtime=s.mtime)
            self._touch_parent(dst)
        else:
            self.copy(s.path, dst, uid=uid, gid=gid, uname=uname, gname=gname,
                      recursive=s.is_dir)
        self.remove(s.path, recursive=s.is_dir)

    def _raw_content(self, path: str) -> Optional[bytes]:
        for realm in ((self.realm, BASE) if self.realm != BASE else (BASE,)):
            rows = self._q("SELECT content FROM nodes WHERE realm=? AND path=?",
                           (realm, path))
            if rows and rows[0]["content"] is not None:
                return bytes(rows[0]["content"])
        return None

    def chmod(self, path: str, mode: int) -> None:
        node = self.resolve(path)
        if node is None:
            raise FSError("No such file or directory", "ENOENT")
        self._copy_up(node)
        self._x("UPDATE nodes SET mode=? WHERE realm=? AND path=?",
                (mode, self.realm, node.path))

    def chown(self, path: str, uid: Optional[int], gid: Optional[int],
              uname: Optional[str], gname: Optional[str]) -> None:
        node = self.resolve(path)
        if node is None:
            raise FSError("No such file or directory", "ENOENT")
        self._copy_up(node)
        self._x("UPDATE nodes SET uid=COALESCE(?,uid), gid=COALESCE(?,gid), "
                "uname=COALESCE(?,uname), gname=COALESCE(?,gname) "
                "WHERE realm=? AND path=?",
                (uid, gid, uname, gname, self.realm, node.path))

    def utime(self, path: str, when: Optional[float] = None) -> None:
        node = self.resolve(path)
        if node is None:
            raise FSError("No such file or directory", "ENOENT")
        self._copy_up(node)
        self._x("UPDATE nodes SET mtime=? WHERE realm=? AND path=?",
                (when if when is not None else time.time(), self.realm,
                 node.path))

    # Copy a base node into the overlay before changing it
    def _copy_up(self, node: Node) -> None:
        if node.realm == self.realm:
            return
        self._put(node.path, kind=node.kind, mode=node.mode, uid=node.uid,
                  gid=node.gid, uname=node.uname, gname=node.gname,
                  size=node.size, target=node.target, mtime=node.mtime,
                  nlink=node.nlink, content=self._raw_content(node.path))

    def _touch_parent(self, path: str) -> None:
        parent = posixpath.dirname(path) or "/"
        node = self.get(parent)
        if node is None:
            return
        self._copy_up(node)
        subdirs = sum(1 for c in self.listdir(parent) if c.is_dir)
        self._x("UPDATE nodes SET mtime=?, nlink=? WHERE realm=? AND path=?",
                (time.time(), subdirs + 2, self.realm, parent))

    # Realm Management

    def reset_realm(self, realm: Optional[str] = None) -> int:
        target = self.realm if realm is None else realm
        if target == BASE:
            raise FSError("refusing to reset the base image", "EPERM")
        self.db.execute("SAVEPOINT reset_realm")
        try:
            cur = self.db.execute("DELETE FROM nodes WHERE realm=?", (target,))
            count = cur.rowcount
            if self.db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='process_lifecycle'").fetchone():
                self.db.execute("DELETE FROM process_lifecycle WHERE realm=?", (target,))
            self.db.execute("RELEASE reset_realm")
            return count
        except BaseException:
            self.db.execute("ROLLBACK TO reset_realm")
            self.db.execute("RELEASE reset_realm")
            raise

    def realms(self) -> list[tuple[str, int]]:
        rows = self._q("SELECT realm, COUNT(*) n FROM nodes WHERE realm<>? "
                       "GROUP BY realm ORDER BY n DESC", (BASE,))
        return [(r["realm"], r["n"]) for r in rows]

    # Identity

    # Parse /etc/passwd from the image so ids stay consistent
    def passwd_users(self) -> dict[str, tuple[int, int, str, str]]:
        out: dict[str, tuple[int, int, str, str]] = {}
        try:
            raw = self.read("/etc/passwd") or b""
        except FSError:
            return out
        for line in raw.decode("utf-8", "replace").splitlines():
            f = line.split(":")
            if len(f) >= 7:
                try:
                    out[f[0]] = (int(f[2]), int(f[3]), f[5], f[6])
                except ValueError:
                    continue
        return out

    def group_names(self) -> dict[int, str]:
        if self._gid_names is not None:
            return self._gid_names
        names: dict[int, str] = {}
        try:
            raw = self.read("/etc/group") or b""
        except FSError:
            raw = b""
        for line in raw.decode("utf-8", "replace").splitlines():
            f = line.split(":")
            if len(f) >= 3:
                try:
                    names[int(f[2])] = f[0]
                except ValueError:
                    continue
        self._gid_names = names
        return names

    def meta(self, key: str, default: str = "") -> str:
        rows = self._q("SELECT value FROM meta WHERE key=?", (key,))
        return rows[0]["value"] if rows else default

    def set_meta(self, key: str, value: str) -> None:
        self._x("INSERT INTO meta(key,value) VALUES(?,?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, value))

    def count(self, realm: Optional[str] = None) -> int:
        r = self.realm if realm is None else realm
        return self._q("SELECT COUNT(*) n FROM nodes WHERE realm=?", (r,))[0]["n"]
