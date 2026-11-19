# Root Filesystem Import
# imports the Ubuntu cloud-image root filesystem into the SQLite store
# every node keeps its mode, owner, size, mtime and link target, and every file its bytes
# the tarball ships /proc empty, ubuntu_profile.py fills it using _cpuinfo() and _meminfo()

# Imports
from __future__ import annotations

import posixpath
import sqlite3
import tarfile
import time

from .vfs import BASE, SCHEMA


def _kind_from_tar(m: tarfile.TarInfo) -> str:
    if m.isdir():
        return "dir"
    if m.issym():
        return "link"
    if m.ischr():
        return "chr"
    if m.isblk():
        return "blk"
    if m.isfifo():
        return "fifo"
    return "file"


# Set each directory's nlink to 2 plus its subdirectories, in one pass
# a correlated UPDATE would scan the database once per directory on the first run
def update_directory_links(db, realm=BASE):
    counts = dict(db.execute("SELECT parent,count(*) FROM nodes WHERE realm=? AND kind='dir' AND deleted=0 AND path<>parent GROUP BY parent", (realm,)))
    directories = [r[0] for r in db.execute("SELECT path FROM nodes WHERE realm=? AND kind='dir' AND deleted=0", (realm,))]
    own = not db.in_transaction
    if own:
        db.execute("BEGIN")
    try:
        db.executemany("UPDATE nodes SET nlink=? WHERE realm=? AND path=?",
                       [(2 + counts.get(p, 0), realm, p) for p in directories])
        if own:
            db.execute("COMMIT")
    except Exception:
        if own:
            db.execute("ROLLBACK")
        raise


class Importer:
    def __init__(self, db_path: str) -> None:
        self.db = sqlite3.connect(db_path, isolation_level=None)
        self.db.executescript(SCHEMA)
        self.db.execute("DELETE FROM nodes WHERE realm=?", (BASE,))
        self.n = 0
        self._batch: list[tuple] = []
        self._batch_bytes = 0

    def add(self, path: str, kind: str, mode: int, uid: int, gid: int,
            uname: str, gname: str, size: int, mtime: float,
            target: str | None = None, content: bytes | None = None) -> None:
        path = "/" + path.strip("/") if path.strip("/") else "/"
        self._batch.append((
            BASE, path, posixpath.dirname(path) or "/",
            posixpath.basename(path) or "/", kind, mode, uid, gid, uname,
            gname, size, mtime, target, 2 if kind == "dir" else 1, content,
        ))
        self.n += 1
        self._batch_bytes += len(content or b"")
        if len(self._batch) >= 5000 or self._batch_bytes >= 8 * 1024 * 1024:
            self.flush()

    def flush(self) -> None:
        if not self._batch:
            return
        owned_transaction = not self.db.in_transaction
        if owned_transaction:
            self.db.execute("BEGIN")
        try:
            self.db.executemany(
                "INSERT OR REPLACE INTO nodes (realm,path,parent,name,kind,mode,"
                "uid,gid,uname,gname,size,mtime,target,nlink,content,deleted) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,0)", self._batch)
            if owned_transaction:
                self.db.execute("COMMIT")
        except Exception:
            if owned_transaction:
                self.db.execute("ROLLBACK")
            raise
        self._batch.clear()
        self._batch_bytes = 0

    # A rootfs tarball has no entry for . so / has to be created
    def ensure_root(self) -> None:
        self.add("/", "dir", 0o755, 0, 0, "root", "root", 4096, time.time())
        self.flush()

    def from_tarball(self, tar_path: str) -> None:
        # Read the archive in order - seeking back for a hard link would decompress the xz stream again
        # hard links are resolved from SQLite after every regular file is imported
        hard_links = []
        with tarfile.open(tar_path, "r|*") as tf:
            for m in tf:
                if ".." in m.name.split("/"):
                    raise ValueError(f"Unsafe archive path: {m.name}")
                path = posixpath.normpath("/" + m.name.lstrip("/"))
                if m.islnk():
                    if ".." in m.linkname.split("/"):
                        raise ValueError(f"Unsafe archive hard link: {m.linkname}")
                    hard_links.append((path, m))
                    continue
                kind = _kind_from_tar(m)
                content = None
                if kind == "file":
                    f = tf.extractfile(m)
                    content = f.read() if f else None
                    if content is None:
                        raise ValueError(f"Cannot read complete archive contents: {path}")
                # The tar format records size 0 for directories and symlinks
                # ext4 reports 4096 for a directory and the target length for a link
                size = 4096 if kind == "dir" else len(m.linkname or "") if kind == "link" else m.size
                self.add(path, kind, m.mode, m.uid, m.gid,
                         m.uname or ("root" if m.uid == 0 else str(m.uid)),
                         m.gname or ("root" if m.gid == 0 else str(m.gid)),
                         size, float(m.mtime), m.linkname or None, content)
        self.flush()
        while hard_links:
            unresolved = []
            for path, m in hard_links:
                target = posixpath.normpath("/" + m.linkname.lstrip("/"))
                source = self.db.execute("SELECT content FROM nodes WHERE realm=? AND path=? AND kind='file'", (BASE, target)).fetchone()
                if not source or source[0] is None:
                    unresolved.append((path, m))
                    continue
                content = bytes(source[0])
                self.add(path, "file", m.mode, m.uid, m.gid,
                         m.uname or ("root" if m.uid == 0 else str(m.uid)),
                         m.gname or ("root" if m.gid == 0 else str(m.gid)),
                         len(content), float(m.mtime), m.linkname, content)
                self.flush()
            if len(unresolved) == len(hard_links):
                raise ValueError(f"Unresolved archive hard link: {unresolved[0][0]}")
            hard_links = unresolved

    def finish(self) -> None:
        self.flush()
        update_directory_links(self.db)
        self.db.execute("ANALYZE")
        self.db.close()


def _cpuinfo() -> str:
    flags = ("fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov "
             "pat pse36 clflush mmx fxsr sse sse2 ss ht syscall nx pdpe1gb "
             "rdtscp lm constant_tsc rep_good nopl xtopology cpuid tsc_known_freq "
             "pni pclmulqdq ssse3 fma cx16 pcid sse4_1 sse4_2 x2apic movbe popcnt "
             "aes xsave avx f16c rdrand hypervisor lahf_lm abm 3dnowprefetch "
             "invpcid_single fsgsbase bmi1 avx2 smep bmi2 erms invpcid rdseed adx "
             "smap clflushopt clwb sha_ni xsaveopt xsavec xgetbv1 xsaves md_clear "
             "flush_l1d arch_capabilities")
    out = []
    for i in range(2):
        out.append("\n".join([
            f"processor\t: {i}",
            "vendor_id\t: GenuineIntel",
            "cpu family\t: 6",
            "model\t\t: 85",
            "model name\t: Intel(R) Xeon(R) Platinum 8259CL CPU @ 2.50GHz",
            "stepping\t: 7",
            "microcode\t: 0x5003604",
            "cpu MHz\t\t: 2500.000",
            "cache size\t: 36608 KB",
            f"physical id\t: 0\nsiblings\t: 2\ncore id\t\t: {i}\ncpu cores\t: 2",
            "apicid\t\t: %d\ninitial apicid\t: %d" % (i, i),
            "fpu\t\t: yes\nfpu_exception\t: yes\ncpuid level\t: 13\nwp\t\t: yes",
            f"flags\t\t: {flags}",
            "bugs\t\t: spectre_v1 spectre_v2 spec_store_bypass swapgs itlb_multihit mmio_stale_data retbleed",
            "bogomips\t: 5000.00",
            "clflush size\t: 64\ncache_alignment\t: 64",
            "address sizes\t: 46 bits physical, 48 bits virtual",
            "power management:",
        ]) + "\n")
    return "\n".join(out)


def _meminfo() -> str:
    rows = [("MemTotal", 4016824), ("MemFree", 2418112), ("MemAvailable", 3341208),
            ("Buffers", 88204), ("Cached", 1012456), ("SwapCached", 0),
            ("Active", 731284), ("Inactive", 632148), ("SwapTotal", 0),
            ("SwapFree", 0), ("Dirty", 176), ("Writeback", 0),
            ("AnonPages", 263216), ("Mapped", 138044), ("Shmem", 1024),
            ("Slab", 148372), ("SReclaimable", 96140), ("SUnreclaim", 52232),
            ("KernelStack", 3968), ("PageTables", 4788), ("CommitLimit", 2008412),
            ("Committed_AS", 1389992), ("VmallocTotal", 34359738367),
            ("VmallocUsed", 22456), ("Hugepagesize", 2048)]
    return "".join(f"{k}:{v:>15} kB\n" for k, v in rows)
