# SFTP and scp
# serves the virtual filesystem to sftp and scp, as Ubuntu's OpenSSH does
# every operation uses the same realm-bound store and permission rules as the shell
# search permission on every parent, write and search to create or delete, the sticky /tmp bit
# owner-only chmod, root-only chown and the session umask for new files
# uploads land in the attacker's overlay, are never executed and are logged with their SHA-256
# user and group names come from the image's /etc/passwd and /etc/group, not the host

# Imports
from __future__ import annotations

import hashlib
import posixpath
import stat as statmod
from typing import Optional

import asyncssh
from asyncssh import SFTPAttrs, SFTPName, SFTPServer, SFTPVFSAttrs

from .fscommands import session_umask
from .tools import VFSTools
from .vfs import FSError
from .vfsio import read_bytes, write_target

FXF_READ, FXF_WRITE, FXF_APPEND, FXF_CREAT, FXF_TRUNC, FXF_EXCL = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20
MAX_OPEN_HANDLES = 64
# All open write buffers of one connection
MAX_BUFFERED_BYTES = 64 * 1024 * 1024
# Stored overlay content of one attacker realm
MAX_REALM_BYTES = 512 * 1024 * 1024

_ERRORS = {
    "ENOENT": asyncssh.SFTPNoSuchFile, "EACCES": asyncssh.SFTPPermissionDenied,
    "EPERM": asyncssh.SFTPPermissionDenied, "EEXIST": asyncssh.SFTPFileAlreadyExists,
    "EISDIR": asyncssh.SFTPFileIsADirectory, "ENOTDIR": asyncssh.SFTPNotADirectory,
    "ENOTEMPTY": asyncssh.SFTPDirNotEmpty, "ELOOP": asyncssh.SFTPLinkLoop,
    "EINVAL": asyncssh.SFTPInvalidParameter, "ENOSPC": asyncssh.SFTPNoSpaceOnFilesystem,
}


def _sftp_error(exc: FSError) -> asyncssh.SFTPError:
    if exc.message == "Directory not empty":
        return asyncssh.SFTPDirNotEmpty(exc.message)
    return _ERRORS.get(exc.errno_name, asyncssh.SFTPFailure)(exc.message)


def _text(path: bytes) -> str:
    return path.decode("utf-8", "replace") if isinstance(path, bytes) else str(path)


# An open SFTP or scp handle
# writes are buffered and published on close
class VFSFile:
    def __init__(self, path: str, data: bytes, *, readable: bool, writable: bool,
                 append: bool, mode: int, existing: bool) -> None:
        self.path, self.buffer = path, bytearray(data)
        self.readable, self.writable, self.append = readable, writable, append
        self.mode, self.existing = mode, existing
        self.dirty = False
        self.bytes_read = 0
        self.mtime: Optional[float] = None


class VFSSFTPServer(SFTPServer):
    def __init__(self, chan, *, controller, persona, log, realm: str, max_bytes: int) -> None:
        super().__init__(chan)
        from .session import SessionState
        conn = chan.get_connection()
        hp = conn.get_extra_info("hp_server")
        username = conn.get_extra_info("username") or "user"
        self.filesystem = controller.filesystem
        self.log = log
        self.max_bytes = max_bytes
        self.session = SessionState.create(persona, username, getattr(hp, "peer_ip", "0.0.0.0"),
                                           getattr(hp, "peer_port", 0))
        self.session.session_id = getattr(hp, "session_id", self.session.session_id)
        self.session.realm = realm
        self.session.interactive = False
        self.session.has_pty = False
        self.session.cwd = self._home()
        command = chan.get_command() or ""
        self.protocol = "scp" if command.startswith("scp") else "sftp"
        self.handles = 0
        self.open_files: set = set()
        log.channel(self.session.session_id, kind=self.protocol, username=username, term=None,
                    term_size=None, command=command or None, subsystem=None if command else "sftp",
                    env={})

    # Helpers

    def _access(self) -> VFSTools:
        return VFSTools(self.filesystem, self.session)

    def _home(self) -> str:
        entry = self.filesystem.vfs.for_realm(self.session.realm).passwd_users().get(self.session.username)
        return entry[2] if entry else ("/root" if self.session.username == "root" else f"/home/{self.session.username}")

    def _abs(self, path: bytes) -> str:
        text = _text(path)
        if not text or text == ".":
            return self.session.cwd
        if text == "~" or text.startswith("~/"):
            text = self._home() + text[1:]
        return posixpath.normpath(text if text.startswith("/") else posixpath.join(self.session.cwd, text))

    def _resolve(self, path: bytes, *, follow: bool = True, want: str = ""):
        try:
            return self._access().resolve(self._abs(path), follow=follow, want=want)
        except FSError as exc:
            raise _sftp_error(exc) from None

    def _attrs(self, node, size: Optional[int] = None) -> SFTPAttrs:
        kind = (asyncssh.FILEXFER_TYPE_DIRECTORY if node.is_dir else asyncssh.FILEXFER_TYPE_SYMLINK
                if node.is_link else asyncssh.FILEXFER_TYPE_REGULAR if node.is_file
                else asyncssh.FILEXFER_TYPE_SPECIAL)
        return SFTPAttrs(type=kind, size=node.size if size is None else size, uid=node.uid, gid=node.gid,
                         permissions=node.st_mode, atime=int(node.mtime), mtime=int(node.mtime),
                         nlink=node.nlink, owner=node.uname, group=node.gname)

    def _record(self, direction: str, path: str, data: bytes, **extra) -> None:
        self.log.emit("file_transfer", self.session.session_id, protocol=self.protocol,
                      direction=direction, path=path, bytes=len(data),
                      sha256=hashlib.sha256(data).hexdigest(), realm=self.session.realm,
                      username=self.session.username, **extra)

    # Creating or deleting needs search on every parent and write and search on the directory
    def _require_write(self, path: str) -> None:
        access = self._access()
        try:
            access.resolve(posixpath.dirname(path) or "/", want="wx")
            access.fs._require_write(self.session, path)
        except FSError as exc:
            raise _sftp_error(exc) from None

    # Names and Paths

    def format_user(self, uid: Optional[int]) -> str:
        if uid is None:
            return ""
        users = self.filesystem.vfs.for_realm(self.session.realm).passwd_users()
        return next((name for name, entry in users.items() if entry[0] == uid), str(uid))

    def format_group(self, gid: Optional[int]) -> str:
        if gid is None:
            return ""
        return self.filesystem.vfs.for_realm(self.session.realm).group_names().get(gid, str(gid))

    def realpath(self, path: bytes) -> bytes:
        target = self._abs(path)
        try:
            node = self._access().resolve(target)
            target = node.path
        except FSError as exc:
            raise _sftp_error(exc) from None
        return target.encode()

    def readlink(self, path: bytes) -> bytes:
        node = self._resolve(path, follow=False)
        if not node.is_link:
            raise asyncssh.SFTPInvalidParameter("Invalid argument")
        return (node.target or "").encode()

    # Stat

    def stat(self, path: bytes) -> SFTPAttrs:
        return self._attrs(self._resolve(path))

    def lstat(self, path: bytes) -> SFTPAttrs:
        return self._attrs(self._resolve(path, follow=False))

    def fstat(self, file_obj: VFSFile) -> SFTPAttrs:
        node = self._access().vfs.resolve(file_obj.path)
        if node is None:
            return SFTPAttrs(size=len(file_obj.buffer), permissions=statmod.S_IFREG | file_obj.mode)
        return self._attrs(node, size=len(file_obj.buffer))

    def _apply_attrs(self, path: str, attrs: SFTPAttrs, *, follow: bool = True) -> None:
        access = self._access()
        try:
            node = access.resolve(path, follow=follow)
            ident = access.ident
            if attrs.uid is not None or attrs.gid is not None:
                changes_owner = (attrs.uid not in (None, node.uid)) or (attrs.gid not in (None, node.gid))
                if changes_owner and not ident.is_root:
                    raise FSError("Operation not permitted", "EPERM")
            if attrs.permissions is not None or attrs.mtime is not None:
                if not ident.is_root and node.uid != ident.uid:
                    raise FSError("Operation not permitted", "EPERM")
            if attrs.size is not None and node.is_file and attrs.size != node.size:
                if not access.fs._can(node, "w", ident):
                    raise FSError("Permission denied", "EACCES")
                data = (access.vfs.read(node.path, node.size) or b"")[:attrs.size]
                data += b"\0" * (attrs.size - len(data))
                access.vfs.write_file(node.path, data, uid=node.uid, gid=node.gid,
                                      uname=node.uname, gname=node.gname, mode=node.mode & 0o7777)
            if attrs.permissions is not None:
                access.vfs.chmod(node.path, attrs.permissions & 0o7777)
            if attrs.mtime is not None:
                access.vfs.utime(node.path, float(attrs.mtime))
        except FSError as exc:
            raise _sftp_error(exc) from None

    def setstat(self, path: bytes, attrs: SFTPAttrs) -> None:
        self._apply_attrs(self._abs(path), attrs)

    def lsetstat(self, path: bytes, attrs: SFTPAttrs) -> None:
        self._apply_attrs(self._abs(path), attrs, follow=False)

    def fsetstat(self, file_obj: VFSFile, attrs: SFTPAttrs) -> None:
        if attrs.size is not None and file_obj.writable:
            del file_obj.buffer[attrs.size:]
            file_obj.buffer.extend(b"\0" * (attrs.size - len(file_obj.buffer)))
            file_obj.dirty = True
        if attrs.permissions is not None:
            file_obj.mode = attrs.permissions & 0o7777
        if attrs.mtime is not None:
            file_obj.mtime = float(attrs.mtime)
        rest = SFTPAttrs(uid=attrs.uid, gid=attrs.gid, permissions=attrs.permissions, mtime=attrs.mtime)
        if self._access().vfs.resolve(file_obj.path) is not None:
            self._apply_attrs(file_obj.path, rest)

    def statvfs(self, path: bytes) -> SFTPVFSAttrs:
        self._resolve(path)
        return SFTPVFSAttrs(bsize=4096, frsize=4096, blocks=7_574_304, bfree=6_022_154,
                            bavail=6_005_770, files=3_870_720, ffree=3_786_421, favail=3_786_421,
                            fsid=0xfd00, flags=0, namemax=255)

    # Listing

    async def scandir(self, path: bytes):
        directory = self._resolve(path, want="rx")
        if not directory.is_dir:
            raise asyncssh.SFTPNotADirectory("Not a directory")
        vfs = self._access().vfs
        parent = vfs.resolve(posixpath.dirname(directory.path) or "/") or directory
        for name, node in ((b".", directory), (b"..", parent)):
            yield SFTPName(name, attrs=self._attrs(node))
        for child in vfs.listdir(directory.path):
            if child.name in (".", ".."):
                continue
            yield SFTPName(child.name.encode(), attrs=self._attrs(child))

    # Files

    def open(self, path: bytes, pflags: int, attrs: SFTPAttrs) -> VFSFile:
        if self.handles >= MAX_OPEN_HANDLES:
            raise asyncssh.SFTPFailure("Too many open files")
        target = self._abs(path)
        readable, writable = bool(pflags & FXF_READ), bool(pflags & (FXF_WRITE | FXF_APPEND))
        if not writable:
            node = self._resolve(path, want="r")
            if node.is_dir:
                raise asyncssh.SFTPFileIsADirectory("Is a directory")
            try:
                data = read_bytes(self.filesystem, self.session, node.path)
            except FSError as exc:
                raise _sftp_error(exc) from None
            handle = VFSFile(node.path, data, readable=True, writable=False, append=False,
                             mode=node.mode & 0o7777, existing=True)
        else:
            try:
                access, resolved, existing = write_target(self.filesystem, self.session, target)
            except FSError as exc:
                raise _sftp_error(exc) from None
            if existing is not None and pflags & FXF_CREAT and pflags & FXF_EXCL:
                raise asyncssh.SFTPFileAlreadyExists("File exists")
            if existing is None and not pflags & FXF_CREAT:
                raise asyncssh.SFTPNoSuchFile("No such file or directory")
            if existing is not None and readable and not access.fs._can(existing, "r", access.ident):
                raise asyncssh.SFTPPermissionDenied("Permission denied")
            data = b""
            if existing is not None and not pflags & FXF_TRUNC:
                data = access.vfs.read(existing.path, existing.size) or b""
            umask = session_umask(self.session, access.vfs)
            requested = attrs.permissions if attrs and attrs.permissions is not None else 0o666
            mode = existing.mode & 0o7777 if existing is not None else requested & 0o777 & ~umask
            handle = VFSFile(resolved, data, readable=readable, writable=True,
                             append=bool(pflags & FXF_APPEND), mode=mode, existing=existing is not None)
            if existing is None or pflags & FXF_TRUNC:
                # Opening with O_CREAT|O_TRUNC takes effect right away, as on a real disk
                self._publish(handle, record=False)
        self.handles += 1
        self.open_files.add(handle)
        return handle

    def read(self, file_obj: VFSFile, offset: int, size: int) -> bytes:
        if not file_obj.readable:
            raise asyncssh.SFTPPermissionDenied("Permission denied")
        chunk = bytes(file_obj.buffer[offset:offset + size])
        file_obj.bytes_read += len(chunk)
        return chunk

    def write(self, file_obj: VFSFile, offset: int, data: bytes) -> int:
        if not file_obj.writable:
            raise asyncssh.SFTPPermissionDenied("Permission denied")
        if file_obj.append:
            offset = len(file_obj.buffer)
        end = offset + len(data)
        growth = max(0, end - len(file_obj.buffer))
        buffered = sum(len(f.buffer) for f in self.open_files if f.writable)
        # Operator protection - per-file size, per-connection memory and per-realm storage
        if end > self.max_bytes or buffered + growth > MAX_BUFFERED_BYTES:
            raise asyncssh.SFTPNoSpaceOnFilesystem("No space left on device")
        if offset > len(file_obj.buffer):
            file_obj.buffer.extend(b"\0" * (offset - len(file_obj.buffer)))
        file_obj.buffer[offset:end] = data
        file_obj.dirty = True
        return len(data)

    def _realm_bytes(self) -> int:
        row = self.filesystem.vfs.db.execute(
            "SELECT COALESCE(SUM(length(content)), 0) FROM nodes WHERE realm=?",
            (self.session.realm,)).fetchone()
        return int(row[0] or 0)

    def _publish(self, handle: VFSFile, *, record: bool = True) -> None:
        access = self._access()
        node = access.vfs.resolve(handle.path)
        if self._realm_bytes() + len(handle.buffer) > MAX_REALM_BYTES:
            raise asyncssh.SFTPNoSpaceOnFilesystem("No space left on device")
        owner = node if node is not None else access.ident
        try:
            access.vfs.write_file(handle.path, bytes(handle.buffer), uid=owner.uid, gid=owner.gid,
                                  uname=owner.uname, gname=owner.gname,
                                  mode=(node.mode & 0o7777) if node is not None and handle.existing else handle.mode)
            if handle.mtime is not None:
                access.vfs.utime(handle.path, handle.mtime)
        except FSError as exc:
            raise _sftp_error(exc) from None
        if record:
            self._record("upload", handle.path, bytes(handle.buffer),
                         replaced_existing=handle.existing)

    def close(self, file_obj: VFSFile) -> None:
        self.handles = max(0, self.handles - 1)
        self.open_files.discard(file_obj)
        if file_obj.writable and file_obj.dirty:
            file_obj.dirty = False
            self._publish(file_obj)
        elif file_obj.readable and file_obj.bytes_read and not file_obj.writable:
            self._record("download", file_obj.path, bytes(file_obj.buffer), bytes_sent=file_obj.bytes_read)

    # Namespace Changes

    def remove(self, path: bytes) -> None:
        target = self._abs(path)
        node = self._resolve(path, follow=False)
        if node.is_dir:
            raise asyncssh.SFTPFileIsADirectory("Is a directory")
        self._require_write(target)
        try:
            self._access().vfs.remove(node.path)
        except FSError as exc:
            raise _sftp_error(exc) from None

    def mkdir(self, path: bytes, attrs: SFTPAttrs) -> None:
        target = self._abs(path)
        self._require_write(target)
        access = self._access()
        requested = attrs.permissions if attrs and attrs.permissions is not None else 0o777
        mode = requested & 0o777 & ~session_umask(self.session, access.vfs)
        ident = access.ident
        try:
            access.vfs.mkdir(target, uid=ident.uid, gid=ident.gid, uname=ident.uname,
                             gname=ident.gname, mode=mode)
        except FSError as exc:
            raise _sftp_error(exc) from None

    def rmdir(self, path: bytes) -> None:
        target = self._abs(path)
        node = self._resolve(path, follow=False)
        if not node.is_dir:
            raise asyncssh.SFTPNotADirectory("Not a directory")
        self._require_write(target)
        access = self._access()
        if access.vfs.listdir(node.path):
            raise asyncssh.SFTPDirNotEmpty("Directory not empty")
        try:
            access.vfs.rmdir(node.path)
        except FSError as exc:
            raise _sftp_error(exc) from None

    def _move(self, oldpath: bytes, newpath: bytes, *, overwrite: bool) -> None:
        source, destination = self._abs(oldpath), self._abs(newpath)
        self._resolve(oldpath, follow=False)
        access = self._access()
        if access.vfs.resolve(destination, follow=False) is not None and not overwrite:
            raise asyncssh.SFTPFileAlreadyExists("File exists")
        self._require_write(source)
        self._require_write(destination)
        ident = access.ident
        try:
            access.vfs.move(source, destination, uid=ident.uid, gid=ident.gid,
                            uname=ident.uname, gname=ident.gname)
        except FSError as exc:
            raise _sftp_error(exc) from None

    def rename(self, oldpath: bytes, newpath: bytes) -> None:
        # SFTPv3 rename never replaces an existing file
        self._move(oldpath, newpath, overwrite=False)

    def posix_rename(self, oldpath: bytes, newpath: bytes) -> None:
        self._move(oldpath, newpath, overwrite=True)

    def symlink(self, oldpath: bytes, newpath: bytes) -> None:
        # OpenSSH's sftp-server always reads the link target first
        # this server announces OpenSSH, so well-behaved clients send that order
        # undo asyncssh's spec-order decoding for clients it does not recognise
        client = self.connection.get_extra_info("client_version") or ""
        if not any(name in client for name in ("OpenSSH", "paramiko")):
            oldpath, newpath = newpath, oldpath
        link = self._abs(newpath)
        self._require_write(link)
        access = self._access()
        ident = access.ident
        try:
            access.vfs.symlink(link, _text(oldpath), uid=ident.uid, gid=ident.gid,
                               uname=ident.uname, gname=ident.gname)
        except FSError as exc:
            raise _sftp_error(exc) from None

    def link(self, oldpath: bytes, newpath: bytes) -> None:
        raise asyncssh.SFTPOpUnsupported("Operation unsupported")

    def exit(self) -> None:
        # Real sshd reports the sftp-server exit status when the subsystem ends
        # without it OpenSSH 9's scp, which uses SFTP by default, exits 1
        chan = getattr(self, "_chan", None)
        if chan is not None and self.protocol == "sftp":
            try:
                chan.exit(0)
            # The channel is already gone because the client vanished
            except Exception:
                pass
        return None


# Build the asyncssh sftp_factory bound to the honeypot's realm policy
def make_sftp_factory(cfg, persona, controller, log):
    if not getattr(cfg, "sftp_enabled", True) or getattr(controller, "filesystem", None) is None:
        return None

    def factory(chan):
        conn = chan.get_connection()
        hp = conn.get_extra_info("hp_server")
        peer_ip = getattr(hp, "peer_ip", "") or "unknown"
        realm = {"ip": peer_ip, "session": getattr(hp, "session_id", peer_ip),
                 "global": "global"}.get(getattr(cfg, "fs_realm_mode", "ip"), peer_ip) or "unknown"
        return VFSSFTPServer(chan, controller=controller, persona=persona, log=log, realm=realm,
                             max_bytes=getattr(cfg, "sftp_max_bytes", 32 << 20))
    return factory
