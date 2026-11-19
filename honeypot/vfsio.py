# Byte I/O
# permission-aware reads and writes of raw bytes in the virtual filesystem, never host paths

# Imports
from __future__ import annotations

import hashlib
import posixpath
import re

from .tools import VFSTools
from .vfs import FSError, MAX_SYMLINKS


def read_bytes(filesystem, session, path, limit=None):
    access = VFSTools(filesystem, session)
    node = access.resolve(path, want="r")
    if not node.is_file:
        raise FSError("Is a directory" if node.is_dir else "Not a regular file", "EISDIR")
    data = access.vfs.read(node.path, node.size if limit is None else limit)
    if data is None:
        raise FSError("Stored file content is unavailable", "ENODATA")
    return data


# Resolve links and every parent's search permission, including new targets
def write_target(filesystem, session, path):
    access = VFSTools(filesystem, session)
    for _ in range(MAX_SYMLINKS + 1):
        try:
            node = access.resolve(path, follow=False)
        except FSError as exc:
            if exc.errno_name != "ENOENT":
                raise
            parent = access.resolve(posixpath.dirname(path) or ".", want="wx")
            name = posixpath.basename(path)
            if not parent.is_dir:
                raise FSError("Not a directory", "ENOTDIR")
            if name in ("", ".", ".."):
                raise FSError("Is a directory", "EISDIR")
            return access, posixpath.join(parent.path, name), None
        if node.is_link:
            path = node.target or ""
            if not path:
                raise FSError("No such file or directory", "ENOENT")
            if not path.startswith("/"):
                path = posixpath.join(posixpath.dirname(node.path), path)
            continue
        if not node.is_file:
            raise FSError("Is a directory" if node.is_dir else "Not a regular file", "EISDIR")
        if not access.fs._can(node, "w", access.ident):
            raise FSError("Permission denied", "EACCES")
        return access, node.path, node
    raise FSError("Too many levels of symbolic links", "ELOOP")


def write_bytes(filesystem, session, path, data, *, append=False):
    access, target, existing = write_target(filesystem, session, path)
    if append and existing:
        previous = access.vfs.read(target, existing.size)
        if previous is None:
            raise FSError("Stored file content is unavailable", "ENODATA")
        data = previous + data
    owner = existing or access.ident
    if existing:
        mode = existing.mode
    else:
        from .fscommands import session_umask
        # The same umask that umask reports
        mode = 0o666 & ~session_umask(session, access.vfs)
    access.vfs.write_file(target, data, uid=owner.uid, gid=owner.gid,
                         uname=owner.uname, gname=owner.gname, mode=mode)
    return target


HASHES = {"md5sum": "md5", "sha1sum": "sha1", "sha224sum": "sha224",
          "sha256sum": "sha256", "sha384sum": "sha384", "sha512sum": "sha512"}


# Yield (display path, bytes or None, error or None) for grep -r style walks
# listing needs read and search permission, and files need read permission
# symlinks met while recursing are followed only with follow=True (grep -R), as GNU grep does
# bounded so a walk of / cannot stall the event loop
def walk_files(filesystem, session, top, *, follow=False, include=(), exclude=(), exclude_dir=(),
               strip_dot=False, max_files=20000, max_bytes=256 << 20):
    import fnmatch
    access = VFSTools(filesystem, session)
    budget = {"files": max_files, "bytes": max_bytes}

    def matches(name, patterns):
        return any(fnmatch.fnmatch(name, p) for p in patterns)

    def read_one(shown, real):
        if budget["files"] <= 0 or budget["bytes"] <= 0:
            return None
        try:
            data = read_bytes(filesystem, session, real)
        except FSError as exc:
            if exc.errno_name == "ENODATA":
                return None
            return (shown, None, exc.message)
        budget["files"] -= 1
        budget["bytes"] -= len(data)
        return (shown, data, None)

    try:
        node = access.resolve(top)
    except FSError as exc:
        yield top, None, exc.message
        return
    if not node.is_dir:
        if node.is_file:
            item = read_one(top, top)
            if item:
                yield item
        return

    def visit(shown, real, depth):
        if depth > 64:
            return
        try:
            directory = access.resolve(real, want="rx")
        except FSError as exc:
            yield shown, None, exc.message
            return
        for child in access.vfs.listdir(directory.path):
            name = child.name
            if name in (".", ".."):
                continue
            child_shown = name if (strip_dot and shown == ".") else posixpath.join(shown, name)
            child_real = posixpath.join(real, name)
            if child.is_link:
                if not follow:
                    continue
                try:
                    child = access.resolve(child_real)
                except FSError:
                    continue
            if child.is_dir:
                if not matches(name, exclude_dir):
                    yield from visit(child_shown, child_real, depth + 1)
            elif child.is_file:
                if (include and not matches(name, include)) or matches(name, exclude):
                    continue
                item = read_one(child_shown, child_real)
                if item:
                    yield item
            if budget["files"] <= 0 or budget["bytes"] <= 0:
                return

    yield from visit(top.rstrip("/") or "/", top, 0)


def _base64(argv, data):
    import base64 as b64
    decode = ignore = False
    wrap = 76
    args = list(argv[1:])
    operands = []
    while args:
        arg = args.pop(0)
        if arg in ("-d", "--decode"):
            decode = True
        elif arg in ("-i", "--ignore-garbage"):
            ignore = True
        elif arg == "-w" and args:
            wrap = args.pop(0)
        elif arg.startswith("-w") and len(arg) > 2:
            wrap = arg[2:]
        elif arg.startswith("--wrap="):
            wrap = arg[7:]
        elif arg.startswith("-") and arg != "-":
            if re.fullmatch(r"-[di]+", arg):
                decode, ignore = decode or "d" in arg, ignore or "i" in arg
            else:
                return None
        else:
            operands.append(arg)
    try:
        wrap = int(wrap)
    except ValueError:
        return b"", f"base64: invalid wrap size: '{wrap}'", 1
    if decode:
        body = re.sub(rb"[^A-Za-z0-9+/=]" if ignore else rb"\s", b"", data)
        try:
            return b64.b64decode(body + b"=" * (-len(body) % 4) if ignore else body, validate=True), "", 0
        except ValueError:
            return b"", "base64: invalid input", 1
    encoded = b64.b64encode(data)
    if wrap > 0:
        encoded = b"\n".join(encoded[i:i + wrap] for i in range(0, len(encoded), wrap))
    # -w 0 - no final newline
    return encoded + (b"\n" if encoded and wrap > 0 else b""), "", 0


# Return (stdout, stderr, status) for byte-exact hashes, wc -c and base64
# stdout is bytes for base64, since echo hello | base64 must encode echo's newline
def inspect_bytes(filesystem, session, argv, stdin=None):
    if not argv:
        return None
    command = argv[0].rsplit("/", 1)[-1]
    if command == "base64":
        operands = [a for a in argv[1:] if not a.startswith("-") or a == "-"]
        operands = [a for a in operands if not (argv[argv.index(a) - 1] == "-w" if argv.index(a) > 0 else False)]
        if len(operands) > 1:
            return None
        if operands and operands[0] != "-":
            try:
                data = read_bytes(filesystem, session, operands[0])
            except FSError as exc:
                return "", f"base64: {operands[0]}: {exc.message}", 1
        elif stdin is not None:
            data = stdin
        else:
            return None
        return _base64([a for a in argv if a not in operands], data)
    if command not in HASHES and command != "wc":
        return None
    operands, literal, binary, count = [], False, False, False
    for arg in argv[1:]:
        if not literal and arg == "--":
            literal = True
        elif not literal and arg.startswith("-") and arg != "-":
            if command == "wc" and arg in ("-c", "--bytes"):
                count = True
            elif command in HASHES and arg in ("-b", "--binary", "-t", "--text"):
                binary = arg in ("-b", "--binary")
            else:
                return None
        else:
            operands.append(arg)
    if command == "wc" and not count:
        return None
    if not operands and stdin is None:
        return None
    rows, errors, total = [], [], 0
    for path in operands or ["-"]:
        try:
            data = (stdin or b"") if path == "-" else read_bytes(filesystem, session, path)
            if command == "wc":
                total += len(data)
                rows.append(f"{len(data):7d} {path}" if operands else str(len(data)))
            else:
                rows.append(f"{hashlib.new(HASHES[command], data).hexdigest()} {'*' if binary else ' '}{path}")
        except FSError as exc:
            errors.append(f"{command}: {path}: {exc.message}")
    if command == "wc" and len(operands) > 1:
        rows.append(f"{total:7d} total")
    return "\n".join(rows), "\n".join(errors), int(bool(errors))
