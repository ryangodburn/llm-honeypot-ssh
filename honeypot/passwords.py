# SSH Passwords
# operator-owned password verifiers, kept outside the attacker filesystem

# Imports
from __future__ import annotations
import asyncio
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import tempfile

ITERATIONS = 600_000
MAX_PASSWORD_BYTES = 1024
USER = re.compile(r'[a-z_][a-z0-9_-]{0,31}\$?\Z')

class PasswordError(ValueError):
    pass


def password_record(password: str) -> dict:
    raw = password.encode('utf-8')
    if not raw or len(raw) > MAX_PASSWORD_BYTES:
        raise PasswordError('Password must contain 1 to 1024 UTF-8 bytes')
    salt = secrets.token_bytes(32)
    return {'algorithm': 'pbkdf2-sha256', 'iterations': ITERATIONS,
            'salt': salt.hex(), 'digest': hashlib.pbkdf2_hmac('sha256', raw, salt, ITERATIONS).hex()}


def _unique(pairs):
    value = {}
    for k, v in pairs:
        if k in value:
            raise PasswordError('Duplicate field or account in password store')
        value[k] = v
    return value


class PasswordStore:
    def __init__(self, users):
        if not isinstance(users, dict) or not users:
            raise PasswordError('Password store must contain at least one account')
        self.users = {}
        for name, r in users.items():
            if not isinstance(name, str) or not USER.fullmatch(name) or not isinstance(r, dict):
                raise PasswordError('Invalid account record')
            if set(r) != {'algorithm', 'iterations', 'salt', 'digest'}:
                raise PasswordError('Invalid password verifier fields')
            if r['algorithm'] != 'pbkdf2-sha256' or type(r['iterations']) is not int or not ITERATIONS <= r['iterations'] <= 2_000_000:
                raise PasswordError('Unsupported password hashing parameters')
            try:
                salt, digest = bytes.fromhex(r['salt']), bytes.fromhex(r['digest'])
            except (ValueError, TypeError):
                raise PasswordError('Invalid verifier encoding') from None
            if len(salt) != 32 or len(digest) != 32:
                raise PasswordError('Invalid verifier length')
            self.users[name] = dict(r)
        # Unknown users still pay one expensive hash and a constant-time comparison
        self._dummy = dict(next(iter(self.users.values())), salt=secrets.token_hex(32), digest=secrets.token_hex(32))
        self._slots = asyncio.Semaphore(4)
        self._workers = set()

    @classmethod
    def from_passwords(cls, passwords):
        return cls({name: password_record(pw) for name, pw in passwords.items()})

    @classmethod
    def load(cls, path):
        try:
            p = Path(path)
            if p.is_symlink() or p.stat().st_size > 1_000_000:
                raise PasswordError('Unsafe password store path or size')
            doc = json.loads(p.read_text(encoding='utf-8'), object_pairs_hook=_unique)
            if not isinstance(doc, dict) or set(doc) != {'version', 'users'} or doc['version'] != 1:
                raise PasswordError('Unsupported password store format')
            return cls(doc['users'])
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise PasswordError('Cannot read password store; use run.py --set-password USER to create it') from exc

    def verify(self, username, password):
        raw = password.encode('utf-8')
        if not raw or len(raw) > MAX_PASSWORD_BYTES:
            return False
        r = self.users.get(username, self._dummy)
        got = hashlib.pbkdf2_hmac('sha256', raw, bytes.fromhex(r['salt']), r['iterations'])
        return hmac.compare_digest(got, bytes.fromhex(r['digest'])) and username in self.users

    async def authenticate(self, username, password):
        await self._slots.acquire()
        worker = asyncio.create_task(asyncio.to_thread(self.verify, username, password))
        self._workers.add(worker)
        def finished(task):
            self._workers.discard(task)
            self._slots.release()
            if not task.cancelled():
                task.exception()
        worker.add_done_callback(finished)
        # Keep the slot until the CPU worker ends, even if the SSH connection closes
        return await asyncio.shield(worker)

    def save(self, path):
        path = Path(path)
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if path.is_symlink():
            raise PasswordError('Refusing a symlink password store')
        fd, temp = tempfile.mkstemp(prefix='.credentials-', dir=path.parent)
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as f:
                json.dump({'version': 1, 'users': self.users}, f, indent=2)
                f.write('\n'); f.flush(); os.fsync(f.fileno())
            os.chmod(temp, 0o600)
            os.replace(temp, path)
        finally:
            if os.path.exists(temp):
                os.unlink(temp)
