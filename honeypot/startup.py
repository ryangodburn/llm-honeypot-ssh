# Startup Checks
# operator-only validation and recovery for the databases and Ollama
# never given guest-controlled paths or URLs

# Imports
from __future__ import annotations

import asyncio
from contextlib import closing, contextmanager
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import shutil
import sqlite3
import struct
import subprocess
import tempfile
import time
from urllib.parse import urlsplit

from .bootstrap import SetupError


# Lock the databases for the life of the server
# OS locks survive stale lock files and are released when the process exits
# lock files are never deleted, or two processes could lock different files for one database
@contextmanager
def runtime_lease(paths):
    handles = []
    try:
        for path in sorted({str(Path(p).resolve()) for p in paths if p}):
            lock = Path(path + '.runtime.lock')
            lock.parent.mkdir(parents=True, exist_ok=True)
            f = lock.open('a+b')
            try:
                if not lock.stat().st_size:
                    f.write(b'\0'); f.flush()
                f.seek(0)
                if os.name == 'nt':
                    import msvcrt
                    msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as exc:
                f.close()
                raise SetupError(f'Database is already in use by another run.py: {path}') from exc
            handles.append(f)
        yield
    finally:
        for f in reversed(handles):
            try:
                if os.name == 'nt':
                    import msvcrt
                    f.seek(0); msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)
            finally:
                f.close()


def _snapshot(source, destination):
    with closing(sqlite3.connect(source.as_uri() + '?mode=ro', uri=True, timeout=5)) as src, closing(sqlite3.connect(destination)) as dst:
        deadline = time.monotonic() + 30
        def progress(status, remaining, total):
            if status in (sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED) and time.monotonic() > deadline:
                raise SetupError('Database backup is busy; stop its other users before restarting')
        src.backup(dst, pages=256, progress=progress)


# Back up a database before it is replaced
# keeps committed WAL data, or the raw files when SQLite cannot read it
def backup_database(path, reason):
    path = Path(path).resolve()
    if not path.exists():
        return None
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    backup = path.with_name(path.name + '.before-' + reason + '-' + stamp + '.bak')
    try:
        _snapshot(path, backup)
    except sqlite3.Error:
        backup.unlink(missing_ok=True)
        shutil.copy2(path, backup)
        for suffix in ('-wal', '-shm', '-journal'):
            sidecar = Path(str(path) + suffix)
            if sidecar.exists():
                shutil.copy2(sidecar, str(backup) + suffix)
    return str(backup)


def _publish(stage, target):
    # Stop an old WAL being replayed into a replacement database
    if target.exists() and target.stat().st_size:
        try:
            with closing(sqlite3.connect(target, timeout=5)) as old:
                old.execute('PRAGMA schema_version').fetchone()
                checkpoint = old.execute('PRAGMA wal_checkpoint(TRUNCATE)').fetchone()
                if checkpoint and checkpoint[0]:
                    raise SetupError('Database is busy; stop its other users before restarting')
                old.execute('PRAGMA journal_mode=DELETE').fetchone()
        except sqlite3.DatabaseError as exc:
            if 'locked' in str(exc).lower() or 'busy' in str(exc).lower():
                raise SetupError('Database is busy; stop its other users before restarting') from exc
            # An unreadable database was already kept as raw bytes
        for suffix in ('-wal', '-shm', '-journal'):
            Path(str(target) + suffix).unlink(missing_ok=True)
    with closing(sqlite3.connect(stage)) as db:
        db.execute('PRAGMA wal_checkpoint(TRUNCATE)')
        db.execute('PRAGMA journal_mode=DELETE')
    os.replace(stage, target)


# Check bytes and audit evidence rather than trusting version markers alone
def validate_database(path, *, allow_expansion_upgrade=False):
    from .bootstrap import inspect_database
    from .ubuntu_profile import EVIDENCE, PROFILE_VERSION
    from .privilege_profile import VERSION, LEGACY_VERSION, BASE_USER, HIGH_USER, PROOF_PATH, TICKET_PATH
    from .ubuntu_analysis import ANALYSIS_VERSION, verify_enrichment
    path = Path(path).resolve()
    status = inspect_database(path)
    if not status['ready']:
        raise SetupError(status['reason'])
    if status.get('import_mode') != 'full_rootfs' or status.get('profile_kind') != 'enriched-import':
        raise SetupError('A complete imported Ubuntu image and analyzed profile are required')
    if status.get('profile') != PROFILE_VERSION or status.get('analysis_version') != ANALYSIS_VERSION:
        raise SetupError('Ubuntu profile or analysis is missing/outdated')
    allowed = (VERSION, LEGACY_VERSION, None) if allow_expansion_upgrade else (VERSION,)
    if status.get('privilege_profile') not in allowed:
        raise SetupError('Privilege expansion is missing/outdated')
    digest = status.get('rootfs_sha256') or ''
    if len(digest) != 64 or any(c not in '0123456789abcdef' for c in digest.lower()):
        raise SetupError('Root filesystem provenance is missing')
    proof = verify_enrichment(path)
    if proof['missing_imported_paths'] or proof['unaccounted_changes']:
        raise SetupError('Imported files or profile additions do not match their audit evidence')
    analysis = proof['analysis']
    if (proof['source_nodes'] != analysis['inventory']['base_nodes'] or
            not proof['source_nodes'] or analysis['stage'] != 'before_profile' or
            analysis['rootfs_sha256'] != digest or analysis['import_mode'] != 'full_rootfs'):
        raise SetupError('Incomplete source manifest or import analysis')
    with closing(sqlite3.connect(path.as_uri() + '?mode=ro', uri=True)) as db:
        metadata = dict(db.execute('SELECT key,value FROM meta'))
        manifest_hash = hashlib.sha256()
        for name, fingerprint in db.execute('SELECT path,node_sha256 FROM ubuntu_source_manifest ORDER BY path'):
            manifest_hash.update((name + '\0' + fingerprint + '\n').encode())
        if manifest_hash.hexdigest() != analysis['source_manifest_sha256'] or manifest_hash.hexdigest() != metadata.get('profile_source_manifest_sha256'):
            raise SetupError('Source manifest digest mismatch')
        if (analysis['inventory']['regular_files_without_content'] or
                db.execute("SELECT count(*) FROM ubuntu_source_manifest WHERE kind='file' AND content_sha256 IS NULL").fetchone()[0] or
                db.execute("SELECT count(*) FROM nodes WHERE realm='' AND deleted=0 AND kind='file' AND content IS NOT NULL AND size!=length(content)").fetchone()[0]):
            raise SetupError('Missing file bytes or incorrect stored sizes')
        missing_parents = db.execute("SELECT n.path,n.parent,p.kind FROM nodes n LEFT JOIN nodes p ON p.realm='' AND p.path=n.parent AND p.deleted=0 WHERE n.realm='' AND n.deleted=0 AND n.path!='/' AND (p.path IS NULL OR p.kind!='dir') ORDER BY n.path LIMIT 5").fetchall()
        if missing_parents:
            details = '; '.join(f'{child!r} requires directory {parent!r} '
                                f'({"missing" if kind is None else "found " + kind})'
                                for child, parent, kind in missing_parents)
            raise SetupError('Missing parent directories (up to 5 shown): ' + details)
        if not set(e[0] for e in EVIDENCE).issubset(r[0] for r in db.execute('SELECT category FROM profile_evidence')):
            raise SetupError('Research evidence is incomplete')
        changes = db.execute('SELECT count(*) FROM profile_changes').fetchone()[0]
        summary = status['patch_summary']
        if not summary or changes < summary['added_paths'] + summary['modified_imported_paths']:
            raise SetupError('Profile patch records are incomplete')
        if status.get('privilege_profile') == VERSION:
            if not db.execute("SELECT 1 FROM profile_evidence WHERE category='sudo delegation scenario'").fetchone():
                raise SetupError('Privilege research evidence is incomplete')
            accounts = json.loads(metadata['privilege_profile_accounts'])
            passwd = db.execute("SELECT content FROM nodes WHERE realm='' AND path='/etc/passwd'").fetchone()[0].decode()
            users = {p[0]: p for l in passwd.splitlines() if len(p := l.split(':')) == 7}
            for name in (BASE_USER, HIGH_USER):
                if users[name][2:4] != [str(accounts[name])] * 2:
                    raise SetupError('Privilege account identities are incomplete')
            for name in (PROOF_PATH, TICKET_PATH):
                if not db.execute('SELECT 1 FROM privilege_profile_changes WHERE path=?', (name,)).fetchone():
                    raise SetupError('Privilege expansion audit is incomplete')
        # ProcessManager creates missing runtime tables as usual
        # a partly written existing table must not crash the server after it starts listening
        if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='process_lifecycle'").fetchone():
            for realm, raw in db.execute('SELECT realm,data FROM process_lifecycle'):
                d = json.loads(raw)
                if (not realm or d['version'] != 1 or
                        any(not isinstance(d[k], dict) for k in ('processes', 'services', 'sessions')) or
                        any(not isinstance(d[k], list) for k in ('events', 'socket_inodes')) or
                        any(not isinstance(d[k], (int, float)) or not math.isfinite(d[k]) for k in ('boot_time', 'next_pid', 'next_inode'))):
                    raise SetupError('Incomplete process lifecycle state')
                _validate_process_records(d)
    return status


def _validate_process_records(d):
    for key, p in d['processes'].items():
        numbers = ('pid', 'ppid', 'pgid', 'sid', 'uid', 'gid', 'nice', 'job')
        strings = ('name', 'cwd', 'owner', 'service', 'env')
        if (any(type(p[k]) is not int for k in numbers) or key != str(p['pid']) or
                any(not isinstance(p[k], str) for k in strings) or p['state'] not in ('R', 'S', 'T', 'Z', 'X') or
                not isinstance(p['argv'], list) or not p['argv'] or any(not isinstance(x, str) for x in p['argv']) or
                any(type(p[k]) is not bool for k in ('nohup', 'disowned')) or
                not isinstance(p['sockets'], list) or any(not isinstance(x, str) or len(x.split()) < 10 for x in p['sockets'])):
            raise SetupError('Incomplete persisted process record')
        for name in ('started', 'deadline', 'remaining', 'ended', 'exit_code'):
            if p[name] is not None and (not isinstance(p[name], (int, float)) or not math.isfinite(p[name])):
                raise SetupError('Invalid process timing or result')
    for saved in d['sessions'].values():
        if type(saved['pid']) is not int or type(saved['next_job']) is not int:
            raise SetupError('Incomplete persisted session')
    for name, service in d['services'].items():
        if (service['name'] != name or type(service['pid']) is not int or
                type(service['restarts']) is not int or type(service['masked']) is not bool or
                any(not isinstance(service[k], str) for k in ('name','path','state','result')) or
                not isinstance(service['config'], dict) or not isinstance(service['templates'], list)):
            raise SetupError('Incomplete persisted service')
        for value in ([service['restart_at']] + service.get('starts', [])):
            if value is not None and (not isinstance(value, (int,float)) or not math.isfinite(value)):
                raise SetupError('Invalid service timing')
        _validate_process_records({'processes':{str(p['pid']):p for p in service['templates']}, 'services':{}, 'sessions':{}})


def _archive(cache_dir, tarball, sha256, progress):
    from . import bootstrap as b
    if tarball:
        path = Path(tarball).resolve()
        if not path.is_file():
            raise SetupError(f'Ubuntu archive does not exist: {path}')
        actual = b.sha256_file(path)
        if sha256 and actual.lower() != sha256.lower():
            raise SetupError('Rootfs SHA256 mismatch; supplied archive was not modified')
        return path, actual, False
    cache = Path(cache_dir).resolve(); cache.mkdir(parents=True, exist_ok=True)
    archive, sums = cache / b.ROOTFS_NAME, cache / 'jammy-SHA256SUMS'
    def valid_pair():
        try:
            expected = next(line.split()[0] for line in sums.read_text(encoding='utf-8').splitlines()
                            if len(line.split()) == 2 and line.split()[1].lstrip('*') == b.ROOTFS_NAME)
            return expected if len(expected) == 64 and archive.is_file() and b.sha256_file(archive) == expected.lower() else None
        except (OSError, UnicodeError, StopIteration):
            return None
    expected = valid_pair()
    if expected:
        progress('Reusing the checksum-verified complete Ubuntu archive')
        return archive, expected, False
    # Also repairs stale checksums, empty or truncated caches and interrupted .part downloads
    # two full attempts cover the current/ image changing during a download
    for attempt in range(2):
        progress('Downloading Ubuntu SHA256SUMS and the complete root filesystem...')
        b.download(b.ROOTFS_BASE + 'SHA256SUMS', sums)
        b.download(b.ROOTFS_BASE + b.ROOTFS_NAME, archive)
        expected = valid_pair()
        if expected:
            return archive, expected, True
        progress('Ubuntu archive checksum mismatch; refreshing the download')
    raise SetupError('Rootfs SHA256 mismatch after refresh; no filesystem was published')


# Reuse verified state, upgrade in a staging copy, or rebuild in full
# the caller holds runtime_lease through setup and the server's whole life
# a rebuild keeps the original as a backup and starts fresh attacker realms
def ensure_runtime_database(db_path, *, cache_dir='data', tarball=None, sha256=None,
                            hostname='srv-web-03', username='ubuntu', progress=print):
    from .bootstrap import ensure_database
    from .ubuntu_profile import install_profile
    requested = Path(db_path)
    if requested.is_symlink() or requested.exists() and not requested.is_file():
        raise SetupError(f'Filesystem database must be a regular file: {requested}')
    target = requested.resolve()
    if target.exists() and not target.is_file():
        raise SetupError(f'Filesystem database must be a regular file: {target}')
    progress(f'Checking the complete Ubuntu filesystem, profile and audit records: {target}')
    try:
        status = validate_database(target)
        progress(f"Reusing verified database: {status['base_nodes']} base nodes")
        return {**status, 'action': 'reused', 'profile_action': 'reused', 'path': str(target)}
    except (SetupError, sqlite3.Error, ValueError, KeyError, TypeError, IndexError) as exc:
        reason = str(exc) or type(exc).__name__
        progress(f'Filesystem setup required: {reason}')
    target.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=target.name + '.prepare-', dir=target.parent) as directory:
        stage = Path(directory) / 'fs.sqlite'
        repaired = False
        if target.exists() and target.stat().st_size:
            try:
                # A valid older expansion can be upgraded
                # without changing passwords, profile secrets or attacker overlays
                validate_database(target, allow_expansion_upgrade=True)
                _snapshot(target, stage)
                install_profile(stage)
                validate_database(stage)
                repaired = True
            except (SetupError, sqlite3.Error, ValueError, KeyError, TypeError, IndexError):
                for suffix in ('', '-wal', '-shm', '-journal'):
                    Path(str(stage) + suffix).unlink(missing_ok=True)
        downloaded = False
        if not repaired:
            archive, digest, downloaded = _archive(cache_dir, tarball, sha256, progress)
            ensure_database(stage, tarball=archive, sha256=digest, hostname=hostname,
                            username=username, profile=True, progress=progress)
        # The publication gate - version markers alone are never enough
        status = validate_database(stage)
        backup = backup_database(target, 'repair' if repaired else 'rebuild')
        if backup:
            progress(f'Previous database preserved: {backup}')
            if not repaired:
                progress('Rebuilding the base and starting fresh attacker realms; previous realms remain in the backup')
        _publish(stage, target)
    return {**status, 'action': 'repaired' if repaired else 'rebuilt' if backup else 'built',
            'profile_action': 'upgraded' if repaired else 'installed', 'path': str(target),
            'backup': backup, 'downloaded': downloaded, 'recovery_reason': reason}


def validate_retrieval(path):
    from .retrieval import SCHEMA_VERSION, HASH_DIMENSIONS, MAX_RECORDS, validate_record
    with closing(sqlite3.connect(Path(path).resolve().as_uri() + '?mode=ro', uri=True)) as db:
        if db.execute('PRAGMA quick_check').fetchone()[0] != 'ok':
            raise SetupError('Retrieval database integrity failed')
        meta = dict(db.execute('SELECT key,value FROM metadata'))
        encoder = json.loads(meta['encoder']); dim = int(meta['dimensions'])
        if meta['schema'] != SCHEMA_VERSION or encoder['type'] != 'featurehash-v1' or dim != HASH_DIMENSIONS:
            raise SetupError('Unsupported retrieval index')
        records, keys = [], set()
        for rid, command, family, kind, subject, raw, blob in db.execute('SELECT * FROM records ORDER BY rowid'):
            obj = json.loads(raw); info = validate_record(obj)
            if info != (command, family, kind, subject) or rid != hashlib.sha256(json.dumps(obj, sort_keys=True, ensure_ascii=False).encode()).hexdigest():
                raise SetupError('Retrieval record metadata mismatch')
            key = (command, obj['profile']['id'], obj['profile']['version_id'])
            if key in keys:
                raise SetupError('Duplicate retrieval records')
            keys.add(key)
            vector = struct.unpack('<' + 'f' * dim, blob)
            norm = sum(x*x for x in vector)
            if any(not math.isfinite(x) for x in vector) or abs(norm - 1) > .001:
                raise SetupError('Invalid retrieval vector')
            records.append(obj)
        if not 1 <= len(records) <= MAX_RECORDS or len(records) != int(meta['records']):
            raise SetupError('Incomplete retrieval corpus')
        if hashlib.sha256(json.dumps(records, sort_keys=True).encode()).hexdigest() != meta['corpus_sha256']:
            raise SetupError('Retrieval corpus digest mismatch')
    return meta


async def ensure_retrieval_database(path, corpus, *, progress=print):
    from .retrieval import RetrievalError, build_store
    if Path(path).is_symlink() or Path(path).exists() and not Path(path).is_file():
        raise SetupError('Retrieval database must be a regular file')
    target = Path(path).resolve()
    try:
        meta = validate_retrieval(target)
        return {'action': 'reused', 'records': int(meta['records'])}
    except (OSError, sqlite3.Error, ValueError, KeyError, TypeError, struct.error, SetupError, RetrievalError) as exc:
        progress(f'Rebuilding missing or incomplete retrieval index: {exc}')
    corpus = Path(corpus)
    if corpus.stat().st_size > 100 * 1024 * 1024:
        raise SetupError('Reference corpus exceeds 100 MiB')
    records = [json.loads(line) for line in corpus.read_text(encoding='utf-8').splitlines() if line.strip()]
    target.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=target.name + '.prepare-', dir=target.parent) as directory:
        stage = Path(directory) / 'retrieval.sqlite'
        await build_store(records, stage)
        meta = validate_retrieval(stage)
        backup = backup_database(target, 'rebuild')
        _publish(stage, target)
    progress(f"Retrieval ready: {meta['records']} genuine captured command references")
    return {'action': 'rebuilt' if backup else 'built', 'records': int(meta['records']), 'backup': backup}


# Load the login store, or create it on the first run with a random password per account
# returns the store and the new passwords - empty when the store already existed
# the passwords are not shown here; the caller shows them once, with the connect commands,
# so they are not repeated and land where they are used; only their verifiers are saved to disk
def prepare_passwords(path, *, announce=print):
    from .passwords import PasswordStore
    import secrets
    path = Path(path)
    if path.exists() or path.is_symlink():
        return PasswordStore.load(path), {}
    passwords = {name: secrets.token_urlsafe(24) for name in ('ubuntu', 'deploy', 'support')}
    store = PasswordStore.from_passwords(passwords)
    store.save(path)
    announce('First run - created SSH logins; their passwords are shown once below, with the connect commands.')
    return store, passwords


# Start Ollama only when it is installed and the URL is the default loopback one
# a daemon that accepts connections but does not answer yet is waited for, not restarted
# that covers the tray app or a fresh ollama serve still finding GPUs, slow on Windows
async def ensure_ollama_service(base_url, *, start=True, log_dir='logs', timeout=60, progress=print):
    import httpx
    url = (base_url if '://' in base_url else 'http://' + base_url).rstrip('/')
    refused = (httpx.ConnectError, httpx.ConnectTimeout)
    starting = (httpx.ReadTimeout, httpx.ReadError, httpx.RemoteProtocolError, httpx.WriteError, httpx.PoolTimeout)
    async def probe():
        async with httpx.AsyncClient(timeout=httpx.Timeout(5.0, connect=2.0), trust_env=False, follow_redirects=False) as client:
            r = await client.get(url + '/api/version'); r.raise_for_status()
            if not isinstance(r.json().get('version'), str):
                raise SetupError('Ollama returned an invalid version response')
    try:
        await probe()
        return {'started': False}
    except refused:
        pass
    except starting:
        progress(f'Waiting for the Ollama service at {url} to finish starting...')
        async with asyncio.timeout(timeout):
            while True:
                await asyncio.sleep(.5)
                try:
                    await probe()
                    return {'started': False}
                except refused + starting:
                    continue
    parts = urlsplit(url)
    if not start or parts.scheme != 'http' or parts.hostname not in ('127.0.0.1', 'localhost') or parts.port != 11434 or parts.path or parts.query or parts.username:
        raise SetupError(f'Ollama is unreachable at {url}; start that service or check --ollama-url')
    executable = shutil.which('ollama')
    if not executable:
        raise SetupError('Ollama is not installed/on PATH. Install Ollama, then run python run.py again')
    folder = Path(log_dir); folder.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, OLLAMA_HOST='127.0.0.1:11434')
    options = {'creationflags': subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP} if os.name == 'nt' else {'start_new_session': True}
    progress('Starting installed Ollama on 127.0.0.1:11434...')
    with (folder / 'ollama-startup.log').open('ab') as output:
        child = subprocess.Popen([executable, 'serve'], stdin=subprocess.DEVNULL, stdout=output,
                                 stderr=subprocess.STDOUT, env=env, **options)
    try:
        async with asyncio.timeout(timeout):
            while True:
                try:
                    await probe()
                    # Our child may have lost the port to an instance that was already starting
                    # either way a daemon now answers
                    return {'started': child.poll() is None, 'pid': child.pid}
                except refused:
                    if child.poll() is not None:
                        raise SetupError('Ollama exited before becoming ready; see logs/ollama-startup.log')
                except starting:
                    # Listening, but not answering yet
                    pass
                await asyncio.sleep(.25)
    except BaseException:
        if child.poll() is None:
            child.terminate()
            try:
                await asyncio.to_thread(child.wait, 5)
            except subprocess.TimeoutExpired:
                child.kill(); await asyncio.to_thread(child.wait, 5)
        raise


# Load the model with an empty generate request, without inventing a warm-up turn
async def load_model(base_url, model, *, timeout=180, num_ctx=8192, progress=print):
    import httpx
    url = (base_url if '://' in base_url else 'http://' + base_url).rstrip('/')
    progress(f'Loading {model} into Ollama (first load may take several minutes)...')
    async with asyncio.timeout(timeout):
        async with httpx.AsyncClient(timeout=timeout, trust_env=False, follow_redirects=False) as client:
            response = await client.post(url + '/api/generate', json={
                'model': model, 'prompt': '', 'stream': False, 'keep_alive': -1,
                'options': {'num_ctx': num_ctx}})
            response.raise_for_status()
            data = response.json()
            if data.get('error') or data.get('done') is not True:
                raise SetupError(f'Model load failed: {data.get("error", "incomplete response")}')
    return {'loaded': True, 'model': model}
