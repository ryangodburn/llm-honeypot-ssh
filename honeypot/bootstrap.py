# Operator Setup
# downloads, imports and checks the Ubuntu image and the Qwen model
# safe to run repeatedly and never given attacker-supplied URLs

# Imports
from __future__ import annotations

import asyncio
from contextlib import closing
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import subprocess
import tarfile
import tempfile
import time
from urllib.parse import urlsplit, urljoin

ROOTFS_NAME = "jammy-server-cloudimg-amd64-root.tar.xz"
ROOTFS_BASE = "https://cloud-images.ubuntu.com/jammy/current/"


class SetupError(RuntimeError):
    pass


def inspect_database(db_path):
    path = Path(db_path).resolve()
    if not path.exists() or path.stat().st_size == 0:
        return {"ready": False, "reason": "missing or empty", "base_nodes": 0,
                "overlay_nodes": 0}
    try:
        with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)) as db:
            if db.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                raise SetupError(f"Database failed quick_check: {path}")
            count = db.execute("SELECT COUNT(*) FROM nodes WHERE realm='' AND deleted=0").fetchone()[0]
            overlays = db.execute("SELECT COUNT(*) FROM nodes WHERE realm<>''").fetchone()[0]
            root = db.execute("SELECT kind FROM nodes WHERE realm='' AND path='/' AND deleted=0").fetchone()
            passwd = db.execute("SELECT content FROM nodes WHERE realm='' AND path='/etc/passwd' AND deleted=0").fetchone()
            readable = db.execute("SELECT COUNT(*) FROM nodes WHERE realm='' AND content IS NOT NULL AND deleted=0").fetchone()[0]
            ready = bool(count and root and root[0] == "dir" and passwd and passwd[0])
            metadata = dict(db.execute("SELECT key,value FROM meta"))
            return {"ready": ready, "base_nodes": count, "overlay_nodes": overlays,
                    "stored_files": readable,
                    "profile": metadata.get("attacker_profile"),
                    "privilege_profile": metadata.get("privilege_profile"),
                    "profile_kind": metadata.get("profile_kind"),
                    "rootfs_sha256": metadata.get("rootfs_sha256"),
                    "import_mode": metadata.get("filesystem_import_mode", "legacy_selective"),
                    "analysis_version": metadata.get("profile_analysis_version"),
                    "patch_summary": json.loads(metadata.get("profile_patch_summary", "null")),
                    "reason": "ready" if ready else "missing base root or readable /etc/passwd"}
    except sqlite3.Error as exc:
        raise SetupError(f"Existing database is not usable; preserved unchanged: {path}: {exc}") from exc


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


# Download over HTTPS into a temporary file
# uses curl when present, otherwise the Python client
def download(url, destination):
    executable = shutil.which("curl")
    if not executable:
        return _python_download(url, destination)
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    part = destination.with_name(destination.name + ".part")
    argv = [executable, "--fail", "--location", "--show-error", "--silent",
            "--retry", "2", "--connect-timeout", "15", "--max-time", "1800",
            "--proto", "=https", "--proto-redir", "=https",
            "--output", str(part), url]
    try:
        subprocess.run(argv, check=True)
        if not part.stat().st_size:
            raise SetupError(f"Empty download: {url}")
        os.replace(part, destination)
    except (OSError, subprocess.CalledProcessError) as exc:
        raise SetupError(f"Download failed: {url}. Retry with network access or supply --tarball.") from exc
    finally:
        part.unlink(missing_ok=True)


def _python_download(url, destination):
    import httpx
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    part = destination.with_name(destination.name + '.part')
    deadline = time.monotonic() + 1800
    try:
        with httpx.Client(trust_env=False, follow_redirects=False, timeout=httpx.Timeout(60, connect=15)) as client:
            for _ in range(11):
                if urlsplit(url).scheme != 'https':
                    raise SetupError('Ubuntu setup downloads and redirects must use HTTPS')
                with client.stream('GET', url) as response:
                    if response.is_redirect:
                        url = urljoin(url, response.headers['location'])
                        continue
                    response.raise_for_status()
                    count = 0
                    with part.open('wb') as output:
                        for chunk in response.iter_bytes(1024 * 1024):
                            if time.monotonic() > deadline:
                                raise SetupError('Ubuntu download exceeded its 30-minute deadline')
                            count += len(chunk); output.write(chunk)
                    length = response.headers.get('content-length')
                    if not count or length is not None and not response.headers.get('content-encoding') and count != int(length):
                        raise SetupError('Ubuntu download was empty or incomplete')
                    os.replace(part, destination)
                    return
            raise SetupError('Too many redirects during Ubuntu download')
    except (httpx.HTTPError, OSError, ValueError, KeyError) as exc:
        raise SetupError(f'Ubuntu HTTPS download failed; retry with network access: {exc}') from exc
    finally:
        part.unlink(missing_ok=True)


# Reuse a valid database or import a new one atomically
# an invalid populated database is kept, never reset - pick a new path or repair it
# the Ubuntu profile is patched into the temporary copy before it is published
# an older unpatched database is backed up and enriched once, overlays are kept
def ensure_database(db_path="fs.sqlite", *, cache_dir="data", tarball=None,
                    sha256=None, hostname="srv-web-03", username="ubuntu",
                    profile=True, progress=print, repair=False):
    if not profile:
        raise SetupError('The honeypot requires the full Ubuntu profile')
    if repair:
        from .startup import ensure_runtime_database
        try:
            return ensure_runtime_database(db_path, cache_dir=cache_dir, tarball=tarball,
                sha256=sha256, hostname=hostname, username=username, progress=progress)
        except (OSError, sqlite3.Error, ValueError, KeyError, TypeError, IndexError) as exc:
            raise SetupError(f'Automatic filesystem setup failed; retry after resolving: {exc}') from exc
    from honeypot.ubuntu_profile import EVIDENCE, PROFILE_VERSION, install_profile
    from honeypot.ubuntu_analysis import analyze_import

    def profile_ready(status):
        installed = status.get("profile")
        if profile and installed and installed != PROFILE_VERSION:
            raise SetupError("A different Ubuntu profile exists; database preserved. An explicit migration is required.")
        from honeypot.privilege_profile import VERSION as PRIVILEGE_VERSION
        return not profile or (installed == PROFILE_VERSION and status.get("privilege_profile") == PRIVILEGE_VERSION)

    def reused(status):
        progress(f"Reusing {db_path.name}: {status['base_nodes']} base nodes")
        if profile and status.get("import_mode") != "full_rootfs":
            progress("Existing database uses the earlier selective import; preserved. Choose a new --db/--fs-db path for a full Ubuntu import.")
        return {**status, "action": "reused", "path": str(db_path),
                "profile_action": "reused" if profile else "not_requested"}

    db_path = Path(db_path).resolve()
    status = inspect_database(db_path)
    if status["ready"] and profile_ready(status):
        return reused(status)
    if not status["ready"] and (status["base_nodes"] or status["overlay_nodes"]):
        raise SetupError(f"Incomplete populated database preserved: {db_path}. Choose a new --db path.")
    db_path.parent.mkdir(parents=True, exist_ok=True)
    lock = db_path.with_name(db_path.name + ".setup.lock")
    try:
        fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError as exc:
        raise SetupError(f"Setup is already running ({lock}). Remove a stale lock only after checking its process.") from exc
    os.close(fd)
    temp_db = None
    importer = None
    try:
        # Another process may have finished setup just before the lock was taken
        current = inspect_database(db_path)
        if current["ready"]:
            if profile_ready(current):
                return reused(current)
            # The SQLite backup also copies committed changes still in the WAL
            stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
            backup = db_path.with_name(db_path.name + ".before-profile-" + stamp + ".bak")
            with backup.open("xb"):
                pass
            with closing(sqlite3.connect(db_path.as_uri() + "?mode=ro", uri=True)) as src, closing(sqlite3.connect(backup)) as dst:
                src.backup(dst)
            progress("Analyzing the existing imported Ubuntu database...")
            analysis = analyze_import(db_path, EVIDENCE)
            progress(f"Adding/merging Ubuntu profile details (backup: {backup})...")
            patched = install_profile(db_path, analysis=analysis)
            return {**inspect_database(db_path), "action": "profile_applied",
                    "profile_action": patched["action"], "path": str(db_path),
                    "backup": str(backup)}
        if current["base_nodes"] or current["overlay_nodes"]:
            raise SetupError(f"Incomplete populated database preserved: {db_path}. Choose a new --db path.")
        downloaded = False
        if tarball:
            archive = Path(tarball).resolve()
            if not archive.is_file():
                raise SetupError(f"Tarball does not exist: {archive}")
            expected = sha256
        else:
            cache = Path(cache_dir).resolve()
            cache.mkdir(parents=True, exist_ok=True)
            archive = cache / ROOTFS_NAME
            checksum_file = cache / "jammy-SHA256SUMS"
            if not checksum_file.exists() or not archive.exists():
                progress("Downloading Ubuntu SHA256SUMS with curl...")
                download(ROOTFS_BASE + "SHA256SUMS", checksum_file)
            sums = checksum_file.read_text(encoding="utf-8")
            expected = next((line.split()[0] for line in sums.splitlines()
                             if len(line.split()) == 2 and
                             line.split()[1].lstrip("*") == ROOTFS_NAME), None)
            if expected is None:
                raise SetupError("Ubuntu SHA256SUMS does not contain the rootfs archive")
            if not archive.exists():
                progress("Downloading Ubuntu root filesystem with curl (several hundred MB)...")
                download(ROOTFS_BASE + ROOTFS_NAME, archive)
                downloaded = True
        digest = sha256_file(archive)
        if expected and (not re.fullmatch(r"[0-9a-fA-F]{64}", expected) or digest.lower() != expected.lower()):
            if downloaded:
                archive.unlink(missing_ok=True)
            raise SetupError("Rootfs SHA256 mismatch. Database unchanged; refresh the cached archive and SHA256SUMS.")
        progress("Importing the complete downloaded filesystem into SQLite (including regular-file contents)...")
        from honeypot.rootfs import Importer
        with tempfile.NamedTemporaryFile(prefix=db_path.name + ".build-", suffix=".sqlite",
                                         dir=db_path.parent, delete=False) as temporary:
            temp_db = Path(temporary.name)
        importer = Importer(str(temp_db))
        importer.ensure_root()
        importer.from_tarball(str(archive))
        if profile:
            # Check the imported image before adding any host files
            # a bad or empty archive must never be published
            release = importer.db.execute("SELECT content FROM nodes WHERE realm='' AND path IN ('/usr/lib/os-release','/etc/os-release') AND content IS NOT NULL ORDER BY path DESC LIMIT 1").fetchone()
            release = bytes(release[0]).decode("utf-8", "replace") if release else ""
            fields = dict(line.split("=", 1) for line in release.splitlines() if "=" in line and not line.startswith("#"))
            if fields.get("ID", "").strip("\"'") != "ubuntu" or fields.get("VERSION_ID", "").strip("\"'") != "22.04":
                raise SetupError("Ubuntu profile requires an imported Ubuntu 22.04 rootfs; no database was published.")
            for required in ("/etc/passwd", "/var/lib/dpkg/status"):
                row = importer.db.execute("SELECT content FROM nodes WHERE realm='' AND path=?", (required,)).fetchone()
                if not row or not row[0]:
                    raise SetupError(f"Ubuntu rootfs is missing readable {required}; no database was published.")
        importer.db.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('rootfs_sha256',?)", (digest,))
        importer.db.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('rootfs_source',?)", (str(archive),))
        importer.db.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('filesystem_import_mode','full_rootfs')")
        importer.finish()
        importer = None
        built = inspect_database(temp_db)
        if not built["ready"]:
            raise SetupError(f"Imported image is incomplete: {built['reason']}")
        profile_action = "not_requested"
        if profile:
            progress("Analyzing the downloaded Ubuntu database: accounts, packages, services, permissions and profile gaps...")
            analysis = analyze_import(temp_db, EVIDENCE)
            if analysis.report["inventory"]["regular_files_without_content"]:
                raise SetupError("Full Ubuntu import has missing file contents; no database was published.")
            progress(f"Analysis complete: {analysis.report['inventory']['base_nodes']} imported nodes; adding/merging attacker-interest profile details into this database...")
            profile_action = install_profile(temp_db, analysis=analysis)["action"]
            built = inspect_database(temp_db)
            if not built["ready"] or built.get("profile") != PROFILE_VERSION:
                raise SetupError("Ubuntu profile setup did not complete; no database was published.")
        # Publish the closed and checkpointed SQLite file as one unit
        with closing(sqlite3.connect(temp_db)) as db:
            db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            db.execute("PRAGMA journal_mode=DELETE")
        os.replace(temp_db, db_path)
        return {**built, "action": "built", "downloaded": downloaded,
                "sha256": digest, "path": str(db_path), "profile_action": profile_action}
    except (OSError, sqlite3.Error, tarfile.TarError, ValueError) as exc:
        raise SetupError(f"Filesystem setup failed; existing database preserved: {exc}") from exc
    finally:
        if importer is not None:
            importer.db.close()
        if temp_db is not None:
            for suffix in ("", "-wal", "-shm"):
                Path(str(temp_db) + suffix).unlink(missing_ok=True)
        lock.unlink(missing_ok=True)


# Require a running Ollama and the exact model tag
# pulls the model only when it is missing
async def ensure_model(base_url, model="qwen3.5:9b", *, pull=True, progress=print, timeout_s=1800):
    import httpx
    base_url = (base_url if "://" in base_url else "http://" + base_url).rstrip("/")

    async def prepare():
        async with httpx.AsyncClient(base_url=base_url.rstrip("/"),
                                     timeout=httpx.Timeout(timeout_s, connect=5),
                                     trust_env=False, follow_redirects=False) as client:
            version = await client.get("/api/version")
            version.raise_for_status()
            tags = await client.get("/api/tags")
            tags.raise_for_status()
            models = tags.json().get("models", [])
            selected = next((m for m in models if model in (m.get("name"), m.get("model"))), None)
            pulled = False
            if selected is None:
                if not pull:
                    raise SetupError(f"Model {model} is missing. Run: ollama pull {model}")
                progress(f"Pulling {model} through Ollama /api/pull...")
                last = None
                success = False
                async with client.stream("POST", "/api/pull", json={"model": model, "stream": True}) as response:
                    response.raise_for_status()
                    async for line in response.aiter_lines():
                        if not line.strip():
                            continue
                        item = json.loads(line)
                        if item.get("error"):
                            raise SetupError(str(item["error"]))
                        status = item.get("status")
                        if status != last:
                            progress(f"Ollama: {status}")
                            last = status
                        success |= status == "success"
                if not success:
                    raise SetupError("Ollama pull ended without a success response")
                pulled = True
                tags = await client.get("/api/tags")
                tags.raise_for_status()
                selected = next((m for m in tags.json().get("models", [])
                                 if model in (m.get("name"), m.get("model"))), None)
                if selected is None:
                    raise SetupError("Requested model is still absent after pull")
            shown = await client.post("/api/show", json={"model": model})
            shown.raise_for_status()
            capabilities = shown.json().get("capabilities")
            if capabilities is not None and "tools" not in capabilities:
                raise SetupError(f"{model} does not advertise native tools; update Ollama/model")
            return {"model": model, "digest": selected.get("digest"),
                    "ollama_version": version.json().get("version"),
                    "capabilities": capabilities, "pulled": pulled}
    try:
        return await asyncio.wait_for(prepare(), timeout=timeout_s)
    except SetupError:
        raise
    except (httpx.HTTPError, ValueError, asyncio.TimeoutError) as exc:
        raise SetupError(f"Cannot prepare real Ollama at {base_url}: {exc}. "
                         "Install/start Ollama (ollama serve), or set --ollama-url to its reachable address.") from exc
