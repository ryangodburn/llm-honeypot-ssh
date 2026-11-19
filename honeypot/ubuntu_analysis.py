# Import Analysis
# inspects the imported Ubuntu database before any scenario patches are applied
# plain analysis of SQLite data - reads no host accounts or secrets and runs no imported file

# Imports
from __future__ import annotations

from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sqlite3

ANALYSIS_VERSION = "ubuntu-import-analysis-1"
NODE_FIELDS = "realm,path,parent,name,kind,mode,uid,gid,uname,gname,size,mtime,target,nlink,content,deleted"


# Hash a node's data and metadata without serialising binary bytes
def node_fingerprint(row):
    fields = list(row)
    content = fields[14]
    fields[14] = hashlib.sha256(content).hexdigest() if content is not None else None
    return hashlib.sha256(json.dumps(fields, ensure_ascii=True, separators=(",", ":")).encode()).hexdigest()


@dataclass
class ImportAnalysis:
    report: dict
    # Maps path -> kind, size, data hash (or None) and full node hash
    manifest: dict


# Read the imported image, list its data and find what the profile still needs
def analyze_import(db_path, targets=()):
    path = Path(db_path).resolve()
    with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)) as db:
        def content(name):
            row = db.execute("SELECT content FROM nodes WHERE realm='' AND path=? AND deleted=0", (name,)).fetchone()
            return bytes(row[0]).decode("utf-8", "replace") if row and row[0] is not None else ""

        manifest, kinds, setuid, world_writable = {}, {}, [], []
        stored_bytes = stored_files = missing_files = 0
        digest = hashlib.sha256()
        for row in db.execute(f"SELECT {NODE_FIELDS} FROM nodes WHERE realm='' AND deleted=0 ORDER BY path"):
            name, kind, mode, data = row[1], row[4], row[5], row[14]
            data_hash = hashlib.sha256(data).hexdigest() if data is not None else None
            fingerprint = node_fingerprint(row)
            manifest[name] = (kind, row[10], data_hash, fingerprint)
            digest.update((name + "\0" + fingerprint + "\n").encode())
            kinds[kind] = kinds.get(kind, 0) + 1
            stored_bytes += len(data) if data is not None else 0
            stored_files += int(data is not None)
            missing_files += int(kind == "file" and data is None)
            if kind == "file" and mode & 0o6000:
                setuid.append({"path": name, "mode": oct(mode), "uid": row[6], "gid": row[7]})
            if mode & 0o002:
                world_writable.append({"path": name, "kind": kind, "mode": oct(mode)})

        release = content("/usr/lib/os-release") or content("/etc/os-release")
        release_fields = {k:v.strip('"\'') for line in release.splitlines()
                          if "=" in line and not line.startswith("#") for k,v in [line.split("=",1)]}
        packages = {}
        for block in content("/var/lib/dpkg/status").split("\n\n"):
            fields = {k:v.strip() for line in block.splitlines() if ":" in line and not line.startswith(" ")
                      for k,v in [line.split(":",1)]}
            if fields.get("Package"):
                packages[fields["Package"]] = {k: fields.get(k) for k in ("Version", "Architecture", "Status")}
        accounts = []
        for line in content("/etc/passwd").splitlines():
            parts = line.split(":")
            if len(parts) == 7:
                accounts.append({"name": parts[0], "uid": int(parts[2]), "gid": int(parts[3]),
                                 "home": parts[5], "shell": parts[6]})
        kernels = sorted({name.removeprefix("/boot/vmlinuz-") for name in manifest
                          if name.startswith("/boot/vmlinuz-")},
                         key=lambda x: [int(n) for n in re.findall(r"\d+",x)], reverse=True)
        categories = []
        for category, paths, techniques, sources in targets:
            categories.append({"category": category, "present": [p for p in paths if p in manifest],
                               "missing": [p for p in paths if p not in manifest],
                               "techniques": techniques, "sources": sources})
        metadata = dict(db.execute("SELECT key,value FROM meta"))
        report = {
            "version": ANALYSIS_VERSION, "analyzed_at": datetime.now(timezone.utc).isoformat(),
            "stage": "before_profile", "method": "deterministic inspection of imported SQLite data",
            "rootfs_sha256": metadata.get("rootfs_sha256"),
            "import_mode": metadata.get("filesystem_import_mode", "legacy_or_fixture"),
            "source_manifest_sha256": digest.hexdigest(),
            "inventory": {"base_nodes": len(manifest), "kinds": kinds, "stored_files": stored_files,
                          "stored_bytes": stored_bytes, "regular_files_without_content": missing_files},
            "release": release_fields, "accounts": accounts, "packages": packages,
            "kernel_candidates": kernels,
            "service_units": [p for p in manifest if p.endswith(".service") and "/systemd/" in p],
            "cron_paths": [p for p in manifest if p.startswith(("/etc/cron", "/var/spool/cron"))],
            "ssh_paths": [p for p in manifest if p.startswith("/etc/ssh/") or "/.ssh/" in p],
            "setuid_setgid": setuid, "world_writable": world_writable,
            "research_categories": categories,
            "policy": "Preserve imported files by default; merge identity/package records and append history/log data; add missing profile paths; audit explicit virtual-host changes."
        }
        return ImportAnalysis(report, manifest)


# Save the analysis inside the transaction that applies the profile
def save_analysis(db, analysis):
    db.execute("CREATE TABLE IF NOT EXISTS profile_analysis (version TEXT PRIMARY KEY, document TEXT NOT NULL)")
    db.execute("INSERT OR REPLACE INTO profile_analysis VALUES (?,?)",
               (ANALYSIS_VERSION,json.dumps(analysis.report,sort_keys=True)))
    db.execute("CREATE TABLE IF NOT EXISTS ubuntu_source_manifest (path TEXT PRIMARY KEY,kind TEXT,size INTEGER,content_sha256 TEXT,node_sha256 TEXT)")
    db.executemany("INSERT OR REPLACE INTO ubuntu_source_manifest VALUES (?,?,?,?,?)",
                   [(path,*values) for path,values in analysis.manifest.items()])


# Check the current base image against the raw-import manifest and patch audit
# attacker overlays are separate from this proof
# scans one node at a time so a full image is never loaded into memory
def verify_enrichment(db_path):
    with closing(sqlite3.connect(Path(db_path).resolve().as_uri()+"?mode=ro", uri=True)) as db:
        analysis = json.loads(db.execute("SELECT document FROM profile_analysis WHERE version=?", (ANALYSIS_VERSION,)).fetchone()[0])
        sources = {r[0]:r[1:] for r in db.execute("SELECT path,kind,size,content_sha256,node_sha256 FROM ubuntu_source_manifest")}
        changes = {r[0]:r[1:] for r in db.execute("SELECT path,before_node,before_content,after_node_sha256 FROM profile_changes")}
        errors, seen, changed = [], set(), 0
        for row in db.execute(f"SELECT {NODE_FIELDS} FROM nodes WHERE realm='' AND deleted=0 ORDER BY path"):
            path = row[1]
            seen.add(path)
            fingerprint = node_fingerprint(row)
            source = sources.get(path)
            change = changes.get(path)
            if source and fingerprint == source[3]:
                continue
            if not change:
                errors.append({"path": path, "error": "change has no profile audit record"})
                continue
            if fingerprint != change[2]:
                errors.append({"path": path, "error": "current node does not match recorded profile result"})
            if source:
                changed += 1
                if change[0] is None:
                    errors.append({"path": path, "error": "missing original imported node"})
                else:
                    before = json.loads(change[0])
                    before[14] = change[1]
                    if node_fingerprint(before) != source[3]:
                        errors.append({"path": path, "error": "saved original does not match import manifest"})
        missing = sorted(set(sources) - seen)
        errors.extend({"path":p, "error":"recorded profile result is missing"} for p in sorted(set(changes)-seen))
        return {"source_nodes": len(sources), "current_base_nodes": len(seen),
                "changed_imported_nodes": changed, "missing_imported_paths": missing,
                "unaccounted_changes": errors, "analysis": analysis}
