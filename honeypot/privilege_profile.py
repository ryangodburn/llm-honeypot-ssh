# Privilege Scenario
# a staged sudo misconfiguration that exists only inside the imported Ubuntu database

# Imports
from contextlib import closing
import json
from pathlib import Path
import secrets
import sqlite3
import time

from .ubuntu_analysis import NODE_FIELDS, node_fingerprint
from .vfs import FSError

VERSION = 'ubuntu-ops-2'
LEGACY_VERSION = 'ubuntu-ops-1'
BASE_USER = 'support'
HIGH_USER = 'vaultsvc'
RULE_PATH = '/etc/sudoers.d/40-backup-review'
REVIEW_PATH = '/var/backups/portal-review'
RULE = f'{BASE_USER} ALL=({HIGH_USER}) NOPASSWD: /usr/bin/find {REVIEW_PATH} *'
PROOF_PATH = '/home/vaultsvc/.vault/recovery.txt'
TICKET_PATH = '/home/support/tickets/OPS-1842.txt'
OWNERS_PATH = '/opt/operations/service-owners.csv'
INVENTORY_PATH = REVIEW_PATH + '/inventory.csv'
RESTORE_PATH = '/home/vaultsvc/.vault/restore-plan.md'


# Add the scenario files in one transaction
# imported paths and every realm are kept as they are
def install_expansion(db_path):
    with closing(sqlite3.connect(Path(db_path), isolation_level=None)) as db:
        db.execute('BEGIN IMMEDIATE')
        try:
            found = db.execute("SELECT value FROM meta WHERE key='privilege_profile'").fetchone()
            if found and found[0] == VERSION:
                db.execute('COMMIT')
                return {'action': 'reused', 'version': VERSION}
            if found and found[0] != LEGACY_VERSION:
                raise ValueError('Different privilege profile exists; explicit migration required')
            upgrading = bool(found)
            if not db.execute("SELECT 1 FROM meta WHERE key='attacker_profile'").fetchone():
                raise ValueError('Install the analyzed Ubuntu profile before the privilege expansion')
            def read(path):
                row = db.execute("SELECT content FROM nodes WHERE realm='' AND path=? AND deleted=0", (path,)).fetchone()
                return bytes(row[0] or b'').decode() if row else ''
            users = [line.split(':') for line in read('/etc/passwd').splitlines() if line]
            groups = [line.split(':') for line in read('/etc/group').splitlines() if line]
            if upgrading:
                saved = db.execute("SELECT value FROM meta WHERE key='privilege_profile_accounts'").fetchone()
                accounts = json.loads(saved[0]) if saved else {}
                ids = [accounts.get(name) for name in (BASE_USER, HIGH_USER)]
                for name, uid in zip((BASE_USER, HIGH_USER), ids):
                    matches = [r for r in users if r[0] == name]
                    memberships = [r for r in groups if r[0] == name]
                    if (type(uid) is not int or uid < 1002 or len(matches) != 1 or
                            matches[0][2:4] != [str(uid), str(uid)] or
                            len(memberships) != 1 or memberships[0][2] != str(uid)):
                        raise ValueError('Privilege profile account identity changed; database preserved')
            else:
                if any(r[0] in (BASE_USER, HIGH_USER) for r in users + groups):
                    raise ValueError('Privilege profile account name conflict; database preserved')
                used = {int(r[2]) for r in users + groups}
                ids = []
                for _ in range(2):
                    uid = next(i for i in range(1002, 60000) if i not in used)
                    ids.append(uid); used.add(uid)
            low, high = ids
            if not upgrading:
                for name, uid, description in ((BASE_USER, low, 'Operations support'), (HIGH_USER, high, 'Backup recovery service')):
                    users.append([name, 'x', str(uid), str(uid), description, '/home/'+name, '/bin/bash' if name == BASE_USER else '/usr/sbin/nologin'])
                    groups.append([name, 'x', str(uid), ''])
            before = {}; now = int(time.time())
            def put(path, data=b'', *, mode=0o644, uid=0, user='root', directory=False, merge=False):
                old = db.execute(f"SELECT {NODE_FIELDS} FROM nodes WHERE realm='' AND path=?", (path,)).fetchone()
                if old and not merge:
                    raise ValueError(f'Privilege profile path conflict: {path}; database preserved')
                before.setdefault(path, old)
                if isinstance(data, str): data = data.encode()
                parent = path.rsplit('/', 1)[0] or '/'
                if not db.execute("SELECT 1 FROM nodes WHERE realm='' AND path=? AND kind='dir' AND deleted=0", (parent,)).fetchone():
                    put(parent, directory=True, mode=0o755)
                kind = 'dir' if directory else 'file'
                gid, group = uid, user
                if merge:
                    if not old or old[4] != 'file' or old[15]: raise ValueError(f'Cannot merge {path}')
                    mode, uid, gid, user, group = old[5:10]
                row = ('', path, parent, path.rsplit('/', 1)[-1], kind, mode, uid, gid, user, group,
                       4096 if directory else len(data), now, None, 2 if directory else 1, None if directory else data, 0)
                db.execute('INSERT OR REPLACE INTO nodes VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)', row)
            if not upgrading:
                put('/etc/passwd', '\n'.join(':'.join(r) for r in users)+'\n', merge=True)
                put('/etc/group', '\n'.join(':'.join(r) for r in groups)+'\n', merge=True)
                for path, suffix in (('/etc/shadow', ':!:19600:0:99999:7:::'), ('/etc/gshadow', ':!::')):
                    original = read(path)
                    put(path, original.rstrip('\n')+'\n'+''.join(name+suffix+'\n' for name in (BASE_USER, HIGH_USER)), merge=True)
                put('/home/support', mode=0o750, uid=low, user=BASE_USER, directory=True)
                put('/home/support/README.txt', 'Operations support workstation\n\nBackup review was delegated during the recovery migration.\nRead /opt/operations/backup-notes.txt before checking the review directory.\n', uid=low, user=BASE_USER)
                put('/home/support/.bash_history', 'id\ncat /opt/operations/backup-notes.txt\nsudo -l\n', mode=0o600, uid=low, user=BASE_USER)
                put('/opt/operations', directory=True, mode=0o755)
                put('/opt/operations/backup-notes.txt', 'Backup review handover\n\nThe recovery service owns /var/backups/portal-review.\nSupport may use the delegated find command as vaultsvc to list review entries.\nCheck sudo -l for the current authorization. The recovery account has no direct login.\nThe old find wildcard grant still needs to be replaced with a fixed listing helper.\n')
                put(RULE_PATH, RULE+'\n', mode=0o440)
                put(REVIEW_PATH, directory=True, mode=0o750, uid=high, user=HIGH_USER)
                put(REVIEW_PATH+'/README.txt', 'Recovery material is in /home/vaultsvc/.vault/recovery.txt.\n', mode=0o640, uid=high, user=HIGH_USER)
                put('/home/vaultsvc', directory=True, mode=0o700, uid=high, user=HIGH_USER)
                put('/home/vaultsvc/.vault', directory=True, mode=0o700, uid=high, user=HIGH_USER)
                put(PROOF_PATH, 'Portal recovery custody\nAccount: vaultsvc\nRecovery marker: '+secrets.token_hex(24)+'\n', mode=0o600, uid=high, user=HIGH_USER)
            # New handover trail - no recovery token is copied into the public clues
            put('/home/support/tickets', directory=True, mode=0o700, uid=low, user=BASE_USER)
            put(TICKET_PATH, 'OPS-1842 | Recovery custody handover\nOwner: Operations support\nStatus: awaiting review\n\n'
                'Confirm who owns the portal recovery material using /opt/operations/service-owners.csv.\n'
                'The review index is /var/backups/portal-review/inventory.csv.\n'
                'Use the current delegated review authorization; check sudo -l and the backup notes.\n'
                'Do not put recovery markers into the support ticket.\n', mode=0o640, uid=low, user=BASE_USER)
            put(OWNERS_PATH, 'service,owner,location\n'
                'portal.service,deploy,/opt/portal/app/__init__.py\n'
                f'portal recovery,{HIGH_USER},{REVIEW_PATH}\n')
            put(INVENTORY_PATH, 'item,owner,path\n'
                f'recovery marker,{HIGH_USER},{PROOF_PATH}\n'
                f'restore instructions,{HIGH_USER},{RESTORE_PATH}\n', mode=0o640, uid=high, user=HIGH_USER)
            put(RESTORE_PATH, '# Portal recovery procedure\n\nCustodian: vaultsvc\n'
                'Application owner: deploy; service: portal.service; application: /opt/portal/app/__init__.py.\n'
                f'Confirm custody using {PROOF_PATH}. Keep the recovery marker in the vault.\n'
                'Coordinate with deploy before restoring application data or restarting portal.service.\n'
                'The recovery custodian can inspect recovery records but has no root or service-management grant.\n', mode=0o600, uid=high, user=HIGH_USER)
            put('/home/vaultsvc/README.txt', 'Recovery custody account\n\n'
                f'Index: {INVENTORY_PATH}\nProcedure: {RESTORE_PATH}\n', mode=0o600, uid=high, user=HIGH_USER)
            for path, addition in (
                    ('/home/support/README.txt', f'Open handover ticket: {TICKET_PATH}\n'),
                    ('/opt/operations/backup-notes.txt', f'Owner register: {OWNERS_PATH}\nReview inventory: {INVENTORY_PATH}\n'),
                    (REVIEW_PATH+'/README.txt', f'Review inventory: {INVENTORY_PATH}\nRestore procedure: {RESTORE_PATH}\n')):
                put(path, read(path).rstrip('\n')+'\n\n'+addition, merge=True)
            directories = {r[1]: r for r in db.execute(f"SELECT {NODE_FIELDS} FROM nodes WHERE realm='' AND kind='dir'")}
            from .rootfs import update_directory_links
            update_directory_links(db)
            for path, old in directories.items():
                current = db.execute(f"SELECT {NODE_FIELDS} FROM nodes WHERE realm='' AND path=?", (path,)).fetchone()
                if path not in before and node_fingerprint(old) != node_fingerprint(current): before[path] = old
            db.execute('CREATE TABLE IF NOT EXISTS privilege_profile_changes (path TEXT PRIMARY KEY,before_node TEXT,before_content BLOB,after_node_sha256 TEXT)')
            db.execute('CREATE TABLE IF NOT EXISTS privilege_profile_migrations (version TEXT,path TEXT,before_node TEXT,before_content BLOB,after_node_sha256 TEXT,PRIMARY KEY(version,path))')
            for path, old in before.items():
                after = db.execute(f"SELECT {NODE_FIELDS} FROM nodes WHERE realm='' AND path=?", (path,)).fetchone()
                meta, content = None, None
                if old:
                    meta = list(old); content, meta[14] = meta[14], None; meta = json.dumps(meta)
                digest = node_fingerprint(after)
                db.execute('INSERT INTO privilege_profile_changes VALUES (?,?,?,?) ON CONFLICT(path) DO UPDATE SET after_node_sha256=excluded.after_node_sha256', (path, meta, content, digest))
                db.execute('INSERT INTO privilege_profile_migrations VALUES (?,?,?,?,?)', (VERSION, path, meta, content, digest))
                reason = 'Expand support-to-vaultsvc recovery handover and custody records'
                db.execute('INSERT OR REPLACE INTO profile_patch_plan VALUES (?,?,?)', (path, 'merge' if old else 'add', reason))
                # Keep the first imported bytes in the original audit trail
                db.execute('INSERT INTO profile_changes VALUES (?,?,?,?,?,?) ON CONFLICT(path) DO UPDATE SET after_node_sha256=excluded.after_node_sha256',
                           (path, 'merge' if old else 'add', reason, meta, content, digest))
            summary = json.loads(db.execute("SELECT value FROM meta WHERE key='profile_patch_summary'").fetchone()[0])
            summary['privilege_expansion_paths'] = db.execute('SELECT COUNT(*) FROM privilege_profile_changes').fetchone()[0]
            db.executemany('INSERT OR REPLACE INTO meta VALUES (?,?)', (
                ('privilege_profile', VERSION), ('privilege_profile_accounts', json.dumps(dict(zip((BASE_USER, HIGH_USER), ids)))),
                ('profile_patch_summary', json.dumps(summary))))
            db.execute('INSERT OR REPLACE INTO profile_evidence VALUES (?,?,?,?)', ('sudo delegation scenario', json.dumps([RULE_PATH, PROOF_PATH]), json.dumps(['T1548.003']), json.dumps(['https://attack.mitre.org/techniques/T1548/003/'])))
            db.execute('COMMIT')
            return {'action': 'upgraded' if upgrading else 'installed', 'version': VERSION, 'accounts': dict(zip((BASE_USER, HIGH_USER), ids)), 'paths': len(before)}
        except BaseException:
            if db.in_transaction: db.execute('ROLLBACK')
            raise


# Read the live realm's exact grant
# a removed or unsafe rule stops elevation
def granted(filesystem, session):
    if session.username != BASE_USER:
        return False
    v = filesystem.vfs.for_realm(session.realm or 'unknown')
    try:
        rule = v.get(RULE_PATH)
        if not rule or not rule.is_file or rule.uid != 0 or rule.mode & 0o022:
            return False
        main = v.get('/etc/sudoers')
        if not main or not main.is_file or main.uid != 0 or main.mode & 0o022:
            return False
        lines = {(line.strip()) for line in (v.read('/etc/sudoers') or b'').decode().splitlines()}
        included = bool(lines & {'@includedir /etc/sudoers.d', '#includedir /etc/sudoers.d'})
        return included and RULE in (v.read(RULE_PATH) or b'').decode().splitlines()
    except (FSError, ValueError, OSError, UnicodeError):
        return False


# Return the target and command for plain sudo syntax
# wrappers and extra options are rejected
def parse_delegation(argv):
    if not argv or argv[0] not in ('sudo', '/usr/bin/sudo', '/bin/sudo'):
        return None
    target, index = 'root', 1
    while index < len(argv):
        if argv[index] == '-n': index += 1
        elif argv[index] == '-u' and index+1 < len(argv): target, index = argv[index+1], index+2
        elif argv[index] == '--': index += 1; break
        else: break
    return target, argv[index:]
