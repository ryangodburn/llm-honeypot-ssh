# SSH Front End
# ends the SSH transport, records every login attempt and hands each channel to its handler
# the banner is set to OpenSSH, since AsyncSSH would otherwise name itself before login
# the algorithm offer follows OpenSSH 8.9 on Ubuntu 22.04, which ssh-audit and nmap read
# host keys are kept between runs, a changing key is a loud tell
# public keys are offered and always fail, so clients fall back to a password as usual

# Imports
from __future__ import annotations

import asyncio
import random
from pathlib import Path
from typing import Optional

import asyncssh

from .config import Config
from .passwords import PasswordStore
from .evallog import EvalLog
from .persona import Persona
from .session import SessionState, run_exec, run_shell

# Ubuntu 22.04 and OpenSSH 8.9p1 defaults in server order
# filtered against what asyncssh implements, so an unknown name never breaks startup
_OPENSSH_KEX = [
    "sntrup761x25519-sha512@openssh.com", "curve25519-sha256",
    "curve25519-sha256@libssh.org", "ecdh-sha2-nistp256",
    "ecdh-sha2-nistp384", "ecdh-sha2-nistp521",
    "diffie-hellman-group-exchange-sha256", "diffie-hellman-group16-sha512",
    "diffie-hellman-group18-sha512", "diffie-hellman-group14-sha256",
]
_OPENSSH_ENC = [
    "chacha20-poly1305@openssh.com", "aes128-ctr", "aes192-ctr", "aes256-ctr",
    "aes128-gcm@openssh.com", "aes256-gcm@openssh.com",
]
_OPENSSH_MAC = [
    "umac-64-etm@openssh.com", "umac-128-etm@openssh.com",
    "hmac-sha2-256-etm@openssh.com", "hmac-sha2-512-etm@openssh.com",
    "hmac-sha1-etm@openssh.com", "umac-64@openssh.com", "umac-128@openssh.com",
    "hmac-sha2-256", "hmac-sha2-512", "hmac-sha1",
]


def _supported(wanted: list[str], available: list[bytes]) -> list[str]:
    have = {a.decode() for a in available}
    return [a for a in wanted if a in have]


def algorithm_options() -> dict:
    from asyncssh.encryption import get_encryption_algs
    from asyncssh.kex import get_kex_algs
    from asyncssh.mac import get_mac_algs

    opts = {}
    kex = _supported(_OPENSSH_KEX, get_kex_algs())
    enc = _supported(_OPENSSH_ENC, get_encryption_algs())
    mac = _supported(_OPENSSH_MAC, get_mac_algs())
    if kex:
        opts["kex_algs"] = kex
    if enc:
        opts["encryption_algs"] = enc
    if mac:
        opts["mac_algs"] = mac
    return opts


# Generate rsa, ecdsa and ed25519 host keys once and reuse them after that
def ensure_host_keys(directory: str | Path) -> list[str]:
    d = Path(directory)
    d.mkdir(parents=True, exist_ok=True)
    specs = [
        ("ssh_host_rsa_key", "ssh-rsa", {"key_size": 3072}),
        ("ssh_host_ecdsa_key", "ecdsa-sha2-nistp256", {}),
        ("ssh_host_ed25519_key", "ssh-ed25519", {}),
    ]
    paths = []
    for name, alg, kwargs in specs:
        p = d / name
        if not p.exists():
            key = asyncssh.generate_private_key(alg, **kwargs)
            key.write_private_key(str(p))
            key.write_public_key(str(p) + ".pub")
            p.chmod(0o600)
        paths.append(str(p))
    return paths


# One instance per TCP connection
class HoneypotSSHServer(asyncssh.SSHServer):
    def __init__(self, cfg: Config, persona: Persona, log: EvalLog, passwords: PasswordStore) -> None:
        self.cfg = cfg
        self.passwords = passwords
        self.persona = persona
        self.log = log
        self.conn: Optional[asyncssh.SSHServerConnection] = None
        self.session_id = ""
        self.peer_ip = ""
        self.peer_port = 0
        self.failures = 0

    # Lifecycle

    def connection_made(self, conn: asyncssh.SSHServerConnection) -> None:
        self.conn = conn
        peer = conn.get_extra_info("peername") or ("?", 0)
        self.peer_ip, self.peer_port = peer[0], peer[1]
        state = SessionState.create(self.persona, "", self.peer_ip, self.peer_port)
        self.session_id = state.session_id
        conn.set_extra_info(hp_server=self, hp_session_id=self.session_id)
        client_version = conn.get_extra_info("client_version", "")
        self.log.connection(self.session_id, self.peer_ip, self.peer_port,
                            client_version)

    def connection_lost(self, exc: Optional[Exception]) -> None:
        if exc is not None:
            self.log.emit("transport_error", self.session_id, error=str(exc))

    def debug_msg_received(self, msg: str, lang: str, always_display: bool) -> None:
        self.log.emit("client_debug", self.session_id, message=msg)

    # Authentication

    def begin_auth(self, username: str) -> bool:
        # Never allow an unauthenticated shell
        return True

    def public_key_auth_supported(self) -> bool:
        return True

    def validate_public_key(self, username: str, key: asyncssh.SSHKey) -> bool:
        try:
            fp = key.get_fingerprint()
            alg = key.get_algorithm()
        except Exception:
            fp, alg = "?", "?"
        self.log.auth(self.session_id, "publickey", username, fp, False,
                      key_algorithm=alg)
        # Force the fallback to a password
        return False

    def password_auth_supported(self) -> bool:
        return True

    async def validate_password(self, username: str, password: str) -> bool:
        cfg = self.cfg
        ok = await self.passwords.authenticate(username, password)
        ok = ok and username not in cfg.deny_usernames

        if ok and self.failures < cfg.min_failed_attempts:
            ok = False

        if not ok:
            self.failures += 1
            await asyncio.sleep(random.uniform(*cfg.auth_fail_delay))
        else:
            await asyncio.sleep(random.uniform(*cfg.auth_ok_delay))

        self.log.auth(self.session_id, "password", username, None, ok,
                      attempt=self.failures + (0 if ok else 0))
        return ok

    def kbdint_auth_supported(self) -> bool:
        return False

    def session_requested(self):
        return True


# Build the coroutine asyncssh calls for each new session channel
def make_process_handler(cfg: Config, persona: Persona, controller, log: EvalLog):
    async def handler(process: asyncssh.SSHServerProcess) -> None:
        conn = process.get_extra_info("connection")
        server: HoneypotSSHServer = conn.get_extra_info("hp_server")
        username = conn.get_extra_info("username") or "user"

        state = SessionState.create(persona, username, server.peer_ip,
                                    server.peer_port)
        # Keep one id for the connection
        state.session_id = server.session_id
        state.realm = {
            "ip": server.peer_ip,
            "session": state.session_id,
            "global": "global",
        }.get(cfg.fs_realm_mode, server.peer_ip) or "unknown"

        term = process.get_terminal_type()
        state.term_type = term
        log.channel(
            state.session_id,
            kind=("subsystem" if process.subsystem else
                  "exec" if process.command else "shell"),
            username=username,
            term=term,
            term_size=process.get_terminal_size() if term else None,
            command=process.command,
            subsystem=process.subsystem,
            env={k: v for k, v in (process.env or {}).items()
                 if k in ("LANG", "TERM", "LC_ALL")},
        )

        manager = getattr(controller, "processes", None)
        original_signal, original_break = process.signal_received, process.break_received
        original_lost = process.connection_lost
        def interrupt():
            task = getattr(state, "_command_task", None)
            if task is None or task.done():
                return False
            if not getattr(state, "_interrupted", False):
                state._interrupted = True
                clear_input = getattr(process.channel, "clear_input", None)
                if clear_input and process.get_terminal_type():
                    clear_input()
                if process.get_terminal_type():
                    process.stdout.write("^C\n")
                task.cancel()
            return True
        def signal_received(signal):
            if signal in ("INT", "SIGINT"):
                if not interrupt():
                    original_break(0)
            elif manager is None or not manager.signal_foreground(state, signal):
                original_signal(signal)
        def break_received(milliseconds):
            if interrupt():
                return True
            return original_break(milliseconds)
        def connection_lost(exc):
            state._channel_closed = True
            task = getattr(state, "_command_task", None)
            if task is not None and not task.done():
                task.cancel()
            try:
                if manager is not None:
                    manager.close_session(state)
            finally:
                original_lost(exc)
        process.signal_received = signal_received
        process.break_received = break_received
        process.connection_lost = connection_lost

        reason = "closed"
        try:
            if process.subsystem:
                # With --no-sftp, fail the way a server without the subsystem does
                process.exit(1)
                reason = "subsystem_refused"
            elif process.command:
                reason = await run_exec(process, state, controller, log)
                process.exit(getattr(state, "last_exit_status", 0))
            else:
                reason = await run_shell(
                    process, state, controller, persona, log,
                    history_turns=cfg.history_turns,
                    stream_output=cfg.stream_output,
                    idle_timeout=cfg.idle_timeout,
                )
                process.exit(0)
        except (asyncssh.ConnectionLost, BrokenPipeError, ConnectionResetError):
            reason = "connection_lost"
        except asyncio.CancelledError:
            reason = "cancelled"
            raise
        # Never let a bug print a Python traceback
        except Exception as exc:
            reason = "error"
            log.emit("handler_error", state.session_id,
                     error=f"{type(exc).__name__}: {exc}")
            try:
                process.exit(1)
            except Exception:
                pass
        finally:
            if getattr(controller, "processes", None) is not None and hasattr(controller.processes, "close_session"):
                controller.processes.close_session(state)
            log.disconnect(state.session_id, reason, state.seq, state.duration)

    return handler


async def start_server(cfg: Config, persona: Persona, controller, log: EvalLog, *, passwords=None):
    passwords = passwords or PasswordStore.load(cfg.auth_store)
    opts = algorithm_options() if cfg.openssh_algorithms else {}
    from .sftp import make_sftp_factory
    sftp_factory = make_sftp_factory(cfg, persona, controller, log)
    if sftp_factory is not None:
        # Ubuntu's OpenSSH serves both, and uploads land in the attacker's realm
        opts.update(sftp_factory=sftp_factory, allow_scp=True)
    return await asyncssh.listen(
        cfg.host,
        cfg.port,
        server_factory=lambda: HoneypotSSHServer(cfg, persona, log, passwords),
        server_host_keys=ensure_host_keys(cfg.host_key_dir),
        process_factory=make_process_handler(cfg, persona, controller, log),
        server_version=cfg.server_version,
        login_timeout=cfg.login_timeout,
        # Password-only decisions need neither Kerberos nor DNS
        # AsyncSSH would otherwise look up a GSS host with socket.getfqdn() during login
        # a slow Windows resolver could use up the client's login deadline before the check runs
        config=None,
        gss_host=None,
        gss_kex=False,
        gss_auth=False,
        rdns_lookup=False,
        host_based_auth=False,
        password_auth=True,
        kbdint_auth=False,
        line_editor=True,
        line_history=500,
        encoding="utf-8",
        errors="replace",
        **opts,
    )
