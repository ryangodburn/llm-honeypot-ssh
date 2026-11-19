#!/usr/bin/env python3
# Honeypot Entry Point
# starts the SSH front end - Ollama and the Qwen model are required
# python run.py - full setup with Qwen and the command tools
# python run.py --host 0.0.0.0 --port 2222 - exposed, read the README first
# python run.py --set-password ubuntu - set an SSH password, then exit

# Imports
from __future__ import annotations

import argparse
import asyncio
import logging
import math
import os
from pathlib import Path
import signal
import sys

ROOT = Path(__file__).resolve().parent
if __name__ == '__main__':
    from honeypot.prerequisites import ensure_python_dependencies
    if not ensure_python_dependencies(ROOT):
        sys.exit(2)

from honeypot.config import Config
from honeypot.controller import Controller
from honeypot.evallog import EvalLog
from honeypot.llm import OllamaClient
from honeypot.persona import Persona
from honeypot.sshfront import start_server


def parse_args(argv=None) -> Config:
    cfg = Config()
    p = argparse.ArgumentParser(description="LLM honeypot SSH front end")

    p.add_argument("--auth-store", default=cfg.auth_store, help="operator-owned SSH password verifier file")
    p.add_argument("--set-password", metavar="USER", help="set USER's SSH password in the auth store, then exit")
    p.add_argument("--generate-password", action="store_true", help="with --set-password: generate and print one")
    p.add_argument("--host-key-dir", default=cfg.host_key_dir)
    p.add_argument("--host", default=cfg.host,
                   help="listen address (default every interface; 127.0.0.1 keeps it on this machine)")
    p.add_argument("--port", type=int, default=None,
                   help=f"listen port (default {cfg.port}, or {cfg.fallback_port} when {cfg.port} cannot be opened)")
    p.add_argument("--template", default=cfg.template)
    p.add_argument("--hostname", default=None, help="override persona hostname")
    p.add_argument("--server-version", default=cfg.server_version)
    p.add_argument("--no-openssh-algs", action="store_true")
    p.add_argument("--no-colour-prompt", action="store_true")

    p.add_argument("--model", default=cfg.model, help="model name (an Ollama tag, or the hosted model id)")
    p.add_argument("--ollama-url", default=cfg.ollama_url)
    p.add_argument("--model-provider", choices=["ollama", "openai", "anthropic"], default=cfg.model_provider,
                   help="ollama for a local model (default), or a hosted API; openai covers OpenAI-compatible APIs")
    p.add_argument("--api-key", default=cfg.api_key,
                   help="API key for a hosted provider (or set HONEYPOT_API_KEY)")
    p.add_argument("--api-base-url", default=cfg.api_base_url,
                   help="override the hosted provider base URL, for an OpenAI-compatible endpoint")
    p.add_argument("--gui", dest="gui", action=argparse.BooleanOptionalAction, default=None,
                   help="show the control window (default when a desktop is available; --no-gui forces the terminal)")
    p.add_argument("--temperature", type=float, default=cfg.temperature)
    p.add_argument("--num-ctx", type=int, default=cfg.num_ctx)
    p.add_argument("--num-predict", type=int, default=cfg.num_predict)
    p.add_argument("--llm-timeout", type=float, default=cfg.llm_timeout_s)
    p.add_argument('--no-ai-fallback', action='store_true', help='strict model evaluation: disable native/reference recovery and circuit bypass')
    p.add_argument('--ai-failure-threshold', type=int, default=cfg.ai_failure_threshold)
    p.add_argument('--ai-cooldown', type=float, default=cfg.ai_cooldown_s, help='seconds before one model recovery probe')
    p.add_argument('--retrieval-timeout', type=float, default=cfg.retrieval_timeout_s)
    p.add_argument("--concurrency", type=int, default=cfg.max_concurrency)
    p.add_argument("--no-warmup", action="store_true")
    p.add_argument('--no-start-ollama', action='store_true', help='do not start an installed local Ollama service')
    p.add_argument('--model-setup-timeout', type=float, default=cfg.model_setup_timeout_s, help='first-run model setup budget in seconds (default: 1800)')
    p.add_argument('--model-load-timeout', type=float, default=cfg.model_load_timeout_s, help='cold model load budget in seconds (default: 180)')
    p.add_argument("--no-native-tools", action="store_true",
                   help="disable native filesystem, retrieval and process tools")
    p.add_argument("--model-process-tools", action="store_true",
                   help="let Ollama call the guarded process_run tool for foreground process commands")
    p.add_argument("--model-command-tools", action=argparse.BooleanOptionalAction, default=None,
                   help="Ollama command_run tools (enabled by default; --no-model-command-tools disables)")
    p.add_argument("--tool-max-rounds", type=int, default=cfg.tool_max_rounds)
    p.add_argument("--tool-max-calls", type=int, default=cfg.tool_max_calls)

    p.add_argument("--history-turns", type=int, default=cfg.history_turns,
                   help="0 = unbounded context (baseline behaviour)")
    p.add_argument("--stream", action="store_true",
                   help="stream plain completions; native tool rounds remain buffered")
    p.add_argument("--min-failed-attempts", type=int,
                   default=cfg.min_failed_attempts)
    p.add_argument("--fs-db", default=cfg.fs_db,
                   help="filesystem database; download/import Ubuntu and apply the profile if missing")
    p.add_argument("--no-fs", action="store_true",
                   help="disable the default database for a pure-model baseline")
    p.add_argument("--auto-setup", action=argparse.BooleanOptionalAction, default=cfg.fs_auto_setup,
                   help="pull a missing Ollama model (default: enabled); filesystem repair is always automatic")
    p.add_argument("--fs-tarball", help="existing Ubuntu 22.04 rootfs archive instead of downloading")
    p.add_argument("--fs-sha256", help="optional expected SHA256 for --fs-tarball")
    p.add_argument("--fs-cache-dir", default=cfg.fs_cache_dir)
    p.add_argument("--fs-realm", default=cfg.fs_realm_mode,
                   choices=("ip", "session", "global"),
                   help="how attacker writes are keyed (default: ip)")
    p.add_argument("--fs-reset", action="store_true",
                   help="clear all attacker overlays at startup")
    p.add_argument("--no-fs-colour", action="store_true")
    p.add_argument("--egress-allow-host", action="append", default=[], help="restrict guest destinations to exact hosts; repeatable")
    p.add_argument("--egress-deny-cidr", action="append", default=[], help="protect additional operator networks/public IPs; repeatable")
    p.add_argument("--no-network", action="store_true", help="disable real ping/DNS/TCP diagnostics")
    p.add_argument("--dns-server", default=cfg.dns_server, help="public DNS resolver IP for dig/host/nslookup")
    p.add_argument("--no-internet-downloads", action="store_true", help="disable curl HTTP(S) transfers")
    p.add_argument("--no-sftp", action="store_true", help="refuse the SFTP subsystem and scp (r28 behaviour)")
    p.add_argument("--sftp-max-bytes", type=int, default=cfg.sftp_max_bytes,
                   help="largest file accepted over SFTP/scp (default: 32 MiB)")
    p.add_argument("--download-port", action="append", type=int,
                   help="permitted curl port; replaces defaults 80 and 443 when supplied (repeatable)")
    p.add_argument("--download-max-bytes", type=int, default=cfg.download_max_bytes,
                   help="maximum body bytes per curl download (default: 10 MiB)")
    p.add_argument("--download-timeout", type=float, default=cfg.download_timeout_s,
                   help="maximum seconds per curl command (default: 30)")
    p.add_argument("--retrieval-db", default=cfg.retrieval_db,
                   help="operator reference vector database (default: retrieval.sqlite)")
    p.add_argument('--retrieval-corpus', default=cfg.retrieval_corpus, help='source JSONL used if the retrieval index needs rebuilding')
    p.add_argument("--no-retrieval", action="store_true", help="disable reference retrieval")
    p.add_argument("--retrieval-top-k", type=int, default=cfg.retrieval_top_k)
    p.add_argument("--retrieval-min-score", type=float, default=cfg.retrieval_min_score)
    p.add_argument("--retrieval-context-bytes", type=int, default=cfg.retrieval_context_bytes)
    p.add_argument("--retrieval-max-age-days", type=float, default=cfg.retrieval_max_age_days)
    p.add_argument("--log-dir", default=cfg.log_dir)
    p.add_argument("--verbose", action="store_true")

    a = p.parse_args(argv)

    cfg.auth_store = a.auth_store
    cfg.host_key_dir = a.host_key_dir
    cfg._set_password = a.set_password, a.generate_password  # type: ignore[attr-defined]
    cfg.host = a.host
    # An explicit port is used exactly as given, only the default one falls back
    if a.port is not None:
        cfg.port, cfg.fallback_port = a.port, 0
    cfg.template, cfg.hostname = a.template, a.hostname
    cfg.server_version = a.server_version
    cfg.openssh_algorithms = not a.no_openssh_algs
    cfg.colour_prompt = not a.no_colour_prompt
    cfg.model, cfg.ollama_url = a.model, a.ollama_url
    cfg.model_provider = a.model_provider
    cfg.api_key = a.api_key or os.environ.get('HONEYPOT_API_KEY', '')
    cfg.api_base_url = a.api_base_url
    cfg._gui = a.gui  # type: ignore[attr-defined]
    cfg.temperature, cfg.num_ctx = a.temperature, a.num_ctx
    cfg.num_predict, cfg.llm_timeout_s = a.num_predict, a.llm_timeout
    cfg.ai_fallback = not a.no_ai_fallback
    cfg.ai_failure_threshold, cfg.ai_cooldown_s = a.ai_failure_threshold, a.ai_cooldown
    cfg.retrieval_timeout_s = a.retrieval_timeout
    if (cfg.ai_failure_threshold < 1 or a.concurrency < 1 or
            any(not math.isfinite(x) or x <= 0 for x in (cfg.llm_timeout_s, cfg.ai_cooldown_s, cfg.retrieval_timeout_s))):
        p.error('AI timeout, cooldown, retrieval timeout, failure threshold and concurrency must be finite and positive')
    cfg.max_concurrency = a.concurrency
    cfg.warm_up = not a.no_warmup
    cfg.start_ollama = not a.no_start_ollama
    cfg.model_setup_timeout_s, cfg.model_load_timeout_s = a.model_setup_timeout, a.model_load_timeout
    if any(not math.isfinite(x) or x <= 0 for x in (cfg.model_setup_timeout_s, cfg.model_load_timeout_s)):
        p.error('Model setup and load deadlines must be finite and positive')
    cfg.native_tools = not a.no_native_tools
    cfg.model_process_tools = a.model_process_tools
    cfg.model_command_tools = (not (a.no_native_tools or a.no_fs)) if a.model_command_tools is None else a.model_command_tools
    if (cfg.model_process_tools or cfg.model_command_tools) and (a.no_native_tools or a.no_fs):
        p.error('model action tools require native tools and a filesystem database')
    cfg.tool_max_rounds, cfg.tool_max_calls = a.tool_max_rounds, a.tool_max_calls
    if min(cfg.tool_max_rounds, cfg.tool_max_calls) < 1:
        p.error("tool budgets must be positive")
    cfg.history_turns, cfg.stream_output = a.history_turns, a.stream
    cfg.min_failed_attempts = a.min_failed_attempts
    cfg.fs_db, cfg.fs_realm_mode = a.fs_db, a.fs_realm
    if a.no_fs:
        cfg.fs_db = None
    cfg.fs_auto_setup, cfg.fs_tarball = a.auto_setup, a.fs_tarball
    cfg.fs_sha256 = a.fs_sha256
    if a.fs_sha256 and not a.fs_tarball:
        p.error("--fs-sha256 requires --fs-tarball")
    cfg.fs_cache_dir = a.fs_cache_dir
    cfg.fs_reset_on_start = a.fs_reset
    cfg.fs_colour_ls = not a.no_fs_colour
    cfg.egress_allow_hosts, cfg.egress_deny_cidrs = a.egress_allow_host, a.egress_deny_cidr
    cfg.network_enabled = not a.no_network
    cfg.dns_server = a.dns_server
    cfg.internet_downloads = not a.no_internet_downloads
    cfg.sftp_enabled = not a.no_sftp
    cfg.sftp_max_bytes = a.sftp_max_bytes
    if cfg.sftp_max_bytes < 1:
        p.error("--sftp-max-bytes must be positive")
    cfg.download_ports = a.download_port if a.download_port is not None else [80, 443]
    from honeypot.downloads import DownloadPolicy
    from honeypot.outbound import EgressPolicy
    try:
        DownloadPolicy(allowed_ports=tuple(cfg.download_ports), egress=EgressPolicy(
            allowed_hosts=tuple(cfg.egress_allow_hosts), denied_cidrs=tuple(cfg.egress_deny_cidrs)))
    except ValueError as exc:
        p.error(str(exc))
    cfg.download_max_bytes, cfg.download_timeout_s = a.download_max_bytes, a.download_timeout
    if cfg.download_max_bytes < 1 or not math.isfinite(cfg.download_timeout_s) or cfg.download_timeout_s <= 0:
        p.error("download limits must be positive and finite")
    cfg.retrieval_db = None if a.no_retrieval or a.no_fs else a.retrieval_db
    cfg.retrieval_corpus = a.retrieval_corpus
    cfg.retrieval_top_k, cfg.retrieval_min_score = a.retrieval_top_k, a.retrieval_min_score
    cfg.retrieval_context_bytes, cfg.retrieval_max_age_days = a.retrieval_context_bytes, a.retrieval_max_age_days
    if not 1 <= a.retrieval_top_k <= 10 or not 0 <= a.retrieval_min_score <= 1:
        p.error("retrieval top-k must be 1..10 and minimum score 0..1")
    if not 1024 <= a.retrieval_context_bytes <= 24000 or not 0 <= a.retrieval_max_age_days < float("inf"):
        p.error("retrieval context must be 1024..24000 bytes and age finite/nonnegative")
    cfg.log_dir = a.log_dir
    cfg._verbose = a.verbose  # type: ignore[attr-defined]
    return cfg


# Set one account's SSH password as a salted PBKDF2 verifier
# restart the server afterwards to load it
def set_password(store: str, username: str, *, generate: bool = False) -> int:
    import getpass
    import secrets
    from honeypot.passwords import PasswordError, PasswordStore, password_record
    try:
        path = Path(store)
        users = PasswordStore.load(path).users if path.exists() else {}
        if generate:
            password = secrets.token_urlsafe(24)
        else:
            password = getpass.getpass('New SSH password: ')
            if password != getpass.getpass('Repeat SSH password: '):
                raise PasswordError('Passwords do not match')
            if len(password) < 16:
                raise PasswordError('Use at least 16 characters')
        users[username] = password_record(password)
        PasswordStore(users).save(path)
    except (PasswordError, OSError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(f'Password updated for {username}. Restart the honeypot to load it.')
    if generate:
        print(f'New password (shown once): {password}')
    return 0


# Whether to show the control window: --gui forces it, --no-gui forces the terminal
# left unset it is shown on a desktop, and skipped where Tk or a display is missing, so a server still runs
def want_gui(cfg):
    choice = getattr(cfg, '_gui', None)
    if choice is False:
        return False
    import importlib.util
    if importlib.util.find_spec('tkinter') is None:
        if choice is True:
            print('The control window needs tkinter, which is not available; '
                  'running in the terminal instead.', file=sys.stderr)
        return False
    if choice is True:
        return True
    if sys.platform.startswith('linux') and not (os.environ.get('DISPLAY') or os.environ.get('WAYLAND_DISPLAY')):
        return False
    return True


async def main() -> int:
    cfg = parse_args()
    # Built-in paths are relative to this project, even when run.py starts from another folder
    # paths given on the command line keep their normal meaning
    args = sys.argv[1:]
    for attr, flag in (('auth_store', '--auth-store'), ('template', '--template'),
            ('fs_db', '--fs-db'), ('fs_cache_dir', '--fs-cache-dir'),
            ('retrieval_db', '--retrieval-db'), ('retrieval_corpus', '--retrieval-corpus'),
            ('log_dir', '--log-dir'), ('host_key_dir', '--host-key-dir')):
        value = getattr(cfg, attr)
        if value and value == getattr(Config(), attr) and not any(x == flag or x.startswith(flag + '=') for x in args):
            setattr(cfg, attr, str(ROOT / value))
    user, generate = getattr(cfg, '_set_password', (None, False))
    if user:
        return set_password(cfg.auth_store, user, generate=generate)
    logging.basicConfig(
        level=logging.DEBUG if getattr(cfg, "_verbose", False) else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(message)s",
    )
    log_ = logging.getLogger("honeypot")

    from honeypot.startup import runtime_lease
    from honeypot.bootstrap import SetupError
    paths = [cfg.fs_db, cfg.retrieval_db]
    if cfg.fs_db and cfg.retrieval_db and Path(cfg.fs_db).resolve() == Path(cfg.retrieval_db).resolve():
        log_.error('Filesystem and retrieval databases must use different files')
        return 2
    protected = {Path(p).resolve() for p in (cfg.auth_store, cfg.template, cfg.retrieval_corpus, cfg.fs_tarball) if p}
    if any(Path(p).resolve() in protected for p in paths if p):
        log_.error('Database paths must not overwrite credentials, templates, archives or the reference corpus')
        return 2
    # Show the control window by default on a desktop, unless --no-gui or a headless environment
    if want_gui(cfg):
        from honeypot.gui import run_gui
        return run_gui(cfg, log_, paths, run_prepared)
    try:
        with runtime_lease(paths):
            return await run_prepared(cfg, log_)
    except (SetupError, OSError) as exc:
        log_.error('Startup failed: %s', exc)
        return 2


# The addresses another machine can reach the listener on
# loopback gives none, every-interface binds give this machine's addresses of that family
def reachable_addresses(host):
    from honeypot.outbound import local_addresses
    if host in ('localhost', '::1') or host.startswith('127.'):
        return []
    if host in ('0.0.0.0', '::', ''):
        found = local_addresses()
        return [a for a in found if ':' not in a] if host == '0.0.0.0' else found
    return [host]


# The accounts that can log in, with their passwords on the run that created them
# later runs can only list the names, because the store keeps verifiers, not passwords
def announce_logins(users, new_logins, log_):
    if new_logins:
        log_.info('Logins created on this first run - save them now, they are not shown again:')
        width = max(len(name) for name in new_logins)
        for name, password in new_logins.items():
            log_.info('  %s  %s', name.ljust(width), password)
    else:
        log_.info('Accounts with a password: %s - add one with --set-password USER', ', '.join(users) or 'none')


# Say where the honeypot can be found and how to connect, once it is listening
def announce_listen(cfg, passwords, reachable, log_, new_logins=None):
    users = sorted(passwords.users)
    user = next((u for u in ('ubuntu', 'root', 'support', 'deploy') if u in users), users[0] if users else 'root')
    flag = '' if cfg.port == 22 else f'-p {cfg.port} '
    if cfg.host in ('localhost', '::1') or cfg.host.startswith('127.'):
        log_.info('Local only - connect from this machine with: ssh %s%s@%s', flag, user, cfg.host)
        announce_logins(users, new_logins, log_)
        log_.info('Leave out --host to listen on the network, where a port scan can find it')
        return
    if not reachable:
        log_.info('Listening on every interface, but this machine has no network address yet - '
                  'connect to a network, then scan TCP port %d', cfg.port)
        announce_logins(users, new_logins, log_)
        return
    log_.info('Reachable from the network on TCP port %d - a port scan of this machine shows it as OpenSSH',
              cfg.port)
    for address in reachable:
        log_.info('  ssh %s%s@%s', flag, user, address)
    announce_logins(users, new_logins, log_)
    log_.info('Check from another machine: nmap -sV -p %d %s', cfg.port, reachable[0])
    log_.info('Keep it on this machine only with --host 127.0.0.1')
    if sys.platform == 'win32':
        log_.info('Windows: allow Python through Windows Defender Firewall when it asks, or open the port '
                  'once from an administrator PowerShell:')
        log_.info('  New-NetFirewallRule -DisplayName "SSH honeypot" -Direction Inbound -Protocol TCP '
                  '-LocalPort %d -Action Allow', cfg.port)


# Build the model client for the selected provider
# local prepares Ollama and the model first; a hosted provider checks the key with one small call
# returns None after logging a clear reason when the model cannot be reached
async def build_llm(cfg, log_):
    provider = (cfg.model_provider or 'ollama').lower()
    if provider in ('ollama', 'local'):
        from honeypot.bootstrap import SetupError, ensure_model
        from honeypot.startup import ensure_ollama_service, load_model
        import httpx
        try:
            async with asyncio.timeout(cfg.model_setup_timeout_s):
                await ensure_ollama_service(cfg.ollama_url, start=cfg.start_ollama,
                                            log_dir=cfg.log_dir, progress=log_.info)
                await ensure_model(cfg.ollama_url, cfg.model, pull=cfg.fs_auto_setup,
                                   timeout_s=cfg.model_setup_timeout_s, progress=log_.info)
                if cfg.warm_up:
                    await load_model(cfg.ollama_url, cfg.model, timeout=cfg.model_load_timeout_s,
                                     num_ctx=cfg.num_ctx, progress=log_.info)
        except (SetupError, TimeoutError, httpx.HTTPError, ValueError, OSError) as exc:
            log_.error("Ollama and %s are required: %s", cfg.model, str(exc) or 'model setup timed out')
            return None
        return OllamaClient(
            cfg.ollama_url, cfg.model, temperature=cfg.temperature, num_ctx=cfg.num_ctx,
            num_predict=cfg.num_predict, timeout_s=cfg.llm_timeout_s, max_concurrency=cfg.max_concurrency,
        )
    from honeypot.apimodel import ApiClient, PROVIDERS
    if provider not in PROVIDERS:
        log_.error("Unknown model provider %r - use ollama, openai or anthropic", provider)
        return None
    try:
        client = ApiClient(provider, cfg.model, cfg.api_key, base_url=cfg.api_base_url or None,
                           temperature=cfg.temperature, num_predict=cfg.num_predict,
                           timeout_s=cfg.llm_timeout_s, max_concurrency=cfg.max_concurrency)
    except ValueError as exc:
        log_.error("%s", exc)
        return None
    label = PROVIDERS[provider]['label']
    log_.info("Using the %s API with model %s", label, cfg.model)
    log_.info("The hosted model generates output; the native command handlers stay on the fast path")
    if cfg.warm_up:
        probe = await client.warm_up()
        if probe.error:
            log_.error("The %s API did not answer: %s", label, probe.error)
            await client.aclose()
            return None
        log_.info("%s API reachable, model %s answered", label, cfg.model)
    return client


async def run_prepared(cfg, log_, *, on_ready=None) -> int:
    from honeypot.passwords import PasswordError
    from honeypot.startup import prepare_passwords
    try:
        passwords, new_logins = prepare_passwords(cfg.auth_store, announce=log_.info)
    except PasswordError as exc:
        log_.error("%s", exc)
        return 2

    from honeypot.outbound import operator_policy
    try:
        egress = await asyncio.to_thread(operator_policy, ollama_url=cfg.ollama_url,
            listen_host=cfg.host, allowed_hosts=cfg.egress_allow_hosts, denied_cidrs=cfg.egress_deny_cidrs)
    except (ValueError, OSError) as exc:
        log_.error("Outbound policy initialization failed: %s", exc)
        return 2

    # The honeypot only runs with a model, so it is prepared first and a failure stops the start
    llm = await build_llm(cfg, log_)
    if llm is None:
        return 2

    persona = Persona.load(cfg.template, hostname=cfg.hostname,
                           server_ip=cfg.server_ip)
    persona.colour_prompt = cfg.colour_prompt

    fs_setup = None
    if cfg.fs_db:
        from honeypot.bootstrap import SetupError, ensure_database
        try:
            fs_setup = ensure_database(cfg.fs_db, cache_dir=cfg.fs_cache_dir,
                            tarball=cfg.fs_tarball, sha256=cfg.fs_sha256,
                            hostname=persona.hostname, profile=True, progress=log_.info, repair=True)
        except SetupError as exc:
            log_.error("%s", exc)
            return 2

    evlog = EvalLog(cfg.log_dir)

    filesystem = None
    if cfg.fs_db:
        from honeypot.fscommands import FilesystemCommands
        from honeypot.vfs import VFS
        vfs = VFS(cfg.fs_db)
        n = vfs.count()
        if not n:
            log_.error("%s has an empty base image; move it aside so run.py rebuilds it",
                       cfg.fs_db)
            return 1
        if cfg.fs_reset_on_start:
            for realm, _ in vfs.realms():
                vfs.reset_realm(realm)
            log_.info("cleared all attacker overlays")
        filesystem = FilesystemCommands(
            vfs, colour=cfg.fs_colour_ls,
            max_cat_bytes=cfg.fs_max_cat_bytes,
            synthesize_binaries=cfg.fs_synthesize_binaries)
        # Host facts recorded at import time win over the template
        # so the store and the persona never disagree about the hostname
        for attr, key in (("hostname", "hostname"), ("distro", "distro"),
                          ("kernel", "kernel"), ("server_ip", "server_ip")):
            val = vfs.meta(key)
            if val:
                setattr(persona, attr, val)
        if cfg.server_version == Config().server_version and vfs.meta("ssh_server_version"):
            cfg.server_version = vfs.meta("ssh_server_version")
        log_.info("filesystem store: %s, %d base nodes, realm=%s",
                  cfg.fs_db, n, cfg.fs_realm_mode)

    retrieval = None
    retrieval_setup = None
    if cfg.retrieval_db:
        from honeypot.retrieval import SQLiteRetrievalStore
        from honeypot.startup import ensure_retrieval_database
        try:
            retrieval_setup = await ensure_retrieval_database(cfg.retrieval_db, cfg.retrieval_corpus, progress=log_.info)
            retrieval = SQLiteRetrievalStore(cfg.retrieval_db, filesystem,
                top_k=cfg.retrieval_top_k, min_score=cfg.retrieval_min_score,
                max_context_bytes=cfg.retrieval_context_bytes,
                max_age_days=cfg.retrieval_max_age_days)
        except Exception as exc:
            log_.error("retrieval initialization failed: %s; build the store or use --no-retrieval", exc)
            if retrieval:
                await retrieval.aclose()
            retrieval = None
            if not cfg.ai_fallback:
                await llm.aclose()
                if filesystem:
                    filesystem.vfs.close()
                evlog.close()
                return 2
            log_.warning('Continuing without reference retrieval; native handlers remain available')
        if retrieval:
            log_.info("retrieval store: %s, %s records, encoder=%s", cfg.retrieval_db,
                      retrieval.meta["records"], retrieval.encoder["type"])

    from honeypot.downloads import CurlCommands, DownloadPolicy
    downloads = CurlCommands(filesystem, DownloadPolicy(enabled=cfg.internet_downloads,
        max_bytes=cfg.download_max_bytes, max_time=cfg.download_timeout_s, egress=egress,
        allowed_ports=tuple(cfg.download_ports)))
    from honeypot.network import NetworkCommands, NetworkPolicy
    network = NetworkCommands(NetworkPolicy(enabled=cfg.network_enabled, resolver=cfg.dns_server,
        timeout=cfg.network_timeout, max_time=cfg.network_max_time, egress=egress))
    controller = Controller(persona, llm, filesystem=filesystem, retrieval=retrieval, downloads=downloads, network=network,
                            strip_prompt=cfg.strip_prompt,
                            max_lines=cfg.max_output_lines,
                            native_tools=cfg.native_tools,
                            model_process_tools=cfg.model_process_tools,
                            model_command_tools=cfg.model_command_tools,
                            ai_fallback=cfg.ai_fallback, ai_timeout_s=cfg.llm_timeout_s,
                            ai_failure_threshold=cfg.ai_failure_threshold, ai_cooldown_s=cfg.ai_cooldown_s,
                            retrieval_timeout_s=cfg.retrieval_timeout_s,
                            tool_max_rounds=cfg.tool_max_rounds,
                            tool_max_calls=cfg.tool_max_calls)
    if controller.processes:
        controller.processes.recover_sessions()
    # The default port falls back when it is taken or reserved for administrators
    # an explicit --port is used as given, so a busy port stops the start with a clear message
    ports = [cfg.port] + ([cfg.fallback_port] if cfg.fallback_port and cfg.fallback_port != cfg.port else [])
    server = None
    for i, port in enumerate(ports):
        cfg.port = port
        try:
            server = await start_server(cfg, persona, controller, evlog, passwords=passwords)
            break
        except OSError as exc:
            reason = exc.strerror or str(exc)
            if i + 1 < len(ports):
                log_.warning("port %d cannot be opened (%s) - using %d instead", port, reason, ports[i + 1])
            else:
                log_.error("cannot listen on %s:%d - %s", cfg.host, port, reason)
    if server is None:
        await llm.aclose()
        if retrieval:
            await retrieval.aclose()
        if filesystem:
            filesystem.vfs.close()
        evlog.close()
        return 2
    reachable = reachable_addresses(cfg.host)
    process_task = asyncio.create_task(controller.processes.serve()) if controller.processes else None
    evlog.emit("startup", None, host=cfg.host, port=cfg.port, reachable=reachable, model=cfg.model,
               history_turns=cfg.history_turns,
               ai_fallback=cfg.ai_fallback, ai_timeout_s=cfg.llm_timeout_s,
               ai_circuit=controller.ai_circuit.state(), retrieval_available=retrieval is not None,
               filesystem_setup=fs_setup,
               retrieval_setup=retrieval_setup, model_command_tools=cfg.model_command_tools,
               model_setup_timeout_s=cfg.model_setup_timeout_s, model_load_timeout_s=cfg.model_load_timeout_s,
               egress_allow_hosts=list(egress.allowed_hosts),
               egress_deny_cidrs=list(egress.denied_cidrs),
               download_ports=list(cfg.download_ports),
               server_version=cfg.server_version,
               retrieval_db=cfg.retrieval_db,
               retrieval_encoder=retrieval.encoder if retrieval else None,
               retrieval_corpus_sha256=retrieval.meta["corpus_sha256"] if retrieval else None)
    log_.info("listening on %s:%d as %r (model=%s)", cfg.host, cfg.port,
              persona.hostname, cfg.model)
    log_.info('Defaults loaded: filesystem=%s; command tools=%s; model=%s ready', cfg.fs_db,
              cfg.model_command_tools, cfg.model)
    # Say plainly what the routing mode costs in latency
    bound = cfg.model_command_tools and cfg.native_tools and getattr(llm, 'supports_native_tools', False)
    log_.info('Routing: %s', ('each natively supported stage is a model-selected action (one Qwen request '
                              'per stage, real output relayed); --no-model-command-tools runs them directly')
              if bound else
              'native handlers answer supported stages directly; the model answers only the rest')
    announce_listen(cfg, passwords, reachable, log_, new_logins)

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    pump = None
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop.set)
        except (NotImplementedError, RuntimeError, ValueError):
            # Windows has no add_signal_handler, and a worker thread such as the GUI's cannot set one
            # the proactor loop also holds back KeyboardInterrupt while idle in a socket wait
            # so give it a regular timer to wake up on; the GUI stops it through on_ready instead
            async def _pump() -> None:
                while True:
                    await asyncio.sleep(0.25)
            pump = pump or asyncio.create_task(_pump())
    # Hand the caller a thread-safe stop and the reachable addresses, so a GUI can drive the server
    if on_ready is not None:
        on_ready({'stop': lambda: loop.call_soon_threadsafe(stop.set),
                  'host': cfg.host, 'port': cfg.port, 'reachable': reachable})

    try:
        await stop.wait()
    except KeyboardInterrupt:
        pass
    finally:
        if pump:
            pump.cancel()

    log_.info("shutting down")
    server.close()
    await server.wait_closed()
    if process_task:
        process_task.cancel()
        await asyncio.gather(process_task, return_exceptions=True)
        controller.processes.recover_sessions()
    await llm.aclose()
    if retrieval:
        await retrieval.aclose()
    if filesystem:
        filesystem.vfs.close()
    evlog.emit("shutdown", None)
    evlog.close()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(asyncio.run(main()))
    except KeyboardInterrupt:
        sys.exit(0)
