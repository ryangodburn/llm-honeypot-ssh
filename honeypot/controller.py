# Command Controller
# parses a command line once and runs it as a pipeline, one component per stage
# each stage goes to the first component that can answer it
# the shell, native handlers, filters, retrieval or Qwen
# real bytes flow between stages, so cat /etc/passwd | grep root | wc -l never reaches the model
# a stage that does reach Qwen gets the store's facts about the paths it names
# filesystem effects of a model answer are written back, so the next command sees them
# model output is checked against the store and disagreements are logged, never repaired

# Imports
from __future__ import annotations

import asyncio
import dataclasses
import posixpath
import re
import shlex
import time
from copy import copy
from dataclasses import dataclass, field
from typing import Optional, Protocol

from . import effects as fx
from . import filters as native
# Registers sed, awk, tr, rev and the digest filters
from . import filters_extra  # noqa: F401
from .accounts import AccountCommands
from .syscmds import SystemCommands
from . import grounding as ground
from . import verify
from .cmdline import ParseError, Segment, Stage, parse_shell
from .gnuopts import invalid_option
from .shell import HANDLED as SHELL_BUILTINS, Shell, ShellError, is_special_device, shell_prefix
from .llm import LLMResult, OllamaClient, clean_shell_output
from .resilience import CircuitBreaker, positive_seconds
from .persona import Persona, normalise_path
from .model_tools import ModelTools, process_command
from .downloads import CurlCommands
from .network import NetworkCommands, COMMANDS as NETWORK_COMMANDS
from .processes import ProcessManager, ProcessResult, COMMANDS as PROCESS_COMMANDS
from .vfs import FSError
from .vfsio import inspect_bytes, read_bytes, walk_files, write_bytes

# Most upstream output handed to a model stage
MAX_PIPED_CHARS = 8_000
MAX_STAGES = 8

# Classification

_FS_CMDS = {
    "ls", "dir", "cat", "less", "more", "head", "tail", "touch", "mkdir",
    "rmdir", "rm", "cp", "mv", "ln", "chmod", "chown", "chgrp", "find",
    "locate", "stat", "file", "du", "df", "tree", "pwd", "cd", "tar", "unzip",
    "gzip", "gunzip", "zip", "truncate", "shred", "readlink", "realpath",
    "basename", "dirname", "mount", "umount", "lsblk", "blkid", "grep",
}
_PROC_CMDS = {
    "ps", "top", "htop", "kill", "killall", "pkill", "pgrep", "jobs", "bg",
    "fg", "nohup", "systemctl", "service", "nice", "renice", "strace",
    "lsof", "pidof", "uptime", "free", "vmstat", "iostat", "wait", "disown", "sleep", "journalctl",
}
_NET_CMDS = {
    "ifconfig", "ip", "netstat", "ss", "ping", "traceroute", "tracepath",
    "dig", "nslookup", "host", "curl", "wget", "nc", "ncat", "netcat",
    "ssh", "scp", "sftp", "telnet", "arp", "route", "iptables", "nft",
    "tcpdump", "nmap", "hostname",
}
_TRANSPARENT = {"sudo", "env", "time", "nohup", "watch", "xargs"}


# Label a command line by the kind of state it touches
def classify(command: str) -> str:
    if re.search(r"(?<![0-9<>])>>?\s*[^\s>|&;]", command):
        return "fs"
    toks = re.split(r"[|;&]+|\$\(|`", command)
    seen: set[str] = set()
    for tok in toks:
        tok = tok.strip()
        if not tok:
            continue
        try:
            words = shlex.split(tok)
        except ValueError:
            words = tok.split()
        for w in words:
            if "=" in w and not w.startswith("-"):
                continue
            base = w.rsplit("/", 1)[-1]
            if base in _TRANSPARENT:
                continue
            if base in _FS_CMDS:
                seen.add("fs")
            elif base in _PROC_CMDS:
                seen.add("proc")
            elif base in _NET_CMDS:
                seen.add("net")
            break
    if len(seen) == 1:
        return seen.pop()
    if seen:
        return "mixed"
    return "other"


# Store Interfaces

class FilesystemStore(Protocol):
    vfs: object
    last_flags: list
    last_store_ms: float

    def run_argv(self, session, argv: list[str]) -> Optional[str]: ...
    def read_for_filter(self, session, path: str) -> str: ...
    def identity(self, session): ...


class ProcessTable(Protocol):
    def run_argv(self, session, argv: list[str],
                 stdin: Optional[str] = None) -> Optional[str]: ...


class RetrievalStore(Protocol):
    async def retrieve(self, session, command: str): ...
# Results

@dataclass
class StageResult:
    command: str
    # Which component answered - fs, proc, filter, retrieval, llm and so on
    by: str
    output: str = ""
    ok: bool = True
    ms: float = 0.0
    flags: list[str] = field(default_factory=list)
    tool_calls: list[dict] = field(default_factory=list)
    llm_rounds: list[dict] = field(default_factory=list)
    rejected_answers: list[dict] = field(default_factory=list)
    retrieval: dict = field(default_factory=dict)
    stdout_bytes: Optional[bytes] = None
    stderr: str = ""
    exit_code: Optional[int] = None
    download: dict = field(default_factory=dict)
    network: dict = field(default_factory=dict)
    streamed: bool = False
    fallback: dict = field(default_factory=dict)

    def as_log(self) -> dict:
        return {"cmd": self.command, "by": self.by, "ok": self.ok,
                "ms": round(self.ms, 3), "flags": self.flags,
                "tool_calls": self.tool_calls, "llm_rounds": self.llm_rounds,
                "rejected_answers": self.rejected_answers,
                "retrieval": self.retrieval, "exit_code": self.exit_code,
                "download": self.download, "network": self.network,
                "fallback": self.fallback}


@dataclass
class Response:
    output: str
    subsystem: str
    category: str = "other"
    exit_session: bool = False
    clear_screen: bool = False
    llm: Optional[LLMResult] = None
    flags: list[str] = field(default_factory=list)
    stages: list[StageResult] = field(default_factory=list)
    store_ms: float = 0.0
    grounded_paths: int = 0
    effects: list[str] = field(default_factory=list)
    # Whether the output ends with a newline
    # echo -n and printf without \n leave the prompt on the same line
    # stdout and stderr stay apart so an exec channel can send stderr on the SSH stderr stream
    newline: bool = True
    streams: list[tuple[str, str]] = field(default_factory=list)


# Error lines a handler printed inline with its output
# they belong on stderr, so they never flow down a pipe, into a redirect or past 2>/dev/null
_ERRNO_TEXT = ("No such file or directory", "Permission denied", "Not a directory",
               "Is a directory", "Operation not permitted", "Too many levels of symbolic links",
               "File exists", "Directory not empty", "Invalid argument", "Input/output error",
               "No space left on device", "Read-only file system", "Resource temporarily unavailable",
               "command not found", "No data available", "Argument list too long")


# Separate cmd: ...: <errno text> lines from real output
def split_diagnostics(argv: list[str], text: str) -> tuple[str, str]:
    if not text or not argv:
        return text, ""
    name = argv[0].rsplit("/", 1)[-1]
    heads = (f"{name}: ", "-bash: ", "bash: ")
    out, err = [], []
    for line in text.split("\n"):
        if line.startswith(heads) and (any(e in line for e in _ERRNO_TEXT)
                                       or line.startswith((f"{name}: cannot ", f"{name}: invalid ",
                                                           f"{name}: unrecognized ", f"{name}: missing "))):
            err.append(line)
        else:
            out.append(line)
    return "\n".join(out), "\n".join(err)


def _text_of(data: bytes) -> str:
    text = data.decode("utf-8", "replace")
    return text[:-1] if text.endswith("\n") else text


class Controller:
    def __init__(
        self,
        persona: Persona,
        llm,
        *,
        filesystem: Optional[FilesystemStore] = None,
        processes: Optional[ProcessTable] = None,
        retrieval: Optional[RetrievalStore] = None,
        strip_prompt: bool = True,
        max_lines: int = 400,
        ground_model: bool = True,
        write_back: bool = True,
        verify_output: bool = True,
        native_tools: bool = True,
        model_process_tools: bool = False,
        model_command_tools: bool = False,
        ai_fallback: bool = True,
        ai_timeout_s: float | None = None,
        ai_failure_threshold: int = 3,
        ai_cooldown_s: float = 30.,
        retrieval_timeout_s: float = 3.,
        tool_max_rounds: int = 6,
        tool_max_calls: int = 12,
        prefetch_reads: bool = True,
        downloads=None,
        network=None,
    ) -> None:
        self.persona = persona
        self.llm = llm
        self.filesystem = filesystem
        # System commands are a view over the filesystem store
        # id reads /etc/passwd, hostname reads /etc/hostname and free reads /proc/meminfo
        # if the attacker edits those files, the commands change with them
        self.system = SystemCommands(filesystem.vfs) if filesystem else None
        # Account commands write /etc/passwd, /etc/group and /etc/shadow
        # so id, su and grep /etc/passwd see a new user without being told
        self.accounts = AccountCommands(filesystem.vfs) if filesystem else None
        from .recon import ReconCommands
        self.recon = ReconCommands(filesystem) if filesystem else None
        self.processes = processes if processes is not None else ProcessManager(filesystem) if filesystem else None
        self.retrieval = retrieval
        self.strip_prompt = strip_prompt
        self.max_lines = max_lines
        self.ground_model = ground_model
        self.write_back = write_back
        self.verify_output = verify_output
        self.native_tools = native_tools
        self.model_process_tools = model_process_tools
        self.model_command_tools = model_command_tools
        self.ai_fallback = ai_fallback
        self.ai_timeout_s = positive_seconds(ai_timeout_s if ai_timeout_s is not None else getattr(llm, 'timeout_s', 20.), 'AI timeout')
        self.retrieval_timeout_s = positive_seconds(retrieval_timeout_s, 'Retrieval timeout')
        self.ai_circuit = CircuitBreaker(ai_failure_threshold, ai_cooldown_s)
        self.tool_max_rounds = tool_max_rounds
        self.tool_max_calls = tool_max_calls
        self.prefetch_reads = prefetch_reads
        self.downloads = downloads if downloads is not None else CurlCommands(filesystem)
        self.network = network if network is not None else NetworkCommands()
        # Bash session state - variables, expansion, builtins and command lookup
        self.shell = Shell(filesystem, self.processes)

    # Builtins

    def _builtin(self, session, command: str) -> Optional[Response]:
        stripped = command.strip()
        head = stripped.split()[0] if stripped else ""

        if head in ("exit", "logout", "quit"):
            from .privilege_runtime import leave_shell
            if leave_shell(self, session):
                return Response("", "profile", "other", flags=["virtual_privilege_return"])
            return Response("", "builtin", "other", exit_session=True)
        if head == "clear":
            return Response("", "builtin", "other", clear_screen=True)

        if self.filesystem is None:
            # Without a store, cd and pwd still have to move the prompt
            # they resolve as plain strings with no directory check, and the store replaces both
            if head == "cd":
                home = self.persona.home_dir(session.username)
                session.cwd = normalise_path(session.cwd,
                                             stripped[2:].strip(), home)
                return Response("", "builtin", "fs")
            if head == "pwd" and stripped == "pwd":
                return Response(session.cwd, "builtin", "fs")
        return None

    # One Stage

    # Only existing native handlers can receive a bound action tool
    def _tool_command_supported(self, argv):
        if not argv or not self.filesystem:
            return False
        from .retrieval import canonical
        if canonical(shlex.join(argv)) is not None:
            # Reference and version queries keep the retrieval route
            return False
        name = argv[0].rsplit('/', 1)[-1]
        # Identity changes and interactive challenges stay outside the model loop
        # the inner stage of an authorised sudo is evaluated separately
        # shell builtins are session state, never a model-selected action
        if name in {'sudo', 'su', 'exit', 'logout', 'quit', 'clear'} or argv[0] in SHELL_BUILTINS:
            return False
        return (process_command(argv) or self.downloads.handles(argv)
                or self.network.handles(argv) or name in self.filesystem.names()
                or name in self.system.names() or name in self.accounts.names()
                or name in native.FILTERS or name in {'ss', 'ip', 'dpkg', 'dpkg-query', 'crontab', 'history', 'ufw'})

    async def _run_stage(self, session, stage: Stage, stdin: Optional[str],
                         *, on_token=None, piped: bool = False, parsed: bool = True,
                         stdin_bytes: Optional[bytes] = None, native_only: bool = False):
        t0 = time.perf_counter()
        argv = stage.argv

        # Bash builtins answer from session state before anything else
        if parsed and argv and argv[0] in SHELL_BUILTINS:
            built = self.shell.run(session, argv, stdin, stdin_bytes)
            if built is not None and built.delegate:
                inner = Stage(argv=list(built.delegate), raw=shlex.join(built.delegate))
                result, llm_result = await self._run_stage(session, inner, stdin, on_token=on_token,
                    piped=piped, parsed=True, stdin_bytes=stdin_bytes, native_only=native_only)
                result.command = stage.raw
                return result, llm_result
            if built is not None:
                return StageResult(stage.raw, "builtin", _text_of(built.stdout), ok=built.status == 0,
                                   ms=(time.perf_counter() - t0) * 1000, stdout_bytes=built.stdout,
                                   stderr=built.stderr, exit_code=built.status), None

        # A command given as a path is not the program of that name
        # /etc/passwd must exist and be executable before any handler sees it
        if parsed and argv and "/" in argv[0]:
            refused = self.shell.not_found(session, argv)
            if refused is not None:
                message, status = refused
                return StageResult(stage.raw, "shell", "", ok=False, stderr=message, exit_code=status,
                                   ms=(time.perf_counter() - t0) * 1000, flags=["exec_refused"]), None

        if (not native_only and parsed and self.model_command_tools and self.native_tools
                and getattr(self.llm, 'supports_native_tools', False)
                and self._tool_command_supported(argv)):
            return await self._run_bound_stage(session, stage, stdin, on_token=on_token, t0=t0,
                                               piped=piped, stdin_bytes=stdin_bytes)

        observed = await self.network.run(session, argv, parsed=parsed,
            emit=getattr(session, "_terminal_output", None) if not piped and not native_only else None)
        if observed is not None:
            return StageResult(stage.raw, "network", observed.stdout,
                ok=observed.exit_code == 0, ms=(time.perf_counter()-t0)*1000,
                flags=["real_network"], stderr=observed.stderr,
                exit_code=observed.exit_code,
                network=dict(observed.audit, stdout=observed.stdout), streamed=observed.streamed), None

        transfer = await self.downloads.run(session, argv, parsed=parsed)
        if transfer is not None:
            return StageResult(stage.raw, "curl", transfer.stdout.decode("utf-8", "replace"),
                ok=transfer.exit_code == 0, ms=(time.perf_counter()-t0)*1000,
                flags=["internet_download"] if transfer.exit_code == 0 else ["download_error"],
                stdout_bytes=transfer.stdout, stderr=transfer.stderr,
                exit_code=transfer.exit_code, download=transfer.audit), None

        if not parsed:
            if native_only:
                return StageResult(stage.raw, 'native', '', ok=False, exit_code=2,
                    stderr='Unsupported command syntax\n'), None
            # Tokens from the shlex fallback are not literal filesystem operands
            # $(cat index) must never become a file name or cause inferred writes
            # the model receives the original expression
            return await self._run_llm_stage(session, stage, stdin,
                on_token=on_token, t0=t0, parsed=False, piped=piped, stdin_bytes=stdin_bytes)

        # The intentionally vulnerable delegation only runs inside the virtual filesystem
        from .privilege_runtime import run as privilege_command
        delegated = await privilege_command(self, session, stage, stdin, piped=piped, on_token=on_token)
        if delegated is not None:
            return delegated, None

        # Lifecycle commands are authoritative - Qwen never invents a process change
        if self.processes is not None:
            if (not native_only and self.model_process_tools and self.native_tools and parsed
                    and isinstance(self.processes, ProcessManager) and self.filesystem
                    and getattr(self.llm, 'supports_native_tools', False)
                    and process_command(argv)):
                return await self._run_llm_stage(session, stage, stdin, on_token=on_token,
                                                 t0=t0, parsed=True, process_request=True, piped=piped, stdin_bytes=stdin_bytes)
            observed = self.processes.run_argv(session, argv, stdin)
            if isinstance(observed, ProcessResult):
                observed = await self.processes.wait_result(session, observed)
                return StageResult(stage.raw, "proc", observed.output,
                    ok=observed.exit_code == 0, exit_code=observed.exit_code,
                    ms=(time.perf_counter()-t0)*1000), None
            if observed is not None:
                return StageResult(stage.raw, "proc", observed, ms=(time.perf_counter()-t0)*1000), None

        # Profile views read the same realm as cat, stat and the native tools
        if self.recon is not None:
            observed = self.recon.run(session, argv, stdin)
            if observed is not None:
                output, status = observed
                return (StageResult(stage.raw, "recon", output, ok=status == 0,
                                    exit_code=status, ms=(time.perf_counter() - t0) * 1000), None)
            if (argv and argv[0].rsplit("/", 1)[-1] == "sudo"
                    and self.filesystem.vfs.meta("attacker_profile")):
                from .recon import sudo_policy
                target, index = "root", 1
                while index < len(argv):
                    if argv[index] == "-n":
                        index += 1
                    elif argv[index] == "-u" and index + 1 < len(argv):
                        target, index = argv[index + 1], index + 2
                    elif argv[index] == "--":
                        index += 1
                        break
                    else:
                        break
                if index < len(argv) and not argv[index].startswith("-"):
                    if not sudo_policy(self.filesystem, session):
                        return StageResult(stage.raw, "recon", "sudo: a password is required", ok=False), None
                    view = self.filesystem.vfs.for_realm(session.realm or "unknown")
                    if target not in view.passwd_users():
                        return StageResult(stage.raw, "recon", f"sudo: unknown user {target}", ok=False), None
                    if getattr(session, "_sudo_depth", 0) >= 8:
                        return StageResult(stage.raw, "recon", "sudo: resource temporarily unavailable", ok=False), None
                    elevated = copy(session)
                    elevated.username, elevated._identity = target, None
                    elevated._sudo_depth = getattr(session, "_sudo_depth", 0) + 1
                    inner = Stage(argv=argv[index:], raw=shlex.join(argv[index:]))
                    result, llm_result = await self._run_stage(elevated, inner, stdin, on_token=on_token, piped=piped,
                                                              stdin_bytes=stdin_bytes, native_only=native_only)
                    result.command = stage.raw
                    result.flags.append("virtual_sudo")
                    return result, llm_result

        if self.filesystem is not None and (stdin is None or stdin_bytes is not None):
            inspected = inspect_bytes(self.filesystem, session, argv,
                stdin_bytes if stdin_bytes is not None else stdin.encode() if stdin is not None else None)
            if inspected is not None:
                stdout, stderr, status = inspected
                raw = stdout if isinstance(stdout, bytes) else None
                return StageResult(stage.raw, "bytes", _text_of(raw) if raw is not None else stdout,
                    ok=status == 0, stderr=stderr, exit_code=status, stdout_bytes=raw,
                    ms=(time.perf_counter()-t0)*1000), None

        # 1. The filesystem store, for a stage that starts a pipeline
        if self.filesystem is not None and stdin is None:
            out = self.filesystem.run_argv(session, argv, piped=piped)
            if out is not None:
                flags = list(self.filesystem.last_flags)
                raw = None
                if piped and argv[0].rsplit("/", 1)[-1] == "cat" and "fs_error" not in flags:
                    cat_flags, operands = self.filesystem._split_flags(argv[1:])
                    if not cat_flags and operands and "-" not in operands:
                        try:
                            raw = b"".join(read_bytes(self.filesystem, session, path,
                                self.filesystem.max_cat_bytes) for path in operands)
                        except Exception:
                            # Files stored without content keep their normal route
                            raw = None
                ok = _stage_ok(argv, out, flags)
                # GNU ls reports an inaccessible operand as serious trouble (2)
                # an unreadable subdirectory under -R is minor (1)
                status = None if ok else (2 if argv[0].rsplit("/", 1)[-1] == "ls" and _ls_serious(argv, out) else None)
                return (StageResult(stage.raw, "fs", out, ok=ok, exit_code=status,
                                    ms=(time.perf_counter() - t0) * 1000,
                                    flags=flags, stdout_bytes=raw), None)

        # 2. System identity and info, computed from files in the store
        if self.system is not None and stdin is None:
            system_result = self.system.run(session, argv, None)
            if system_result is not None:
                stdout, stderr, status = system_result
                out = (stdout + stderr).rstrip("\n")
                return (StageResult(stage.raw, "sys", out,
                                    ok=status == 0, exit_code=status,
                                    ms=(time.perf_counter() - t0) * 1000), None)

        # 3. Account management, which writes the identity files
        if self.accounts is not None:
            out = self.accounts.run_argv(session, argv, stdin)
            if out is not None:
                flags = list(self.accounts.last_flags)
                return (StageResult(stage.raw, "accounts", out, flags=flags,
                                    ok=self.accounts.last_exit_code == 0, exit_code=self.accounts.last_exit_code,
                                    ms=(time.perf_counter() - t0) * 1000), None)

        # 4. Native filters, reading through the store when given operands
        if self.filesystem is not None:
            def read(path: str) -> str:
                return self.filesystem.read_for_filter(session, path)
            read.bytes = lambda path: read_bytes(self.filesystem, session, path)
            read.walk = lambda top, **kw: walk_files(self.filesystem, session, top, **kw)
        else:
            def read(path: str) -> str:
                raise FileNotFoundError(path)
        read.tty = (not piped) and getattr(session, "has_pty", True)
        out = native.run(argv, stdin, read)
        if isinstance(out, native.FilterResult):
            return (StageResult(stage.raw, "filter", out.stdout, ok=out.status == 0,
                                exit_code=out.status, stderr=out.stderr + "\n" if out.stderr else "",
                                ms=(time.perf_counter() - t0) * 1000), None)
        if out is not None:
            return (StageResult(stage.raw, "filter", out,
                                ms=(time.perf_counter() - t0) * 1000), None)

        if native_only:
            # Internal marker only - _run_bound_stage never shows this text to an attacker
            # it re-routes the stage or prints GNU's own error
            return StageResult(stage.raw, 'native', '', ok=False, exit_code=127,
                stderr=f'{argv[0]}: unsupported native command form\n', flags=['native_declined']), None

        # A program that is not installed gets bash's answer, not Qwen's
        # the store decides with the same PATH lookup which and type use
        missing = self.shell.not_found(session, argv) if parsed and not self._known_native(argv) else None
        if missing is not None:
            message, status = missing
            return StageResult(stage.raw, "shell", "", ok=False, stderr=message, exit_code=status,
                               ms=(time.perf_counter() - t0) * 1000, flags=["command_not_found"]), None

        # An option GNU itself rejects gets GNU's exact message in either routing mode
        # the bound path applies the same check after a decline
        rejected = invalid_option(argv) if parsed else None
        if rejected is not None:
            message, status = rejected
            return StageResult(stage.raw, "shell", "", ok=False, stderr=message, exit_code=status,
                               ms=(time.perf_counter() - t0) * 1000, flags=["gnu_option_error"]), None

        # Retrieval gives the model context after the authoritative handlers
        # Qwen can pick an exact match through retrieval_search
        # the runtime then rechecks it and relays the literal output when enabled
        return await self._run_llm_stage(session, stage, stdin,
                                         on_token=on_token, t0=t0, piped=piped, stdin_bytes=stdin_bytes)

    # A command some native handler implements
    # Ubuntu ships it, whatever flags it declined
    def _known_native(self, argv) -> bool:
        if not argv:
            return False
        name = argv[0].rsplit("/", 1)[-1]
        if "/" in argv[0]:
            return False
        known = set(native.FILTERS) | {"ss", "ip", "dpkg", "dpkg-query", "crontab", "history", "ufw",
                                       "sudo", "su", "md5sum", "sha1sum", "sha256sum", "sha512sum",
                                       "base64", "wc"}
        for handler in (self.filesystem, self.system, self.accounts):
            if handler is not None:
                known |= set(handler.names())
        if name in known or process_command(argv) or self.downloads.handles(argv) or self.network.handles(argv):
            return True
        from .retrieval import canonical
        # Captured Ubuntu programs such as getconf and ldd
        return canonical(shlex.join(argv)) is not None

    # Run a model-selected native action (command_run)
    # a known command in a form no handler implements is declined and changes nothing
    # its history entry is dropped and the stage gets an honest answer instead
    # GNU's exact message when GNU rejects the option too, otherwise the grounded model path
    async def _run_bound_stage(self, session, stage, stdin, *, on_token, t0, piped, stdin_bytes):
        async def execute_bound_stage():
            result, _ = await self._run_stage(session, stage, stdin, piped=piped,
                parsed=True, stdin_bytes=stdin_bytes, native_only=True)
            return result
        history_mark = len(session.history)
        result, llm_result = await self._run_llm_stage(session, stage, stdin, on_token=on_token,
            t0=t0, command_runner=execute_bound_stage, piped=piped, stdin_bytes=stdin_bytes)
        if 'native_declined' not in result.flags:
            return result, llm_result
        del session.history[history_mark:]
        first_attempt = {'tool_calls': result.tool_calls, 'llm_rounds': result.llm_rounds,
                         'rejected_answers': result.rejected_answers,
                         'model_error': llm_result.error if llm_result else None}
        rejected = invalid_option(stage.argv)
        if rejected is not None:
            message, status = rejected
            session.history.extend([{'role': 'user', 'content': stage.raw},
                                    {'role': 'assistant', 'content': message}])
            return StageResult(stage.raw, 'shell', '', ok=False, stderr=message, exit_code=status,
                               ms=(time.perf_counter() - t0) * 1000,
                               flags=['native_declined', 'gnu_option_error'],
                               fallback={'declined_attempt': first_attempt}), llm_result
        if llm_result is not None and llm_result.error:
            # Qwen already failed on this stage - do not spend a second deadline
            name = shlex.quote(stage.argv[0][:128]) if stage.argv else 'command'
            unavailable = StageResult(stage.raw, 'unavailable', '', ok=False,
                stderr=f'{shell_prefix(session)}{name}: Resource temporarily unavailable\n',
                exit_code=124 if llm_result.timed_out else 75)
            return self._fallback_result(session, stage, unavailable, llm_result,
                                         ['native_declined'], 'native_declined_model_unavailable', t0)
        rerouted, rerouted_llm = await self._run_llm_stage(session, stage, stdin, on_token=on_token,
            t0=t0, parsed=True, piped=piped, stdin_bytes=stdin_bytes)
        rerouted.flags = list(dict.fromkeys(rerouted.flags + ['native_declined', 'native_declined_rerouted']))
        rerouted.tool_calls = result.tool_calls + rerouted.tool_calls
        rerouted.llm_rounds = result.llm_rounds + rerouted.llm_rounds
        rerouted.rejected_answers = result.rejected_answers + rerouted.rejected_answers
        rerouted.fallback = dict(rerouted.fallback, declined_attempt=first_attempt)
        return rerouted, rerouted_llm

    async def _retrieve_bounded(self, session, command):
        from .retrieval import RetrievalResult
        try:
            return await asyncio.wait_for(self.retrieval.retrieve(session, command), self.retrieval_timeout_s)
        except TimeoutError:
            return RetrievalResult(reason='timeout', error='Reference lookup timed out')
        except Exception:
            return RetrievalResult(reason='unavailable', error='Reference lookup unavailable')

    def _fallback_result(self, session, stage, observed, result, flags, reason, t0):
        observed.by += '+fallback'
        observed.ms = (time.perf_counter()-t0)*1000
        observed.flags.extend(flags + result.flags + ['ai_fallback', 'llm_error'])
        observed.tool_calls = result.tool_calls
        observed.llm_rounds = result.rounds
        observed.rejected_answers = result.rejected_answers
        observed.fallback = {'used': True, 'reason': reason, 'source': observed.by.split('+')[0],
                             'trigger': 'timeout' if result.timed_out else 'circuit_open' if result.error == 'circuit_open' else 'model_error',
                             'circuit': self.ai_circuit.state()}
        result.text = observed.output
        session.history.extend([{'role':'user', 'content':stage.raw},
            {'role':'assistant', 'content':(observed.output+observed.stderr)[:MAX_PIPED_CHARS]}])
        return observed, result

    async def _recover_model_failure(self, session, stage, stdin, *, access, result, flags, t0,
                                     parsed, piped, stdin_bytes):
        observed = None
        reason = 'unavailable'
        if access is not None and access.action_name:
            if not access.action_started:
                started = time.perf_counter()
                outcome = await access.dispatch(access.action_name, {})
                result.tool_calls.append({'name':access.action_name, 'arguments':{}, 'result':outcome,
                    'origin':'runtime_fallback', 'ms':(time.perf_counter()-started)*1000})
            observed = access.executed_stage
            reason = 'native_action'
            if observed is None:
                # Never retry an action that already began
                reason = 'action_outcome_unavailable'
        elif parsed and self._tool_command_supported(stage.argv):
            observed, _ = await self._run_stage(session, stage, stdin, parsed=True, piped=piped,
                                              stdin_bytes=stdin_bytes, native_only=True)
            if 'native_declined' in observed.flags:
                observed = None
            reason = 'native_handler'
        if observed is None and reason != 'action_outcome_unavailable' and self.retrieval is not None and stdin is None:
            # Recheck at recovery time, the state may have changed while Qwen was waiting
            # never replay a near match or a truncated record
            fresh = await self._retrieve_bounded(session, stage.raw)
            if fresh.expected is not None and not fresh.error:
                record = next((x for x in fresh.observations if x['exact'] and not x['truncated']), None)
                if record is not None:
                    observed = StageResult(stage.raw, 'reference', record['stdout'],
                        stdout_bytes=record['stdout'].encode(), stderr=record['stderr'],
                        exit_code=record['exit_code'], ok=record['exit_code'] == 0,
                        retrieval=fresh.as_log())
                    reason = 'revalidated_exact_reference'
        if observed is None:
            name = shlex.quote(stage.argv[0][:128]) if stage.argv else 'command'
            observed = StageResult(stage.raw, 'unavailable', '', ok=False,
                stderr=f'{shell_prefix(session)}{name}: Resource temporarily unavailable\n',
                exit_code=124 if result.timed_out else 75)
        return self._fallback_result(session, stage, observed, result, flags, reason, t0)

    async def _run_llm_stage(self, session, stage: Stage, stdin: Optional[str],
                             *, on_token, t0: float, parsed: bool = True, process_request=False,
                             command_runner=None, piped=False, stdin_bytes=None):
        # Aliases - the model sees the command as typed (see _model_argv)
        if getattr(stage, "model_argv", None):
            stage = dataclasses.replace(stage, argv=list(stage.model_argv),
                                        raw=shlex.join(stage.model_argv), model_argv=None)
        messages = list(session.history)
        flags: list[str] = []
        label = "llm"
        grounded_paths = 0
        reference = None
        if self.retrieval is not None and stdin is None and not process_request and command_runner is None:
            reference = await self._retrieve_bounded(session, stage.raw)
            if reference.error:
                flags.append("retrieval_error")
        access = (ModelTools(self.filesystem, session, command=stage.raw, argv=stage.argv,
                           processes=self.processes, retrieval=self.retrieval,
                           process_request=process_request, stdin=stdin, reference=reference,
                           command_runner=command_runner,
                           relay_reference_output=self.ai_fallback,
                           relay_action_output=self.ai_fallback,
                           retrieval_timeout_s=self.retrieval_timeout_s,
                           require_tools=stdin is None and classify(stage.raw) == "fs" and not (reference and reference.text))
                  if self.filesystem else None)
        use_tools = (self.native_tools and access is not None
                     and getattr(self.llm, "supports_native_tools", False))
        if use_tools:
            # The persona's shell-only examples include cat reporting a missing file without a lookup
            # keep the persona rules and the real session turns, but not that habit on the native tool path
            seed_len = getattr(session, "seed_len", 0)
            messages = ([m for m in messages[:seed_len] if m.get("role") == "system"]
                        + messages[seed_len:])
            if self.prefetch_reads and (access.answer_policy.read_paths or
                                        access.answer_policy.reference_path is not None):
                # A current file read must not inherit an old answer from history
                # or another user's protected bytes
                messages = [m for m in messages if m.get("role") == "system"]
            # The native client adds the tool guide and session context for every caller
            # including this production path

        if self.ground_model and self.filesystem is not None and parsed:
            g = ground.build(access.vfs, session, stage.argv)
            if g is not None:
                grounded_paths = g.paths_checked
                flags.append("state_grounded")
                flags.extend(g.flags)
                label = "llm+state"
                messages.append({"role": "system",
                                 "content": ground.SYSTEM_PREAMBLE + g.text})

        if reference and reference.text:
            label += "+retrieval"
            flags.append("retrieval_grounded")
            if use_tools and access.relay_reference_output and reference.expected is not None:
                messages.append({'role': 'system', 'content':
                    'An exact reference is available. Call retrieval_search for the current command. '
                    'The runtime will revalidate and relay its literal output.'})
            else:
                messages.append({"role": "system", "content": reference.text})

        if stdin is not None:
            piped = stdin[:MAX_PIPED_CHARS]
            if len(stdin) > MAX_PIPED_CHARS:
                flags.append("pipe_truncated")
            label += "+piped"
            messages.append({
                "role": "system",
                "content": "The previous command in this pipeline produced "
                           "exactly the following on stdout. Apply the next "
                           "command to it and print only the result.\n"
                           "<<<STDIN\n" + piped + "\nSTDIN>>>"})

        messages.append({"role": "user", "content": stage.raw})
        stop = [f"{session.username}@{self.persona.hostname}:"]
        async def invoke():
            if use_tools:
                return await self.llm.complete_with_tools(
                    messages, access, stop=stop,
                    max_rounds=self.tool_max_rounds, max_tool_calls=self.tool_max_calls,
                    prefetch_reads=self.prefetch_reads)
            if (reference and reference.expected is not None and
                    callable(getattr(self.llm, "complete_with_reference", None))):
                return await self.llm.complete_with_reference(messages, reference.expected, stop=stop)
            return await self.llm.complete(messages, stop=stop,
                on_token=None if self.ai_fallback or (reference and reference.text) else on_token)

        if use_tools:
            label += '+tools'
        permit = self.ai_circuit.acquire() if self.ai_fallback else None
        if self.ai_fallback and permit is None:
            result = LLMResult(error='circuit_open', model=getattr(self.llm, 'model', ''), flags=['ai_circuit_open'])
        else:
            try:
                # OllamaClient's deadline covers queue and model time but pauses during native execution
                # other drivers get a wall-clock bound
                result = await invoke() if isinstance(self.llm, OllamaClient) else await asyncio.wait_for(invoke(), self.ai_timeout_s)
            except asyncio.CancelledError:
                self.ai_circuit.finish(permit, cancelled=True)
                raise
            except TimeoutError:
                result = LLMResult(error='timeout', timed_out=True, model=getattr(self.llm, 'model', ''))
            except Exception as exc:
                result = LLMResult(error=f'{type(exc).__name__}: {exc}', model=getattr(self.llm, 'model', ''))
            self.ai_circuit.finish(permit, failed=bool(result.error))

        if use_tools:
            reference = access.reference
            if reference and reference.text and 'retrieval_grounded' not in flags:
                flags.append('retrieval_grounded'); label += '+retrieval'
        receipt = access.process_receipt if use_tools else None
        if receipt is not None:
            flags.append('command_tool_executed' if command_runner else 'process_tool_executed')

        if use_tools and access.executed_stage is not None:
            # Native execution already happened - keep its exact bytes, status and audits
            # even if the model's answer afterwards failed
            # never infer another change from the model's completion
            observed = access.executed_stage
            if result.error and self.ai_fallback:
                observed.flags.append('llm_error_after_execution')
                return self._fallback_result(session, stage, observed, result, flags, 'executed_result', t0)
            observed.by += '+tools'
            observed.ms = (time.perf_counter() - t0) * 1000
            observed.flags.extend(flags + result.flags + (['llm_error_after_execution'] if result.error else []))
            observed.tool_calls = result.tool_calls
            observed.llm_rounds = result.rounds
            observed.rejected_answers = result.rejected_answers
            result.text = observed.output
            session.history.extend([{'role': 'user', 'content': stage.raw},
                                    {'role': 'assistant', 'content': observed.output[:MAX_PIPED_CHARS]}])
            return observed, result

        if result.error:
            if self.ai_fallback:
                return await self._recover_model_failure(session, stage, stdin, access=access if use_tools else None,
                    result=result, flags=flags, t0=t0, parsed=parsed, piped=piped, stdin_bytes=stdin_bytes)
            return (StageResult(stage.raw, label, "", ok=False,
                                ms=(time.perf_counter() - t0) * 1000,
                                flags=flags + result.flags + ["llm_error"],
                                tool_calls=result.tool_calls, llm_rounds=result.rounds,
                                rejected_answers=result.rejected_answers,
                                retrieval=reference.as_log() if reference else {}), result)

        if (use_tools and result.tool_output is not None
                and result.tool_output.get('source') in ('retrieval_tool', 'vfs_tool')):
            output = result.tool_output
            text, stderr, code = output['stdout'], output['stderr'], output['exit_code']
            session.history.extend([{'role': 'user', 'content': stage.raw},
                                    {'role': 'assistant', 'content': (text + stderr)[:MAX_PIPED_CHARS]}])
            # Literal records skip sanitising and inferred side effects
            # source ids and the model's selection stay visible in the log
            relay_label = 'reference+tools' if output['source'] == 'retrieval_tool' else 'fs+tools'
            return (StageResult(stage.raw, relay_label, text, ok=code == 0,
                                stdout_bytes=text.encode('utf-8'), stderr=stderr, exit_code=code,
                                ms=(time.perf_counter() - t0) * 1000, flags=flags + result.flags,
                                tool_calls=result.tool_calls, llm_rounds=result.rounds,
                                rejected_answers=result.rejected_answers,
                                retrieval=reference.as_log() if reference else {}), result)

        literal = result.raw_text.replace("\r\n", "\n").strip("\n")
        if ((reference and reference.expected is not None and literal == reference.expected)
                or (receipt is not None and literal == access.literal_output)):
            # A verified literal record may itself contain markdown or words such as Output:
            # those are data, not assistant commentary
            text, clean_flags = literal, []
        else:
            text, clean_flags = clean_shell_output(
                result.raw_text, strip_prompt=self.strip_prompt,
                max_lines=self.max_lines)
        result.text = text
        result.flags.extend(clean_flags)
        flags.extend(result.flags)
        if reference and reference.expected is not None and text != reference.expected:
            flags.append("retrieval_output_mismatch")

        # Verification and write-back, both against the store
        if self.filesystem is not None:
            # Write-back first - a path this command really created must exist
            # before verification looks for invented ones
            if self.write_back and parsed:
                ident = access.ident
                notes = fx.apply(access.vfs, session, stage.argv,
                                 text, ident=ident,
                                 may_write=access.fs.may_write)
                if notes:
                    flags.append("effects_applied")
                    prior = list(getattr(session, "_last_effects", []) or [])
                    setattr(session, "_last_effects", prior + notes)
            if self.verify_output and parsed:
                v = verify.check(access.vfs, session, stage.argv, text)
                flags.extend(v.flags)

        session.history.append({"role": "user", "content": stage.raw})
        session.history.append({"role": "assistant", "content": text})

        _ = grounded_paths
        ok = not fx.looks_failed(text)
        if reference and reference.expected is not None and text == reference.expected:
            ok = reference.exit_code == 0
        if receipt is not None:
            ok = receipt['exit_code'] == 0
        return (StageResult(stage.raw, label, text, ok=ok,
                            exit_code=receipt['exit_code'] if receipt is not None else None,
                            ms=(time.perf_counter() - t0) * 1000, flags=flags,
                            tool_calls=result.tool_calls, llm_rounds=result.rounds,
                            rejected_answers=result.rejected_answers,
                            retrieval=reference.as_log() if reference else {}),
                result)

    # The Whole Line

    async def handle(self, session, command: str, *, on_token=None) -> Response:
        category = classify(command)
        if isinstance(self.processes, ProcessManager):
            self.processes.refresh(session)

        if self.filesystem and self.filesystem.vfs.meta("attacker_profile"):
            if not hasattr(session, "command_history"):
                session.command_history = []
            session.command_history.append(command)
            session.command_history = session.command_history[-1000:]
        self.shell.record_history(session, command)

        if self.filesystem is not None:
            self.filesystem.last_store_ms = 0.0

        builtin = self._builtin(session, command)
        if builtin is not None:
            if builtin.category == "other":
                builtin.category = category
            return builtin

        parsed = True
        try:
            segments = parse_shell(command)
        except ParseError:
            # Command substitution, compound commands and here-documents are not approximated
            # the line goes to the model whole
            segments = [Segment(stages=[Stage(argv=shlex_safe(command),
                                              raw=command)])]
            parsed = False
            tokens = shlex_safe(command)
            names = {word.rsplit("/", 1)[-1] for word in tokens}
            if names & NETWORK_COMMANDS:
                result = StageResult(command, "network", f"{shell_prefix(session)}unsupported network command syntax", ok=False, exit_code=2)
                return Response(result.output, "network", category, stages=[result],
                                streams=[("err", result.output)])
            if self.processes and (names & PROCESS_COMMANDS or "&" in command):
                result = StageResult(command, "proc", f"{shell_prefix(session)}unsupported process command syntax", ok=False, exit_code=2)
                return Response(result.output, "proc", category, stages=[result],
                                streams=[("err", result.output)])

        if not segments:
            return Response("", "builtin", category)

        setattr(session, "_last_effects", [])
        # ("out" or "err", text) pairs in terminal order
        blocks: list[tuple[str, str]] = []
        all_stages: list[StageResult] = []
        all_flags: list[str] = []
        last_llm: Optional[LLMResult] = None
        store_ms = 0.0
        grounded = 0
        previous_ok = True
        shell_exited = False
        trailing_newline = True
        separate = not getattr(session, "has_pty", True)

        def emit(kind: str, text: str) -> None:
            # The terminal writer adds one newline
            # keep any further blank lines a program printed on purpose, as command-not-found does
            if text:
                blocks.append((kind, text[:-1] if kind == "err" and text.endswith("\n") else text))

        for seg in segments:
            # && and || need an exit status
            # a stage fails when the store reported an error or the output has a failure message
            # crude, but it makes cd /nope && rm -rf / behave the way an attacker expects
            if seg.joiner == "&&" and not previous_ok:
                continue
            if seg.joiner == "||" and previous_ok:
                continue

            # Expand this segment now, after the earlier segments ran
            if parsed:
                try:
                    for stage in seg.stages:
                        self._expand_stage(session, stage)
                    if seg.redirect:
                        seg.redirect = (seg.redirect[0], self.shell.expand_one(session, seg.redirect[1]))
                except ShellError as exc:
                    sr = StageResult(seg.raw, "shell", "", ok=False, stderr=exc.message + "\n",
                                     exit_code=exc.status, flags=["expansion_error"])
                    all_stages.append(sr)
                    emit("err", sr.stderr)
                    previous_ok = False
                    session.last_exit_status = exc.status
                    trailing_newline = True
                    continue

            if seg.background:
                if any(self.network.handles(st.argv) for st in seg.stages):
                    result = ProcessResult(f"{shell_prefix(session)}background network diagnostics are not supported", 2)
                elif not isinstance(self.processes, ProcessManager) or len(seg.stages) != 1:
                    result = ProcessResult(f"{shell_prefix(session)}background pipelines are not supported", 2)
                else:
                    # A background command's job notice is never redirected
                    # permission failures come before any process is created
                    try:
                        if seg.redirect and not is_special_device(self._abs(session, seg.redirect[1])):
                            write_bytes(self.filesystem, session, seg.redirect[1], b"", append=seg.redirect[0] == ">>")
                        result = self.processes.run_argv(session, seg.stages[0].argv, background=True)
                    except Exception as exc:
                        result = ProcessResult(shell_prefix(session) + getattr(exc,"message",str(exc)), 1)
                sr = StageResult(seg.raw, "proc", result.output, ok=result.exit_code == 0, exit_code=result.exit_code)
                all_stages.append(sr)
                previous_ok = sr.ok
                session.last_exit_status = sr.exit_code
                emit("out", sr.output)
                trailing_newline = True
                continue

            stdin: Optional[str] = None
            stdin_bytes: Optional[bytes] = None
            seg_ok = True
            deferred_err = ""
            stages = seg.stages[:MAX_STAGES]
            for idx, stage in enumerate(stages):
                # A stage is piped when its stdout feeds another stage or a file
                # only the final stage of an unredirected segment writes to the terminal
                piped = (idx < len(stages) - 1) or seg.redirect is not None
                if stage.stdin_path is not None and parsed:
                    try:
                        stdin_bytes = self._read_input(session, stage.stdin_path)
                        stdin = _text_of(stdin_bytes)
                    except FSError as exc:
                        sr = StageResult(stage.raw, "shell", "", ok=False, exit_code=1,
                                         stderr=f"{shell_prefix(session)}{stage.stdin_path}: {exc.message}\n")
                        all_stages.append(sr)
                        emit("err", sr.stderr)
                        stdin, stdin_bytes, seg_ok = "", b"", False
                        continue
                if parsed and not stage.argv:
                    # Assignment-only (X=1) or redirect-only (> file) stage
                    sr = self._assignment_stage(session, stage)
                else:
                    sr, llm_res = await self._run_stage(session, stage, stdin,
                                                        on_token=(on_token if len(segments) == 1
                                                                  and len(stages) == 1
                                                                  and not seg.redirect else None),
                                                        piped=piped, parsed=parsed, stdin_bytes=stdin_bytes)
                    if llm_res is not None:
                        last_llm = llm_res
                all_stages.append(sr)
                all_flags.extend(sr.flags)
                if sr.by.split('+')[0] == "fs" and self.filesystem is not None:
                    store_ms += self.filesystem.last_store_ms
                if sr.by.startswith("llm"):
                    grounded += 1
                if parsed and stage.argv:
                    if stage.argv[0] == "cd" and sr.ok:
                        self.shell.ensure(session)
                        session.shell_cd_count += 1
                    if sr.by.split('+')[0] in ("fs", "sys", "filter", "proc", "recon", "bytes",
                                               "accounts", "network", "curl"):
                        self.shell.note_command(session, stage.argv[0])

                # Route stdout and stderr the way bash would
                out_text = "" if sr.streamed else sr.output
                out_bytes = None if sr.streamed else sr.stdout_bytes
                # Raw text - emit() removes the one newline the terminal adds back
                err_text = sr.stderr or ""
                merge = stage.stderr in (("stdout",), ("same",))
                if not merge and (piped or stage.stderr is not None or stage.stdout_to_stderr or separate):
                    kept, diagnostics = split_diagnostics(stage.argv, out_text)
                    if diagnostics:
                        out_text, out_bytes = kept, None
                        err_text = "\n".join(x for x in (diagnostics, err_text) if x)
                if merge and err_text:
                    out_text = "\n".join(x for x in (err_text[:-1] if err_text.endswith("\n") else err_text, out_text) if x)
                    out_bytes, err_text = None, ""
                if stage.stderr and stage.stderr[0] in (">", ">>"):
                    try:
                        self._write_redirect(session, stage.stderr[1],
                                             (err_text if err_text.endswith("\n") else err_text + "\n").encode()
                                             if err_text else b"", append=stage.stderr[0] == ">>")
                    except FSError as exc:
                        # A failed write to stderr itself goes unreported
                        if exc.errno_name != "ENOSPC":
                            emit("err", f"{shell_prefix(session)}{stage.stderr[1]}: {exc.message}")
                            sr.ok, sr.exit_code = False, 1
                    err_text = ""
                if sr.by == "builtin" and idx == len(stages) - 1 and not seg.redirect:
                    # Builtins report errors after their output
                    deferred_err = err_text
                else:
                    emit("err", err_text)
                if stage.stdout_to_stderr:
                    emit("err", out_text)
                    out_text, out_bytes = "", b""
                if out_bytes is None:
                    out_bytes = (out_text + "\n").encode() if out_text else b""
                stdin, stdin_bytes = out_text, out_bytes
                seg_ok = sr.ok
                shell_status = self.processes.session_exit_code(session) if isinstance(self.processes, ProcessManager) else None
                if shell_status is not None:
                    sr.exit_code, sr.ok = shell_status, shell_status == 0
                    shell_exited = True
                    break
            previous_ok = seg_ok
            if all_stages:
                session.last_exit_status = all_stages[-1].exit_code if all_stages[-1].exit_code is not None else int(not seg_ok)

            final = stdin or ""
            if seg.redirect and (self.filesystem is not None or is_special_device(seg.redirect[1])):
                op, path = seg.redirect
                try:
                    if all_stages[-1].download and not all_stages[-1].ok:
                        # Failed downloads never publish partial or error files
                        pass
                    else:
                        shown = self._write_redirect(session, path, stdin_bytes or b"", append=op == ">>")
                        if shown:
                            # Covers > /dev/stdout, > /dev/stderr and > /dev/tty
                            emit(shown, final)
                        all_flags.append("fs_redirect")
                except FSError as exc:
                    if exc.errno_name == "ENOSPC" and stages and stages[-1].argv:
                        # /dev/full - the open succeeds and the program's write fails
                        # so the program, or the builtin with bash's prefix, reports it
                        program = stages[-1].argv[0]
                        prefix = shell_prefix(session) if all_stages[-1].by == "builtin" else ""
                        emit("err", f"{prefix}{program}: write error: No space left on device")
                    else:
                        emit("err", f"{shell_prefix(session)}{path}: {exc.message}")
                    all_flags.append("fs_error")
                    all_stages[-1].ok = False
                    all_stages[-1].exit_code = 1
                    previous_ok = False
                    session.last_exit_status = 1
                trailing_newline = True
            elif final or stdin_bytes:
                emit("out", final)
                trailing_newline = not stdin_bytes or stdin_bytes.endswith(b"\n")
            emit("err", deferred_err)
            if shell_exited:
                break

        effects = list(getattr(session, "_last_effects", []) or [])
        kinds = list(dict.fromkeys(s.by.split("+")[0] for s in all_stages))
        subsystem = "+".join(kinds) or "builtin"
        if "llm" in kinds and any("state_grounded" in s.flags
                                  for s in all_stages):
            subsystem = subsystem.replace("llm", "llm+state")
        if "llm" in kinds and any("native_tools_used" in s.flags or
                                  "runtime_evidence_prefetched" in s.flags for s in all_stages):
            subsystem += "+tools"
        elif any('command_tool_executed' in s.flags or 'process_tool_executed' in s.flags
                 or 'vfs_tool_relay' in s.flags or 'reference_tool_relay' in s.flags for s in all_stages):
            subsystem += '+tools'
        if ("llm" in kinds or "reference" in kinds) and any("retrieval_grounded" in s.flags for s in all_stages):
            subsystem += "+retrieval"

        if all_stages:
            last = all_stages[-1]
            session.last_exit_status = last.exit_code if last.exit_code is not None else int(not last.ok)
        if blocks and blocks[-1][0] == "err":
            trailing_newline = True
        return Response(
            output="\n".join(text for _, text in blocks if text),
            subsystem=subsystem,
            category=category,
            exit_session=shell_exited,
            llm=last_llm,
            flags=list(dict.fromkeys(all_flags)),
            stages=all_stages,
            store_ms=round(store_ms, 4),
            grounded_paths=grounded,
            effects=effects,
            newline=trailing_newline,
            streams=blocks,
        )

    # Shell Helpers

    def _abs(self, session, path: str) -> str:
        home = self.shell.home(session) or "/"
        if path == "~" or path.startswith("~/"):
            path = home + path[1:]
        return posixpath.normpath(posixpath.join(session.cwd, path)) if not path.startswith("/") else posixpath.normpath(path)

    # Expand marked words into argv
    # tilde, parameters, word splitting, globs and aliases
    def _expand_stage(self, session, stage: Stage) -> None:
        if stage.words is None:
            return
        typed = self.shell.expand_words(session, stage.words)
        head = stage.words[0] if stage.words else ""
        argv = self.shell.expand_alias(session, typed, quoted_head="\x00" in head)
        stage.argv = argv
        stage.raw = shlex.join(argv) if argv else ""
        stage.model_argv = _model_argv(typed, argv)
        stage.assignments = [self._expand_assignment(session, a) for a in stage.assignments]
        if stage.stderr and stage.stderr[0] in (">", ">>"):
            stage.stderr = (stage.stderr[0], self.shell.expand_one(session, stage.stderr[1]))
        if stage.stdin_path is not None:
            stage.stdin_path = self.shell.expand_one(session, stage.stdin_path)
        stage.words = None

    def _expand_assignment(self, session, word: str) -> str:
        name, _, value = word.partition("=")
        expanded = self.shell.expand_words(session, [value], glob=False) if value else [""]
        return name + "=" + " ".join(expanded)

    def _assignment_stage(self, session, stage: Stage) -> StageResult:
        for assignment in stage.assignments:
            name, _, value = assignment.partition("=")
            try:
                self.shell.set_var(session, name, value)
            except ShellError as exc:
                return StageResult(stage.raw, "builtin", "", ok=False, stderr=exc.message + "\n", exit_code=exc.status)
        return StageResult(stage.raw or " ".join(stage.assignments), "builtin", "", exit_code=0,
                           stdout_bytes=b"")

    def _read_input(self, session, path: str) -> bytes:
        absolute = self._abs(session, path)
        if absolute in ("/dev/null", "/dev/full"):
            return b""
        if absolute == "/dev/zero":
            return b"\0" * 4096
        if self.filesystem is None:
            raise FSError("No such file or directory", "ENOENT")
        return read_bytes(self.filesystem, session, path)

    # Write a redirect target
    # returns "out" or "err" when the target is the terminal
    def _write_redirect(self, session, path: str, data: bytes, *, append: bool) -> Optional[str]:
        absolute = self._abs(session, path)
        if absolute == "/dev/full":
            if not data:
                # Nothing written and nothing fails - true > /dev/full succeeds
                return None
            raise FSError("No space left on device", "ENOSPC")
        if absolute in ("/dev/stdout", "/dev/fd/1", "/dev/tty"):
            return "out"
        if absolute in ("/dev/stderr", "/dev/fd/2"):
            return "err"
        if is_special_device(absolute):
            return None
        if self.filesystem is None:
            raise FSError("Read-only file system", "EROFS")
        write_bytes(self.filesystem, session, path, data, append=append)
        return None


_COLOUR_SWITCHES = ("--color", "--colour")


# The command Qwen and the retrieval index see after alias expansion
# native handlers run the full expansion, where Ubuntu's ls and grep aliases add --color=auto
# the model gets the alias without its colour switch, so ls --version still matches the captures
# while ll still becomes the more informative ls -alF
def _model_argv(typed: list[str], argv: list[str]) -> Optional[list[str]]:
    if not typed or argv == typed or len(argv) < len(typed):
        return None
    alias_words = argv[:len(argv) - len(typed) + 1]
    kept = [w for w in alias_words if not (w in _COLOUR_SWITCHES or w.startswith(tuple(s + "=" for s in _COLOUR_SWITCHES)))]
    model = (kept or alias_words) + typed[1:]
    return model if model != argv else None


def _ls_serious(argv: list[str], out: str) -> bool:
    if "cannot access" in out:
        return True
    operands = [a for a in argv[1:] if a == "-" or not a.startswith("-")]
    return any(f"ls: cannot open directory '{op}'" in out for op in operands)


# Exit status for a store stage
# cd and similar commands report failure by returning the message rather than raising
# matched only at the start of a line and only against this command's own name
# because grep for "Permission denied" in a log file is not itself a failure
def _stage_ok(argv: list[str], output: str, flags: list[str]) -> bool:
    if "fs_error" in flags:
        return False
    head = argv[0].rsplit("/", 1)[-1] if argv else ""
    if head == "which":
        # Debian's which exits 1 when any operand is missing, printing the rest
        wanted = [a for a in argv[1:] if not a.startswith("-")]
        return len([line for line in output.splitlines() if line]) >= len(wanted)
    if not output:
        return True
    first = output.split("\n", 1)[0]
    return not first.startswith((f"{head}: ", "bash: ", "-bash: "))


def shlex_safe(command: str) -> list[str]:
    try:
        return shlex.split(command)
    except ValueError:
        return command.split()
