# SSH Session
# per-connection state and the shell loop
# the loop reads a line, hands it to the controller, writes the bytes back and logs
# the prompt is written here, not by the model, so it is always right and costs nothing
# on a PTY the asyncssh line editor handles echo, history and \r\n, so this code writes plain \n
# without a PTY (ssh host 'cmd' or ssh -T) there is no editor, echo or translation, like real sshd

# Imports
from __future__ import annotations

import asyncio
import time
import uuid
from dataclasses import dataclass, field
from typing import Optional

import asyncssh

from .persona import Persona

CLEAR_SCREEN = "\x1b[H\x1b[2J\x1b[3J"


@dataclass
class SessionState:
    session_id: str
    username: str
    peer_ip: str
    peer_port: int
    cwd: str
    history: list[dict[str, str]] = field(default_factory=list)
    seed_len: int = 0
    seq: int = 0
    started: float = field(default_factory=time.monotonic)
    oldpwd: str = "/"
    term_width: int = 80
    has_pty: bool = True
    realm: str = ""
    # False for ssh host 'cmd', which follows bash -c rules
    interactive: bool = True
    term_type: Optional[str] = None

    @classmethod
    def create(cls, persona: Persona, username: str, peer_ip: str,
               peer_port: int) -> "SessionState":
        seed = persona.seed_messages(username)
        return cls(
            session_id=uuid.uuid4().hex[:12],
            username=username,
            peer_ip=peer_ip,
            peer_port=peer_port,
            cwd=persona.home_dir(username),
            oldpwd=persona.home_dir(username),
            realm=peer_ip,
            history=seed,
            seed_len=len(seed),
        )

    # Keep the seed plus the last max_turns user and assistant pairs
    # 0 means unbounded, the baseline where the model carries the whole session
    # that keeps the latency growth the honours thesis measured
    def trim_history(self, max_turns: int) -> None:
        if max_turns <= 0:
            return
        keep = max_turns * 2
        tail = self.history[self.seed_len:]
        if len(tail) > keep:
            self.history = self.history[: self.seed_len] + tail[-keep:]

    @property
    def duration(self) -> float:
        return time.monotonic() - self.started


# Run one command as a cancellable task per SSH channel
# the shell itself stays alive
async def execute_command(process, state, controller, command, *, on_token=None):
    from .controller import Response, StageResult, classify
    state._interrupted = False
    state._terminal_output = process.stdout.write
    task = asyncio.create_task(controller.handle(state, command, on_token=on_token))
    state._command_task = task
    try:
        return await task
    except asyncio.CancelledError:
        if not state._interrupted or getattr(state, "_channel_closed", False):
            raise
        state.last_exit_status = 130
        return Response("", "interrupt", classify(command), flags=["interrupted"],
            stages=[StageResult(command, "interrupt", ok=False, exit_code=130,
                                flags=["interrupted"])])
    finally:
        state._command_task = None
        state._terminal_output = None


# Interactive shell loop
# returns the disconnect reason
async def run_shell(process, state: SessionState, controller, persona: Persona,
                    log, *, history_turns: int = 0, stream_output: bool = False,
                    idle_timeout: float = 900.0) -> str:
    stdout = process.stdout
    stdin = process.stdin

    clear_input = getattr(process.channel, "clear_input", None)
    size = process.get_terminal_size()
    state.term_width = (size[0] if size and size[0] else 80)
    state.has_pty = bool(process.get_terminal_type())

    stdout.write(persona.login_banner(state.username,
                                      previous=_previous_login(controller, state)))
    _install_completion(process, state, controller)

    reason = "closed"
    show_prompt = True
    while True:
        if show_prompt:
            stdout.write(persona.prompt(state.username, state.cwd))
        show_prompt = True

        try:
            line = await asyncio_wait_line(stdin, idle_timeout)
        except asyncssh.BreakReceived:
            # Ctrl-C - bash echoes ^C, drops the line and redraws the prompt
            if clear_input and state.has_pty:
                clear_input()
            stdout.write("^C\n")
            state.last_exit_status = 130
            continue
        except asyncssh.TerminalSizeChanged as exc:
            # The line editor redraws the pending input at the new width itself
            # printing another prompt here would garble the screen
            state.term_width = exc.width or state.term_width
            show_prompt = False
            continue
        except asyncssh.SignalReceived as exc:
            if exc.signal == COMPLETION_SIGNAL:
                # Second Tab - list the candidates, then a fresh prompt
                # the editor redraws the pending input after it, as readline does
                from .shell import format_completions
                listing = format_completions(getattr(state, "_completion_listing", []), state.term_width)
                stdout.write("\n" + listing + "\n" + persona.prompt(state.username, state.cwd))
            show_prompt = False
            continue
        except TimeoutError:
            reason = "idle_timeout"
            break
        except (asyncssh.ConnectionLost, BrokenPipeError, ConnectionResetError):
            reason = "connection_lost"
            break

        # Ctrl-D on an empty line, or channel EOF
        if line == "":
            stdout.write("logout\n")
            reason = "eof"
            break

        command = line.rstrip("\r\n")
        if not command.strip():
            continue

        state.seq += 1
        t0 = time.perf_counter()

        on_token = (lambda piece: stdout.write(piece)) if stream_output else None
        resp = await execute_command(process, state, controller, command, on_token=on_token)

        if resp.clear_screen:
            stdout.write(CLEAR_SCREEN)
        elif resp.output:
            if not (stream_output and resp.llm and resp.llm.streamed):
                # Commands like echo -n x and printf x leave the prompt on the same line
                stdout.write(resp.output + ("\n" if resp.newline else ""))
            else:
                stdout.write("\n")

        latency = time.perf_counter() - t0
        state.trim_history(history_turns)

        r = resp.llm
        log.command(
            state.session_id,
            seq=state.seq,
            store_ms=resp.store_ms,
            stages=[st.as_log() for st in resp.stages],
            effects=resp.effects,
            command=command,
            cwd=state.cwd,
            category=resp.category,
            subsystem=resp.subsystem,
            response=resp.output,
            raw_response=r.raw_text if r else "",
            latency_s=latency,
            flags=resp.flags,
            ttft_s=r.ttft_s if r else None,
            llm_total_s=r.total_s if r else None,
            prompt_eval_count=r.prompt_eval_count if r else None,
            eval_count=r.eval_count if r else None,
            load_duration_ns=r.load_duration_ns if r else None,
            prompt_eval_duration_ns=r.prompt_eval_duration_ns if r else None,
            eval_duration_ns=r.eval_duration_ns if r else None,
            total_duration_ns=r.total_duration_ns if r else None,
            history_messages=len(state.history),
            model_requests=model_requests(resp),
            model=r.model if r else "",
            error=r.error if r else None,
        )

        if resp.exit_session:
            stdout.write("logout\n")
            reason = "exit"
            break

    return reason


COMPLETION_SIGNAL = "HP-COMPLETE"


# Tab completion against the session's realm, for interactive PTY sessions only
def _install_completion(process, state, controller) -> None:
    register = getattr(process.channel, "register_key", None)
    shell = getattr(controller, "shell", None)
    if register is None or shell is None or not state.has_pty:
        return
    state._tab_last = None

    def on_tab(line, pos):
        try:
            outcome = shell.complete(state, line, pos)
        except Exception:
            return False
        if outcome[0] == "insert":
            state._tab_last = None
            return outcome[1], outcome[2]
        if outcome[0] == "list":
            if state._tab_last == (line, pos):
                state._tab_last = None
                state._completion_listing = outcome[1]
                return COMPLETION_SIGNAL, -1
            state._tab_last = (line, pos)
        return False
    try:
        register("\t", on_tab)
    except Exception:
        pass


# Ollama requests this command cost
# tool rounds, or one plain completion
def model_requests(resp) -> int:
    total = 0
    for stage in resp.stages:
        rounds = len(getattr(stage, "llm_rounds", []) or [])
        total += rounds or (1 if stage.by.startswith("llm") else 0)
    return total


# Read and update the per-user lastlog record kept in the store's metadata
def _previous_login(controller, state):
    filesystem = getattr(controller, "filesystem", None)
    if filesystem is None:
        return None
    key = "lastlog:" + state.username
    try:
        previous = filesystem.vfs.meta(key)
        filesystem.vfs.set_meta(key, f"{time.time():.0f}|{state.peer_ip}")
        when, _, source = previous.partition("|")
        return (float(when), source) if previous and source else None
    except Exception:
        return None


# Non-interactive ssh host 'command'
# attackers use this a lot for one-shot recon
# no banner, prompt or echo, and \n line endings
async def run_exec(process, state: SessionState, controller, log) -> str:
    command = (process.command or "").strip()
    state.has_pty = False
    state.interactive = False
    state.seq += 1
    t0 = time.perf_counter()
    resp = await execute_command(process, state, controller, command)
    latency = time.perf_counter() - t0

    last = resp.stages[-1] if resp.stages else None
    state.last_exit_status = (last.exit_code if last and last.exit_code is not None
                              else int(not last.ok) if last else 0)

    source = last.by.split('+')[0] if last else ''
    literal_read = bool(last and 'vfs_tool_relay' in last.flags)
    if (last and len(resp.stages) == 1 and (literal_read or last.stderr or source in ('curl', 'network', 'reference', 'unavailable'))
            and 'fs_redirect' not in resp.flags):
        if last.output and not last.streamed:
            process.stdout.write(last.output + ("\n" if not literal_read and source not in ('curl', 'reference') and not last.output.endswith("\n") else ""))
        if last.stderr:
            process.stderr.write(last.stderr if source == 'reference' or last.stderr.endswith('\n') else last.stderr + '\n')
    elif resp.streams:
        # Send stdout and stderr to their own SSH streams, as real sshd does
        last_index = len(resp.streams) - 1
        for index, (kind, text) in enumerate(resp.streams):
            stream = process.stderr if kind == "err" else process.stdout
            bare = text.endswith("\n") or (index == last_index and kind == "out" and not resp.newline)
            stream.write(text if bare else text + "\n")
    elif resp.output:
        process.stdout.write(resp.output if resp.output.endswith("\n") or not resp.newline else resp.output + "\n")

    r = resp.llm
    log.command(
        state.session_id,
        seq=state.seq,
        stages=[st.as_log() for st in resp.stages],
        effects=resp.effects,
        store_ms=resp.store_ms,
        command=command,
        cwd=state.cwd,
        category=resp.category,
        subsystem=resp.subsystem,
        response=resp.output,
        raw_response=r.raw_text if r else "",
        latency_s=latency,
        flags=resp.flags + ["exec_channel"],
        ttft_s=r.ttft_s if r else None,
        llm_total_s=r.total_s if r else None,
        prompt_eval_count=r.prompt_eval_count if r else None,
        eval_count=r.eval_count if r else None,
        load_duration_ns=r.load_duration_ns if r else None,
        prompt_eval_duration_ns=r.prompt_eval_duration_ns if r else None,
        eval_duration_ns=r.eval_duration_ns if r else None,
        total_duration_ns=r.total_duration_ns if r else None,
        history_messages=len(state.history),
        model_requests=model_requests(resp),
        model=r.model if r else "",
        error=r.error if r else None,
    )
    return "exec"


async def asyncio_wait_line(stdin, timeout: float) -> str:
    if timeout and timeout > 0:
        return await asyncio.wait_for(stdin.readline(), timeout)
    return await stdin.readline()
