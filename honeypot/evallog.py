# Evaluation Logging
# events.jsonl - one JSON object per event, the machine-readable record for analysis
# sessions/<session_id>.log - a plain transcript per session, read like a Cowrie log
# commands.log - one readable line per command across every connection, easy to tail
# each command record carries the data-collection fields and which subsystem answered
# fields are written even when null, so runs with different settings share one schema

# Imports
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


class EvalLog:
    def __init__(self, log_dir: str | Path = "logs", run_id: Optional[str] = None) -> None:
        self.dir = Path(log_dir)
        (self.dir / "sessions").mkdir(parents=True, exist_ok=True)
        self.run_id = run_id or datetime.now().strftime("%Y%m%d-%H%M%S")
        self._events = open(self.dir / "events.jsonl", "a", encoding="utf-8")
        self._transcripts: dict[str, Any] = {}
        # One readable line per command, across all sessions; peer and user come from the session
        self._commands = open(self.dir / "commands.log", "a", encoding="utf-8")
        self._who: dict[str, dict[str, str]] = {}

    # Low Level

    def emit(self, event: str, session_id: Optional[str] = None, **fields: Any) -> None:
        rec = {
            "ts": _now(),
            "run_id": self.run_id,
            "event": event,
            "session_id": session_id,
        }
        rec.update(fields)
        self._events.write(json.dumps(rec, ensure_ascii=False, default=str) + "\n")
        self._events.flush()

    def transcript(self, session_id: str):
        f = self._transcripts.get(session_id)
        if f is None:
            f = open(self.dir / "sessions" / f"{session_id}.log", "a", encoding="utf-8")
            self._transcripts[session_id] = f
        return f

    def write_transcript(self, session_id: str, text: str) -> None:
        f = self.transcript(session_id)
        f.write(text)
        f.flush()

    # Typed Events

    def connection(self, session_id: str, peer_ip: str, peer_port: int,
                   client_version: str) -> None:
        # One SSH connection can open several channels, each ending in its own disconnect,
        # so the peer and user are kept for the whole run and only bounded here, not popped per channel
        if len(self._who) >= 10000:
            self._who.pop(next(iter(self._who)), None)
        self._who[session_id] = {"peer": peer_ip, "user": "-"}
        self.emit("connect", session_id, peer_ip=peer_ip, peer_port=peer_port,
                  client_version=client_version)
        self.write_transcript(
            session_id,
            f"=== {_now()} connect from {peer_ip}:{peer_port} "
            f"client={client_version!r}\n",
        )

    def auth(self, session_id: str, method: str, username: str,
             credential: Optional[str], success: bool, **extra: Any) -> None:
        if method == "password":
            credential = "[REDACTED]"
        if success:
            self._who.setdefault(session_id, {"peer": "-", "user": "-"})["user"] = username
        self.emit("auth", session_id, method=method, username=username,
                  credential=credential, success=success, **extra)
        self.write_transcript(
            session_id,
            f"=== auth {method} user={username!r} cred={credential!r} "
            f"{'OK' if success else 'FAIL'}\n",
        )

    # Log a channel request
    # kind is shell, exec, subsystem or pty
    def channel(self, session_id: str, kind: str, **extra: Any) -> None:
        self.emit("channel", session_id, kind=kind, **extra)

    def command(
        self,
        session_id: str,
        *,
        seq: int,
        command: str,
        cwd: str,
        category: str,
        subsystem: str,
        response: str,
        latency_s: float,
        raw_response: str = "",
        flags: Optional[list[str]] = None,
        ttft_s: Optional[float] = None,
        llm_total_s: Optional[float] = None,
        prompt_eval_count: Optional[int] = None,
        eval_count: Optional[int] = None,
        load_duration_ns: Optional[int] = None,
        prompt_eval_duration_ns: Optional[int] = None,
        eval_duration_ns: Optional[int] = None,
        total_duration_ns: Optional[int] = None,
        history_messages: Optional[int] = None,
        store_ms: Optional[float] = None,
        stages: Optional[list] = None,
        effects: Optional[list] = None,
        model: str = "",
        error: Optional[str] = None,
        model_requests: Optional[int] = None,
    ) -> None:
        self.emit(
            "command", session_id,
            seq=seq, command=command, cwd=cwd,
            # Ollama requests this command cost
            model_requests=model_requests,
            category=category, subsystem=subsystem,
            latency_s=round(latency_s, 6),
            ttft_s=None if ttft_s is None else round(ttft_s, 6),
            llm_total_s=None if llm_total_s is None else round(llm_total_s, 6),
            prompt_eval_count=prompt_eval_count,
            eval_count=eval_count,
            load_duration_ns=load_duration_ns,
            prompt_eval_duration_ns=prompt_eval_duration_ns,
            eval_duration_ns=eval_duration_ns,
            total_duration_ns=total_duration_ns,
            history_messages=history_messages,
            store_ms=store_ms,
            stages=stages or [],
            effects=effects or [],
            model=model,
            flags=flags or [],
            response=response,
            raw_response=raw_response,
            error=error,
        )
        route = " | ".join(f"{s['cmd']}->{s['by']}" for s in (stages or []))
        self.write_transcript(
            session_id,
            f"\n$ {command}\n[{subsystem}/{category} {latency_s:.3f}s"
            + (f"  {route}" if route else "") + f"]\n{response}\n",
        )
        # One line in the shared command log; newlines are escaped so each command stays on its line
        who = self._who.get(session_id, {})
        flat = command.replace("\\", "\\\\").replace("\n", "\\n").replace("\r", "")
        self._commands.write(
            f"{_now()} {who.get('peer', '-')} {who.get('user', '-')} "
            f"{session_id[:8]} [{subsystem}] $ {flat}\n"
        )
        self._commands.flush()

    def disconnect(self, session_id: str, reason: str, commands: int,
                   duration_s: float) -> None:
        self.emit("disconnect", session_id, reason=reason, commands=commands,
                  duration_s=round(duration_s, 3))
        self.write_transcript(
            session_id,
            f"=== {_now()} disconnect ({reason}) commands={commands} "
            f"duration={duration_s:.1f}s\n",
        )
        f = self._transcripts.pop(session_id, None)
        if f:
            f.close()

    def close(self) -> None:
        for f in self._transcripts.values():
            f.close()
        self._transcripts.clear()
        self._commands.close()
        self._events.close()
