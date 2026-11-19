# Persona
# who the fake host claims to be - prompt, MOTD and host facts
# rendered in Python rather than asked of the model
# they have one correct answer, must never drift between commands and cost microseconds

# Imports
from __future__ import annotations

import time
from typing import Optional

import json
import posixpath
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .gotmpl import prompt_symbol, render

# Ubuntu's default coloured prompt - bold green user@host, bold blue directory
_C_USER = "\x1b[01;32m"
_C_PATH = "\x1b[01;34m"
_C_OFF = "\x1b[00m"


@dataclass
class Persona:
    hostname: str
    distro: str
    kernel: str
    messages: list[dict[str, str]]
    motd: str
    server_ip: str = "10.0.12.31"
    colour_prompt: bool = True

    @classmethod
    def load(cls, path: str | Path, **overrides: Any) -> "Persona":
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls(
            hostname=overrides.get("hostname") or raw.get("hostname", "ubuntu"),
            distro=overrides.get("distro") or raw.get("distro", "Ubuntu 22.04.3 LTS"),
            kernel=overrides.get("kernel") or raw.get("kernel", "5.15.0-58-generic"),
            messages=raw.get("messages", []),
            motd=raw.get("motd", ""),
            server_ip=overrides.get("server_ip") or raw.get("server_ip", "10.0.12.31"),
        )

    # Context

    def context(self, username: str) -> dict[str, str]:
        return {
            "Username": username,
            "Hostname": self.hostname,
            "Distro": self.distro,
            "Kernel": self.kernel,
            "ServerIP": self.server_ip,
            "Date": datetime.now(timezone.utc).strftime("%a %b %d %H:%M:%S UTC %Y"),
        }

    # Rendered Pieces

    # System prompt and example turns with the template variables filled in
    def seed_messages(self, username: str) -> list[dict[str, str]]:
        ctx = self.context(username)
        return [
            {"role": m["role"], "content": render(m.get("content", ""), ctx)}
            for m in self.messages
        ]

    def render_motd(self, username: str) -> str:
        return render(self.motd, self.context(username))

    def home_dir(self, username: str) -> str:
        return "/root" if username == "root" else f"/home/{username}"

    def display_cwd(self, username: str, cwd: str) -> str:
        home = self.home_dir(username)
        if cwd == home:
            return "~"
        if cwd.startswith(home + "/"):
            return "~" + cwd[len(home):]
        return cwd

    # The prompt a real Ubuntu bash would print, including the trailing space
    def prompt(self, username: str, cwd: str) -> str:
        path = self.display_cwd(username, cwd)
        sym = prompt_symbol(username)
        if self.colour_prompt:
            return (
                f"{_C_USER}{username}@{self.hostname}{_C_OFF}:"
                f"{_C_PATH}{path}{_C_OFF}{sym} "
            )
        return f"{username}@{self.hostname}:{path}{sym} "

    # MOTD plus sshd's Last login line
    # the line describes the previous login (time and source) in UTC, as pam_lastlog does
    # without a recorded previous login, a stable earlier admin login from the server's subnet is shown
    def login_banner(self, username: str,
                     previous: Optional[tuple[float, str]] = None) -> str:
        if previous is None:
            base = self.server_ip.rsplit(".", 1)[0] if self.server_ip and self.server_ip.count(".") == 3 else "10.0.12"
            when = time.time() - 97_000 - (sum(map(ord, username)) * 37) % 9_000
            previous = (when, base + ".5")
        stamp = time.strftime("%a %b %e %H:%M:%S %Y", time.gmtime(previous[0]))
        return (
            self.render_motd(username)
            + f"Last login: {stamp} from {previous[1]}\n"
        )


# Pure string cd resolution with no existence check
# used when there is no filesystem store, which checks directories itself
def normalise_path(cwd: str, target: str, home: str) -> str:
    if not target or target == "~":
        return home
    if target.startswith("~/"):
        target = home + target[1:]
    if target == "-":
        # OLDPWD handling belongs in the session, not here
        return cwd
    if not target.startswith("/"):
        target = posixpath.join(cwd, target)
    return posixpath.normpath(target) or "/"
