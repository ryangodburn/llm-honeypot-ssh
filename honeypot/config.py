# Runtime Settings
# every option run.py accepts, with its default

# Imports
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


# Settings for one honeypot run, filled from the command line by run.py
@dataclass
class Config:
    # Listener

    # Every interface on the standard SSH port, so a port scan of this machine finds it
    # 127.0.0.1 keeps the honeypot on this machine only
    host: str = "0.0.0.0"
    port: int = 22
    # Used when the default port cannot be opened - taken, or reserved for administrators
    # an explicit --port turns the fallback off
    fallback_port: int = 2222
    host_key_dir: str = "hostkeys"
    # OpenSSH banner string
    # the AsyncSSH default would give the honeypot away to any banner grab
    server_version: str = "OpenSSH_8.9p1 Ubuntu-3ubuntu0.10"
    openssh_algorithms: bool = True
    login_timeout: float = 120.0
    idle_timeout: float = 900.0

    # Authentication

    auth_store: str = "auth/credentials.json"
    # Fail the first N login attempts before letting the attacker in
    # a server that accepts the very first password is itself a tell
    min_failed_attempts: int = 0
    deny_usernames: list[str] = field(default_factory=list)
    auth_fail_delay: tuple[float, float] = (0.3, 0.8)
    auth_ok_delay: tuple[float, float] = (0.05, 0.15)

    # Persona

    template: str = "templates/ubuntu.json"
    hostname: Optional[str] = None
    server_ip: str = "10.0.12.31"
    colour_prompt: bool = True

    # Model

    # Model provider: local runs a model through Ollama; openai and anthropic call a hosted API with a key
    # a hosted model generates output but does not drive the native command tools, so those stay on Ollama
    model_provider: str = "ollama"
    api_key: str = ""
    api_base_url: str = ""
    ollama_url: str = "http://127.0.0.1:11434"
    model: str = "qwen3.5:9b"
    temperature: float = 0.2
    num_ctx: int = 8192
    num_predict: int = 512
    llm_timeout_s: float = 20.0
    ai_fallback: bool = True
    ai_failure_threshold: int = 3
    ai_cooldown_s: float = 30.0
    retrieval_timeout_s: float = 3.0
    max_concurrency: int = 1
    warm_up: bool = True
    start_ollama: bool = True
    model_setup_timeout_s: float = 1800.0
    model_load_timeout_s: float = 180.0
    native_tools: bool = True
    model_process_tools: bool = False
    model_command_tools: bool = True
    tool_max_rounds: int = 6
    tool_max_calls: int = 12

    # Filesystem Store

    # Downloaded, imported and patched on first use
    fs_db: Optional[str] = "fs.sqlite"
    # How overlay writes are keyed
    # ip survives reconnection from the same attacker, session isolates each connection
    # global shares one overlay across everyone
    fs_realm_mode: str = "ip"
    fs_colour_ls: bool = True
    fs_max_cat_bytes: int = 256_000
    fs_synthesize_binaries: bool = True
    fs_reset_on_start: bool = False
    # Pull the selected model automatically when it is missing
    fs_auto_setup: bool = True
    fs_tarball: Optional[str] = None
    fs_sha256: Optional[str] = None
    fs_cache_dir: str = "data"

    # Downloads and SFTP

    internet_downloads: bool = True
    # SFTP subsystem and scp over the virtual filesystem
    sftp_enabled: bool = True
    sftp_max_bytes: int = 32 * 1024 * 1024
    download_max_bytes: int = 10 * 1024 * 1024
    download_timeout_s: float = 30.0
    download_ports: list[int] = field(default_factory=lambda: [80, 443])

    # Network Diagnostics

    egress_allow_hosts: list[str] = field(default_factory=list)
    egress_deny_cidrs: list[str] = field(default_factory=list)
    network_enabled: bool = True
    dns_server: str = "1.1.1.1"
    network_timeout: float = 3.0
    network_max_time: float = 60.0

    # Reference Store

    retrieval_db: Optional[str] = "retrieval.sqlite"
    retrieval_corpus: str = "data/ubuntu_reference.jsonl"
    retrieval_top_k: int = 3
    retrieval_min_score: float = 0.35
    retrieval_context_bytes: int = 6000
    retrieval_max_age_days: float = 0.0

    # Behaviour

    # Model context in turns - 0 keeps the whole session, the baseline the honours thesis measured
    history_turns: int = 8
    stream_output: bool = False
    strip_prompt: bool = True
    max_output_lines: int = 400

    # Logging

    log_dir: str = "logs"
