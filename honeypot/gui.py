# Control Window
# a small Tkinter panel that starts and stops the honeypot and shows its log
# it picks the model: a local one through Ollama, or a hosted API with a key
# the server runs in a worker thread with its own event loop, so the window stays responsive
# nothing here changes how the honeypot answers - it only fills in the same Config the terminal uses

# Imports
from __future__ import annotations

import asyncio
import logging
import queue
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext

PAD = {"padx": 8, "pady": 4}


# A logging handler that hands formatted lines to the window through a queue
class QueueHandler(logging.Handler):
    def __init__(self, sink):
        super().__init__()
        self.sink = sink

    def emit(self, record):
        try:
            self.sink.put_nowait(self.format(record))
        except queue.Full:
            pass


class HoneypotGUI:
    def __init__(self, cfg, log_, paths, serve_coro):
        self.cfg = cfg
        self.log_ = log_
        self.paths = paths
        self.serve_coro = serve_coro
        self.logs: queue.Queue = queue.Queue(10000)
        self.thread = None
        self.stop_server = None
        self.exit_code = 0

        self.root = tk.Tk()
        self.root.title("SSH Honeypot")
        self.root.minsize(760, 560)
        self._build()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self.root.after(120, self._drain_logs)

    # Layout
    def _build(self):
        main = ttk.Frame(self.root, padding=10)
        main.pack(fill="both", expand=True)
        main.columnconfigure(0, weight=1)
        main.rowconfigure(3, weight=1)

        # Model source
        model = ttk.LabelFrame(main, text="Model", padding=8)
        model.grid(row=0, column=0, sticky="ew")
        model.columnconfigure(1, weight=1)
        self.provider = tk.StringVar(value="ollama" if self.cfg.model_provider in ("ollama", "local")
                                     else self.cfg.model_provider)
        ttk.Radiobutton(model, text="Local model (Ollama)", variable=self.provider, value="ollama",
                        command=self._sync_provider).grid(row=0, column=0, sticky="w", columnspan=2)
        ttk.Radiobutton(model, text="Hosted API (OpenAI-compatible)", variable=self.provider, value="openai",
                        command=self._sync_provider).grid(row=1, column=0, sticky="w", columnspan=2)
        ttk.Radiobutton(model, text="Hosted API (Anthropic)", variable=self.provider, value="anthropic",
                        command=self._sync_provider).grid(row=2, column=0, sticky="w", columnspan=2)

        ttk.Label(model, text="Model name").grid(row=3, column=0, sticky="w", **PAD)
        self.model_name = tk.StringVar(value=self.cfg.model)
        ttk.Entry(model, textvariable=self.model_name).grid(row=3, column=1, sticky="ew", **PAD)

        self.ollama_row = ttk.Frame(model)
        self.ollama_row.grid(row=4, column=0, columnspan=2, sticky="ew")
        self.ollama_row.columnconfigure(1, weight=1)
        ttk.Label(self.ollama_row, text="Ollama URL").grid(row=0, column=0, sticky="w", **PAD)
        self.ollama_url = tk.StringVar(value=self.cfg.ollama_url)
        ttk.Entry(self.ollama_row, textvariable=self.ollama_url).grid(row=0, column=1, sticky="ew", **PAD)

        self.api_row = ttk.Frame(model)
        self.api_row.grid(row=5, column=0, columnspan=2, sticky="ew")
        self.api_row.columnconfigure(1, weight=1)
        ttk.Label(self.api_row, text="API key").grid(row=0, column=0, sticky="w", **PAD)
        self.api_key = tk.StringVar(value=self.cfg.api_key)
        self.api_key_entry = ttk.Entry(self.api_row, textvariable=self.api_key, show="*")
        self.api_key_entry.grid(row=0, column=1, sticky="ew", **PAD)
        self.show_key = tk.BooleanVar(value=False)
        ttk.Checkbutton(self.api_row, text="Show", variable=self.show_key,
                        command=self._toggle_key).grid(row=0, column=2, **PAD)
        ttk.Label(self.api_row, text="Base URL (optional)").grid(row=1, column=0, sticky="w", **PAD)
        self.api_base = tk.StringVar(value=self.cfg.api_base_url)
        ttk.Entry(self.api_row, textvariable=self.api_base).grid(row=1, column=1, sticky="ew", **PAD)
        ttk.Label(self.api_row, text="A hosted model generates output; local command handlers stay on the fast path.",
                  foreground="#666").grid(row=2, column=0, columnspan=3, sticky="w", padx=8)

        # Listener
        listen = ttk.LabelFrame(main, text="Listener", padding=8)
        listen.grid(row=1, column=0, sticky="ew", pady=(8, 0))
        listen.columnconfigure(1, weight=1)
        listen.columnconfigure(3, weight=1)
        ttk.Label(listen, text="Host").grid(row=0, column=0, sticky="w", **PAD)
        self.host = tk.StringVar(value=self.cfg.host)
        ttk.Entry(listen, textvariable=self.host, width=16).grid(row=0, column=1, sticky="ew", **PAD)
        ttk.Label(listen, text="Port").grid(row=0, column=2, sticky="w", **PAD)
        self.port = tk.StringVar(value=str(self.cfg.port))
        ttk.Entry(listen, textvariable=self.port, width=8).grid(row=0, column=3, sticky="w", **PAD)
        ttk.Label(listen, text="Host 0.0.0.0 is found by a port scan; 127.0.0.1 stays on this machine.",
                  foreground="#666").grid(row=1, column=0, columnspan=4, sticky="w", padx=8)

        # Controls
        controls = ttk.Frame(main)
        controls.grid(row=2, column=0, sticky="ew", pady=8)
        self.start_btn = ttk.Button(controls, text="Start", command=self._start)
        self.start_btn.pack(side="left")
        self.stop_btn = ttk.Button(controls, text="Stop", command=self._stop, state="disabled")
        self.stop_btn.pack(side="left", padx=6)
        self.status = tk.StringVar(value="Stopped")
        ttk.Label(controls, textvariable=self.status).pack(side="left", padx=12)

        # Log
        logframe = ttk.LabelFrame(main, text="Log", padding=4)
        logframe.grid(row=3, column=0, sticky="nsew")
        logframe.columnconfigure(0, weight=1)
        logframe.rowconfigure(0, weight=1)
        self.logbox = scrolledtext.ScrolledText(logframe, height=16, wrap="word", state="disabled",
                                                font=("TkFixedFont", 9))
        self.logbox.grid(row=0, column=0, sticky="nsew")

        self._sync_provider()

    def _toggle_key(self):
        self.api_key_entry.configure(show="" if self.show_key.get() else "*")

    # Show only the fields that belong to the chosen source
    def _sync_provider(self):
        local = self.provider.get() == "ollama"
        for child in self.ollama_row.winfo_children():
            child.configure(state="normal" if local else "disabled")
        for child in self.api_row.winfo_children():
            try:
                child.configure(state="disabled" if local else "normal")
            except tk.TclError:
                pass
        if not local and not self.show_key.get():
            self.api_key_entry.configure(show="*")

    def _set_running(self, running):
        self.start_btn.configure(state="disabled" if running else "normal")
        self.stop_btn.configure(state="normal" if running else "disabled")

    def _append(self, line):
        self.logbox.configure(state="normal")
        self.logbox.insert("end", line + "\n")
        self.logbox.see("end")
        self.logbox.configure(state="disabled")

    def _drain_logs(self):
        try:
            while True:
                self._append(self.logs.get_nowait())
        except queue.Empty:
            pass
        self.root.after(120, self._drain_logs)

    # Copy the window's fields into the Config the server will use
    def _apply_fields(self):
        provider = self.provider.get()
        self.cfg.model_provider = provider
        self.cfg.model = self.model_name.get().strip() or self.cfg.model
        if provider == "ollama":
            self.cfg.ollama_url = self.ollama_url.get().strip() or self.cfg.ollama_url
        else:
            self.cfg.api_key = self.api_key.get().strip()
            self.cfg.api_base_url = self.api_base.get().strip()
        self.cfg.host = self.host.get().strip() or self.cfg.host
        port = self.port.get().strip()
        if port:
            if not port.isdigit() or not (1 <= int(port) <= 65535):
                raise ValueError("Port must be a number between 1 and 65535")
            # A port typed here is used as given, so it does not silently fall back
            self.cfg.port, self.cfg.fallback_port = int(port), 0

    def _start(self):
        try:
            self._apply_fields()
        except ValueError as exc:
            self.status.set(str(exc))
            return
        if self.provider.get() != "ollama" and not self.cfg.api_key:
            self.status.set("Enter an API key for a hosted model")
            return
        self._set_running(True)
        self.status.set("Starting...")
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _stop(self):
        self.stop_btn.configure(state="disabled")
        self.status.set("Stopping...")
        if self.stop_server:
            self.stop_server()

    # Worker thread: its own event loop runs the same run_prepared the terminal uses
    def _serve(self):
        from honeypot.startup import runtime_lease
        from honeypot.bootstrap import SetupError

        handler = QueueHandler(self.logs)
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)-7s %(message)s", "%H:%M:%S"))
        root_log = logging.getLogger()
        root_log.addHandler(handler)

        def on_ready(info):
            self.stop_server = info["stop"]
            self.root.after(0, lambda: self._ready(info))

        try:
            with runtime_lease(self.paths):
                self.exit_code = asyncio.run(self.serve_coro(self.cfg, self.log_, on_ready=on_ready))
        except (SetupError, OSError) as exc:
            self.log_.error("Startup failed: %s", exc)
            self.exit_code = 2
        except Exception as exc:  # noqa: BLE001 - surface anything else in the window
            self.log_.error("%s: %s", type(exc).__name__, exc)
            self.exit_code = 2
        finally:
            root_log.removeHandler(handler)
            self.stop_server = None
            self.root.after(0, self._stopped)

    def _ready(self, info):
        self.status.set(f"Running on {info['host']}:{info['port']}")

    def _stopped(self):
        self._set_running(False)
        self.status.set("Stopped")

    def _on_close(self):
        if self.stop_server:
            self.stop_server()
            # Give the server a moment to close the socket before the window goes away
            self.root.after(400, self.root.destroy)
        else:
            self.root.destroy()

    def run(self):
        self.root.mainloop()
        if self.thread and self.thread.is_alive():
            if self.stop_server:
                self.stop_server()
            self.thread.join(timeout=5)
        return self.exit_code


# Entry point used by run.py
# serve_coro is run_prepared, passed in so the window does not re-import the entry script
def run_gui(cfg, log_, paths, serve_coro):
    return HoneypotGUI(cfg, log_, paths, serve_coro).run()
