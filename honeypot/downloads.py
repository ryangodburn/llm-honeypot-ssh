# Curl Downloads
# real, bounded HTTP and HTTPS downloads written only into the virtual filesystem
# GET and HEAD go to public, DNS-pinned addresses and every redirect is checked again
# no host shell, proxy settings, credentials, uploads or running of downloaded files

# Imports
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field, replace
import hashlib
import http.client
import ipaddress
import math
import os
import posixpath
import socket
import ssl
import time
import threading
from urllib.parse import urljoin, urlsplit, urlunsplit, quote

from .outbound import EgressPolicy, OutboundError, canonical_host, verify_peer
from .vfs import FSError
from .vfsio import write_bytes, write_target


class CurlError(Exception):
    def __init__(self, code, message, *, audit=None):
        super().__init__(message)
        self.code = code
        self.audit = audit or {}


@dataclass(frozen=True)
class DownloadPolicy:
    enabled: bool = True
    max_bytes: int = 10 * 1024 * 1024
    max_time: float = 30.0
    connect_timeout: float = 10.0
    max_redirects: int = 5
    concurrency: int = 4
    egress: EgressPolicy = field(default_factory=EgressPolicy)
    allowed_ports: tuple[int, ...] = (80, 443)

    def __post_init__(self):
        if not self.allowed_ports or any(type(p) is not int or not 1 <= p <= 65535 for p in self.allowed_ports):
            raise ValueError('Download ports must be integers from 1 through 65535')
        object.__setattr__(self, 'allowed_ports', tuple(self.allowed_ports))

    def destination(self, host, port):
        host = self.egress.host(host)
        # This host is a connection destination
        # a DNS or PTR query may instead send a numeric value as data to an approved resolver
        try:
            ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            self.egress.address(host)
        if port not in self.allowed_ports:
            raise OutboundError('destination port is not permitted for downloads')
        return host


@dataclass
class Options:
    url: str = ""
    output: str | None = None
    remote_name: bool = False
    follow: bool = False
    fail: bool = False
    silent: bool = False
    show_error: bool = False
    head: bool = False
    include: bool = False
    verbose: bool = False
    max_time: float = 30.0
    connect_timeout: float = 10.0
    user_agent: str = "curl/7.81.0"


@dataclass
class Transfer:
    stdout: bytes = b""
    stderr: str = ""
    exit_code: int = 0
    audit: dict = field(default_factory=dict)


def parse_options(argv, policy):
    o = Options(max_time=policy.max_time, connect_timeout=policy.connect_timeout)
    boolean = {"s": "silent", "S": "show_error", "f": "fail", "L": "follow",
               "O": "remote_name", "I": "head", "i": "include", "v": "verbose"}
    long_bool = {"--silent": "s", "--show-error": "S", "--fail": "f", "--location": "L",
                 "--remote-name": "O", "--head": "I", "--include": "i", "--verbose": "v"}
    values = {"-o": "output", "--output": "output", "--url": "url",
              "-m": "max_time", "--max-time": "max_time", "--connect-timeout": "connect_timeout",
              "-A": "user_agent", "--user-agent": "user_agent", "-X": "method", "--request": "method"}
    urls, i, literal = [], 1, False
    while i < len(argv):
        arg = argv[i]
        i += 1
        if arg == "--" and not literal:
            literal = True
            continue
        if literal or not arg.startswith("-"):
            urls.append(arg)
            continue
        option, equal, attached = arg.partition("=") if arg.startswith("--") else (arg, "", "")
        if option in long_bool and not equal:
            setattr(o, boolean[long_bool[option]], True)
            continue
        if not arg.startswith("--"):
            letters = arg[1:]
            while letters and letters[0] in boolean:
                setattr(o, boolean[letters[0]], True)
                letters = letters[1:]
            if not letters:
                continue
            option, attached = "-" + letters[0], letters[1:]
            equal = bool(attached)
        if option not in values:
            raise CurlError(2, f"option {option}: unsupported option")
        if not equal:
            if i == len(argv):
                raise CurlError(2, f"option {option}: requires a parameter")
            attached, i = argv[i], i + 1
        key = values[option]
        if key in ("max_time", "connect_timeout"):
            try:
                value = float(attached)
                if not math.isfinite(value) or value <= 0:
                    raise ValueError()
            except ValueError:
                raise CurlError(2, f"option {option}: requires a positive number") from None
            setattr(o, key, min(value, getattr(policy, key)))
        elif key == "method":
            if attached.upper() not in ("GET", "HEAD"):
                raise CurlError(2, "only GET and HEAD requests are supported")
            o.head = attached.upper() == "HEAD"
        elif key == "url":
            urls.append(attached)
        else:
            if any(ord(c) < 32 or ord(c) == 127 for c in attached):
                raise CurlError(2, "invalid option parameter")
            setattr(o, key, attached)
    if len(urls) != 1:
        raise CurlError(2, "specify exactly one HTTP or HTTPS URL")
    o.url = urls[0]
    if not urlsplit(o.url).scheme:
        o.url = "http://" + o.url
    if o.remote_name and o.output is None:
        o.output = posixpath.basename(urlsplit(o.url).path)
        if o.output in ("", ".", ".."):
            raise CurlError(23, "Remote file name has no length")
    if o.output == "-":
        o.output = None
    return o


# TLS context with the OS trust store plus the packaged public roots
# operator CA overrides are honoured
def verified_tls_context():
    context = ssl.create_default_context()
    if not (os.environ.get('SSL_CERT_FILE') or os.environ.get('SSL_CERT_DIR')):
        # The certifi roots come with httpx, and OS roots stay trusted, including Windows admin roots
        # never download a CA from the requested site or relax hostname and certificate checks
        import certifi
        context.load_verify_locations(cafile=certifi.where())
    context.set_alpn_protocols(['http/1.1'])
    return context


class PinnedConnection(http.client.HTTPConnection):
    def __init__(self, host, port, address, *, timeout, tls, policy=None):
        super().__init__(host, port, timeout=timeout)
        self.address, self.tls = address, tls
        self.policy = policy or DownloadPolicy()

    def connect(self):
        # Check again at the transport boundary, including direct and fallback calls
        self.policy.destination(self.host, self.port)
        self.policy.egress.address(self.address)
        # Connect to the numeric address directly so the hostname is not resolved twice
        ip = ipaddress.ip_address(self.address)
        sock = socket.socket(socket.AF_INET6 if ip.version == 6 else socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        # Cancellation owns the socket even during connect and TLS
        self.sock = sock
        try:
            sock.connect((str(ip), self.port))
            verify_peer(sock.getpeername(), str(ip))
            if self.tls:
                context = verified_tls_context()
                sock = context.wrap_socket(sock, server_hostname=self.host)
                verify_peer(sock.getpeername(), str(ip))
            self.sock = sock
        except BaseException:
            sock.close()
            raise


# Closes the active socket on cancellation
# DNS workers keep their slot until they finish
class TransferControl:
    def __init__(self):
        self.stopped = threading.Event()
        self.lock = threading.Lock()
        self.conn = None
    def check(self):
        if self.stopped.is_set():
            raise CurlError(42, "Operation canceled")
    def attach(self, conn):
        with self.lock:
            self.conn = conn
        if self.stopped.is_set():
            self.cancel()
            self.check()
    def cancel(self):
        self.stopped.set()
        with self.lock:
            conn = self.conn
        sock = getattr(conn, "sock", None)
        if sock is not None:
            try: sock.shutdown(socket.SHUT_RDWR)
            except OSError: pass
            try: sock.close()
            except OSError: pass


class HTTPFetcher:
    def __init__(self, policy=None):
        self.policy = policy or DownloadPolicy()
        self._local = threading.local()
        self._slots = asyncio.Semaphore(self.policy.concurrency)
        # A timed-out or cancelled caller cannot stop an OS DNS or socket worker
        # keep ownership until it really finishes, including its concurrency slot
        self._workers: set[asyncio.Task] = set()

    def resolve(self, host, port):
        try:
            host = self.policy.destination(host, port)
            try:
                addresses = [str(ipaddress.ip_address(host))]
            except ValueError:
                # An absolute DNS name stops the resolver adding search suffixes
                name = host if host == "localhost" else host + "."
                addresses = sorted({r[4][0] for r in socket.getaddrinfo(name, port, type=socket.SOCK_STREAM)},
                                   key=lambda value: ipaddress.ip_address(value).version)
            return self.policy.egress.addresses(addresses)
        except socket.gaierror as exc:
            raise CurlError(6, f"Could not resolve host: {host}") from exc
        except OutboundError as exc:
            raise CurlError(7, str(exc), audit={'policy_denied': True}) from exc

    @staticmethod
    def validate_url(url):
        if len(url) > 8192 or any(c.isspace() or ord(c) <= 32 or ord(c) == 127 or c == "\\" for c in url):
            raise CurlError(3, "URL rejected: invalid URL")
        try:
            parsed = urlsplit(url)
            if parsed.scheme.lower() not in ("http", "https"):
                raise CurlError(1, "Protocol is not supported; use HTTP or HTTPS")
            if (not parsed.hostname or parsed.username is not None or parsed.password is not None
                    or "%" in parsed.netloc or parsed.netloc.endswith(":")):
                raise ValueError()
            host = canonical_host(parsed.hostname)
            # Python's urlsplit accepts trailing junk after a bracketed IPv6 host
            # check the full authority, not only the parsed hostname
            authority = parsed.netloc
            if authority.startswith('['):
                end = authority.index(']')
                suffix = authority[end+1:]
                if ipaddress.ip_address(host).version != 6:
                    raise ValueError()
            else:
                suffix = authority[authority.index(':'):] if ':' in authority else ''
            if suffix and (not suffix.startswith(':') or not suffix[1:].isascii() or not suffix[1:].isdigit()):
                raise ValueError()
            port = parsed.port if parsed.port is not None else (443 if parsed.scheme.lower() == "https" else 80)
            if not 1 <= port <= 65535:
                raise ValueError()
            return parsed, host, port
        except (ValueError, UnicodeError) as exc:
            raise CurlError(3, "URL rejected: invalid host, credentials, or port") from exc

    async def fetch(self, options):
        started = time.monotonic()
        try:
            await asyncio.wait_for(self._slots.acquire(), options.max_time)
        except asyncio.TimeoutError as exc:
            raise CurlError(28, "Operation timed out") from exc
        remaining = options.max_time - (time.monotonic() - started)
        if remaining <= 0:
            self._slots.release()
            raise CurlError(28, "Operation timed out")
        control = TransferControl()
        def work():
            self._local.control = control
            try:
                return self._fetch(replace(options, max_time=remaining))
            finally:
                self._local.control = None
        worker = asyncio.create_task(asyncio.to_thread(work))
        self._workers.add(worker)
        def finished(task):
            # Cancelling a caller cannot stop an OS DNS lookup
            # hold its slot until the worker really ends, so timeouts cannot pile up background transfers
            # late bytes and errors are discarded
            self._slots.release()
            self._workers.discard(task)
            if not task.cancelled():
                task.exception()
        worker.add_done_callback(finished)
        # Waiting with wait() does not cancel the worker on timeout or caller cancellation
        # unlike wait_for(shield(...)) it adds no second exception logger in Python 3.14
        # the owner callback consumes late exceptions, result() still raises errors that arrive in time
        try:
            done, _ = await asyncio.wait({worker}, timeout=remaining)
            if not done:
                control.cancel()
                raise CurlError(28, "Operation timed out")
            return worker.result()
        except asyncio.CancelledError:
            control.cancel()
            raise

    def _fetch(self, options):
        history = []
        active = {'url': options.url}
        try:
            return self._fetch_checked(options, history, active)
        except CurlError as exc:
            exc.audit.setdefault('redirects', history)
            if exc.audit.get('policy_denied') or exc.code in (1, 3):
                exc.audit.setdefault('blocked_url', active['url'])
            raise

    def _fetch_checked(self, options, history, active):
        control = getattr(self._local, "control", None) or TransferControl()
        started, deadline = time.monotonic(), time.monotonic() + options.max_time
        url = options.url
        for hop in range(self.policy.max_redirects + 1):
            active['url'] = url
            control.check()
            parsed, host, port = self.validate_url(url)
            try:
                host = self.policy.destination(host, port)
                addresses = self.policy.egress.addresses(self.resolve(host, port))
            except OutboundError as exc:
                raise CurlError(7, str(exc), audit={'policy_denied': True}) from exc
            control.check()
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise CurlError(28, "Operation timed out")
            conn = None
            try:
                for index, address in enumerate(addresses):
                    conn = PinnedConnection(host, port, address,
                        timeout=min(options.connect_timeout, max(.01, deadline-time.monotonic())),
                        tls=parsed.scheme.lower() == "https", policy=self.policy)
                    try:
                        control.attach(conn)
                        conn.connect()
                        control.attach(conn)
                        break
                    except ssl.SSLCertVerificationError:
                        raise
                    except OSError:
                        conn.close()
                        if index == len(addresses)-1 or time.monotonic() >= deadline:
                            raise
                conn.sock.settimeout(max(.01, deadline-time.monotonic()))
                target = quote(urlunsplit(("", "", parsed.path or "/", parsed.query, "")),
                               safe="/%?=&:+,;@!$'()*[]~-._")
                conn.request("HEAD" if options.head else "GET", target,
                    headers={"User-Agent": options.user_agent, "Accept": "*/*",
                             "Accept-Encoding": "identity", "Connection": "close"})
                reply = conn.getresponse()
                headers = reply.getheaders()
                header_bytes = (f"HTTP/{'1.0' if reply.version == 10 else '1.1'} {reply.status} {reply.reason}\r\n" +
                                "".join(f"{k}: {v}\r\n" for k, v in headers) + "\r\n").encode("latin-1", "replace")
                if len(header_bytes) > 65536:
                    raise CurlError(63, "Response headers exceed the transfer limit")
                history.append({"url": url, "status": reply.status, "peer_ip": address})
                location = reply.getheader("Location")
                if options.follow and reply.status in (301, 302, 303, 307, 308) and location:
                    if hop == self.policy.max_redirects:
                        raise CurlError(47, "Maximum redirects followed")
                    if len(location) > 8192 or any(c.isspace() or ord(c) <= 32 or ord(c) == 127 or c == "\\" for c in location):
                        raise CurlError(3, "Redirect URL rejected: invalid URL", audit={'blocked_url': location})
                    url = urljoin(url, location)
                    continue
                if options.fail and reply.status >= 400:
                    raise CurlError(22, f"The requested URL returned error: {reply.status}")
                declared = reply.getheader("Content-Length")
                try:
                    length = int(declared) if declared is not None else None
                    if length is not None and length < 0:
                        raise ValueError()
                except ValueError:
                    raise CurlError(18, "Invalid Content-Length") from None
                if not options.head and length is not None and length > self.policy.max_bytes:
                    raise CurlError(63, "Response exceeds the maximum download size")
                data = bytearray()
                if not options.head:
                    while True:
                        if time.monotonic() >= deadline:
                            raise CurlError(28, "Operation timed out")
                        chunk = reply.read1(min(65536, self.policy.max_bytes + 1 - len(data)))
                        if not chunk:
                            break
                        data.extend(chunk)
                        if len(data) > self.policy.max_bytes:
                            raise CurlError(63, "Response exceeds the maximum download size")
                    if length is not None and len(data) != length:
                        raise CurlError(18, "Transfer closed with outstanding data remaining")
                body = bytes(data)
                output = (header_bytes if options.head or options.include else b"") + body
                return output, {"url": options.url, "final_url": url, "http_status": reply.status,
                    "redirects": history, "body_bytes": len(body), "body_sha256": hashlib.sha256(body).hexdigest(),
                    "stored_bytes": len(output), "sha256": hashlib.sha256(output).hexdigest(),
                    "content_type": reply.getheader("Content-Type", ""), "elapsed_s": round(time.monotonic()-started, 4)}
            except OutboundError as exc:
                raise CurlError(7, str(exc), audit={'policy_denied': True}) from exc
            except ssl.SSLCertVerificationError as exc:
                reason = str(getattr(exc, 'verify_message', None) or exc)[:512]
                raise CurlError(60, 'SSL certificate verification failed: ' + reason,
                    audit={'tls_verify_code': getattr(exc, 'verify_code', None),
                           'tls_verify_message': reason}) from exc
            except (socket.timeout, TimeoutError) as exc:
                raise CurlError(28, "Operation timed out") from exc
            except ssl.SSLError as exc:
                raise CurlError(35, "SSL connection error") from exc
            except http.client.IncompleteRead as exc:
                raise CurlError(18, "Transfer closed with outstanding data remaining") from exc
            except (OSError, http.client.HTTPException) as exc:
                raise CurlError(7, f"Could not connect to {host}:{port}") from exc
            finally:
                if conn:
                    conn.close()
        raise CurlError(47, "Maximum redirects followed")


class CurlCommands:
    def __init__(self, filesystem, policy=None, fetcher=None):
        self.filesystem = filesystem
        self.policy = policy or DownloadPolicy()
        self.fetcher = fetcher or HTTPFetcher(self.policy)

    @staticmethod
    def handles(argv):
        return bool(argv and argv[0] in ("curl", "/usr/bin/curl", "/bin/curl"))

    async def run(self, session, argv, *, parsed=True):
        if not self.handles(argv):
            return None
        if parsed and argv[1:] in (["--version"], ["-V"], ["--help"], ["-h"]):
            # The Ubuntu reference and version handlers own these
            return None
        options = None
        started = time.perf_counter()
        try:
            if not parsed:
                raise CurlError(2, "unsupported shell syntax")
            options = parse_options(argv, self.policy)
            if not self.policy.enabled:
                raise CurlError(7, "Internet downloads are disabled")
            if self.filesystem is None:
                raise CurlError(23, "Virtual filesystem is unavailable")
            if options.output:
                write_target(self.filesystem, session, options.output)
            data, audit = await self.fetcher.fetch(options)
            # Resolve permissions and the realm again after waiting on the network
            if options.output:
                audit["saved_path"] = write_bytes(self.filesystem, session, options.output, data)
                output = b""
            else:
                output = data
            diagnostic = ""
            if options.verbose:
                diagnostic = f"* Connected to {audit['final_url']}\n< HTTP status {audit['http_status']}\n* Received {audit['body_bytes']} bytes"
            return Transfer(output, diagnostic, 0, audit)
        except FSError as exc:
            error = CurlError(23, f"Failed writing received data: {exc.message}")
        except CurlError as exc:
            error = exc
        except (ValueError, UnicodeError):
            error = CurlError(3, "URL rejected: invalid URL")
        quiet = bool(options and options.silent and not options.show_error)
        return Transfer(stderr="" if quiet else f"curl: ({error.code}) {error}", exit_code=error.code,
                        audit={**error.audit, "url": options.url if options else "", "error": str(error),
                               "exit_code": error.code, "elapsed_s": round(time.perf_counter()-started, 4)})
