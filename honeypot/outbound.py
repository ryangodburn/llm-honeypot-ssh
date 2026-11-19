# Outbound Policy
# shared SSRF boundary for destinations the attacker picks, never decided by the model
# only ordinary public unicast addresses are allowed
# operator allow lists can narrow access but never permit private or reserved addresses

# Imports
from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import re
import socket
from urllib.parse import urlsplit


class OutboundError(ValueError):
    pass


# Explicit ranges keep the boundary the same across Python versions
# IPv6 transition mechanisms can embed a forbidden IPv4 destination
# nothing here needs them, so they are rejected entirely
_V4_DENIED = tuple(map(ipaddress.ip_network, (
    '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8',
    '169.254.0.0/16', '172.16.0.0/12', '192.0.0.0/24', '192.0.2.0/24',
    '192.88.99.0/24', '192.168.0.0/16', '198.18.0.0/15',
    '198.51.100.0/24', '203.0.113.0/24', '224.0.0.0/4', '240.0.0.0/4')))
_V6_PUBLIC = ipaddress.ip_network('2000::/3')
_V6_DENIED = tuple(map(ipaddress.ip_network, (
    '2001::/23', '2001:db8::/32', '2002::/16', '3fff::/20')))
_LOCAL_NAMES = ('localhost', 'local', 'localdomain', 'internal', 'home.arpa')


def public_address(value):
    try:
        if '%' in value:
            return False
        ip = ipaddress.ip_address(value)
    except (ValueError, TypeError):
        return False
    if ip.version == 4:
        return ip.is_global and not any(ip in net for net in _V4_DENIED)
    return (ip in _V6_PUBLIC and ip.is_global and
            not any(ip in net for net in _V6_DENIED))


# Normalise a host name without DNS
# rejects parser ambiguities before any lookup
def canonical_host(value):
    if (not isinstance(value, str) or not value or len(value) > 253 or
            any(c.isspace() or ord(c) <= 32 or ord(c) == 127 or c in '/%\\@#?' for c in value)):
        raise OutboundError('invalid destination host')
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass
    try:
        name = (value[:-1] if value.endswith('.') else value).encode('idna').decode('ascii').lower()
    except UnicodeError as exc:
        raise OutboundError('invalid destination host') from exc
    parts = name.split('.')
    if (len(name) > 253 or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', p) for p in parts)
            or all(re.fullmatch(r'(?:[0-9]+|0x[0-9a-f]+)', p) for p in parts)):
        raise OutboundError('invalid or ambiguous destination host')
    return name


@dataclass(frozen=True)
class EgressPolicy:
    allowed_hosts: tuple[str, ...] = ()
    denied_hosts: tuple[str, ...] = ()
    denied_cidrs: tuple[str, ...] = ()

    def __post_init__(self):
        object.__setattr__(self, 'allowed_hosts', tuple(canonical_host(h) for h in self.allowed_hosts))
        object.__setattr__(self, 'denied_hosts', tuple(canonical_host(h) for h in self.denied_hosts))
        object.__setattr__(self, '_networks', tuple(ipaddress.ip_network(c, strict=False) for c in self.denied_cidrs))

    def host(self, value, *, allowlist=True):
        host = canonical_host(value)
        if host in self.denied_hosts:
            raise OutboundError('destination is an operator-protected host')
        try:
            ipaddress.ip_address(host)
        except ValueError:
            if '.' not in host or any(host == s or host.endswith('.'+s) for s in _LOCAL_NAMES):
                raise OutboundError('local destination names are not permitted')
        if allowlist and self.allowed_hosts and host not in self.allowed_hosts:
            raise OutboundError('destination is not in the operator allowlist')
        return host

    def address(self, value):
        try:
            ip = ipaddress.ip_address(value)
        except ValueError as exc:
            raise OutboundError('invalid resolved address') from exc
        if '%' in value or any(ip in net for net in self._networks if ip.version == net.version):
            raise OutboundError('destination is an operator-protected address')
        if not public_address(value):
            raise OutboundError('destination is not a permitted public internet address')
        return str(ip)

    def addresses(self, values):
        if not values:
            raise OutboundError('destination has no usable addresses')
        # Reject the whole answer set, including unsafe alternate A or AAAA records
        return list(dict.fromkeys(self.address(v) for v in values))


def verify_peer(actual, expected):
    try:
        if not actual or '%' in actual[0] or ipaddress.ip_address(actual[0]) != ipaddress.ip_address(expected):
            raise ValueError()
    except (TypeError, ValueError) as exc:
        raise OutboundError('connected peer differs from the validated destination') from exc


# Keep the operator's own services out of reach even when they have public addresses
# operator names resolve once at startup, and a failure stops startup
# guest-controlled names never come through here
# This machine's own unicast addresses, main interface first, without loopback or link-local
# a UDP socket aimed at a documentation address picks the main interface and sends nothing
def local_addresses():
    found = []
    for target, family in (('192.0.2.1', socket.AF_INET), ('2001:db8::1', socket.AF_INET6)):
        try:
            with socket.socket(family, socket.SOCK_DGRAM) as probe:
                probe.connect((target, 9))
                found.append(probe.getsockname()[0])
        except OSError:
            pass
    try:
        found.extend(info[4][0] for info in socket.getaddrinfo(socket.gethostname(), None, type=socket.SOCK_STREAM))
    except OSError:
        pass
    result = []
    for value in found:
        value = value.split('%')[0]
        try:
            ip = ipaddress.ip_address(value)
        except ValueError:
            continue
        if ip.is_loopback or ip.is_link_local or ip.is_unspecified or value in result:
            continue
        result.append(value)
    # IPv4 first, the address most people scan and connect to
    return sorted(result, key=lambda a: ':' in a)


def operator_policy(*, ollama_url, listen_host, allowed_hosts=(), denied_cidrs=()):
    parsed = urlsplit(ollama_url if '://' in ollama_url else 'http://'+ollama_url)
    if (parsed.scheme not in ('http', 'https') or not parsed.hostname
            or parsed.username is not None or parsed.password is not None
            or parsed.port == 0 or parsed.netloc.endswith(':')):
        raise ValueError('invalid operator Ollama URL')
    hosts = [parsed.hostname]
    if listen_host not in ('0.0.0.0', '::', ''):
        hosts.append(listen_host)
    # Every address of this machine is protected, whichever address the honeypot listens on
    # so a guest cannot reach other services on the honeypot host through its own public address
    cidrs = list(denied_cidrs) + local_addresses()
    for host in hosts:
        name = canonical_host(host)
        try:
            addresses = [str(ipaddress.ip_address(name))]
        except ValueError:
            if name == 'localhost':
                addresses = ['127.0.0.1', '::1']
            else:
                addresses = [r[4][0] for r in socket.getaddrinfo(name+'.', None, type=socket.SOCK_STREAM)]
                if not addresses:
                    raise ValueError('operator service could not be resolved')
        cidrs.extend(addresses)
    return EgressPolicy(tuple(allowed_hosts), tuple(hosts), tuple(cidrs))
