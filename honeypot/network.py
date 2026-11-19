# Network Diagnostics
# real, bounded DNS, ICMP and TCP checks for ping, dig, host and nc
# no shell or guest program ever runs

# Imports
from __future__ import annotations
import asyncio
from dataclasses import dataclass, field
import ipaddress
import math
import os
import secrets
import socket
import struct
import time
from .outbound import EgressPolicy, OutboundError, canonical_host, verify_peer

COMMANDS = {'ping', 'ping6', 'dig', 'nslookup', 'host', 'getent', 'nc', 'netcat', 'ncat'}
TYPES = {'A': 1, 'NS': 2, 'CNAME': 5, 'PTR': 12, 'MX': 15, 'TXT': 16, 'AAAA': 28}

class NetworkError(ValueError):
    pass

@dataclass(frozen=True)
class NetworkPolicy:
    enabled: bool = True
    resolver: str = '1.1.1.1'
    dns_port: int = 53
    timeout: float = 3.0
    max_time: float = 60.0
    max_count: int = 20
    concurrency: int = 4
    egress: EgressPolicy = field(default_factory=EgressPolicy)

@dataclass
class NetworkResult:
    stdout: str = ''
    stderr: str = ''
    exit_code: int = 0
    audit: dict = field(default_factory=dict)
    streamed: bool = False


def hostname(value):
    try:
        return canonical_host(value)
    except OutboundError as exc:
        raise NetworkError(str(exc)) from exc


def permitted(ip, policy):
    try:
        policy.egress.address(ip)
        return True
    except OutboundError:
        return False


def _name(packet, start):
    labels, pos, end, seen = [], start, None, set()
    while True:
        if pos >= len(packet) or pos in seen:
            raise NetworkError('invalid DNS name')
        seen.add(pos)
        n = packet[pos]; pos += 1
        if n & 0xC0 == 0xC0:
            if pos >= len(packet):
                raise NetworkError('truncated DNS pointer')
            end = pos + 1 if end is None else end
            pos = ((n & 63) << 8) | packet[pos]
            continue
        if n & 0xC0 or n > 63 or pos+n > len(packet):
            raise NetworkError('invalid DNS label')
        if not n:
            return '.'.join(labels), (end if end is not None else pos)
        raw = packet[pos:pos+n]
        labels.append(''.join(chr(c) if 33 <= c <= 126 and chr(c) not in '\\.' else f'\\{c:03d}' for c in raw))
        if len(labels) > 127:
            raise NetworkError('DNS name too long')
        pos += n


def parse_dns(packet, ident, query, qtype):
    if len(packet) < 12:
        raise NetworkError('truncated DNS response')
    rid, flags, nq, na, nn, ne = struct.unpack('!6H', packet[:12])
    if rid != ident or not flags & 0x8000 or flags & 0x7800 or nq != 1:
        raise NetworkError('invalid DNS response identity')
    name, pos = _name(packet, 12)
    if pos+4 > len(packet) or name.lower() != query.rstrip('.').lower() or struct.unpack('!HH',packet[pos:pos+4]) != (qtype,1):
        raise NetworkError('DNS question mismatch')
    pos += 4
    answers = []
    if na+nn+ne > 256:
        raise NetworkError('too many DNS records')
    for index in range(na+nn+ne):
        name, pos = _name(packet, pos)
        if pos+10 > len(packet):
            raise NetworkError('truncated DNS record')
        typ, cls, ttl, size = struct.unpack('!HHIH', packet[pos:pos+10]); pos += 10
        start, end = pos, pos+size
        if end > len(packet):
            raise NetworkError('truncated DNS data')
        data = packet[start:end]; pos=end
        if index >= na or cls != 1 or typ not in TYPES.values():
            continue
        if typ == 1 and size == 4:
            text = socket.inet_ntop(socket.AF_INET, data)
        elif typ == 28 and size == 16:
            text = socket.inet_ntop(socket.AF_INET6, data)
        elif typ in (2, 5, 12):
            text, used = _name(packet,start)
            if used != end: raise NetworkError('invalid DNS record length')
            text += '.'
        elif typ == 15 and size >= 3:
            target, used = _name(packet,start+2)
            if used != end: raise NetworkError('invalid DNS MX length')
            text = f'{int.from_bytes(data[:2],"big")} {target}.'
        elif typ == 16:
            parts=[]; j=0
            while j < len(data):
                count=data[j];j+=1
                if j+count > len(data): raise NetworkError('invalid DNS TXT length')
                # Escape control bytes and quotes
                # DNS data never becomes terminal control codes
                parts.append('"'+''.join(chr(c) if 32 <= c <= 126 and chr(c) not in '\\"' else f'\\{c:03d}' for c in data[j:j+count])+'"');j+=count
            text=' '.join(parts)
        else:
            raise NetworkError('invalid DNS address record length')
        answers.append((name,ttl,next(k for k,v in TYPES.items() if v==typ),text))
    return flags & 15, answers, bool(flags & 0x200)


def checksum(data):
    if len(data)%2: data += b'\0'
    total=sum(struct.unpack('!'+str(len(data)//2)+'H',data))
    total=(total >> 16)+(total & 0xffff);total += total >> 16
    return (~total) & 0xffff


def _windows_echo(ip, timeout, payload):
    import ctypes as c
    # Only read the fixed 16-byte prefix shared by ICMP_ECHO_REPLY and ICMP_ECHO_REPLY32
    # never follow native or truncated Data pointers
    api=c.WinDLL('iphlpapi.dll',use_last_error=True)
    api.IcmpCreateFile.argtypes=[]
    api.IcmpCreateFile.restype=c.c_void_p
    api.IcmpCloseHandle.argtypes=[c.c_void_p]
    api.IcmpCloseHandle.restype=c.c_int
    api.IcmpSendEcho.argtypes=[c.c_void_p,c.c_uint32,c.c_void_p,c.c_uint16,c.c_void_p,c.c_void_p,c.c_uint32,c.c_uint32]
    api.IcmpSendEcho.restype=c.c_uint32
    handle=api.IcmpCreateFile()
    if handle == c.c_void_p(-1).value: raise NetworkError('ICMP is unavailable on this host')
    try:
        request=c.create_string_buffer(payload)
        reply=c.create_string_buffer(512+len(payload))
        count=api.IcmpSendEcho(handle,struct.unpack('=I',socket.inet_aton(ip))[0],request,len(payload),None,reply,len(reply),max(1,int(timeout*1000)))
        if not count:
            error=c.get_last_error()
            if error in (11010,11002,11003,11004,11005): return None
            raise NetworkError(f'ICMP request failed with system error {error}')
        address,status,rtt,size,_=struct.unpack_from('<IIIHH',reply.raw)
        if status: return None
        if address != struct.unpack('=I',socket.inet_aton(ip))[0] or size != len(payload) or payload not in reply.raw[16:]:
            raise NetworkError('ICMP reply payload mismatch')
        return float(rtt), None
    finally:
        api.IcmpCloseHandle(handle)


class NetworkBackend:
    def __init__(self, policy):
        self.policy=policy
        self.workers=set()
        self.worker_slots=asyncio.Semaphore(policy.concurrency)

    async def thread(self, fn, *args):
        await self.worker_slots.acquire()
        task=asyncio.create_task(asyncio.to_thread(fn,*args));self.workers.add(task)
        def finished(t):
            self.workers.discard(t);self.worker_slots.release()
            if not t.cancelled(): t.exception()
        task.add_done_callback(finished)
        done,_=await asyncio.wait({task},timeout=self.policy.timeout+1)
        if not done: raise NetworkError('operation timed out')
        return task.result()

    async def resolve(self, host):
        try:
            return [str(ipaddress.ip_address(host))]
        except ValueError:
            rows=await self.thread(socket.getaddrinfo,host if host=="localhost" else host+".",None,socket.AF_UNSPEC,socket.SOCK_STREAM)
            return sorted({r[4][0] for r in rows},key=lambda ip:(ipaddress.ip_address(ip).version,ip))

    async def dns(self, name, typ, server):
        server=self.policy.egress.address(server)
        ident=secrets.randbelow(65536)
        wire=b''.join(bytes([len(label)])+label.encode('ascii') for label in name.rstrip('.').split('.'))+b'\0'
        query=struct.pack('!6H',ident,0x0100,1,0,0,0)+wire+struct.pack('!HH',TYPES[typ],1)
        family=socket.AF_INET6 if ':' in server else socket.AF_INET
        sock=socket.socket(family,socket.SOCK_DGRAM);sock.setblocking(False)
        loop=asyncio.get_running_loop()
        try:
            await loop.sock_connect(sock,(server,self.policy.dns_port))
            verify_peer(sock.getpeername(),server)
            await loop.sock_sendall(sock,query)
            packet=await asyncio.wait_for(loop.sock_recv(sock,65535),self.policy.timeout)
        finally:
            sock.close()
        # A truncated UDP answer is completed over TCP, never shown as complete
        if len(packet)>=4 and int.from_bytes(packet[2:4],'big') & 0x200:
            reader,writer=await asyncio.wait_for(asyncio.open_connection(server,self.policy.dns_port),self.policy.timeout)
            try:
                verify_peer(writer.get_extra_info("peername"),server)
                writer.write(struct.pack('!H',len(query))+query);await writer.drain()
                size=int.from_bytes(await asyncio.wait_for(reader.readexactly(2),self.policy.timeout),'big')
                packet=await asyncio.wait_for(reader.readexactly(size),self.policy.timeout)
            finally:
                writer.close();await writer.wait_closed()
        code,records,truncated=parse_dns(packet,ident,name,TYPES[typ])
        if truncated: raise NetworkError('truncated DNS answer')
        return code,records

    async def tcp(self, ip, port, timeout):
        ip=self.policy.egress.address(ip)
        reader,writer=await asyncio.wait_for(asyncio.open_connection(ip,port),timeout)
        try:
            verify_peer(writer.get_extra_info("peername"),ip)
        finally:
            writer.close();await writer.wait_closed()

    async def echo(self, ip, timeout, sequence):
        ip=self.policy.egress.address(ip)
        payload=secrets.token_bytes(56)
        if os.name == 'nt':
            return await self.thread(_windows_echo,ip,timeout,payload)
        # Linux ping sockets need no raw-socket privilege when ping_group_range allows them
        raw=False
        try:
            sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM,socket.IPPROTO_ICMP)
        except OSError:
            try:
                sock=socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_ICMP);raw=True
            except OSError as exc:
                raise NetworkError('ICMP is unavailable; the host must permit ping sockets') from exc
        sock.setblocking(False);loop=asyncio.get_running_loop()
        try:
            sock.bind(('0.0.0.0',0))
            ident=secrets.randbelow(65535)+1 if raw else sock.getsockname()[1]
            header=struct.pack('!BBHHH',8,0,0,ident,sequence)
            packet=struct.pack('!BBHHH',8,0,checksum(header+payload),ident,sequence)+payload
            started=time.perf_counter();end=loop.time()+timeout
            await loop.sock_sendto(sock,packet,(ip,0))
            while True:
                try:
                    reply,peer=await asyncio.wait_for(loop.sock_recvfrom(sock,65535),max(.001,end-loop.time()))
                except TimeoutError:
                    return None
                ttl=None
                if raw:
                    ttl=reply[8] if len(reply)>8 else None
                    reply=reply[(reply[0]&15)*4:] if reply else b''
                if peer[0]==ip and len(reply)>=8 and reply[0:2]==b'\0\0' and struct.unpack('!HH',reply[4:8])==(ident,sequence) and reply[8:]==payload and checksum(reply)==0:
                    return (time.perf_counter()-started)*1000,ttl
                if loop.time() >= end: return None
        finally:
            sock.close()


class NetworkCommands:
    def __init__(self, policy=None, backend=None):
        self.policy=policy or NetworkPolicy()
        self.backend=backend or NetworkBackend(self.policy)
        self.slots=asyncio.Semaphore(self.policy.concurrency)

    @staticmethod
    def handles(argv):
        if not argv: return False
        name=argv[0].rsplit('/',1)[-1]
        return name in COMMANDS and (name!='getent' or len(argv)>1 and argv[1] in ('hosts','ahosts','ahostsv4','ahostsv6'))

    async def _addresses(self, name, *, allowlist=True):
        name=self.policy.egress.host(name,allowlist=allowlist)
        ips=await self.backend.resolve(name)
        if not ips or any(not permitted(ip,self.policy) for ip in ips):
            raise NetworkError('destination is not a permitted public internet address')
        return ips

    async def run(self, session, argv, *, parsed=True, emit=None):
        if not self.handles(argv): return None
        name=argv[0].rsplit('/',1)[-1];started=time.perf_counter()
        try:
            if argv[0] not in (name,'/bin/'+name,'/usr/bin/'+name):
                raise NetworkError('unsupported executable path')
            if not parsed: raise NetworkError('unsupported shell syntax')
            if not self.policy.enabled: raise NetworkError('network diagnostics are disabled')
            async with asyncio.timeout(self.policy.max_time+2):
                async with self.slots:
                    if name in ('ping','ping6'): result=await self.ping(argv,emit)
                    elif name in ('nc','netcat','ncat'): result=await self.connect(argv)
                    elif name=='getent': result=await self.getent(argv)
                    else: result=await self.lookup(argv)
            result.audit.update(command=name,elapsed_s=round(time.perf_counter()-started,4))
            return result
        except (NetworkError,OSError,TimeoutError,ValueError,UnicodeError,asyncio.IncompleteReadError) as exc:
            message='operation timed out' if isinstance(exc,TimeoutError) else str(exc)
            return NetworkResult(stderr=f'{name}: {message}',exit_code=2,audit={'command':name,'error':message})

    async def ping(self, argv, emit):
        count=None;interval=1.0;timeout=min(self.policy.timeout,3);deadline=self.policy.max_time;target=None;i=1
        if argv[0].endswith('ping6'): raise NetworkError('IPv6 ICMP is not supported')
        while i<len(argv):
            a=argv[i];i+=1
            if a in ('-n','-4'): continue
            if a in ('-c','-i','-W','-w'):
                if i>=len(argv): raise NetworkError('missing option value')
                val=float(argv[i]);i+=1
                if not math.isfinite(val): raise NetworkError('invalid option value')
                if a=='-c':
                    if not val.is_integer() or not 1<=val<=self.policy.max_count: raise NetworkError('count exceeds permitted range')
                    count=int(val)
                elif a=='-i':
                    if not .2<=val<=10: raise NetworkError('interval must be 0.2 to 10 seconds')
                    interval=val
                elif a=='-W':
                    if not .1<=val<=self.policy.timeout: raise NetworkError('timeout exceeds configured limit')
                    timeout=val
                else:
                    if not .1<=val<=self.policy.max_time: raise NetworkError('deadline exceeds configured limit')
                    deadline=val
            elif a.startswith('-') or target is not None: raise NetworkError('unsupported option or extra target')
            else: target=hostname(a)
        if target is None: raise NetworkError('missing destination')
        ips=await self._addresses(target);ip=next((x for x in ips if ':' not in x),None)
        if ip is None: raise NetworkError('no IPv4 address for destination')
        lines=[];sent=0;times=[];start=time.perf_counter()
        def output(line):
            lines.append(line)
            if emit: emit(line+'\n')
        output(f'PING {target} ({ip}) 56(84) bytes of data.')
        def summary():
            loss=100*(sent-len(times))/sent if sent else 0
            output(f'--- {target} ping statistics ---')
            output(f'{sent} packets transmitted, {len(times)} received, {loss:g}% packet loss, time {int((time.perf_counter()-start)*1000)}ms')
            if times: output(f'rtt min/avg/max = {min(times):.3f}/{sum(times)/len(times):.3f}/{max(times):.3f} ms')
        try:
            while count is None or sent<count:
                remaining=deadline-(time.perf_counter()-start)
                if remaining<=0: break
                sent+=1
                answer=await self.backend.echo(ip,min(timeout,remaining),sent)
                if answer is not None:
                    rtt,ttl=answer;times.append(rtt)
                    output(f'64 bytes from {ip}: icmp_seq={sent}'+(f' ttl={ttl}' if ttl is not None else '')+f' time={rtt:.3f} ms')
                if count is not None and sent>=count: break
                remaining=deadline-(time.perf_counter()-start)
                if remaining>0: await asyncio.sleep(min(interval,remaining))
        except asyncio.CancelledError:
            if emit: summary()
            raise
        summary()
        return NetworkResult('\n'.join(lines),exit_code=0 if times else 1,audit={'address':ip,'sent':sent,'received':len(times)},streamed=bool(emit))

    async def connect(self,argv):
        args=argv[1:];zero=False;timeout=self.policy.timeout;operands=[];i=0
        while i<len(args):
            a=args[i];i+=1
            if a in ('-z','-v','-vz','-zv'):
                zero=zero or 'z' in a
            elif a=='-w':
                if i>=len(args): raise NetworkError('missing timeout')
                timeout=float(args[i]);i+=1
                if not math.isfinite(timeout) or not .1<=timeout<=self.policy.timeout: raise NetworkError('timeout exceeds configured limit')
            elif a.startswith('-'): raise NetworkError('only TCP connect checks using -z are supported')
            else: operands.append(a)
        if not zero or len(operands)!=2 or not operands[1].isdigit(): raise NetworkError('usage: nc -z [-v] [-w seconds] host port')
        port=int(operands[1])
        if not 1<=port<=65535: raise NetworkError('invalid TCP port')
        target=hostname(operands[0]);ips=await self._addresses(target)
        error=None
        for ip in ips[:4]:
            try:
                await self.backend.tcp(ip,port,timeout)
                return NetworkResult(stderr=f'Connection to {target} ({ip}) {port} port [tcp/*] succeeded!',audit={'address':ip,'port':port})
            except (OSError,TimeoutError) as exc: error=exc
        return NetworkResult(stderr=f'nc: connect to {target} port {port} (tcp) failed: '+('Connection timed out' if isinstance(error,TimeoutError) else 'Connection refused or unreachable'),exit_code=1,audit={'addresses':ips,'port':port})

    async def getent(self,argv):
        if len(argv)!=3: raise NetworkError('usage: getent hosts|ahosts|ahostsv4|ahostsv6 hostname')
        target=hostname(argv[2]);ips=await self._addresses(target)
        if argv[1]=='ahostsv4': ips=[ip for ip in ips if ':' not in ip]
        if argv[1]=='ahostsv6': ips=[ip for ip in ips if ':' in ip]
        lines=[f'{ip} {target}' if argv[1]=='hosts' else f'{ip} STREAM {target}' for ip in ips]
        return NetworkResult('\n'.join(lines),exit_code=0 if lines else 2,audit={'addresses':ips})

    async def lookup(self,argv):
        command=argv[0].rsplit('/',1)[-1];typ='A';short=False;server=self.policy.resolver;operands=[];i=1
        while i<len(argv):
            a=argv[i];i+=1
            if a=='+short' and command=='dig': short=True
            elif a.startswith('@') and command=='dig': server=a[1:]
            elif a in ('-t','-type') and command in ('host','nslookup'):
                if i>=len(argv): raise NetworkError('missing record type')
                typ=argv[i].upper();i+=1
            elif a.startswith(('-type=','-query=')) and command=='nslookup': typ=a.split('=',1)[1].upper()
            elif a.upper() in TYPES and command=='dig': typ=a.upper()
            elif a.startswith(('-','+','@')): raise NetworkError('unsupported DNS option')
            else: operands.append(a)
        if len(operands)==2 and command in ('host','nslookup'): server=operands.pop()
        if len(operands)!=1 or typ not in TYPES: raise NetworkError('expected one host and a supported DNS record type')
        target=self.policy.egress.host(operands[0])
        try:
            address=ipaddress.ip_address(target)
            if command in ('host','nslookup'): target=address.reverse_pointer;typ='PTR'
        except ValueError: pass
        resolver_ips=await self._addresses(server,allowlist=False);server=resolver_ips[0]
        code,records=await self.backend.dns(target,typ,server)
        status={0:'NOERROR',1:'FORMERR',2:'SERVFAIL',3:'NXDOMAIN',4:'NOTIMP',5:'REFUSED'}.get(code,str(code))
        if command=='dig':
            output='\n'.join(r[3] for r in records) if short else f';; status: {status}\n;; SERVER: {server}#{self.policy.dns_port}\n'+ '\n'.join(f'{n}. {ttl} IN {t} {value}' for n,ttl,t,value in records)
        elif code:
            output=f'Host {target} not found: {status}'
        elif command=='host':
            output='\n'.join(f'{n} '+('has address ' if t=='A' else 'has IPv6 address ' if t=='AAAA' else f'{t} ')+value for n,ttl,t,value in records)
        else:
            output=f'Server: {server}\nAddress: {server}#{self.policy.dns_port}\n\n'+'\n'.join(f'Name: {n}\n'+('Address: ' if t in ('A','AAAA') else t+': ')+value for n,ttl,t,value in records)
        return NetworkResult(output,exit_code=0 if not code or command=='dig' and code==3 else 1,audit={'resolver':server,'dns_status':status,'record_type':typ,'records':len(records)})
