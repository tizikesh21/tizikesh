"""SulgX Telegram proxy layer.

SOCKS5 and HTTP CONNECT are general-purpose authenticated relays in this
module: any TCP destination is allowed, credentials are checked per link.
MTProto and WEB proxying stay Telegram-only and are delegated to the telemt
binary: one shared telemt child serves classic MTProto for every inbound,
and one telemt child per WEB inbound serves that inbound token. The panel
never implements the MTProto or WEB wire protocols itself any more.
"""
import asyncio
import base64
import errno
import hashlib
import hmac as hmac_mod
import ipaddress
import json
import logging
import os
import re
import secrets
import shutil
import socket
import struct
import tempfile
import time
from datetime import datetime, timezone
from urllib.parse import quote as _url_quote
from urllib.parse import quote as _url_path_quote
import urllib.error
import urllib.request

try:
    import httpx as _httpx
except Exception:
    _httpx = None

try:
    from cryptography.hazmat.primitives.ciphers import Cipher as _AES_CIPHER
    from cryptography.hazmat.primitives.ciphers.algorithms import AES as _AES_ALG
    from cryptography.hazmat.primitives.ciphers.modes import CTR as _AES_CTR
except Exception:
    _AES_CIPHER = None
    _AES_ALG = None
    _AES_CTR = None

_LOG = logging.getLogger("sulgx.telegram")

TELEMT_VERSION = "3.5.17"
_TELEMT_DEFAULT_BIN = "/usr/local/bin/telemt"
_TELEMT_DEFAULT_DIR = "/data/telemt"
_TELEMT_LOG_MAX = 500
_TELEMT_BACKOFF = (1, 2, 5, 10, 30)
_TELEMT_MAX_FAILURES = 5
_TELEMT_FAILURE_WINDOW = 60.0
_TELEMT_BOOT_LOG_MAX = 40
_TELEMT_DECOY_HTML = "<!doctype html><html><head><meta charset=\"utf-8\"><title>OK</title></head><body>OK</body></html>"
_HTTP_METHODS = (b"CONNECT ", b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ", b"PATCH ", b"TRACE ")
_HTTP_KNOWN_TOKENS = frozenset((b"CONNECT", b"GET", b"POST", b"HEAD", b"PUT", b"DELETE", b"OPTIONS", b"PATCH", b"TRACE"))
_HTTP_HOP_BY_HOP = frozenset((b"connection", b"proxy-connection", b"keep-alive", b"te", b"trailer", b"transfer-encoding", b"upgrade", b"proxy-authorization", b"proxy-authenticate"))
_HTTP_TOKEN_BYTES = frozenset(b"!#$%&'*+-.^_`|~0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
_TELEMT_USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
_TELEMT_TOKEN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$")
_TELEMT_HOST_RE = re.compile(r"^[a-z0-9][a-z0-9.-]*[a-z0-9]$")
_HEXDIGITS = frozenset("0123456789abcdefABCDEF")

_SECRET = b""
_DOMAIN = "www.google.com"
_AUTH_LOOKUP = None
_COUNT_TRAFFIC = None
_MTPROXY_QUOTA_OK = None
_SESSION_ALLOWED = None
ACTIVE_PROXY = {}
_SERVERS = []
_BOUND_PORTS = set()
_BIND_ERRORS = {}
_STATS = {"socks_connections": 0, "socks_bytes": 0, "mtproxy_connections": 0, "mtproxy_bytes": 0, "http_connections": 0, "http_bytes": 0, "panel_forward_connections": 0}
_MTPROXY_LINK_SECRETS = {}
_PANEL_FORWARD = None

_TELEMT_DIR_CACHED = ""
_TELEMT_DECOY_READY = False
_TELEMT_MTPROTO = None
_TELEMT_MTPROTO_USERS = {}
_TELEMT_WEB = {}
_TELEMT_LOCKS = {}
_MTPROXY_FLUSHED = {}


def configure(secret, domain="www.google.com"):
    global _SECRET, _DOMAIN
    if not isinstance(secret, (bytes, bytearray)) or len(secret) != 16:
        raise ValueError("mtproxy secret must be 16 bytes")
    _SECRET = bytes(secret)
    _DOMAIN = domain or "www.google.com"


def secret_hex():
    return _SECRET.hex()


def mtproxy_link(host, port):
    return "tg://proxy?server=" + str(host) + "&port=" + str(port) + "&secret=" + _SECRET.hex()


def mtproxy_faketls_link(host, port):
    return "tg://proxy?server=" + str(host) + "&port=" + str(port) + "&secret=ee" + _SECRET.hex() + _DOMAIN.encode().hex()


def mtproxy_dd_link(host, port):
    return "tg://proxy?server=" + str(host) + "&port=" + str(port) + "&secret=dd" + _SECRET.hex()


def mtproxy_secret_for_uid(uid):
    return hashlib.sha256(_SECRET + b"mtproxy-link-v1\x00" + str(uid).encode("utf-8")).digest()[:16]


def mtproxy_register_link(uid):
    secret = mtproxy_secret_for_uid(uid)
    _MTPROXY_LINK_SECRETS[str(uid)] = secret
    return secret


def mtproxy_unregister_link(uid):
    _MTPROXY_LINK_SECRETS.pop(str(uid), None)


def mtproxy_link_for_uid(host, port, uid, variant="dd", domain="www.google.com"):
    secret = mtproxy_secret_for_uid(uid)
    if variant == "faketls":
        dom = (domain or "www.google.com").strip() or "www.google.com"
        return "tg://proxy?server=" + str(host) + "&port=" + str(port) + "&secret=" + "ee" + secret.hex() + dom.encode("utf-8").hex()
    if variant == "plain":
        return "tg://proxy?server=" + str(host) + "&port=" + str(port) + "&secret=" + secret.hex()
    return "tg://proxy?server=" + str(host) + "&port=" + str(port) + "&secret=" + "dd" + secret.hex()


def mtproxy_links_for_uid(host, port, uid, domain="www.google.com"):
    return {
        "plain": mtproxy_link_for_uid(host, port, uid, "plain", domain),
        "dd": mtproxy_link_for_uid(host, port, uid, "dd", domain),
        "faketls": mtproxy_link_for_uid(host, port, uid, "faketls", domain),
    }


def socks5_link(host, port, username, password):
    return "socks5://" + _url_quote(str(username), safe="") + ":" + _url_quote(str(password), safe="") + "@" + str(host) + ":" + str(port)


def http_proxy_link(host, port, username, password):
    return "http://" + _url_quote(str(username), safe="") + ":" + _url_quote(str(password), safe="") + "@" + str(host) + ":" + str(port)


def stats():
    return dict(_STATS)


def set_panel_forward(host, port):
    global _PANEL_FORWARD
    try:
        wanted = int(port or 0)
    except (TypeError, ValueError):
        wanted = 0
    if wanted:
        _PANEL_FORWARD = (str(host or "127.0.0.1"), wanted)
    else:
        _PANEL_FORWARD = None
    return _PANEL_FORWARD


def panel_forward():
    return _PANEL_FORWARD


_TCP_PROXY_GRAPHQL_URL = "https://backboard.railway.com/graphql/v2"
_TCP_PROXY_GRAPHQL_CREATE = "mutation($input: TCPProxyCreateInput!) { tcpProxyCreate(input: $input) { applicationPort domain environmentId id proxyPort serviceId } }"
_TCP_PROXY_GRAPHQL_DELETE = "mutation($id: String!) { tcpProxyDelete(id: $id) }"
_TCP_PROXY_GRAPHQL_LIST = "query($environmentId: String, $serviceId: String) { tcpProxies(environmentId: $environmentId, serviceId: $serviceId) { applicationPort domain environmentId id proxyPort serviceId } }"


class TcpProxyProvider:
    name = "none"

    async def create_public_proxy(self, local_port):
        raise NotImplementedError("tcp proxy provider is not configured")

    async def delete_public_proxy(self, proxy_id):
        return False

    async def list_public_proxies(self):
        return []

    def has_token(self):
        return False


class RailwayTcpProxyProvider(TcpProxyProvider):
    name = "railway"

    def __init__(self, token, service_id, environment_id):
        self.token = token or ""
        self.service_id = service_id or ""
        self.environment_id = environment_id or ""

    def has_token(self):
        return bool(self.token and self.service_id and self.environment_id)

    async def _graphql(self, query, variables):
        if _httpx is None:
            raise RuntimeError("httpx is not available for the Railway TCP proxy provider")
        if not self.has_token():
            raise RuntimeError("Railway token, service id and environment id are required")
        async with _httpx.AsyncClient(timeout=20.0) as client:
            response = await client.post(_TCP_PROXY_GRAPHQL_URL, json={"query": query, "variables": variables}, headers={"Authorization": "Bearer " + self.token, "Content-Type": "application/json"})
        if response.status_code >= 400:
            raise RuntimeError("Railway API rejected the TCP proxy request with HTTP " + str(response.status_code))
        payload = response.json()
        errors = payload.get("errors") or []
        if errors:
            first = errors[0] or {}
            raise RuntimeError("Railway API error: " + str(first.get("message") or first))
        return payload.get("data") or {}

    async def create_public_proxy(self, local_port):
        data = await self._graphql(_TCP_PROXY_GRAPHQL_CREATE, {"input": {"applicationPort": int(local_port), "environmentId": self.environment_id, "serviceId": self.service_id}})
        created = data.get("tcpProxyCreate") or {}
        if not created.get("domain") or not created.get("proxyPort"):
            raise RuntimeError("Railway TCP proxy create returned no public endpoint")
        return {"domain": str(created["domain"]), "port": int(created["proxyPort"]), "id": str(created["id"]), "application_port": int(created.get("applicationPort") or local_port)}

    async def delete_public_proxy(self, proxy_id):
        if not proxy_id:
            return False
        try:
            await self._graphql(_TCP_PROXY_GRAPHQL_DELETE, {"id": str(proxy_id)})
        except Exception as exc:
            _LOG.warning("Railway TCP proxy delete failed for " + str(proxy_id) + ": " + str(exc))
            return False
        return True

    async def list_public_proxies(self):
        data = await self._graphql(_TCP_PROXY_GRAPHQL_LIST, {"environmentId": self.environment_id, "serviceId": self.service_id})
        out = []
        for item in data.get("tcpProxies") or []:
            out.append({"domain": str(item.get("domain") or ""), "port": int(item.get("proxyPort") or 0), "id": str(item.get("id") or ""), "application_port": int(item.get("applicationPort") or 0)})
        return out


class MockTcpProxyProvider(TcpProxyProvider):
    name = "mock"

    def __init__(self):
        self._servers = {}
        self._targets = {}
        self._next = 0

    def has_token(self):
        return True

    async def create_public_proxy(self, local_port):
        self._next += 1
        proxy_id = "mock-" + str(self._next)
        target_port = int(local_port)

        async def _forward(reader, writer):
            try:
                upstream_reader, upstream_writer = await asyncio.open_connection("127.0.0.1", target_port)
            except OSError:
                try:
                    writer.close()
                except OSError:
                    pass
                return

            async def _pipe(src, dst):
                try:
                    while True:
                        chunk = await src.read(65536)
                        if not chunk:
                            break
                        dst.write(chunk)
                        await dst.drain()
                except (ConnectionError, asyncio.IncompleteReadError, asyncio.TimeoutError, OSError):
                    pass
                finally:
                    try:
                        dst.write_eof()
                    except (AttributeError, OSError, RuntimeError):
                        try:
                            dst.close()
                        except OSError:
                            pass

            await asyncio.gather(_pipe(reader, upstream_writer), _pipe(upstream_reader, writer), return_exceptions=True)
            try:
                upstream_writer.close()
            except OSError:
                pass
            try:
                writer.close()
            except OSError:
                pass

        server = await asyncio.start_server(_forward, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        self._servers[proxy_id] = server
        self._targets[proxy_id] = target_port
        return {"domain": "127.0.0.1", "port": port, "id": proxy_id, "application_port": target_port}

    async def delete_public_proxy(self, proxy_id):
        server = self._servers.pop(str(proxy_id), None)
        self._targets.pop(str(proxy_id), None)
        if server is None:
            return True
        server.close()
        await server.wait_closed()
        return True

    async def list_public_proxies(self):
        out = []
        for proxy_id, server in self._servers.items():
            out.append({"domain": "127.0.0.1", "port": server.sockets[0].getsockname()[1], "id": proxy_id, "application_port": int(self._targets.get(proxy_id) or 0)})
        return out


_TCP_PROXY_PROVIDER = None


def set_tcp_proxy_provider(provider):
    global _TCP_PROXY_PROVIDER
    _TCP_PROXY_PROVIDER = provider
    return _TCP_PROXY_PROVIDER


def tcp_proxy_provider():
    return _TCP_PROXY_PROVIDER


def configure_proxy_callbacks(auth_lookup, count_traffic, mtproxy_quota_ok, session_allowed=None):
    global _AUTH_LOOKUP, _COUNT_TRAFFIC, _MTPROXY_QUOTA_OK, _SESSION_ALLOWED
    _AUTH_LOOKUP = auth_lookup
    _COUNT_TRAFFIC = count_traffic
    _MTPROXY_QUOTA_OK = mtproxy_quota_ok
    _SESSION_ALLOWED = session_allowed


def _bind_error_text(port, exc):
    text = str(exc)
    try:
        errno = getattr(exc, "errno", 0) or 0
    except Exception:
        errno = 0
    if errno in (98, 48) and _PANEL_FORWARD is not None and int(port) == int(_PANEL_FORWARD[1]):
        return "port " + str(port) + " is the panel web server's own listen port; restart the panel with the panel on an internal port (set PORT to an internal port such as 8000 and PANEL_BIND_HOST to 127.0.0.1) so the multiplexer can own port " + str(port) + " and forward panel traffic to it"
    return text


def _ordered_targets(ips):
    targets = []
    for ip in ips or []:
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            continue
        if ip not in targets:
            targets.append(ip)
    targets.sort(key=lambda item: ipaddress.ip_address(item).version)
    return targets


def _socks_rep_for_error(exc):
    if isinstance(exc, asyncio.TimeoutError):
        return 0x01
    err = getattr(exc, "errno", None)
    if err == errno.ECONNREFUSED:
        return 0x05
    if err == errno.EHOSTUNREACH:
        return 0x04
    if err == errno.ENETUNREACH:
        return 0x03
    if err == errno.EACCES or err == errno.EPERM:
        return 0x02
    return 0x01


async def _connect_target(targets, port):
    deadline = time.monotonic() + 30.0
    seen = []
    for target_ip in targets:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(target_ip, port), timeout=min(10.0, remaining))
            return reader, writer, 0x00
        except (OSError, asyncio.TimeoutError) as exc:
            seen.append(_socks_rep_for_error(exc))
            continue
    for rep in (0x05, 0x04, 0x03, 0x02):
        if rep in seen:
            return None, None, rep
    return None, None, 0x01


async def _read_exact(reader, n, timeout=10.0):
    data = b""
    deadline = time.monotonic() + timeout
    while len(data) < n:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise asyncio.TimeoutError("read timed out")
        chunk = await asyncio.wait_for(reader.read(n - len(data)), timeout=remaining)
        if not chunk:
            raise ConnectionError("connection closed while reading")
        data += chunk
    return data


def active_proxy_sessions():
    out = []
    for s in list(ACTIVE_PROXY.values()):
        out.append({k: v for k, v in s.items() if k != "writer"})
    return out


def disconnect_proxy_session(sid):
    entry = ACTIVE_PROXY.get(sid)
    if entry is None:
        return False
    writer = entry.get("writer")
    if writer is not None:
        try:
            writer.close()
        except OSError:
            pass
    ACTIVE_PROXY.pop(sid, None)
    return True

class _PrefixedReader:
    def __init__(self, reader, prefix):
        self._reader = reader
        self._buf = bytearray(prefix or b"")

    async def read(self, n=-1):
        if n is None or n < 0:
            chunks = [bytes(self._buf)]
            self._buf.clear()
            while True:
                chunk = await self._reader.read(65536)
                if not chunk:
                    break
                chunks.append(chunk)
            return b"".join(chunks)
        if self._buf:
            out = bytes(self._buf[:n])
            del self._buf[:n]
            return out
        chunk = await self._reader.read(n)
        return bytes(chunk or b"")

    async def readexactly(self, n):
        data = b""
        while len(data) < n:
            chunk = await self.read(n - len(data))
            if not chunk:
                raise asyncio.IncompleteReadError(data, n)
            data += chunk
        return data

    async def readuntil(self, separator=b"\n"):
        while True:
            idx = self._buf.find(separator)
            if idx >= 0:
                end = idx + len(separator)
                out = bytes(self._buf[:end])
                del self._buf[:end]
                return out
            if len(self._buf) > 65536:
                raise asyncio.LimitOverrunError("header exceeds 65536 bytes", len(self._buf))
            chunk = await self._reader.read(65536)
            if not chunk:
                raise asyncio.IncompleteReadError(bytes(self._buf), None)
            self._buf += chunk


def _looks_http(prefix):
    if not prefix:
        return False
    upper = bytes(prefix).upper()
    for method in _HTTP_METHODS:
        if upper.startswith(method):
            return True
        if len(upper) >= 3 and len(upper) < len(method) and method.startswith(upper):
            return True
    return False


def _looks_socks5(prefix):
    if len(prefix) < 2:
        return False
    if prefix[0] != 0x05:
        return False
    count = prefix[1]
    if count < 1:
        return False
    for byte in prefix[2:2 + count]:
        if byte in (0x00, 0x01, 0x02):
            return True
    return False


def _could_be_http_or_socks5(prefix):
    if not prefix:
        return True
    upper = bytes(prefix).upper()
    for method in _HTTP_METHODS:
        if method.startswith(upper):
            return True
    if prefix[0] == 0x05:
        if len(prefix) < 2:
            return True
        count = prefix[1]
        if count < 1:
            return False
        if len(prefix) < 2 + count:
            return True
        for byte in prefix[2:2 + count]:
            if byte in (0x00, 0x01, 0x02):
                return True
        return False
    return False


async def _peek_prefix(reader):
    prefix = b""
    deadline = time.monotonic() + 10.0
    while len(prefix) < 16 or (len(prefix) >= 2 and prefix[0] == 0x05 and len(prefix) < min(2 + prefix[1], 16)):
        try:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            chunk = await asyncio.wait_for(reader.read(16 - len(prefix)), timeout=remaining)
        except asyncio.TimeoutError:
            break
        except (ConnectionError, OSError):
            break
        if not chunk:
            break
        prefix += bytes(chunk)
        if _looks_http(prefix):
            break
        if _looks_socks5(prefix) and len(prefix) >= 2 + prefix[1]:
            break
        if not _could_be_http_or_socks5(prefix):
            break
    return prefix


def _mtproto_candidate_secrets():
    candidates = []
    seen = set()
    for username, info in list(_TELEMT_MTPROTO_USERS.items()):
        try:
            secret = bytes.fromhex(str((info or {}).get("secret_hex") or ""))
        except ValueError:
            continue
        if len(secret) != 16:
            continue
        uid = str((info or {}).get("uid") or username)
        if uid in seen:
            continue
        seen.add(uid)
        candidates.append((uid, secret))
    for link_uid, secret in list(_MTPROXY_LINK_SECRETS.items()):
        uid = str(link_uid)
        if uid in seen:
            continue
        if not isinstance(secret, (bytes, bytearray)) or len(secret) != 16:
            continue
        seen.add(uid)
        candidates.append((uid, bytes(secret)))
    return candidates


def _mtproto_trial_obfs_tag(init, secret):
    if _AES_CIPHER is None or len(init) < 64 or len(secret) != 16:
        return None
    try:
        enc_key = hashlib.sha256(bytes(init[8:40]) + bytes(secret)).digest()
        cipher = _AES_CIPHER(_AES_ALG(enc_key), _AES_CTR(bytes(init[40:56])))
        stream = cipher.encryptor()
        stream.update(bytes(56))
        tail = stream.update(bytes(init[56:64]))
    except Exception:
        return None
    tag = bytes(tail[:4])
    if tag == b"\xdd\xdd\xdd\xdd":
        return "dd"
    if tag == b"\xef\xef\xef\xef":
        return "plain"
    if tag == b"\xee\xee\xee\xee":
        return "faketls"
    return None


def _mtproto_identify_obfs(init):
    for uid, secret in _mtproto_candidate_secrets():
        if _mtproto_trial_obfs_tag(init, secret) is not None:
            return uid
    return ""


def _mtproto_identify_faketls(hello):
    if len(hello) < 43:
        return ""
    zeroed = bytes(hello[:11]) + b"\x00" * 32 + bytes(hello[43:])
    rand = bytes(hello[11:43])
    now = int(time.time())
    for uid, secret in _mtproto_candidate_secrets():
        digest = hmac_mod.new(bytes(secret), zeroed, hashlib.sha256).digest()
        if not hmac_mod.compare_digest(rand[:28], digest[:28]):
            continue
        stamp = bytes(a ^ b for a, b in zip(rand[28:32], digest[28:32]))
        stamp_value = struct.unpack("<I", stamp)[0]
        if abs(stamp_value - now) <= 900:
            return uid
    return ""


async def _handle_mtproto_relay(reader, writer, prefix):
    upstream_reader = None
    upstream_writer = None
    sid = None
    entry = None
    total_bytes = 0
    up_flushed = 0
    down_flushed = 0
    link_uid = ""
    close_reason = "done"
    peer = writer.get_extra_info("peername")
    peer_ip = peer[0] if peer else ""
    try:
        if _MTPROXY_QUOTA_OK is not None:
            if not await _MTPROXY_QUOTA_OK():
                close_reason = "quota"
                writer.close()
                return
        port = telemt_mtproto_port()
        if port is None:
            close_reason = "child-down"
            _LOG.warning("telemt MTProto child is not running; closing MTProto connection")
            writer.close()
            return
        head = bytes(prefix or b"")
        if head and head[0] == 0x16 and len(head) >= 5 and head[1] == 0x03:
            total_len = 5 + struct.unpack(">H", head[3:5])[0]
            if total_len > len(head) and total_len <= 65535:
                try:
                    head += bytes(await asyncio.wait_for(reader.readexactly(total_len - len(head)), timeout=3.0))
                except (asyncio.TimeoutError, asyncio.IncompleteReadError, ConnectionError, OSError):
                    pass
            link_uid = _mtproto_identify_faketls(head)
        else:
            if len(head) < 64:
                try:
                    head += bytes(await asyncio.wait_for(reader.readexactly(64 - len(head)), timeout=3.0))
                except (asyncio.TimeoutError, asyncio.IncompleteReadError, ConnectionError, OSError):
                    pass
            if len(head) == 64:
                link_uid = _mtproto_identify_obfs(head)
        if not link_uid:
            close_reason = "unknown-secret"
            _STATS["mtproxy_unknown_secret"] = int(_STATS.get("mtproxy_unknown_secret") or 0) + 1
            if len(head) >= 5 and head[0] == 0x16 and head[1] == 0x03:
                _LOG.warning("proxy mux dropped unidentified TLS hello from " + _mux_peer_text(writer) + " prefix " + bytes(head[:8]).hex() + " without opening the MTProto upstream")
            else:
                _LOG.info("proxy mux dropped unidentified obfs init from " + _mux_peer_text(writer) + " prefix " + bytes(head[:8]).hex())
            try:
                writer.close()
            except OSError:
                pass
            return
        _STATS["mtproxy_connections"] += 1
        if link_uid and _COUNT_TRAFFIC is not None:
            if not await _COUNT_TRAFFIC(link_uid, 0):
                close_reason = "quota"
                writer.close()
                return
        if link_uid and _SESSION_ALLOWED is not None:
            _peer = writer.get_extra_info("peername")
            _cip = _peer[0] if _peer else ""
            if not _SESSION_ALLOWED(link_uid, _cip):
                close_reason = "session-limit"
                writer.close()
                return
        try:
            upstream_reader, upstream_writer = await asyncio.wait_for(
                asyncio.open_connection("127.0.0.1", port), timeout=10
            )
        except (OSError, asyncio.TimeoutError):
            close_reason = "upstream-fail"
            _LOG.warning("mtproxy child dial failed peer=" + peer_ip + " child=127.0.0.1:" + str(port))
            writer.close()
            return
        peer = writer.get_extra_info("peername")
        sid = "mtproxy-" + os.urandom(6).hex()
        entry = {"id": sid, "username": link_uid, "protocol": "mtproto", "client_ip": peer[0] if peer else "", "started_at": datetime.now(timezone.utc).isoformat(), "bytes_up": 0, "bytes_down": 0, "bytes_flushed": 0, "writer": writer}
        ACTIVE_PROXY[sid] = entry

        async def _count(n, direction):
            nonlocal total_bytes, up_flushed, down_flushed
            total_bytes += n
            if link_uid:
                _STATS["mtproxy_bytes"] += n
            pending = 0
            if direction == "up":
                entry["bytes_up"] += n
                pending = entry["bytes_up"] - up_flushed
            else:
                entry["bytes_down"] += n
                pending = entry["bytes_down"] - down_flushed
            if link_uid and _COUNT_TRAFFIC is not None and pending >= 1048576:
                if await _COUNT_TRAFFIC(link_uid, pending):
                    if direction == "up":
                        up_flushed += pending
                    else:
                        down_flushed += pending
                    entry["bytes_flushed"] = up_flushed + down_flushed
                    _MTPROXY_FLUSHED[link_uid] = int(_MTPROXY_FLUSHED.get(link_uid, 0) or 0) + pending
                else:
                    try:
                        writer.close()
                    except OSError:
                        pass
                    try:
                        upstream_writer.close()
                    except OSError:
                        pass

        async def _relay(src, dst, direction):
            try:
                while True:
                    chunk = await src.read(65536)
                    if not chunk:
                        break
                    dst.write(chunk)
                    await dst.drain()
                    await _count(len(chunk), direction)
            except (ConnectionError, asyncio.IncompleteReadError, asyncio.TimeoutError, OSError):
                pass
            finally:
                try:
                    dst.write_eof()
                except (AttributeError, OSError, RuntimeError):
                    try:
                        dst.close()
                    except OSError:
                        pass

        if head:
            upstream_writer.write(head)
            await upstream_writer.drain()
            await _count(len(head), "up")
        up_task = asyncio.create_task(_relay(reader, upstream_writer, "up"))
        down_task = asyncio.create_task(_relay(upstream_reader, writer, "down"))
        done, pending = await asyncio.wait((up_task, down_task), return_when=asyncio.FIRST_COMPLETED)
        for task in pending:
            task.cancel()
        await asyncio.gather(up_task, down_task, return_exceptions=True)
    except (ConnectionError, asyncio.IncompleteReadError, asyncio.TimeoutError, OSError):
        if close_reason == "done":
            close_reason = "relay-error"
        pass
    finally:
        _LOG.info("mtproxy close peer=%s uid=%s bytes=%d reason=%s", peer_ip, link_uid or "unknown", total_bytes, close_reason)
        if link_uid and _COUNT_TRAFFIC is not None and total_bytes - (up_flushed + down_flushed) > 0:
            remainder = total_bytes - (up_flushed + down_flushed)
            try:
                if await _COUNT_TRAFFIC(link_uid, remainder):
                    _MTPROXY_FLUSHED[link_uid] = int(_MTPROXY_FLUSHED.get(link_uid, 0) or 0) + remainder
            except (ConnectionError, asyncio.TimeoutError, OSError):
                pass
        if upstream_writer is not None:
            try:
                upstream_writer.close()
            except OSError:
                pass
        if sid is not None:
            ACTIVE_PROXY.pop(sid, None)
        try:
            writer.close()
        except OSError:
            pass


async def _handle_panel_forward(reader, writer):
    _STATS["panel_forward_connections"] += 1
    target = _PANEL_FORWARD
    upstream_writer = None
    _panel_peer = _mux_peer_text(writer)
    try:
        _LOG.info("panel forward from " + _panel_peer + " to " + str(target[0]) + ":" + str(target[1]) if target else "panel forward from " + _panel_peer + " with no target")
        if not target or int(target[1]) in _BOUND_PORTS:
            writer.write(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            await writer.drain()
            return
        try:
            upstream_reader, upstream_writer = await asyncio.wait_for(asyncio.open_connection(target[0], target[1]), timeout=5)
        except (OSError, asyncio.TimeoutError):
            writer.write(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            await writer.drain()
            return
        peer = writer.get_extra_info("peername")
        peer_ip = peer[0] if peer else ""
        head = None
        try:
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=5.0)
        except (asyncio.TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError, ConnectionError, OSError):
            head = None
        if head:
            text = head.decode("iso-8859-1", "ignore")
            lines = text.split("\r\n")
            kept = []
            for line in lines:
                if line.lower().startswith("x-forwarded-for:"):
                    continue
                kept.append(line)
            if peer_ip:
                kept.insert(len(kept) - 2, "X-Forwarded-For: " + peer_ip)
            upstream_writer.write("\r\n".join(kept).encode("iso-8859-1"))
            await upstream_writer.drain()

        async def _relay(src, dst):
            try:
                while True:
                    chunk = await src.read(65536)
                    if not chunk:
                        break
                    dst.write(chunk)
                    await dst.drain()
            except (ConnectionError, asyncio.IncompleteReadError, asyncio.TimeoutError, OSError):
                pass
            finally:
                try:
                    dst.write_eof()
                except (AttributeError, OSError, RuntimeError):
                    try:
                        dst.close()
                    except OSError:
                        pass

        await asyncio.gather(_relay(reader, upstream_writer), _relay(upstream_reader, writer))
    except (ConnectionError, asyncio.IncompleteReadError, asyncio.TimeoutError, OSError):
        pass
    finally:
        _LOG.info("panel forward close peer=" + _panel_peer)
        if upstream_writer is not None:
            try:
                upstream_writer.close()
            except OSError:
                pass
        try:
            writer.close()
        except OSError:
            pass


async def _http_send_error(writer, status, reason, extra_headers=None):
    try:
        lines = [b"HTTP/1.1 " + str(status).encode("ascii") + b" " + reason.encode("ascii")]
        for header in extra_headers or ():
            lines.append(header)
        lines.append(b"Content-Length: 0")
        lines.append(b"Connection: close")
        writer.write(b"\r\n".join(lines) + b"\r\n\r\n")
        await asyncio.wait_for(writer.drain(), timeout=5.0)
    except Exception:
        pass


def _http_split_token(prefix):
    for idx, byte in enumerate(bytes(prefix or b"")):
        if byte in (0x20, 0x09, 0x0d, 0x0a):
            return bytes(prefix[:idx]), idx
    return None, None


async def _extend_http_prefix(reader, prefix):
    while len(prefix) < 32:
        _token, sep = _http_split_token(prefix)
        if sep is not None and len(prefix) >= sep + 9:
            break
        if sep is None and len(prefix) >= 16 and not bytes(prefix).isalpha():
            break
        try:
            chunk = await asyncio.wait_for(reader.read(32 - len(prefix)), timeout=5.0)
        except (asyncio.TimeoutError, ConnectionError, OSError):
            break
        if not chunk:
            break
        prefix += bytes(chunk)
    return prefix


def _http_headers_get(headers, name):
    wanted = bytes(name).lower()
    for entry_name, _orig, value in headers:
        if entry_name == wanted:
            return value
    return None


def _http_connection_tokens(headers):
    tokens = set()
    for entry_name, _orig, value in headers:
        if entry_name == b"connection":
            for item in bytes(value).split(b","):
                item = item.strip().lower()
                if item:
                    tokens.add(item)
    return tokens


def _parse_http_request_head(head):
    if not head.endswith(b"\r\n\r\n"):
        return None
    lines = bytes(head[:-4]).split(b"\r\n")
    if not lines or not lines[0]:
        return None
    parts = lines[0].split()
    if len(parts) < 2 or len(parts) > 3:
        return None
    method = parts[0]
    if not method or len(method) > 32 or any(byte not in _HTTP_TOKEN_BYTES for byte in method):
        return None
    target = parts[1]
    if not target or any(byte < 0x21 or byte == 0x7f for byte in target):
        return None
    version = None
    if len(parts) == 3:
        version = parts[2]
        if len(version) != 8 or not version.startswith(b"HTTP/") or version[5] not in b"0123456789" or version[6:7] != b"." or version[7] not in b"0123456789":
            return None
    headers = []
    for line in lines[1:]:
        if not line:
            continue
        if b":" not in line:
            return None
        name, value = line.split(b":", 1)
        name = bytes(name).strip()
        if not name or any(byte not in _HTTP_TOKEN_BYTES for byte in name):
            return None
        value = bytes(value).strip(b" \t")
        if any(byte < 0x20 and byte != 0x09 or byte == 0x7f for byte in value):
            return None
        headers.append((name.lower(), name, value))
    return method.decode("ascii"), target, version, headers


def _parse_http_response_head(head):
    if not head.endswith(b"\r\n\r\n"):
        return None
    lines = bytes(head[:-4]).split(b"\r\n")
    if not lines or not lines[0]:
        return None
    parts = lines[0].split(b" ", 2)
    if len(parts) < 2:
        return None
    version = parts[0]
    if len(version) != 8 or not version.startswith(b"HTTP/") or version[5] not in b"0123456789" or version[6:7] != b"." or version[7] not in b"0123456789":
        return None
    code = parts[1]
    if len(code) != 3 or not code.isdigit():
        return None
    reason = parts[2] if len(parts) > 2 else b""
    headers = []
    for line in lines[1:]:
        if not line:
            continue
        if b":" not in line:
            continue
        name, value = line.split(b":", 1)
        name = bytes(name).strip()
        if not name or any(byte not in _HTTP_TOKEN_BYTES for byte in name):
            continue
        value = bytes(value).strip(b" \t")
        if any(byte < 0x20 and byte != 0x09 or byte == 0x7f for byte in value):
            continue
        headers.append((name.lower(), name, value))
    return version, int(code), reason, headers


def _parse_proxy_auth(headers):
    raw = _http_headers_get(headers, b"proxy-authorization")
    if raw is None:
        return None
    parts = bytes(raw).split(None, 1)
    if len(parts) != 2 or parts[0].lower() != b"basic":
        return None
    try:
        decoded = base64.b64decode(parts[1].strip(), validate=True)
    except ValueError:
        return None
    if b":" not in decoded:
        return None
    username, password = decoded.split(b":", 1)
    if not username:
        return None
    try:
        return username.decode("utf-8"), password.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _parse_host_port(authority, default_port):
    if not authority or any(byte < 0x21 or byte == 0x7f for byte in authority):
        return None
    try:
        authority.decode("ascii")
    except UnicodeDecodeError:
        return None
    if authority.startswith(b"["):
        close = authority.find(b"]")
        if close < 0:
            return None
        host_raw = authority[1:close]
        try:
            ipaddress.IPv6Address(host_raw.decode("ascii"))
        except ValueError:
            return None
        rest = authority[close + 1:]
        if not rest:
            return authority, default_port
        if not rest.startswith(b":") or not rest[1:].isdigit():
            return None
        port = int(rest[1:])
        if port < 1 or port > 65535:
            return None
        return authority, port
    if authority.count(b":") != 1:
        return None
    host_raw, port_text = authority.split(b":", 1)
    if not host_raw or not port_text.isdigit():
        return None
    port = int(port_text)
    if port < 1 or port > 65535:
        return None
    if len(host_raw) > 253:
        return None
    if any(byte not in b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.~!$&'()*+,;=%" for byte in host_raw):
        return None
    return host_raw, port


def _parse_connect_authority(target):
    if any(byte in target for byte in (b"/", b"?", b"#", b"@")):
        return None
    parsed = _parse_host_port(target, 0)
    if parsed is None:
        return None
    host_raw, port = parsed
    if port == 0:
        return None
    return host_raw.decode("ascii"), port


def _parse_absolute_uri(target):
    lowered = bytes(target).lower()
    if lowered.startswith(b"https://"):
        return "https"
    if not lowered.startswith(b"http://"):
        return None
    rest = bytes(target)[7:]
    if not rest:
        return None
    end = len(rest)
    for sep in (b"/", b"?", b"#"):
        pos = rest.find(sep)
        if pos >= 0 and pos < end:
            end = pos
    authority = rest[:end]
    if not authority or b"@" in authority:
        return None
    parsed = _parse_host_port(authority, 80)
    if parsed is None:
        return None
    host_raw, port = parsed
    tail = rest[end:]
    if tail.startswith(b"#"):
        tail = b""
    elif b"#" in tail:
        tail = tail.split(b"#", 1)[0]
    if not tail:
        path = b"/"
    elif tail.startswith(b"?"):
        path = b"/" + tail
    else:
        path = tail
    return host_raw.decode("ascii"), port, authority, path


async def _http_connect_target(targets, port):
    deadline = time.monotonic() + 10.0
    for target_ip in targets:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None, "timeout"
        try:
            return await asyncio.wait_for(asyncio.open_connection(target_ip, port), timeout=remaining), ""
        except asyncio.TimeoutError:
            return None, "timeout"
        except (OSError, ConnectionError):
            continue
    return None, "refused"


async def _http_resolve_and_connect(host, port):
    loop = asyncio.get_running_loop()
    try:
        infos = await asyncio.wait_for(loop.getaddrinfo(host, None, proto=socket.IPPROTO_TCP), timeout=10.0)
    except asyncio.TimeoutError:
        return None, None, "timeout"
    except (OSError, UnicodeError):
        return None, None, "refused"
    ips = list({info[4][0] for info in infos})
    targets = _ordered_targets(ips)
    if not targets:
        return None, None, "refused"
    pair, reason = await _http_connect_target(targets, port)
    if pair is None:
        return None, None, reason
    return pair[0], pair[1], ""


def _http_connect_failure_status(reason):
    if reason == "timeout":
        return 504, "Gateway Timeout"
    return 502, "Bad Gateway"


def _mux_peer_text(writer):
    peer = writer.get_extra_info("peername")
    if peer:
        if peer[1]:
            return str(peer[0]) + ":" + str(peer[1])
        return str(peer[0]) + " (ws)"
    return ""


async def _handle_multi(reader, writer):
    prefix = await _peek_prefix(reader)
    peer_text = _mux_peer_text(writer)
    if not prefix:
        _LOG.info("proxy mux connection from " + peer_text + " closed without bytes count " + str(_mux_dispatch_count("empty")))
        await _http_send_error(writer, 408, "Request Timeout")
        try:
            writer.close()
        except OSError:
            pass
        return
    prefix_hex = bytes(prefix).hex()
    if len(prefix) < 64 and ((len(prefix) >= 2 and prefix[0] == 0x05 and 1 <= prefix[1] <= 3) or _looks_socks5(prefix)):
        deadline = time.monotonic() + 0.05
        while len(prefix) < 64:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                extra = await asyncio.wait_for(reader.read(64 - len(prefix)), timeout=remaining)
            except (asyncio.TimeoutError, ConnectionError, OSError):
                break
            if not extra:
                break
            prefix += bytes(extra)
        if len(prefix) >= 64 and _mtproto_identify_obfs(prefix[:64]):
            _LOG.info("proxy mux dispatch mtproto from " + peer_text + " prefix " + bytes(prefix).hex() + " count " + str(_mux_dispatch_count("mtproto")))
            await _handle_mtproto_relay(reader, writer, prefix)
            return
        prefix_hex = bytes(prefix).hex()
    if _looks_socks5(prefix):
        _LOG.info("proxy mux dispatch socks5 from " + peer_text + " prefix " + prefix_hex + " count " + str(_mux_dispatch_count("socks5")))
        await _handle_socks5(_PrefixedReader(reader, prefix), writer)
        return
    if len(prefix) >= 2 and prefix[0] == 0x05 and 1 <= prefix[1] <= 3 and len(prefix) >= 2 + prefix[1]:
        _LOG.info("proxy mux dispatch socks5 from " + peer_text + " prefix " + prefix_hex + " count " + str(_mux_dispatch_count("socks5")))
        await _handle_socks5(_PrefixedReader(reader, prefix), writer)
        return
    token, _sep = _http_split_token(prefix)
    if token is not None and token.upper() in _HTTP_KNOWN_TOKENS:
        prefix = await _extend_http_prefix(reader, prefix)
        token, sep = _http_split_token(prefix)
        if token is not None and token.upper() == b"CONNECT":
            _LOG.info("proxy mux dispatch http-connect from " + peer_text + " prefix " + prefix_hex + " count " + str(_mux_dispatch_count("http_connect")))
            await _handle_http_proxy(_PrefixedReader(reader, prefix), writer)
            return
        if sep is not None:
            after = bytes(prefix[sep + 1:sep + 9]).lower()
            if after.startswith(b"http://") or after.startswith(b"https://"):
                _LOG.info("proxy mux dispatch http-absolute from " + peer_text + " prefix " + prefix_hex + " count " + str(_mux_dispatch_count("http_absolute")))
                await _handle_http_proxy(_PrefixedReader(reader, prefix), writer)
                return
        _LOG.info("proxy mux dispatch panel-forward from " + peer_text + " prefix " + prefix_hex + " count " + str(_mux_dispatch_count("panel_forward")))
        await _handle_panel_forward(_PrefixedReader(reader, prefix), writer)
        return
    if prefix and prefix[:1].isalpha() and all(0x20 <= byte <= 0x7e or byte in (0x0d, 0x0a) for byte in prefix):
        if b"\n" in bytes(prefix):
            _LOG.info("proxy mux dispatch http from " + peer_text + " prefix " + prefix_hex + " count " + str(_mux_dispatch_count("http")))
            await _handle_http_proxy(_PrefixedReader(reader, prefix), writer)
            return
        extra = b""
        try:
            extra = bytes(await asyncio.wait_for(reader.readuntil(b"\n"), timeout=2.0))
        except asyncio.LimitOverrunError:
            _LOG.info("proxy mux dispatch http from " + peer_text + " prefix " + prefix_hex + " count " + str(_mux_dispatch_count("http")))
            await _handle_http_proxy(_PrefixedReader(reader, prefix), writer)
            return
        except (asyncio.TimeoutError, asyncio.IncompleteReadError, ConnectionError, OSError):
            if any(method.startswith(bytes(prefix).upper()) for method in _HTTP_METHODS):
                _LOG.info("proxy mux dispatch http from " + peer_text + " prefix " + prefix_hex + " count " + str(_mux_dispatch_count("http")))
                await _handle_http_proxy(_PrefixedReader(reader, prefix), writer)
                return
            _LOG.info("proxy mux dispatch unknown from " + peer_text + " prefix " + prefix_hex + " count " + str(_mux_dispatch_count("unknown")))
            try:
                writer.close()
            except OSError:
                pass
            return
        else:
            combined = bytes(prefix) + extra
            if extra and all(0x20 <= byte <= 0x7e or byte in (0x0d, 0x0a) for byte in extra):
                _LOG.info("proxy mux dispatch http from " + peer_text + " prefix " + prefix_hex + " count " + str(_mux_dispatch_count("http")))
                await _handle_http_proxy(_PrefixedReader(reader, combined), writer)
                return
            if extra:
                _LOG.info("proxy mux dispatch mtproto from " + peer_text + " prefix " + prefix_hex + " count " + str(_mux_dispatch_count("mtproto")))
                await _handle_mtproto_relay(reader, writer, combined)
                return
    _LOG.info("proxy mux dispatch mtproto from " + peer_text + " prefix " + prefix_hex + " count " + str(_mux_dispatch_count("mtproto")))
    await _handle_mtproto_relay(reader, writer, prefix)


class _WSStreamReader(asyncio.StreamReader):
    def __init__(self):
        super().__init__()
        self._ws_closed = False

    def feed_ws_eof(self):
        if not self._ws_closed:
            self._ws_closed = True
            self.feed_eof()


class _WSStreamWriter:
    def __init__(self, send_bytes, close_ws, client_ip):
        self._send_bytes = send_bytes
        self._close_ws = close_ws
        self._client_ip = client_ip or ""
        self._pending = bytearray()
        self._closing = False
        self._closed = False
        self._close_task = None
        self._send_lock = asyncio.Lock()
        self.transport = "ws"

    def get_extra_info(self, name, default=None):
        if name == "peername":
            return (self._client_ip, 0)
        if name == "sockname":
            return ("0.0.0.0", 0)
        return default

    def is_closing(self):
        return self._closing or self._closed

    def write(self, data):
        if self._closing or self._closed or not data:
            return
        self._pending += bytes(data)

    async def drain(self):
        if not self._pending or self._closed:
            return
        data = bytes(self._pending)
        self._pending = bytearray()
        try:
            async with self._send_lock:
                if self._closed:
                    return
                await self._send_bytes(data)
        except (ConnectionError, asyncio.TimeoutError, OSError, RuntimeError):
            self._closed = True
            self._pending = bytearray()
            raise ConnectionError("ws closed")

    async def drain_and_close(self):
        if self._closed:
            return
        self._closing = True
        try:
            await self.drain()
        except (ConnectionError, asyncio.TimeoutError, OSError, RuntimeError):
            pass
        finally:
            async with self._send_lock:
                self._closed = True
                try:
                    await self._close_ws()
                except (ConnectionError, asyncio.TimeoutError, OSError, RuntimeError):
                    pass

    def _schedule_close(self):
        if self._close_task is None or self._close_task.done():
            try:
                loop = asyncio.get_running_loop()
            except RuntimeError:
                return
            self._close_task = loop.create_task(self.drain_and_close())

    def write_eof(self):
        self._closing = True
        self._schedule_close()

    def close(self):
        self._closing = True
        self._schedule_close()


async def handle_proxy_websocket(receive_bytes, send_bytes, close_ws, protocol, client_ip, first_chunk=b""):
    reader = _WSStreamReader()
    writer = _WSStreamWriter(send_bytes, close_ws, client_ip)
    if first_chunk:
        reader.feed_data(bytes(first_chunk))
    stop = asyncio.Event()

    async def _recv_loop():
        try:
            while not stop.is_set():
                chunk = await receive_bytes()
                if not chunk:
                    continue
                reader.feed_data(bytes(chunk))
        except (ConnectionError, asyncio.IncompleteReadError, asyncio.TimeoutError, OSError):
            pass
        finally:
            reader.feed_ws_eof()

    recv_task = asyncio.create_task(_recv_loop())
    _LOG.info("proxy ws dispatch " + str(protocol) + " from " + str(client_ip))
    try:
        if protocol == "socks5":
            await _handle_socks5(reader, writer, transport="ws")
        elif protocol == "http-proxy":
            await _handle_http_proxy(reader, writer)
        else:
            _LOG.info("proxy ws dispatch unknown protocol " + str(protocol) + " from " + str(client_ip))
            return
    finally:
        _LOG.info("proxy ws session end " + str(protocol) + " from " + str(client_ip))
        stop.set()
        recv_task.cancel()
        await asyncio.gather(recv_task, return_exceptions=True)
        await writer.drain_and_close()


async def _socks_send(writer, data):
    try:
        writer.write(data)
        await writer.drain()
        return True
    except (ConnectionError, asyncio.TimeoutError, OSError, RuntimeError):
        return False


def _socks_failure_reply(rep):
    return b"\x05" + bytes([rep]) + b"\x00\x01\x00\x00\x00\x00\x00\x00"


async def _socks5_read_address(reader, atyp):
    if atyp == 0x01:
        addr_bytes = await _read_exact(reader, 4)
        host = socket.inet_ntoa(addr_bytes)
        ips = [host]
    elif atyp == 0x03:
        dlen = (await _read_exact(reader, 1))[0]
        if dlen == 0:
            return None, None, None, 0x04
        host = (await _read_exact(reader, dlen)).decode("utf-8", "ignore")
        loop = asyncio.get_running_loop()
        try:
            infos = await asyncio.wait_for(loop.getaddrinfo(host, None, proto=socket.IPPROTO_TCP), timeout=10.0)
        except Exception:
            return None, None, None, 0x04
        ips = list({info[4][0] for info in infos})
    elif atyp == 0x04:
        addr_bytes = await _read_exact(reader, 16)
        host = socket.inet_ntop(socket.AF_INET6, addr_bytes)
        ips = [host]
    else:
        return None, None, None, 0x08
    port = struct.unpack(">H", await _read_exact(reader, 2))[0]
    return host, port, ips, None


def _socks5_udp_parse(data):
    if len(data) < 4:
        return None
    if data[2] != 0:
        return None
    atyp = data[3]
    pos = 4
    if atyp == 0x01:
        if len(data) < pos + 4 + 2:
            return None
        host = socket.inet_ntoa(data[pos:pos + 4])
        pos += 4
    elif atyp == 0x03:
        if len(data) < pos + 1:
            return None
        dlen = data[pos]
        pos += 1
        if dlen == 0 or len(data) < pos + dlen + 2:
            return None
        host = data[pos:pos + dlen].decode("utf-8", "ignore")
        pos += dlen
    elif atyp == 0x04:
        if len(data) < pos + 16 + 2:
            return None
        host = socket.inet_ntop(socket.AF_INET6, data[pos:pos + 16])
        pos += 16
    else:
        return None
    if pos + 2 > len(data):
        return None
    port = struct.unpack(">H", data[pos:pos + 2])[0]
    return atyp, host, port, data[pos + 2:]


def _socks5_udp_reply_header(src_ip, src_port):
    try:
        if ":" in src_ip:
            return b"\x00\x00\x00\x04" + socket.inet_pton(socket.AF_INET6, src_ip) + struct.pack(">H", int(src_port))
        return b"\x00\x00\x00\x01" + socket.inet_aton(src_ip) + struct.pack(">H", int(src_port))
    except (OSError, ValueError):
        return None


async def _handle_socks5_udp_associate(reader, writer, username, link, transport="raw"):
    uid = link.get("uid", "")
    total_bytes = 0
    up_flushed = 0
    down_flushed = 0
    sid = None
    entry = None
    udp_sock = None
    if transport == "ws":
        _LOG.info("socks5 udp associate unsupported on websocket transport user " + username + " from " + _mux_peer_text(writer))
        await _socks_send(writer, _socks_failure_reply(0x07))
        return
    try:
        if _COUNT_TRAFFIC is not None:
            if not await _COUNT_TRAFFIC(uid, 0):
                await _socks_send(writer, _socks_failure_reply(0x02))
                return
        local = writer.get_extra_info("sockname")
        local_ip = ""
        if local:
            local_ip = str(local[0])
        try:
            local_addr = ipaddress.ip_address(local_ip)
        except ValueError:
            local_addr = ipaddress.ip_address("0.0.0.0")
        if local_addr.version == 6:
            udp_sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            udp_sock.bind(("::", 0))
        else:
            udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp_sock.bind(("0.0.0.0", 0))
        udp_sock.setblocking(False)
        udp_port = udp_sock.getsockname()[1]
        try:
            if local_addr.version == 6:
                reply = b"\x05\x00\x00\x04" + socket.inet_pton(socket.AF_INET6, str(local_addr)) + struct.pack(">H", udp_port)
            else:
                reply = b"\x05\x00\x00\x01" + socket.inet_aton(str(local_addr)) + struct.pack(">H", udp_port)
        except (OSError, ValueError):
            reply = b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        if not await _socks_send(writer, reply):
            return
        peer = writer.get_extra_info("peername")
        peer_ip = ""
        if peer:
            peer_ip = str(peer[0])
        try:
            peer_addr = ipaddress.ip_address(peer_ip)
        except ValueError:
            peer_addr = None
        sid = "socks5-udp-" + os.urandom(6).hex()
        entry = {"id": sid, "username": username, "protocol": "socks5", "client_ip": peer_ip, "started_at": datetime.now(timezone.utc).isoformat(), "bytes_up": 0, "bytes_down": 0, "bytes_flushed": 0, "writer": writer}
        ACTIVE_PROXY[sid] = entry
        loop = asyncio.get_running_loop()
        routes = {}
        dns_cache = {}
        last_activity = time.monotonic()

        async def _count(n, direction):
            nonlocal total_bytes, up_flushed, down_flushed
            total_bytes += n
            _STATS["socks_bytes"] += n
            pending = 0
            if direction == "up":
                entry["bytes_up"] += n
                pending = entry["bytes_up"] - up_flushed
            else:
                entry["bytes_down"] += n
                pending = entry["bytes_down"] - down_flushed
            if _COUNT_TRAFFIC is not None and pending >= 1048576:
                if await _COUNT_TRAFFIC(uid, pending):
                    if direction == "up":
                        up_flushed += pending
                    else:
                        down_flushed += pending
                    entry["bytes_flushed"] = up_flushed + down_flushed
                    return True
                return False
            return True

        async def _udp_recv():
            return await loop.sock_recvfrom(udp_sock, 65535)

        async def _control_read():
            return await reader.read(1)

        udp_task = asyncio.create_task(_udp_recv())
        control_task = asyncio.create_task(_control_read())
        try:
            while True:
                remaining = 300.0 - (time.monotonic() - last_activity)
                if remaining <= 0:
                    break
                done, pending = await asyncio.wait((udp_task, control_task), timeout=remaining, return_when=asyncio.FIRST_COMPLETED)
                if not done:
                    break
                if udp_task in done:
                    try:
                        data, src = udp_task.result()
                    except (ConnectionError, OSError):
                        data = None
                        src = None
                    udp_task = asyncio.create_task(_udp_recv())
                    if data is None:
                        await asyncio.sleep(0.01)
                        continue
                    last_activity = time.monotonic()
                    src_key = (str(src[0]), int(src[1]))
                    if src_key in routes:
                        client_src = routes[src_key]
                        header = _socks5_udp_reply_header(str(src[0]), int(src[1]))
                        if header is None:
                            continue
                        try:
                            await loop.sock_sendto(udp_sock, header + data, client_src)
                        except OSError:
                            continue
                        if not await _count(len(data), "down"):
                            return
                        continue
                    if peer_addr is not None:
                        try:
                            src_ip = ipaddress.ip_address(str(src[0]))
                        except ValueError:
                            continue
                        if src_ip != peer_addr:
                            continue
                    parsed = _socks5_udp_parse(data)
                    if parsed is None:
                        continue
                    atyp, target_host, target_port, payload = parsed
                    if atyp == 0x03:
                        cached = dns_cache.get(target_host)
                        if cached is None:
                            try:
                                infos = await asyncio.wait_for(loop.getaddrinfo(target_host, None, proto=socket.IPPROTO_UDP), timeout=10.0)
                            except Exception:
                                continue
                            cached = list({info[4][0] for info in infos})
                            dns_cache[target_host] = cached
                        target_ips = _ordered_targets(cached)
                    else:
                        target_ips = [target_host]
                    if not target_ips:
                        continue
                    used_ip = None
                    for target_ip in target_ips:
                        try:
                            await loop.sock_sendto(udp_sock, payload, (target_ip, target_port))
                            used_ip = target_ip
                            break
                        except OSError:
                            if atyp == 0x03:
                                dns_cache.pop(target_host, None)
                            continue
                    if used_ip is None:
                        continue
                    if not await _count(len(payload), "up"):
                        return
                    routes[(used_ip, target_port)] = src
                if control_task in done:
                    try:
                        chunk = control_task.result()
                    except (ConnectionError, OSError):
                        chunk = b""
                    control_task = asyncio.create_task(_control_read())
                    if not chunk:
                        break
                    last_activity = time.monotonic()
        finally:
            for task in (udp_task, control_task):
                try:
                    task.cancel()
                except (OSError, RuntimeError):
                    pass
            await asyncio.gather(udp_task, control_task, return_exceptions=True)
    except (ConnectionError, asyncio.IncompleteReadError, asyncio.TimeoutError, OSError):
        pass
    finally:
        if link is not None and _COUNT_TRAFFIC is not None and total_bytes - (up_flushed + down_flushed) > 0:
            try:
                await _COUNT_TRAFFIC(link.get("uid", ""), total_bytes - (up_flushed + down_flushed))
            except (ConnectionError, asyncio.TimeoutError, OSError):
                pass
        if sid is not None:
            ACTIVE_PROXY.pop(sid, None)
        if udp_sock is not None:
            try:
                udp_sock.close()
            except OSError:
                pass


async def _handle_socks5(reader, writer, transport="raw"):
    _STATS["socks_connections"] += 1
    peer_text = _mux_peer_text(writer)
    username = ""
    link = None
    total_bytes = 0
    up_flushed = 0
    down_flushed = 0
    sid = None
    entry = None
    target_writer = None
    try:
        try:
            greeting = await _read_exact(reader, 2)
        except (asyncio.IncompleteReadError, asyncio.TimeoutError, ConnectionError, OSError):
            _LOG.info("socks5 greeting rejected from " + peer_text)
            await _socks_send(writer, b"\x05\xff")
            return
        if greeting[0] != 0x05:
            _LOG.info("socks5 greeting rejected bad version byte " + format(greeting[0], "02x") + " from " + peer_text)
            await _socks_send(writer, b"\x05\xff")
            return
        nmethods = greeting[1]
        try:
            methods = await _read_exact(reader, nmethods)
        except (asyncio.IncompleteReadError, asyncio.TimeoutError, ConnectionError, OSError):
            _LOG.info("socks5 greeting rejected from " + peer_text)
            await _socks_send(writer, b"\x05\xff")
            return
        if 0x02 in methods:
            if not await _socks_send(writer, b"\x05\x02"):
                return
        else:
            _LOG.info("socks5 greeting rejected no userpass method methods " + bytes(methods).hex() + " from " + peer_text)
            await _socks_send(writer, b"\x05\xff")
            return
        try:
            auth_head = await _read_exact(reader, 2)
            if auth_head[0] != 0x01:
                await _socks_send(writer, b"\x01\x01")
                return
            ulen = auth_head[1]
            username = (await _read_exact(reader, ulen)).decode("utf-8", "ignore")
            plen = (await _read_exact(reader, 1))[0]
            password = (await _read_exact(reader, plen)).decode("utf-8", "ignore")
        except (asyncio.IncompleteReadError, asyncio.TimeoutError, ConnectionError, OSError):
            await _socks_send(writer, b"\x01\x01")
            return
        if _AUTH_LOOKUP is not None:
            link = _AUTH_LOOKUP(username, password)
        if link is None:
            _LOG.info("socks5 auth failed user " + username + " from " + peer_text)
            await _socks_send(writer, b"\x01\x01")
            return
        if _SESSION_ALLOWED is not None:
            peer = writer.get_extra_info("peername")
            cip = peer[0] if peer else ""
            if not _SESSION_ALLOWED(username, cip):
                _LOG.info("socks5 session denied user " + username + " from " + peer_text)
                await _socks_send(writer, b"\x01\x01")
                return
        if not await _socks_send(writer, b"\x01\x00"):
            return
        try:
            req = await _read_exact(reader, 4)
        except (asyncio.IncompleteReadError, asyncio.TimeoutError, ConnectionError, OSError):
            await _socks_send(writer, _socks_failure_reply(0x01))
            return
        if req[0] != 0x05:
            await _socks_send(writer, _socks_failure_reply(0x01))
            return
        cmd = req[1]
        atyp = req[3]
        if cmd not in (0x01, 0x03):
            await _socks_send(writer, _socks_failure_reply(0x07))
            return
        try:
            host, port, ips, addr_err = await _socks5_read_address(reader, atyp)
        except (asyncio.IncompleteReadError, asyncio.TimeoutError, ConnectionError, OSError):
            await _socks_send(writer, _socks_failure_reply(0x01))
            return
        if addr_err is not None:
            await _socks_send(writer, _socks_failure_reply(addr_err))
            return
        if cmd == 0x03:
            await _handle_socks5_udp_associate(reader, writer, username, link, transport)
            return
        targets = _ordered_targets(ips)
        if not targets:
            await _socks_send(writer, _socks_failure_reply(0x04))
            return
        uid = link.get("uid", "")
        if _COUNT_TRAFFIC is not None:
            if not await _COUNT_TRAFFIC(uid, 0):
                await _socks_send(writer, _socks_failure_reply(0x02))
                return
        target_reader, target_writer, rep = await _connect_target(targets, port)
        if target_writer is None:
            _LOG.info("socks5 connect failed user " + username + " to " + str(host) + ":" + str(port) + " rep " + str(rep) + " from " + peer_text)
            await _socks_send(writer, _socks_failure_reply(rep))
            return
        bound = target_writer.get_extra_info("sockname")
        try:
            if bound and ":" in str(bound[0]):
                reply = b"\x05\x00\x00\x04" + socket.inet_pton(socket.AF_INET6, bound[0]) + struct.pack(">H", bound[1])
            elif bound:
                reply = b"\x05\x00\x00\x01" + socket.inet_aton(bound[0]) + struct.pack(">H", bound[1])
            else:
                reply = b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        except (OSError, ValueError):
            reply = b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        if not await _socks_send(writer, reply):
            return
        _LOG.info("socks5 connect user " + username + " to " + str(host) + ":" + str(port) + " transport " + str(transport) + " from " + peer_text)
        peer = writer.get_extra_info("peername")
        sid = "socks5-" + os.urandom(6).hex()
        entry = {"id": sid, "username": username, "protocol": "socks5", "client_ip": peer[0] if peer else "", "started_at": datetime.now(timezone.utc).isoformat(), "bytes_up": 0, "bytes_down": 0, "bytes_flushed": 0, "writer": writer}
        ACTIVE_PROXY[sid] = entry

        async def _count(n, direction):
            nonlocal total_bytes, up_flushed, down_flushed
            total_bytes += n
            _STATS["socks_bytes"] += n
            pending = 0
            if entry is not None:
                if direction == "up":
                    entry["bytes_up"] += n
                    pending = entry["bytes_up"] - up_flushed
                else:
                    entry["bytes_down"] += n
                    pending = entry["bytes_down"] - down_flushed
            if _COUNT_TRAFFIC is not None and pending >= 1048576:
                if await _COUNT_TRAFFIC(uid, pending):
                    if direction == "up":
                        up_flushed += pending
                    else:
                        down_flushed += pending
                    if entry is not None:
                        entry["bytes_flushed"] = up_flushed + down_flushed
                else:
                    try:
                        writer.close()
                    except OSError:
                        pass
                    try:
                        target_writer.close()
                    except OSError:
                        pass

        async def _relay(src, dst, direction):
            outcome = "eof"
            try:
                while True:
                    chunk = await src.read(65536)
                    if not chunk:
                        break
                    dst.write(chunk)
                    await dst.drain()
                    await _count(len(chunk), direction)
            except (ConnectionError, asyncio.IncompleteReadError, asyncio.TimeoutError, OSError):
                outcome = "error"
            finally:
                try:
                    dst.write_eof()
                except (AttributeError, OSError, RuntimeError):
                    try:
                        dst.close()
                    except OSError:
                        pass
            return outcome

        up_task = asyncio.create_task(_relay(reader, target_writer, "up"))
        down_task = asyncio.create_task(_relay(target_reader, writer, "down"))
        done, pending = await asyncio.wait((up_task, down_task), return_when=asyncio.FIRST_COMPLETED)
        errored = False
        for task in done:
            try:
                if task.result() == "error":
                    errored = True
            except (asyncio.CancelledError, Exception):
                errored = True
        if errored:
            for task in pending:
                task.cancel()
        await asyncio.gather(up_task, down_task, return_exceptions=True)
        try:
            target_writer.close()
        except OSError:
            pass
    except (ConnectionError, asyncio.IncompleteReadError, asyncio.TimeoutError, OSError):
        pass
    finally:
        if entry is not None:
            _LOG.info("socks5 session end user " + username + " up " + str(entry.get("bytes_up", 0)) + " down " + str(entry.get("bytes_down", 0)) + " from " + peer_text)
        if link is not None and _COUNT_TRAFFIC is not None and total_bytes - (up_flushed + down_flushed) > 0:
            try:
                await _COUNT_TRAFFIC(link.get("uid", ""), total_bytes - (up_flushed + down_flushed))
            except (ConnectionError, asyncio.TimeoutError, OSError):
                pass
        if sid is not None:
            ACTIVE_PROXY.pop(sid, None)
        if target_writer is not None:
            try:
                target_writer.close()
            except OSError:
                pass
        try:
            writer.close()
        except OSError:
            pass


async def _http_check_proxy_access(writer, headers):
    peer_text = _mux_peer_text(writer)
    creds = _parse_proxy_auth(headers)
    if creds is None:
        _LOG.info("http proxy connect no credentials from " + peer_text)
        return None, "", (407, "Proxy Authentication Required", (b"Proxy-Authenticate: Basic realm=\"SulgX\"",))
    username, password = creds
    link = None
    if _AUTH_LOOKUP is not None:
        link = _AUTH_LOOKUP(username, password)
    if link is None:
        _LOG.info("http proxy connect wrong credentials user " + str(username) + " from " + peer_text)
        return None, "", (407, "Proxy Authentication Required", (b"Proxy-Authenticate: Basic realm=\"SulgX\"",))
    if _SESSION_ALLOWED is not None:
        peer = writer.get_extra_info("peername")
        cip = peer[0] if peer else ""
        if not _SESSION_ALLOWED(username, cip):
            return None, "", (403, "Forbidden", None)
    uid = link.get("uid", "")
    if _COUNT_TRAFFIC is not None and not await _COUNT_TRAFFIC(uid, 0):
        return None, "", (403, "Forbidden", None)
    return link, username, None


def _http_register_session(writer, username):
    peer = writer.get_extra_info("peername")
    sid = "http-" + os.urandom(6).hex()
    entry = {"id": sid, "username": username, "protocol": "http-proxy", "client_ip": peer[0] if peer else "", "started_at": datetime.now(timezone.utc).isoformat(), "bytes_up": 0, "bytes_down": 0, "bytes_flushed": 0, "writer": writer}
    ACTIVE_PROXY[sid] = entry
    return sid, entry


async def _http_forward_exact(src, dst, count, direction, n):
    remaining = n
    while remaining > 0:
        try:
            chunk = await asyncio.wait_for(src.read(min(65536, remaining)), timeout=30.0)
        except (asyncio.TimeoutError, ConnectionError, OSError):
            return False
        if not chunk:
            return False
        try:
            dst.write(chunk)
            await dst.drain()
        except (ConnectionError, OSError):
            return False
        await count(len(chunk), direction)
        remaining -= len(chunk)
    return True


async def _http_forward_chunked(src, dst, count, direction):
    trailer_total = 0
    while True:
        try:
            line = await asyncio.wait_for(src.readuntil(b"\r\n"), timeout=30.0)
        except (asyncio.TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError, ConnectionError, OSError):
            return False
        size_text = bytes(line).split(b";", 1)[0].strip()
        try:
            size = int(size_text, 16)
        except ValueError:
            return False
        if size < 0:
            return False
        try:
            dst.write(line)
            await dst.drain()
        except (ConnectionError, OSError):
            return False
        await count(len(line), direction)
        if size == 0:
            while True:
                try:
                    trailer = await asyncio.wait_for(src.readuntil(b"\r\n"), timeout=30.0)
                except (asyncio.TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError, ConnectionError, OSError):
                    return False
                trailer_total += len(trailer)
                if trailer_total > 65536:
                    return False
                try:
                    dst.write(trailer)
                    await dst.drain()
                except (ConnectionError, OSError):
                    return False
                await count(len(trailer), direction)
                if trailer == b"\r\n":
                    return True
        if not await _http_forward_exact(src, dst, count, direction, size):
            return False
        try:
            ending = await asyncio.wait_for(src.readexactly(2), timeout=30.0)
        except (asyncio.TimeoutError, asyncio.IncompleteReadError, ConnectionError, OSError):
            return False
        if ending != b"\r\n":
            return False
        try:
            dst.write(ending)
            await dst.drain()
        except (ConnectionError, OSError):
            return False
        await count(2, direction)


async def _http_forward_until_eof(src, dst, count, direction, deadline):
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        try:
            chunk = await asyncio.wait_for(src.read(65536), timeout=min(30.0, remaining))
        except (asyncio.TimeoutError, ConnectionError, OSError):
            return False
        if not chunk:
            return True
        try:
            dst.write(chunk)
            await dst.drain()
        except (ConnectionError, OSError):
            return False
        await count(len(chunk), direction)


async def _http_serve_connect(reader, writer, target, headers):
    parsed = _parse_connect_authority(target)
    if parsed is None:
        await _http_send_error(writer, 400, "Bad Request")
        return
    host, port = parsed
    link, username, error = await _http_check_proxy_access(writer, headers)
    if error is not None:
        await _http_send_error(writer, error[0], error[1], error[2])
        return
    target_reader, target_writer, reason = await _http_resolve_and_connect(host, port)
    if target_reader is None:
        status, phrase = _http_connect_failure_status(reason)
        _LOG.info("http proxy connect failed user " + str(username) + " to " + str(host) + ":" + str(port) + " " + str(reason) + " from " + _mux_peer_text(writer))
        await _http_send_error(writer, status, phrase)
        return
    uid = link.get("uid", "")
    total_bytes = 0
    up_flushed = 0
    down_flushed = 0
    sid = None
    entry = None
    try:
        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await writer.drain()
        _LOG.info("http proxy connect user " + str(username) + " to " + str(host) + ":" + str(port) + " from " + _mux_peer_text(writer))
        sid, entry = _http_register_session(writer, username)

        async def _count(n, direction):
            nonlocal total_bytes, up_flushed, down_flushed
            total_bytes += n
            _STATS["http_bytes"] += n
            pending = 0
            if entry is not None:
                if direction == "up":
                    entry["bytes_up"] += n
                    pending = entry["bytes_up"] - up_flushed
                else:
                    entry["bytes_down"] += n
                    pending = entry["bytes_down"] - down_flushed
            if _COUNT_TRAFFIC is not None and pending >= 1048576:
                if await _COUNT_TRAFFIC(uid, pending):
                    if direction == "up":
                        up_flushed += pending
                    else:
                        down_flushed += pending
                    if entry is not None:
                        entry["bytes_flushed"] = up_flushed + down_flushed
                else:
                    try:
                        writer.close()
                    except OSError:
                        pass
                    try:
                        target_writer.close()
                    except OSError:
                        pass

        async def _relay(src, dst, direction):
            outcome = "eof"
            try:
                while True:
                    chunk = await src.read(65536)
                    if not chunk:
                        break
                    dst.write(chunk)
                    await dst.drain()
                    await _count(len(chunk), direction)
            except (ConnectionError, asyncio.IncompleteReadError, asyncio.TimeoutError, OSError):
                outcome = "error"
            finally:
                try:
                    dst.write_eof()
                except (AttributeError, OSError, RuntimeError):
                    try:
                        dst.close()
                    except OSError:
                        pass
            return outcome

        up_task = asyncio.create_task(_relay(reader, target_writer, "up"))
        down_task = asyncio.create_task(_relay(target_reader, writer, "down"))
        done, pending = await asyncio.wait((up_task, down_task), return_when=asyncio.FIRST_COMPLETED)
        errored = False
        for task in done:
            try:
                if task.result() == "error":
                    errored = True
            except (asyncio.CancelledError, Exception):
                errored = True
        if errored:
            for task in pending:
                task.cancel()
        await asyncio.gather(up_task, down_task, return_exceptions=True)
    except (ConnectionError, asyncio.IncompleteReadError, asyncio.TimeoutError, OSError):
        pass
    finally:
        if link is not None and _COUNT_TRAFFIC is not None and total_bytes - (up_flushed + down_flushed) > 0:
            try:
                await _COUNT_TRAFFIC(link.get("uid", ""), total_bytes - (up_flushed + down_flushed))
            except (ConnectionError, asyncio.TimeoutError, OSError):
                pass
        if sid is not None:
            ACTIVE_PROXY.pop(sid, None)
        try:
            target_writer.close()
        except OSError:
            pass


async def _http_serve_absolute(reader, writer, method, target, version, headers):
    parsed = _parse_absolute_uri(target)
    if parsed is None or parsed == "https":
        await _http_send_error(writer, 400, "Bad Request")
        return
    host, port, authority, path = parsed
    link, username, error = await _http_check_proxy_access(writer, headers)
    if error is not None:
        await _http_send_error(writer, error[0], error[1], error[2])
        return
    expect = _http_headers_get(headers, b"expect")
    if expect is not None and expect.strip().lower() != b"100-continue":
        await _http_send_error(writer, 417, "Expectation Failed")
        return
    te_raw = _http_headers_get(headers, b"transfer-encoding")
    cl_raw = _http_headers_get(headers, b"content-length")
    te_chunked = False
    if te_raw is not None:
        codings = [item.strip().lower() for item in bytes(te_raw).split(b",")]
        if not codings or codings[-1] != b"chunked" or any(item == b"" for item in codings):
            await _http_send_error(writer, 501, "Not Implemented")
            return
        te_chunked = True
    content_length = None
    if cl_raw is not None and not te_chunked:
        seen_lengths = set()
        for entry_name, _orig, value in headers:
            if entry_name == b"content-length":
                seen_lengths.add(bytes(value).strip())
        if len(seen_lengths) != 1:
            await _http_send_error(writer, 400, "Bad Request")
            return
        only_length = next(iter(seen_lengths))
        if not only_length.isdigit():
            await _http_send_error(writer, 400, "Bad Request")
            return
        content_length = int(only_length)
    target_reader, target_writer, reason = await _http_resolve_and_connect(host, port)
    if target_reader is None:
        status, phrase = _http_connect_failure_status(reason)
        _LOG.info("http proxy absolute failed user " + str(username) + " to " + str(host) + ":" + str(port) + " " + str(reason) + " from " + _mux_peer_text(writer))
        await _http_send_error(writer, status, phrase)
        return
    uid = link.get("uid", "")
    total_bytes = 0
    up_flushed = 0
    down_flushed = 0
    sid = None
    entry = None
    try:
        sid, entry = _http_register_session(writer, username)
        _LOG.info("http proxy absolute user " + str(username) + " to " + str(host) + ":" + str(port) + " " + str(method) + " from " + _mux_peer_text(writer))

        async def _count(n, direction):
            nonlocal total_bytes, up_flushed, down_flushed
            total_bytes += n
            _STATS["http_bytes"] += n
            pending = 0
            if entry is not None:
                if direction == "up":
                    entry["bytes_up"] += n
                    pending = entry["bytes_up"] - up_flushed
                else:
                    entry["bytes_down"] += n
                    pending = entry["bytes_down"] - down_flushed
            if _COUNT_TRAFFIC is not None and pending >= 1048576:
                if await _COUNT_TRAFFIC(uid, pending):
                    if direction == "up":
                        up_flushed += pending
                    else:
                        down_flushed += pending
                    if entry is not None:
                        entry["bytes_flushed"] = up_flushed + down_flushed
                else:
                    try:
                        writer.close()
                    except OSError:
                        pass
                    try:
                        target_writer.close()
                    except OSError:
                        pass

        if expect is not None:
            writer.write(b"HTTP/1.1 100 Continue\r\n\r\n")
            await writer.drain()
        conn_tokens = _http_connection_tokens(headers)
        request_version = version if version is not None else b"HTTP/1.1"
        out_lines = [method.encode("ascii") + b" " + bytes(path) + b" " + bytes(request_version)]
        for entry_name, _orig_name, value in headers:
            if entry_name == b"transfer-encoding" and te_chunked:
                out_lines.append(entry_name + b": " + bytes(value))
                continue
            if entry_name in _HTTP_HOP_BY_HOP or entry_name in conn_tokens:
                continue
            if entry_name == b"host":
                continue
            if entry_name == b"expect":
                continue
            if entry_name == b"content-length" and te_chunked:
                continue
            out_lines.append(entry_name + b": " + bytes(value))
        out_lines.append(b"Host: " + bytes(authority))
        out_lines.append(b"Connection: close")
        request_head = b"\r\n".join(out_lines) + b"\r\n\r\n"
        try:
            target_writer.write(request_head)
            await target_writer.drain()
        except (ConnectionError, OSError):
            await _http_send_error(writer, 502, "Bad Gateway")
            return
        await _count(len(request_head), "up")
        if te_chunked:
            if not await _http_forward_chunked(reader, target_writer, _count, "up"):
                await _http_send_error(writer, 400, "Bad Request")
                return
        elif content_length is not None:
            if not await _http_forward_exact(reader, target_writer, _count, "up", content_length):
                await _http_send_error(writer, 400, "Bad Request")
                return
        try:
            resp_head = await asyncio.wait_for(target_reader.readuntil(b"\r\n\r\n"), timeout=30.0)
        except asyncio.TimeoutError:
            await _http_send_error(writer, 504, "Gateway Timeout")
            return
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, ConnectionError, OSError):
            await _http_send_error(writer, 502, "Bad Gateway")
            return
        resp_parsed = _parse_http_response_head(resp_head)
        if resp_parsed is None:
            await _http_send_error(writer, 502, "Bad Gateway")
            return
        resp_version, resp_code, resp_reason, resp_headers = resp_parsed
        resp_conn_tokens = _http_connection_tokens(resp_headers)
        resp_te = _http_headers_get(resp_headers, b"transfer-encoding")
        resp_cl_values = set()
        for entry_name, _orig, value in resp_headers:
            if entry_name == b"content-length":
                resp_cl_values.add(bytes(value).strip())
        no_body = method.upper() == "HEAD" or resp_code in (204, 304) or 100 <= resp_code < 200
        body_mode = "close"
        body_length = 0
        if not no_body:
            if resp_te is not None:
                resp_codings = [item.strip().lower() for item in bytes(resp_te).split(b",")]
                if resp_codings and resp_codings[-1] == b"chunked":
                    body_mode = "chunked"
                else:
                    body_mode = "close"
            elif resp_cl_values:
                if len(resp_cl_values) != 1 or not next(iter(resp_cl_values)).isdigit():
                    await _http_send_error(writer, 502, "Bad Gateway")
                    return
                body_mode = "length"
                body_length = int(next(iter(resp_cl_values)))
        status_line = bytes(resp_version) + b" " + str(resp_code).encode("ascii")
        if resp_reason:
            status_line += b" " + bytes(resp_reason)
        resp_lines = [status_line]
        for entry_name, _orig_name, value in resp_headers:
            if entry_name == b"transfer-encoding" and resp_te is not None:
                resp_lines.append(entry_name + b": " + bytes(value))
                continue
            if entry_name in _HTTP_HOP_BY_HOP or entry_name in resp_conn_tokens:
                continue
            if entry_name == b"content-length" and body_mode == "chunked":
                continue
            resp_lines.append(entry_name + b": " + bytes(value))
        resp_lines.append(b"Connection: close")
        response_head = b"\r\n".join(resp_lines) + b"\r\n\r\n"
        try:
            writer.write(response_head)
            await writer.drain()
        except (ConnectionError, OSError):
            return
        await _count(len(response_head), "down")
        if no_body:
            return
        if body_mode == "chunked":
            await _http_forward_chunked(target_reader, writer, _count, "down")
        elif body_mode == "length":
            await _http_forward_exact(target_reader, writer, _count, "down", body_length)
        else:
            await _http_forward_until_eof(target_reader, writer, _count, "down", time.monotonic() + 120.0)
    except (ConnectionError, asyncio.IncompleteReadError, asyncio.TimeoutError, OSError):
        pass
    finally:
        if link is not None and _COUNT_TRAFFIC is not None and total_bytes - (up_flushed + down_flushed) > 0:
            try:
                await _COUNT_TRAFFIC(link.get("uid", ""), total_bytes - (up_flushed + down_flushed))
            except (ConnectionError, asyncio.TimeoutError, OSError):
                pass
        if sid is not None:
            _LOG.info("http proxy absolute end user " + str(username) + " bytes=" + str(total_bytes) + " from " + _mux_peer_text(writer))
            ACTIVE_PROXY.pop(sid, None)
        try:
            target_writer.close()
        except OSError:
            pass


async def _read_http_head(reader):
    buf = b""
    deadline = time.monotonic() + 10.0
    while True:
        for sep in (b"\r\n\r\n", b"\n\n"):
            at = buf.find(sep)
            if at >= 0:
                head = buf[:at + len(sep)]
                rest = buf[at + len(sep):]
                if b"\r\n" not in head:
                    head = head.replace(b"\n", b"\r\n")
                return head, rest
        if len(buf) > 65536:
            raise asyncio.LimitOverrunError("http head over 64KiB", b"")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise asyncio.TimeoutError()
        chunk = await asyncio.wait_for(reader.read(65536), timeout=remaining)
        if not chunk:
            raise asyncio.IncompleteReadError(buf, None)
        buf += bytes(chunk)


async def _handle_http_proxy(reader, writer):
    _STATS["http_connections"] += 1
    peer_text = _mux_peer_text(writer)
    try:
        try:
            head, rest = await _read_http_head(reader)
            if rest:
                reader = _PrefixedReader(reader, rest)
        except asyncio.TimeoutError:
            _LOG.info("http proxy head timeout from " + peer_text)
            await _http_send_error(writer, 408, "Request Timeout")
            return
        except asyncio.LimitOverrunError:
            _LOG.info("http proxy head too large from " + peer_text)
            await _http_send_error(writer, 431, "Request Header Fields Too Large")
            return
        except (asyncio.IncompleteReadError, ConnectionError, OSError):
            return
        parsed = _parse_http_request_head(head)
        if parsed is None:
            await _http_send_error(writer, 400, "Bad Request")
            return
        method, target, version, headers = parsed
        if method.upper() == "CONNECT":
            await _http_serve_connect(reader, writer, target, headers)
            return
        lowered = bytes(target).lower()
        if lowered.startswith(b"http://") or lowered.startswith(b"https://"):
            await _http_serve_absolute(reader, writer, method, target, version, headers)
            return
        if method.upper().encode("ascii") in _HTTP_KNOWN_TOKENS:
            await _handle_panel_forward(_PrefixedReader(reader, head), writer)
            return
        await _http_send_error(writer, 501, "Not Implemented")
        return
    except (ConnectionError, asyncio.IncompleteReadError, asyncio.TimeoutError, OSError):
        pass
    finally:
        try:
            writer.close()
        except OSError:
            pass

def _telemt_binary():
    env_bin = (os.environ.get("TELEMT_BIN") or "").strip()
    if env_bin:
        return env_bin
    found = shutil.which("telemt")
    if found:
        return found
    return _TELEMT_DEFAULT_BIN


def telemt_available():
    path = _telemt_binary()
    return os.path.isfile(path) and os.access(path, os.X_OK)


def _telemt_dir():
    global _TELEMT_DIR_CACHED
    if _TELEMT_DIR_CACHED:
        return _TELEMT_DIR_CACHED
    wanted = (os.environ.get("TELEMT_DIR") or "").strip() or _TELEMT_DEFAULT_DIR
    try:
        os.makedirs(wanted, exist_ok=True)
        probe = os.path.join(wanted, ".write-test")
        with open(probe, "w", encoding="utf-8") as handle:
            handle.write("ok")
        os.unlink(probe)
        _TELEMT_DIR_CACHED = wanted
        return wanted
    except OSError:
        fallback = tempfile.mkdtemp(prefix="sulgx-telemt-")
        _TELEMT_DIR_CACHED = fallback
        return fallback


def _telemt_lock(name):
    lock = _TELEMT_LOCKS.get(name)
    if lock is None:
        lock = asyncio.Lock()
        _TELEMT_LOCKS[name] = lock
    return lock


def _free_loopback_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _stable_loopback_port(env_names, default_port):
    if isinstance(env_names, str):
        env_names = (env_names,)
    wanted = 0
    for env_name in env_names:
        try:
            wanted = int(os.environ.get(env_name, "") or 0)
        except (TypeError, ValueError):
            wanted = 0
        if wanted:
            break
    if not wanted:
        wanted = int(default_port)
    if wanted <= 0 or wanted > 65535:
        wanted = int(default_port)
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        probe.bind(("127.0.0.1", wanted))
    except OSError:
        _LOG.warning("telemt fixed loopback port " + str(wanted) + " is busy, using an ephemeral port")
        return _free_loopback_port()
    finally:
        try:
            probe.close()
        except OSError:
            pass
    return wanted


def _random_bearer():
    return secrets.token_hex(24)


def _toml_escape(value):
    return str(value).replace("\\", "\\\\").replace('"', '\\"')


def _telemt_username(uid):
    name = str(uid)
    if _TELEMT_USERNAME_RE.match(name):
        return name
    return "u" + hashlib.sha256(name.encode("utf-8")).hexdigest()[:40]


def telemt_web_username(uid):
    return _telemt_username(uid)


def _valid_secret_hex(value):
    return isinstance(value, str) and len(value) == 32 and all(c in _HEXDIGITS for c in value)


def _valid_web_host(host):
    if not isinstance(host, str):
        return False
    text = host.strip().lower()
    if not text or len(text) > 253 or "." not in text:
        return False
    if not _TELEMT_HOST_RE.match(text):
        return False
    for label in text.split("."):
        if not label or label.startswith("-") or label.endswith("-"):
            return False
    try:
        ipaddress.ip_address(text)
        return False
    except ValueError:
        return True


def _ensure_decoy_dir():
    global _TELEMT_DECOY_READY
    base = _telemt_dir()
    decoy_dir = os.path.join(base, "decoy")
    if not _TELEMT_DECOY_READY:
        os.makedirs(decoy_dir, exist_ok=True)
        index_path = os.path.join(decoy_dir, "index.html")
        if not os.path.exists(index_path):
            with open(index_path, "w", encoding="utf-8") as handle:
                handle.write(_TELEMT_DECOY_HTML)
        _TELEMT_DECOY_READY = True
    return decoy_dir


def _write_text(path, text):
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text)


def _telemt_tls_host_ok(value):
    if not isinstance(value, str):
        return False
    text = value.strip().lower()
    if not text or ".." in text:
        return False
    if text.startswith((".", "-")) or text.endswith((".", "-")):
        return False
    for ch in text:
        if ch.isspace() or ch in ("/", "\\"):
            return False
    return True


def sanitize_faketls_domain(raw, default="www.google.com"):
    if not raw:
        return default
    text = str(raw).strip()
    match = re.match(r"^\[([^\]]+)\]\(.*\)$", text)
    if match:
        text = match.group(1).strip()
    text = re.sub(r"^[a-zA-Z]+://", "", text).split("/")[0].split("?")[0].strip()
    if not re.fullmatch(r"[A-Za-z0-9.\-]{1,253}", text) or "." not in text:
        return default
    return text.lower()


def _telemt_tls_set(primary, extras=None):
    domain = sanitize_faketls_domain(primary)
    if not _telemt_tls_host_ok(domain):
        domain = "www.google.com"
    domains = []
    for item in extras or []:
        text = sanitize_faketls_domain(item, default="")
        if not text or text == domain:
            continue
        if not _telemt_tls_host_ok(text):
            continue
        if text not in domains:
            domains.append(text)
    return domain, domains


def _mtproto_config_text(api_port, token, port, bootstrap_secret, users=None, tls_domain="www.google.com", tls_domains=None, public_host=None, public_port=None):
    primary, extra_domains = _telemt_tls_set(tls_domain, tls_domains)
    lines = [
        "[general]",
        "use_middle_proxy = false",
        'log_level = "normal"',
        "",
    ]
    if public_host and public_port:
        lines.extend([
            "[general.links]",
            'public_host = "' + _toml_escape(str(public_host)) + '"',
            "public_port = " + str(int(public_port)),
            "",
        ])
    lines.extend([
        "[general.modes]",
        "classic = true",
        "secure = true",
        "tls = true",
        "",
        "[server.api]",
        "enabled = true",
        'listen = "127.0.0.1:' + str(api_port) + '"',
        'whitelist = ["127.0.0.1/32", "::1/128"]',
        'auth_header = "Bearer ' + token + '"',
        "",
        "[[server.listeners]]",
        'ip = "127.0.0.1"',
        "port = " + str(port),
        'transport = "mtproxy"',
        "",
        "[[server.listeners]]",
        'ip = "::1"',
        "port = " + str(port),
        'transport = "mtproxy"',
        "",
        "[censorship]",
        'tls_domain = "' + _toml_escape(primary) + '"',
    ])
    if extra_domains:
        lines.append('tls_domains = ["' + '", "'.join(_toml_escape(item) for item in extra_domains) + '"]')
    lines.extend([
        "mask = true",
        "tls_emulation = true",
        "",
        "[censorship.tls_fetch]",
        "total_budget_ms = 5000",
        "attempt_timeout_ms = 2000",
        "",
        "[access.users]",
        'bootstrap = "' + bootstrap_secret + '"',
    ])
    entries = []
    if users:
        for username in sorted(users):
            info = users[username] or {}
            secret = str(info.get("secret_hex") or "")
            if not _valid_secret_hex(secret):
                continue
            entries.append((username, info))
            lines.append('"' + _toml_escape(username) + '" = "' + secret.lower() + '"')
    max_conns = [(username, int(info.get("max_conns") or 0)) for username, info in entries if int(info.get("max_conns") or 0) > 0]
    if max_conns:
        lines.append("")
        lines.append("[access.user_max_tcp_conns]")
        for username, value in max_conns:
            lines.append('"' + _toml_escape(username) + '" = ' + str(value))
    quotas = [(username, int(info.get("limit_bytes") or 0)) for username, info in entries if int(info.get("limit_bytes") or 0) > 0]
    if quotas:
        lines.append("")
        lines.append("[access.user_data_quota]")
        for username, value in quotas:
            lines.append('"' + _toml_escape(username) + '" = ' + str(value))
    expirations = []
    for username, info in entries:
        stamp = _rfc3339(info.get("expires_at"))
        if stamp:
            expirations.append((username, stamp))
    if expirations:
        lines.append("")
        lines.append("[access.user_expirations]")
        for username, stamp in expirations:
            lines.append('"' + _toml_escape(username) + '" = "' + stamp + '"')
    return "\n".join(lines) + "\n"


def _web_config_text(fields):
    username = _telemt_username(fields["uid"])
    base_path = "" if fields.get("root_enabled") else fields["web_token"]
    profiles = fields.get("profiles")
    if profiles:
        profile_rows = []
        for item in profiles:
            profile_rows.append({
                "user": _telemt_username(str(item.get("uid") or "")),
                "secret_hex": str(item.get("secret_hex") or "").lower(),
                "max_sessions": int(item.get("max_sessions") or 8),
                "max_streams": int(item.get("max_streams") or 512),
            })
    else:
        profile_rows = [{
            "user": username,
            "secret_hex": str(fields["secret_hex"]).lower(),
            "max_sessions": int(fields["max_sessions"]),
            "max_streams": int(fields["max_streams"]),
        }]
    lines = [
        "[general]",
        "use_middle_proxy = false",
        'log_level = "normal"',
        "",
        "[general.modes]",
        "classic = true",
        "secure = true",
        "tls = false",
        "",
        "[server.api]",
        "enabled = true",
        'listen = "127.0.0.1:' + str(fields["api_port"]) + '"',
        'whitelist = ["127.0.0.1/32", "::1/128"]',
        'auth_header = "Bearer ' + fields["bearer"] + '"',
        "",
        "[[server.listeners]]",
        'ip = "127.0.0.1"',
        "port = " + str(fields["port"]),
        'transport = "web"',
        "proxy_protocol = false",
        "reuse_allow = false",
        'web_client_ip_source = "x_forwarded_for"',
        'web_trusted_proxy_cidrs = ["127.0.0.1/32"]',
        "",
        "[web]",
        "enabled = true",
        'carrier = "https"',
        'carriers = ["websocket-lanes", "websocket", "https-lanes", "https"]',
        "carrier_learning = true",
        'carrier_negotiation_aggressiveness = "aggressive"',
        "",
        "[web.retry_jitter]",
        "enabled = false",
        "",
        "[[web.vhosts]]",
        'host = "' + _toml_escape(fields["host"]) + '"',
        'base_path = "' + _toml_escape(base_path) + '"',
        'public_addr = "' + _toml_escape(_telemt_public_addr(fields["public_ip"])) + '"',
        "",
        "[web.vhosts.decoy]",
        'mode = "static_directory"',
        'directory = "' + _toml_escape(_ensure_decoy_dir()) + '"',
        'index = "index.html"',
        "",
    ]
    for row in profile_rows:
        lines.extend([
            "[[web.vhosts.profiles]]",
            'user = "' + _toml_escape(row["user"]) + '"',
            'secret_mode = "dd"',
            "max_sessions = " + str(row["max_sessions"]),
            "max_streams = " + str(row["max_streams"]),
            "max_streams_per_session = 64",
            "",
        ])
    lines.extend([
        "[censorship]",
        'tls_domain = "www.google.com"',
        "mask = true",
        "",
        "[censorship.tls_fetch]",
        "total_budget_ms = 5000",
        "attempt_timeout_ms = 2000",
        "",
        "[access.users]",
    ])
    for row in profile_rows:
        lines.append('"' + _toml_escape(row["user"]) + '" = "' + row["secret_hex"] + '"')
    return "\n".join(lines) + "\n"


def _web_root_vhost(fields, enabled, profiles=None):
    if profiles:
        profile_rows = [{"user": _telemt_username(str(item.get("uid") or "")), "secret_mode": "dd", "max_sessions": int(item.get("max_sessions") or 8), "max_streams": int(item.get("max_streams") or 512), "max_streams_per_session": 64} for item in profiles]
    else:
        profile_rows = [{"user": _telemt_username(fields["uid"]), "secret_mode": "dd", "max_sessions": fields["max_sessions"], "max_streams": fields["max_streams"], "max_streams_per_session": 64}]
    return {
        "host": fields["host"],
        "base_path": "" if enabled else fields["web_token"],
        "public_addr": _telemt_public_addr(fields["public_ip"]),
        "decoy": {"mode": "static_directory", "directory": _ensure_decoy_dir(), "index": "index.html"},
        "profiles": profile_rows,
    }


def _telemt_api(api_port, token, method, path, body=None, timeout=8.0):
    url = "http://127.0.0.1:" + str(api_port) + path
    data = None
    headers = {"Content-Type": "application/json", "Accept": "application/json", "Authorization": "Bearer " + token}
    if body is not None:
        data = json.dumps(body).encode("utf-8")
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read()
            status = response.status
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        status = exc.code
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return None, {"ok": False, "error": {"code": "transport", "message": str(exc)}}
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return status, {"ok": False, "error": {"code": "invalid_response", "message": "telemt API did not return JSON"}}
    if not isinstance(payload, dict):
        return status, {"ok": False, "error": {"code": "invalid_response", "message": "telemt API did not return a JSON object"}}
    return status, payload


def _telemt_api_error(payload):
    error = payload.get("error") if isinstance(payload, dict) else None
    if isinstance(error, dict):
        message = error.get("message") or error.get("code") or "telemt API error"
        code = error.get("code") or ""
        if code:
            return code + ": " + str(message)
        return str(message)
    if isinstance(error, str) and error:
        return error
    data = payload.get("data") if isinstance(payload, dict) else None
    if isinstance(data, dict):
        detail = data.get("error") or data.get("message") or ""
        if detail:
            state = data.get("state") or ""
            if state:
                return "reload " + str(state) + ": " + str(detail)
            return str(detail)
    return "telemt API error"


def _telemt_error_code(payload):
    try:
        error = (payload or {}).get("error") or {}
        return error.get("code") or ""
    except (AttributeError, TypeError):
        return ""


async def _telemt_api_async(api_port, token, method, path, body=None, timeout=8.0):
    return await asyncio.to_thread(_telemt_api, api_port, token, method, path, body, timeout)


async def _resolve_public_ip(host):
    try:
        infos = await asyncio.to_thread(socket.getaddrinfo, host, 443, socket.AF_INET, socket.SOCK_STREAM)
    except (OSError, UnicodeError):
        return None
    for info in infos or []:
        sockaddr = info[4] if len(info) > 4 else None
        if sockaddr:
            return str(sockaddr[0])
    return None


def _telemt_public_addr(ip_text):
    text = str(ip_text or "").strip()
    try:
        parsed = ipaddress.ip_address(text)
    except ValueError:
        parsed = ipaddress.ip_address("127.0.0.1")
    if isinstance(parsed, ipaddress.IPv6Address):
        return "[" + str(parsed) + "]:443"
    return str(parsed) + ":443"


def _redact_log_line(text):
    text = re.sub(r"secret=[^&\s]*", "secret=REDACTED", text)
    text = re.sub(r"Bearer [A-Za-z0-9._-]+", "Bearer REDACTED", text)
    return text


async def _stream_child_output(entry, proc):
    try:
        while True:
            line = await proc.stdout.readline()
            if not line:
                break
            text = line.decode("utf-8", "ignore").rstrip()
            text = _ANSI_RE.sub("", text)
            if not text:
                continue
            text = _redact_log_line(text)
            if len(text) > _TELEMT_LOG_MAX:
                text = text[:_TELEMT_LOG_MAX]
            entry["boot_log"].append(text)
            if len(entry["boot_log"]) > _TELEMT_BOOT_LOG_MAX:
                del entry["boot_log"][:len(entry["boot_log"]) - _TELEMT_BOOT_LOG_MAX]
            lowered = text.lower()
            if "error" in lowered or "panic" in lowered:
                _LOG.warning("telemt[%s]: %s", entry["key"], text)
            else:
                _LOG.info("telemt[%s]: %s", entry["key"], text)
    except asyncio.CancelledError:
        raise
    except (OSError, ValueError):
        pass


async def _terminate_proc(proc):
    if proc.returncode is not None:
        return
    try:
        proc.terminate()
        await asyncio.wait_for(proc.wait(), timeout=5.0)
    except asyncio.TimeoutError:
        try:
            proc.kill()
            await proc.wait()
        except ProcessLookupError:
            pass
    except ProcessLookupError:
        pass


def _telemt_note_failure(entry, rc):
    now = time.monotonic()
    entry["failures"] = [item for item in entry["failures"] if now - item <= _TELEMT_FAILURE_WINDOW]
    entry["failures"].append(now)
    if len(entry["failures"]) >= _TELEMT_MAX_FAILURES:
        entry["gave_up"] = True
        entry["error"] = "telemt " + entry["kind"] + " " + str(entry["key"]) + " failed 5 times within 60s; last exit code " + str(rc) + "; not retrying until explicitly restarted"
        _LOG.warning("telemt[%s]: %s", entry["key"], entry["error"])
        return False
    return True


def _telemt_backoff(entry):
    index = len(entry["failures"]) - 1
    if index < 0:
        index = 0
    if index >= len(_TELEMT_BACKOFF):
        index = len(_TELEMT_BACKOFF) - 1
    return _TELEMT_BACKOFF[index]


async def _wait_web_running(entry, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        proc = entry.get("proc")
        if proc is not None and proc.returncode is not None:
            return False, entry.get("error") or "telemt WEB child exited during startup"
        status, payload = await _telemt_api_async(entry["api_port"], entry["token"], "GET", "/v1/runtime/web/status", timeout=2.0)
        if status == 200 and payload.get("ok"):
            data = payload.get("data") or {}
            ingress = data.get("ingress") or {}
            if data.get("lifecycle") == "running" and ingress.get("accepting_connections") is True:
                return True, ""
        await asyncio.sleep(0.25)
    return False, "telemt WEB runtime did not reach running state within 10s"


async def _wait_child_ready(entry, proc):
    api_ok = False
    deadline = time.monotonic() + 10.0
    while time.monotonic() < deadline:
        if proc.returncode is not None:
            tail = entry["boot_log"][-5:]
            entry["error"] = "telemt exited during startup with code " + str(proc.returncode) + (": " + " | ".join(tail) if tail else "")
            return "dead"
        status, payload = await _telemt_api_async(entry["api_port"], entry["token"], "GET", "/v1/system/info", timeout=2.0)
        if status is not None and status < 500:
            api_ok = True
            break
        await asyncio.sleep(0.25)
    if not api_ok:
        if proc.returncode is not None:
            tail = entry["boot_log"][-5:]
            entry["error"] = "telemt exited during startup with code " + str(proc.returncode) + (": " + " | ".join(tail) if tail else "")
            return "dead"
        entry["error"] = "telemt API did not answer within 10s"
        return "starting"
    if entry["kind"] == "web":
        ok, reason = await _wait_web_running(entry, 10.0)
        if ok:
            return "ready"
        if proc.returncode is not None:
            entry["error"] = reason
            return "dead"
        entry["error"] = reason
        return "starting"
    return "ready"


async def _wait_child_starting(entry, proc, timeout=60.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if proc.returncode is not None:
            tail = entry["boot_log"][-5:]
            entry["error"] = "telemt exited during startup with code " + str(proc.returncode) + (": " + " | ".join(tail) if tail else "")
            return "dead"
        status, payload = await _telemt_api_async(entry["api_port"], entry["token"], "GET", "/v1/system/info", timeout=2.0)
        if status is not None and status < 500:
            if entry["kind"] == "web":
                ok, reason = await _wait_web_running(entry, 10.0)
                if ok:
                    return "ready"
                if proc.returncode is not None:
                    entry["error"] = reason
                    return "dead"
                entry["error"] = reason
                continue
            return "ready"
        await asyncio.sleep(0.5)
    entry["error"] = "telemt did not become ready within 60s"
    return "starting"


def _new_telemt_entry(kind, key, run_dir, config_path, port, api_port, token):
    return {"kind": kind, "key": key, "run_dir": run_dir, "config_path": config_path, "port": port, "api_port": api_port, "token": token, "proc": None, "task": None, "ready": False, "error": "", "stopping": False, "gave_up": False, "failures": [], "restarts": 0, "boot_log": [], "config_written": False, "config_text": "", "fields": {}}


async def _spawn_entry(entry):
    if entry["kind"] == "web":
        fields = dict(entry["fields"])
        fields["port"] = entry["port"]
        fields["api_port"] = entry["api_port"]
        fields["bearer"] = entry["token"]
        entry["config_text"] = _web_config_text(fields)
        _write_text(entry["config_path"], entry["config_text"])
    elif entry["kind"] == "mtproto":
        fields = entry["fields"]
        fields["generation"] = int(fields.get("generation") or 0) + 1
        live_primary, live_extras = _telemt_tls_set(str(fields.get("tls_domain") or "www.google.com"), fields.get("tls_domains"))
        entry["config_text"] = _mtproto_config_text(entry["api_port"], entry["token"], entry["port"], str(fields.get("bootstrap_secret") or ""), users=_TELEMT_MTPROTO_USERS, tls_domain=live_primary, tls_domains=live_extras, public_host=fields.get("public_host"), public_port=fields.get("public_port"))
        fields["tls_domain_live"] = live_primary
        fields["tls_domains_live"] = live_extras
        fields["links_host_live"] = str(fields.get("public_host") or "").strip() or None
        try:
            fields["links_port_live"] = int(fields.get("public_port")) if fields.get("public_port") is not None else None
        except (TypeError, ValueError):
            fields["links_port_live"] = None
        _write_text(entry["config_path"], entry["config_text"])
        entry["config_written"] = True
    elif not entry.get("config_written"):
        _write_text(entry["config_path"], entry["config_text"])
        entry["config_written"] = True
    proc = await asyncio.create_subprocess_exec(
        _telemt_binary(), "run", entry["config_path"],
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT, cwd=entry["run_dir"],
    )
    entry["proc"] = proc
    return proc


async def _supervise_entry(entry):
    while not entry["stopping"]:
        entry["ready"] = False
        try:
            proc = await _spawn_entry(entry)
        except (OSError, ValueError) as exc:
            entry["error"] = "failed to start telemt: " + str(exc)
            if not _telemt_note_failure(entry, None):
                break
            await asyncio.sleep(_telemt_backoff(entry))
            continue
        entry["error"] = ""
        entry["restarts"] += 1
        reader_task = asyncio.create_task(_stream_child_output(entry, proc))
        state = await _wait_child_ready(entry, proc)
        if state == "starting":
            state = await _wait_child_starting(entry, proc)
        if state == "ready":
            entry["ready"] = True
            entry["error"] = ""
            rc = await proc.wait()
            entry["ready"] = False
            reader_task.cancel()
            try:
                await reader_task
            except asyncio.CancelledError:
                pass
            if entry["stopping"]:
                break
            entry["error"] = "telemt exited with code " + str(rc)
            if not _telemt_note_failure(entry, rc):
                break
            await asyncio.sleep(_telemt_backoff(entry))
            continue
        reader_task.cancel()
        try:
            await reader_task
        except asyncio.CancelledError:
            pass
        await _terminate_proc(proc)
        if entry["stopping"]:
            break
        if not entry["error"]:
            entry["error"] = "telemt did not become ready"
        if not _telemt_note_failure(entry, None):
            break
        await asyncio.sleep(_telemt_backoff(entry))


async def _stop_entry(entry):
    entry["stopping"] = True
    entry["ready"] = False
    proc = entry.get("proc")
    if proc is not None:
        await _terminate_proc(proc)
    task = entry.get("task")
    if task is not None and not task.done():
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
    entry["proc"] = None
    entry["task"] = None


async def _wait_entry_ready(entry, timeout=30.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if entry.get("ready"):
            return True
        if entry.get("gave_up"):
            return False
        await asyncio.sleep(0.2)
    return bool(entry.get("ready"))

def telemt_web_port(uid):
    entry = _TELEMT_WEB.get(str(uid))
    if entry is None:
        return None
    proc = entry.get("proc")
    if proc is None or proc.returncode is not None:
        return None
    return entry["port"]


def telemt_mtproto_port():
    entry = _TELEMT_MTPROTO
    if entry is None:
        return None
    proc = entry.get("proc")
    if proc is None or proc.returncode is not None:
        return None
    return entry["port"]


async def telemt_start_mtproto(tls_domain=None, tls_domains=None, public_host=None, public_port=None):
    global _TELEMT_MTPROTO
    if not telemt_available():
        return {"enabled": False, "port": 0, "api_port": 0, "error": "telemt binary not found at " + _telemt_binary()}
    async with _telemt_lock("mtproto"):
        entry = _TELEMT_MTPROTO
        if entry is not None and entry.get("proc") is not None and entry["proc"].returncode is None and entry.get("ready"):
            return {"enabled": True, "port": entry["port"], "api_port": entry["api_port"], "error": ""}
        prev_fields = {}
        if entry is not None:
            prev_fields = entry.get("fields") or {}
        if tls_domain is None:
            tls_domain = prev_fields.get("tls_domain")
        if tls_domains is None:
            tls_domains = prev_fields.get("tls_domains")
        if public_host is None:
            public_host = prev_fields.get("public_host")
        if public_port is None:
            public_port = prev_fields.get("public_port")
        if entry is not None:
            await _stop_entry(entry)
        base = _telemt_dir()
        run_dir = os.path.join(base, "mtproto")
        os.makedirs(run_dir, exist_ok=True)
        config_path = os.path.join(run_dir, "config.toml")
        port = _stable_loopback_port(("TELEMT_PORT", "TELEMT_MTPROTO_PORT"), 8477)
        api_port = _stable_loopback_port(("TELEMT_API_PORT", "TELEMT_MTPROTO_API_PORT"), 8478)
        token = _random_bearer()
        try:
            start_port = int(public_port) if public_port is not None else None
        except (TypeError, ValueError):
            start_port = None
        fields = {"bootstrap_secret": secrets.token_hex(16), "tls_domain": tls_domain, "tls_domains": tls_domains, "public_host": str(public_host or "").strip() or None, "public_port": start_port}
        config_text = _mtproto_config_text(api_port, token, port, fields["bootstrap_secret"], tls_domain=str(tls_domain or "www.google.com"), tls_domains=tls_domains, public_host=fields["public_host"], public_port=fields["public_port"])
        entry = _new_telemt_entry("mtproto", "mtproto", run_dir, config_path, port, api_port, token)
        entry["config_text"] = config_text
        entry["fields"] = fields
        _TELEMT_MTPROTO = entry
        entry["task"] = asyncio.create_task(_supervise_entry(entry))
        ready = await _wait_entry_ready(entry, timeout=30.0)
        if ready:
            return {"enabled": True, "port": port, "api_port": api_port, "error": ""}
        return {"enabled": False, "port": port, "api_port": api_port, "error": entry.get("error") or "telemt MTProto child did not become ready"}


def _rfc3339(value):
    if isinstance(value, datetime):
        moment = value
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=timezone.utc)
        return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    if isinstance(value, (int, float)):
        try:
            moment = datetime.fromtimestamp(float(value), tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
        return moment.strftime("%Y-%m-%dT%H:%M:%SZ")
    if isinstance(value, str):
        text = value.strip()
        if text:
            return text
        return None
    return None


def _write_mtproto_config(entry):
    fields = entry.get("fields") or {}
    entry["config_text"] = _mtproto_config_text(entry["api_port"], entry["token"], entry["port"], str(fields.get("bootstrap_secret") or ""), users=_TELEMT_MTPROTO_USERS, tls_domain=str(fields.get("tls_domain") or "www.google.com"), tls_domains=fields.get("tls_domains"), public_host=fields.get("public_host"), public_port=fields.get("public_port"))
    _write_text(entry["config_path"], entry["config_text"])


def _telemt_mtproto_links_live(entry):
    fields = entry.get("fields") or {}
    if "links_host_live" in fields:
        host = fields.get("links_host_live")
    else:
        host = fields.get("public_host")
    if "links_port_live" in fields:
        port = fields.get("links_port_live")
    else:
        port = fields.get("public_port")
    try:
        port = int(port) if port is not None else None
    except (TypeError, ValueError):
        port = None
    return (str(host or "") or None, port)


def telemt_mtproto_links():
    entry = _TELEMT_MTPROTO
    if entry is None:
        return (None, None)
    return _telemt_mtproto_links_live(entry)


async def telemt_mtproto_set_links(public_host, public_port):
    entry = _TELEMT_MTPROTO
    if entry is None or not entry.get("ready"):
        return False
    async with _telemt_lock("mtproto-upsert"):
        entry = _TELEMT_MTPROTO
        if entry is None or not entry.get("ready"):
            return False
        wanted_host = str(public_host or "").strip() or None
        try:
            wanted_port = int(public_port) if public_port is not None else None
        except (TypeError, ValueError):
            wanted_port = None
        if wanted_host is None:
            wanted_port = None
        live_host, live_port = _telemt_mtproto_links_live(entry)
        if wanted_host == live_host and wanted_port == live_port:
            return True
        fields = entry.get("fields") or {}
        fields["public_host"] = wanted_host
        fields["public_port"] = wanted_port
        entry["fields"] = fields
        try:
            _write_mtproto_config(entry)
        except OSError:
            return False
        if not await _restart_mtproto_entry(entry):
            return False
        return True


async def _restart_mtproto_entry(entry):
    global _TELEMT_MTPROTO
    await _stop_entry(entry)
    fresh = _new_telemt_entry("mtproto", "mtproto", entry["run_dir"], entry["config_path"], entry["port"], entry["api_port"], entry["token"])
    fresh["fields"] = entry["fields"]
    _TELEMT_MTPROTO = fresh
    fresh["task"] = asyncio.create_task(_supervise_entry(fresh))
    return await _wait_entry_ready(fresh, timeout=30.0)


def telemt_mtproto_generation():
    entry = _TELEMT_MTPROTO
    if entry is None:
        return 0
    try:
        return int((entry.get("fields") or {}).get("generation") or 0)
    except (TypeError, ValueError):
        return 0


def _telemt_mtproto_tls_live(entry):
    fields = entry.get("fields") or {}
    primary = str(fields.get("tls_domain_live") or fields.get("tls_domain") or "")
    extras = fields.get("tls_domains_live")
    if extras is None:
        extras = fields.get("tls_domains") or []
    if not isinstance(extras, list):
        extras = []
    return (primary, [str(item) for item in extras])


def telemt_mtproto_tls():
    entry = _TELEMT_MTPROTO
    if entry is None:
        return ("", [])
    return _telemt_mtproto_tls_live(entry)


async def telemt_mtproto_set_tls(tls_domain, tls_domains=None):
    entry = _TELEMT_MTPROTO
    if entry is None or not entry.get("ready"):
        return False
    async with _telemt_lock("mtproto-upsert"):
        entry = _TELEMT_MTPROTO
        if entry is None or not entry.get("ready"):
            return False
        wanted_primary, wanted_extras = _telemt_tls_set(tls_domain, tls_domains)
        live_primary, live_extras = _telemt_mtproto_tls_live(entry)
        if wanted_primary == live_primary and sorted(wanted_extras) == sorted(live_extras):
            return True
        fields = entry.get("fields") or {}
        fields["tls_domain"] = wanted_primary
        fields["tls_domains"] = wanted_extras
        entry["fields"] = fields
        try:
            _write_mtproto_config(entry)
        except OSError:
            return False
        if not await _restart_mtproto_entry(entry):
            return False
        return True


def mtproto_counted_bytes(uid):
    target = str(uid)
    total = int(_MTPROXY_FLUSHED.get(target, 0) or 0)
    for session in list(ACTIVE_PROXY.values()):
        if session.get("protocol") != "mtproto":
            continue
        if str(session.get("username") or "") != target:
            continue
        total += int(session.get("bytes_up", 0) or 0) + int(session.get("bytes_down", 0) or 0) - int(session.get("bytes_flushed", 0) or 0)
    return total


async def _telemt_mtproto_wait_user_gone(entry, username, timeout=12.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        status, payload = await _telemt_api_async(entry["api_port"], entry["token"], "GET", "/v1/users/" + _url_path_quote(username, safe=""))
        if status == 404:
            return True
        if status is None:
            return False
        await asyncio.sleep(0.5)
    return False


async def _telemt_mtproto_reload(entry):
    status, payload = await _telemt_api_async(entry["api_port"], entry["token"], "POST", "/v1/system/reload")
    return status in (200, 202) and bool(payload.get("ok"))


async def _telemt_mtproto_wait_live(entry, username, timeout=10.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        status, payload = await _telemt_api_async(entry["api_port"], entry["token"], "GET", "/v1/users/" + _url_path_quote(username, safe=""))
        if status is None:
            return False
        if status == 404:
            return False
        if status == 200 and payload.get("ok"):
            data = payload.get("data") or {}
            if data.get("in_runtime", True):
                return True
        await asyncio.sleep(0.5)
    return False


async def telemt_mtproto_upsert_user(uid, secret_hex, variant="dd", domain="www.google.com", max_conns=0, limit_bytes=0, expires_at=None, tls_domain=None, tls_domains=None, public_host=None, public_port=None):
    if not _valid_secret_hex(secret_hex):
        _LOG.warning("telemt MTProto upsert refused for uid %s: secret must be 32 hex characters", uid)
        return False
    try:
        int(max_conns or 0)
        int(limit_bytes or 0)
    except (TypeError, ValueError):
        return False
    expires_text = None
    if expires_at is not None:
        expires_text = _rfc3339(expires_at)
        if expires_text is None:
            return False
    username = _telemt_username(uid)
    async with _telemt_lock("mtproto-upsert"):
        _TELEMT_MTPROTO_USERS[username] = {"uid": str(uid), "secret_hex": secret_hex.lower(), "max_conns": int(max_conns or 0), "limit_bytes": int(limit_bytes or 0), "expires_at": expires_text}
        entry = _TELEMT_MTPROTO
        if tls_domain is not None or tls_domains is not None or public_host is not None or public_port is not None:
            if entry is not None:
                fields = entry.get("fields") or {}
                if tls_domain is not None:
                    fields["tls_domain"] = tls_domain
                if tls_domains is not None:
                    fields["tls_domains"] = tls_domains
                if public_host is not None:
                    fields["public_host"] = str(public_host or "").strip() or None
                if public_port is not None:
                    try:
                        fields["public_port"] = int(public_port)
                    except (TypeError, ValueError):
                        fields["public_port"] = None
                entry["fields"] = fields
        if entry is None or not entry.get("ready"):
            if entry is not None and not entry.get("gave_up"):
                if await _wait_entry_ready(entry, timeout=30.0):
                    entry = _TELEMT_MTPROTO
                else:
                    started = await telemt_start_mtproto(tls_domain, tls_domains, public_host, public_port)
                    if not started.get("enabled"):
                        return False
                    entry = _TELEMT_MTPROTO
                    return await _telemt_mtproto_wait_live(entry, username)
            else:
                started = await telemt_start_mtproto(tls_domain, tls_domains, public_host, public_port)
                if not started.get("enabled"):
                    return False
                entry = _TELEMT_MTPROTO
                return await _telemt_mtproto_wait_live(entry, username)
        try:
            _write_mtproto_config(entry)
        except OSError:
            pass
        _want_primary, _want_extras = _telemt_tls_set(str((entry.get("fields") or {}).get("tls_domain") or "www.google.com"), (entry.get("fields") or {}).get("tls_domains"))
        _live_primary, _live_extras = _telemt_mtproto_tls_live(entry)
        _live_links_host, _live_links_port = _telemt_mtproto_links_live(entry)
        _want_links_host = str((entry.get("fields") or {}).get("public_host") or "").strip() or None
        try:
            _want_links_port = int((entry.get("fields") or {}).get("public_port")) if (entry.get("fields") or {}).get("public_port") is not None else None
        except (TypeError, ValueError):
            _want_links_port = None
        if _want_primary != _live_primary or sorted(_want_extras) != sorted(_live_extras) or _want_links_host != _live_links_host or _want_links_port != _live_links_port:
            if not await _restart_mtproto_entry(entry):
                return False
            return await _telemt_mtproto_wait_live(_TELEMT_MTPROTO, username)
        if await _telemt_mtproto_wait_live(entry, username, timeout=12.0):
            return True
        await _telemt_mtproto_reload(entry)
        if await _telemt_mtproto_wait_live(entry, username, timeout=8.0):
            return True
        _LOG.warning("telemt MTProto user %s did not go live from the config; restarting the MTProto child so the user is live from its config", username)
        if not await _restart_mtproto_entry(entry):
            return False
        return await _telemt_mtproto_wait_live(_TELEMT_MTPROTO, username)


async def telemt_mtproto_remove_user(uid):
    username = _telemt_username(uid)
    async with _telemt_lock("mtproto-upsert"):
        _TELEMT_MTPROTO_USERS.pop(username, None)
        entry = _TELEMT_MTPROTO
        if entry is None:
            return True
        try:
            _write_mtproto_config(entry)
        except OSError:
            pass
        if not entry.get("ready"):
            if not await _restart_mtproto_entry(entry):
                return False
            return await _telemt_mtproto_wait_user_gone(_TELEMT_MTPROTO, username, timeout=10.0)
        if await _telemt_mtproto_wait_user_gone(entry, username, timeout=12.0):
            return True
        await _telemt_mtproto_reload(entry)
        if await _telemt_mtproto_wait_user_gone(entry, username, timeout=8.0):
            return True
        _LOG.warning("telemt MTProto user %s did not go away from the config; restarting the MTProto child so the user is gone from its config", uid)
        if not await _restart_mtproto_entry(entry):
            return False
        return await _telemt_mtproto_wait_user_gone(_TELEMT_MTPROTO, username, timeout=10.0)


async def telemt_mtproto_user_stats(uid):
    entry = _TELEMT_MTPROTO
    if entry is None or not entry.get("ready"):
        return {}
    username = _telemt_username(uid)
    path = "/v1/users/" + _url_path_quote(username, safe="")
    status, payload = await _telemt_api_async(entry["api_port"], entry["token"], "GET", path)
    if status != 200 or not payload.get("ok"):
        return {}
    data = payload.get("data") or {}
    try:
        return {"total_octets": int(data.get("total_octets") or 0), "current_connections": int(data.get("current_connections") or 0), "active_unique_ips": int(data.get("active_unique_ips") or 0)}
    except (TypeError, ValueError):
        return {}


async def telemt_start_web(uid, token, secret_hex, host, max_sessions=8, max_streams=512, public_ip=None, root_enabled=False, profiles=None):
    key = str(uid)
    if not telemt_available():
        return {"enabled": False, "port": 0, "api_port": 0, "error": "telemt binary not found at " + _telemt_binary()}
    if not _valid_secret_hex(secret_hex):
        return {"enabled": False, "port": 0, "api_port": 0, "error": "WEB secret for uid " + key + " is invalid: WEB secret must be 32 hex characters"}
    if not isinstance(token, str) or not _TELEMT_TOKEN_RE.match(token):
        return {"enabled": False, "port": 0, "api_port": 0, "error": "WEB token for uid " + key + " is invalid: base_path must use [A-Za-z0-9_-] segments"}
    if not _valid_web_host(host):
        return {"enabled": False, "port": 0, "api_port": 0, "error": "telemt WEB host must be a public FQDN, got '" + str(host) + "'"}
    try:
        max_sessions = int(max_sessions)
        max_streams = int(max_streams)
    except (TypeError, ValueError):
        return {"enabled": False, "port": 0, "api_port": 0, "error": "max_sessions and max_streams must be integers"}
    if max_sessions <= 0 or max_streams <= 0:
        return {"enabled": False, "port": 0, "api_port": 0, "error": "max_sessions and max_streams must be positive"}
    wanted_profiles = None
    if profiles:
        wanted_profiles = []
        for item in sorted(profiles, key=lambda entry: str(entry.get("uid") or "")):
            item_secret = str(item.get("secret_hex") or "").lower()
            if not _valid_secret_hex(item_secret):
                return {"enabled": False, "port": 0, "api_port": 0, "error": "WEB secret for uid " + str(item.get("uid") or "") + " is invalid: WEB secret must be 32 hex characters"}
            item_sessions = int(item.get("max_sessions") or 0)
            if item_sessions <= 0:
                item_sessions = 8
            item_streams = int(item.get("max_streams") or 0)
            if item_streams <= 0:
                item_streams = 512
            wanted_profiles.append({"uid": str(item.get("uid") or ""), "secret_hex": item_secret, "max_sessions": item_sessions, "max_streams": item_streams})
    host = str(host).strip().lower()
    if public_ip is not None:
        resolved_ip = str(public_ip).strip()
    else:
        try:
            resolved_ip = await asyncio.wait_for(_resolve_public_ip(host), timeout=5.0)
        except asyncio.TimeoutError:
            resolved_ip = None
        if not resolved_ip:
            resolved_ip = "127.0.0.1"
    try:
        ipaddress.ip_address(resolved_ip)
    except ValueError:
        resolved_ip = "127.0.0.1"
    async with _telemt_lock("web:" + key):
        entry = _TELEMT_WEB.get(key)
        if entry is not None and entry.get("proc") is not None and entry["proc"].returncode is None and entry.get("ready"):
            fields = entry["fields"]
            if fields.get("web_token") == token and fields.get("secret_hex") == secret_hex.lower() and fields.get("host") == host and fields.get("public_ip") == resolved_ip and fields.get("max_sessions") == max_sessions and fields.get("max_streams") == max_streams and bool(fields.get("root_enabled")) == bool(root_enabled) and fields.get("profiles") == wanted_profiles:
                return {"enabled": True, "port": entry["port"], "api_port": entry["api_port"], "error": ""}
        if entry is not None:
            await _stop_entry(entry)
            _TELEMT_WEB.pop(key, None)
        base = _telemt_dir()
        run_dir = os.path.join(base, _telemt_username(key))
        os.makedirs(run_dir, exist_ok=True)
        config_path = os.path.join(run_dir, "config.toml")
        port = _stable_loopback_port("TELEMT_WEB_PORT", 8479)
        api_port = _stable_loopback_port("TELEMT_WEB_API_PORT", 8480)
        bearer = _random_bearer()
        fields = {"uid": key, "web_token": token, "secret_hex": secret_hex.lower(), "host": host, "public_ip": resolved_ip, "max_sessions": max_sessions, "max_streams": max_streams, "root_enabled": bool(root_enabled), "profiles": wanted_profiles}
        entry = _new_telemt_entry("web", key, run_dir, config_path, port, api_port, bearer)
        entry["fields"] = fields
        _TELEMT_WEB[key] = entry
        entry["task"] = asyncio.create_task(_supervise_entry(entry))
        ready = await _wait_entry_ready(entry, timeout=30.0)
        if ready:
            return {"enabled": True, "port": port, "api_port": api_port, "error": ""}
        return {"enabled": False, "port": port, "api_port": api_port, "error": entry.get("error") or "telemt WEB child did not become ready"}


async def telemt_stop_web(uid):
    key = str(uid)
    async with _telemt_lock("web:" + key):
        entry = _TELEMT_WEB.pop(key, None)
        if entry is None:
            return False
        await _stop_entry(entry)
        return True


async def telemt_web_base_path(uid):
    key = str(uid)
    entry = _TELEMT_WEB.get(key)
    if entry is None:
        return None, "no telemt WEB child for uid " + key
    status, payload = await _telemt_api_async(entry["api_port"], entry["token"], "GET", "/v1/config", timeout=5.0)
    if status != 200 or not payload.get("ok"):
        return None, "telemt WEB config read failed: " + _telemt_api_error(payload)
    try:
        vhosts = list(((payload.get("data") or {}).get("web") or {}).get("vhosts") or [])
    except (AttributeError, TypeError):
        return None, "telemt WEB config has no web vhosts"
    host = str(entry["fields"].get("host", "")).lower()
    for vhost in vhosts:
        if isinstance(vhost, dict) and str(vhost.get("host", "")).lower() == host:
            return str(vhost.get("base_path", "")), ""
    return None, "telemt WEB config has no vhost for host " + str(entry["fields"].get("host", ""))


def telemt_web_root_error(uid):
    entry = _TELEMT_WEB.get(str(uid))
    if entry is None:
        return ""
    return str(entry.get("root_error") or "")


def _web_profile_row(item):
    return {"user": _telemt_username(str(item.get("uid") or "")), "secret_mode": "dd", "max_sessions": int(item.get("max_sessions") or 8), "max_streams": int(item.get("max_streams") or 512), "max_streams_per_session": 64}


async def _telemt_web_upsert_api(entry, username, body):
    path = "/v1/users/" + _url_path_quote(username, safe="")
    status, payload = None, {}
    for attempt in range(5):
        status, payload = await _telemt_api_async(entry["api_port"], entry["token"], "GET", path)
        if status == 200 and payload.get("ok"):
            status, payload = await _telemt_api_async(entry["api_port"], entry["token"], "PATCH", path, body)
            if status == 409 and _telemt_error_code(payload) == "reload_in_progress":
                await asyncio.sleep(1.0)
                continue
            return status in (200, 202) and bool(payload.get("ok"))
        if status == 404:
            create = {"username": username}
            create.update(body)
            status, payload = await _telemt_api_async(entry["api_port"], entry["token"], "POST", "/v1/users", create)
            if status == 409 and _telemt_error_code(payload) == "reload_in_progress":
                await asyncio.sleep(1.0)
                continue
            return status in (200, 201, 202) and bool(payload.get("ok"))
        if status == 409 and _telemt_error_code(payload) == "reload_in_progress":
            await asyncio.sleep(1.0)
            continue
        break
    _LOG.warning("telemt WEB upsert failed for user %s: %s", username, _telemt_api_error(payload))
    return False


async def _telemt_web_wait_live(entry, username, timeout=10.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        status, payload = await _telemt_api_async(entry["api_port"], entry["token"], "GET", "/v1/users/" + _url_path_quote(username, safe=""))
        if status is None:
            return False
        if status == 404:
            return False
        if status == 200 and payload.get("ok"):
            data = payload.get("data") or {}
            if data.get("in_runtime", True):
                return True
        await asyncio.sleep(0.5)
    return False


async def _web_patch_vhosts(entry, new_vhosts):
    patched = False
    patch_ok = False
    status, payload = None, {}
    for attempt in range(5):
        status, payload = await _telemt_api_async(entry["api_port"], entry["token"], "PATCH", "/v1/config?reload=instant", {"web": {"vhosts": new_vhosts}})
        if status == 200 and payload.get("ok"):
            patched = True
            patch_ok = True
            break
        if status == 202 and payload.get("ok"):
            patched = True
            break
        if status == 409 and _telemt_error_code(payload) in ("reload_in_progress", "runtime_conflict"):
            await asyncio.sleep(1.0)
            continue
        break
    if not patched:
        entry["root_error"] = "telemt WEB vhost PATCH failed: " + _telemt_api_error(payload)
        _LOG.warning("telemt WEB vhost PATCH failed for uid %s: %s", entry["key"], _telemt_api_error(payload))
        return False
    if patch_ok:
        entry["root_error"] = ""
        return True
    reload_id = None
    try:
        reload_id = ((payload.get("data") or {}).get("reload") or {}).get("reload_id")
    except (AttributeError, TypeError):
        reload_id = None
    if reload_id is None:
        entry["root_error"] = "telemt WEB vhost PATCH failed: reload id missing"
        _LOG.warning("telemt WEB vhost PATCH failed for uid %s: reload id missing", entry["key"])
        return False
    deadline = time.monotonic() + 30.0
    while time.monotonic() < deadline:
        status, payload = await _telemt_api_async(entry["api_port"], entry["token"], "GET", "/v1/system/reload/" + str(reload_id))
        if status == 200 and payload.get("ok"):
            state = (payload.get("data") or {}).get("state")
            if state == "succeeded":
                entry["root_error"] = ""
                return True
            if state == "failed":
                policy = (payload.get("data") or {}).get("failure_policy") or ""
                if policy == "keep_new":
                    entry["root_error"] = ""
                    return True
                entry["root_error"] = "telemt WEB vhost reload " + str(state) + ": " + _telemt_api_error(payload)
                _LOG.warning("telemt WEB vhost reload %s for uid %s: %s", state, entry["key"], _telemt_api_error(payload))
                return False
            if state == "rolled_back":
                entry["root_error"] = "telemt WEB vhost reload " + str(state) + ": " + _telemt_api_error(payload)
                _LOG.warning("telemt WEB vhost reload %s for uid %s: %s", state, entry["key"], _telemt_api_error(payload))
                return False
        await asyncio.sleep(0.5)
    entry["root_error"] = "telemt WEB vhost reload timed out after 30s (reload stayed in preparing state)"
    _LOG.warning("telemt WEB vhost reload timed out for uid %s", entry["key"])
    return False


async def telemt_web_sync_profiles(uid, profiles, host):
    key = str(uid)
    entry = _TELEMT_WEB.get(key)
    if entry is None:
        return False
    async with _telemt_lock("web:" + key):
        entry = _TELEMT_WEB.get(key)
        if entry is None or not entry.get("ready"):
            entry["root_error"] = "telemt WEB child is not ready yet, shared profiles cannot be synced" if entry is not None else "no telemt WEB child for uid " + key
            return False
        wanted = []
        for item in sorted(profiles or [], key=lambda row: str(row.get("uid") or "")):
            item_secret = str(item.get("secret_hex") or "").lower()
            if not _valid_secret_hex(item_secret):
                entry["root_error"] = "WEB secret for uid " + str(item.get("uid") or "") + " is invalid: WEB secret must be 32 hex characters"
                return False
            item_sessions = int(item.get("max_sessions") or 0)
            if item_sessions <= 0:
                item_sessions = 8
            item_streams = int(item.get("max_streams") or 0)
            if item_streams <= 0:
                item_streams = 512
            wanted.append({"uid": str(item.get("uid") or ""), "secret_hex": item_secret, "max_sessions": item_sessions, "max_streams": item_streams})
        wanted_users = {}
        for item in wanted:
            wanted_users[_telemt_username(item["uid"])] = item
        for username in sorted(wanted_users):
            item = wanted_users[username]
            if not await _telemt_web_upsert_api(entry, username, {"secret": item["secret_hex"]}):
                return False
        status, payload = await _telemt_api_async(entry["api_port"], entry["token"], "GET", "/v1/config")
        if status != 200 or not payload.get("ok"):
            entry["root_error"] = "telemt config read failed: " + _telemt_api_error(payload)
            _LOG.warning("telemt WEB profile sync aborted for uid %s: config read failed: %s", entry["key"], _telemt_api_error(payload))
            return False
        try:
            vhosts = list(((payload.get("data") or {}).get("web") or {}).get("vhosts") or [])
        except (AttributeError, TypeError):
            entry["root_error"] = "telemt config has no web vhosts"
            _LOG.warning("telemt WEB profile sync aborted for uid %s: config has no web vhosts", entry["key"])
            return False
        fields = entry["fields"]
        current_users = set()
        new_vhosts = []
        replaced = False
        for vhost in vhosts:
            if isinstance(vhost, dict) and str(vhost.get("host", "")).lower() == str(host).strip().lower():
                for row in vhost.get("profiles") or []:
                    if isinstance(row, dict) and row.get("user"):
                        current_users.add(str(row.get("user")))
                item = dict(vhost)
                item["base_path"] = ""
                item["profiles"] = [_web_profile_row(row) for row in wanted]
                new_vhosts.append(item)
                replaced = True
            else:
                new_vhosts.append(vhost)
        if not replaced:
            new_vhosts.append(_web_root_vhost(fields, True, profiles=wanted))
        if not await _web_patch_vhosts(entry, new_vhosts):
            return False
        for stale_user in sorted(current_users - set(wanted_users)):
            try:
                await _telemt_api_async(entry["api_port"], entry["token"], "DELETE", "/v1/users/" + _url_path_quote(stale_user, safe=""))
            except Exception:
                pass
        for username in sorted(wanted_users):
            if not await _telemt_web_wait_live(entry, username):
                entry["root_error"] = "telemt WEB user " + username + " did not become live after the profile sync"
                return False
        status, payload = await _telemt_api_async(entry["api_port"], entry["token"], "GET", "/v1/config")
        if status == 200 and payload.get("ok"):
            try:
                live_vhosts = list(((payload.get("data") or {}).get("web") or {}).get("vhosts") or [])
            except (AttributeError, TypeError):
                live_vhosts = []
            live_users = set()
            for vhost in live_vhosts:
                if isinstance(vhost, dict) and str(vhost.get("host", "")).lower() == str(host).strip().lower():
                    for row in vhost.get("profiles") or []:
                        if isinstance(row, dict) and row.get("user"):
                            live_users.add(str(row.get("user")))
            if live_users != set(wanted_users):
                entry["root_error"] = "telemt WEB profile sync verification failed: live profiles are " + ",".join(sorted(live_users)) + " instead of " + ",".join(sorted(wanted_users))
                return False
        fields["profiles"] = wanted
        entry["root_error"] = ""
        return True


async def telemt_web_status(uid):
    key = str(uid)
    entry = _TELEMT_WEB.get(key)
    if entry is None:
        return {"enabled": False, "port": 0, "error": "no telemt WEB child for uid " + key, "sessions": 0, "healthy": False}
    port = entry["port"]
    proc = entry.get("proc")
    if proc is None or proc.returncode is not None:
        return {"enabled": False, "port": port, "error": entry.get("error") or "telemt WEB child is not running", "sessions": 0, "healthy": False}
    status, payload = await _telemt_api_async(entry["api_port"], entry["token"], "GET", "/v1/runtime/web/status", timeout=5.0)
    if status != 200 or not payload.get("ok"):
        return {"enabled": False, "port": port, "error": "telemt WEB API did not answer", "sessions": 0, "healthy": False}
    data = payload.get("data") or {}
    ingress = data.get("ingress") or {}
    healthy = data.get("lifecycle") == "running" and ingress.get("accepting_connections") is True
    sessions = 0
    session_rows = []
    status, payload = await _telemt_api_async(entry["api_port"], entry["token"], "GET", "/v1/runtime/web/sessions?limit=200", timeout=5.0)
    if status == 200 and payload.get("ok"):
        rows = (payload.get("data") or {}).get("sessions") or []
        session_rows = rows if isinstance(rows, list) else []
        sessions = len(session_rows)
    error = ""
    if not healthy:
        error = str(data.get("reason") or data.get("lifecycle") or "WEB runtime is not running")
    return {"enabled": True, "port": port, "error": error, "sessions": sessions, "session_rows": session_rows, "healthy": healthy}


async def telemt_stop_all():
    global _TELEMT_MTPROTO
    entry = _TELEMT_MTPROTO
    if entry is not None:
        await _stop_entry(entry)
    _TELEMT_MTPROTO = None
    for key in list(_TELEMT_WEB.keys()):
        item = _TELEMT_WEB.pop(key, None)
        if item is not None:
            await _stop_entry(item)


async def telemt_health():
    available = telemt_available()
    error = ""
    if not available:
        error = "telemt binary not found at " + _telemt_binary()
    mtproto = {"enabled": False, "port": 0, "api_port": 0, "error": error or "telemt MTProto child is not running", "healthy": False, "users_live": 0, "users_total": len(_TELEMT_MTPROTO_USERS)}
    entry = _TELEMT_MTPROTO
    if entry is not None and entry.get("proc") is not None and entry["proc"].returncode is None:
        status, payload = await _telemt_api_async(entry["api_port"], entry["token"], "GET", "/v1/health", timeout=5.0)
        healthy = status == 200 and bool(payload.get("ok"))
        mtproto = {"enabled": True, "port": entry["port"], "api_port": entry["api_port"], "error": "" if healthy else (entry.get("error") or "telemt MTProto API did not answer"), "healthy": healthy, "users_live": 0, "users_total": len(_TELEMT_MTPROTO_USERS)}
        if healthy:
            live = 0
            for username in list(_TELEMT_MTPROTO_USERS):
                user_status, user_payload = await _telemt_api_async(entry["api_port"], entry["token"], "GET", "/v1/users/" + _url_path_quote(username, safe=""), timeout=2.0)
                if user_status == 200 and (user_payload.get("data") or {}).get("in_runtime"):
                    live += 1
            mtproto["users_live"] = live
    elif entry is not None and entry.get("error"):
        mtproto["error"] = entry["error"]
    web = {}
    for key in list(_TELEMT_WEB.keys()):
        web[key] = await telemt_web_status(key)
    return {"available": available, "mtproto": mtproto, "web": web, "error": error}


_MUX_BIND_MODES = {}


def mux_bind_modes():
    return dict(_MUX_BIND_MODES)


def _mux_dispatch_count(kind):
    key = "dispatch_" + kind
    _STATS[key] = int(_STATS.get(key) or 0) + 1
    return _STATS[key]


async def _start_mux_server(port):
    sock = None
    try:
        sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        sock.bind(("::", port))
        sock.listen(256)
        server = await asyncio.start_server(_handle_multi, sock=sock)
        sock = None
        _MUX_BIND_MODES[port] = "dual-stack"
        _LOG.info("proxy mux bind mode dual-stack on port " + str(port))
        return server
    except OSError as exc:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
        server = await asyncio.start_server(_handle_multi, "0.0.0.0", port)
        _MUX_BIND_MODES[port] = "ipv4-only"
        _LOG.info("proxy mux bind mode ipv4-only on port " + str(port) + " after dual-stack failed: " + str(exc))
        return server


async def start_all(multi_ports, auth_lookup, count_traffic, mtproxy_quota_ok, session_allowed=None):
    global _AUTH_LOOKUP, _COUNT_TRAFFIC, _MTPROXY_QUOTA_OK, _SESSION_ALLOWED
    _AUTH_LOOKUP = auth_lookup
    _COUNT_TRAFFIC = count_traffic
    _MTPROXY_QUOTA_OK = mtproxy_quota_ok
    _SESSION_ALLOWED = session_allowed
    if isinstance(multi_ports, int):
        wanted = [multi_ports]
    else:
        wanted = list(multi_ports or [])
    ports = []
    for item in wanted:
        try:
            port = int(item)
        except (TypeError, ValueError):
            continue
        if port and port not in ports:
            ports.append(port)
    if telemt_available():
        mt = await telemt_start_mtproto()
    else:
        mt = {"enabled": False, "port": 0, "api_port": 0, "error": "telemt binary not found at " + _telemt_binary()}
    status = {
        "socks": {"enabled": False, "port": 0, "error": ""},
        "mtproxy": {"enabled": False, "port": 0, "error": mt.get("error", "")},
        "http": {"enabled": False, "port": 0, "error": ""},
    }
    bound = []
    bind_error = ""
    failed = {}
    for port in ports:
        try:
            server = await _start_mux_server(port)
            _SERVERS.append(server)
            _BOUND_PORTS.add(port)
            _BIND_ERRORS.pop(port, None)
            bound.append(port)
            _LOG.info("proxy mux listening on port " + str(port))
        except OSError as exc:
            failed[port] = _bind_error_text(port, exc)
            _BIND_ERRORS[port] = _bind_error_text(port, exc)
            _LOG.warning("proxy mux failed to bind port " + str(port) + ": " + _bind_error_text(port, exc))
            if not bind_error:
                bind_error = _bind_error_text(port, exc)
    first = bound[0] if bound else 0
    status["socks"]["port"] = first
    status["http"]["port"] = first
    status["mtproxy"]["port"] = first
    status["socks"]["ports"] = list(bound)
    status["http"]["ports"] = list(bound)
    status["mtproxy"]["ports"] = list(bound)
    status["socks"]["failed_ports"] = {str(k): v for k, v in failed.items()}
    status["http"]["failed_ports"] = {str(k): v for k, v in failed.items()}
    status["mtproxy"]["failed_ports"] = {str(k): v for k, v in failed.items()}
    if bound:
        status["socks"]["enabled"] = True
        status["http"]["enabled"] = True
        if mt.get("enabled"):
            status["mtproxy"]["enabled"] = True
        elif not mt.get("error"):
            status["mtproxy"]["error"] = "telemt MTProto child is not running"
    else:
        status["socks"]["error"] = bind_error or "no proxy ports configured"
        status["http"]["error"] = bind_error or "no proxy ports configured"
        if not status["mtproxy"]["error"]:
            status["mtproxy"]["error"] = bind_error or "no proxy ports configured"
    return status


async def ensure_proxy_ports(ports):
    wanted = []
    for item in ports or []:
        try:
            port = int(item)
        except (TypeError, ValueError):
            continue
        if port and port not in wanted:
            wanted.append(port)
    bound = []
    failed = {}
    for port in wanted:
        if port in _BOUND_PORTS:
            continue
        try:
            server = await _start_mux_server(port)
            _SERVERS.append(server)
            _BOUND_PORTS.add(port)
            _BIND_ERRORS.pop(port, None)
            bound.append(port)
            _LOG.info("proxy mux listening on port " + str(port))
        except OSError as exc:
            failed[port] = _bind_error_text(port, exc)
            _BIND_ERRORS[port] = _bind_error_text(port, exc)
            _LOG.warning("proxy mux failed to bind port " + str(port) + ": " + _bind_error_text(port, exc))
    return {"bound": bound, "failed": {str(k): v for k, v in failed.items()}, "ports": sorted(_BOUND_PORTS), "errors": {str(k): v for k, v in _BIND_ERRORS.items()}}


def proxy_bound_ports():
    return sorted(_BOUND_PORTS)


def proxy_bind_errors():
    return dict(_BIND_ERRORS)


async def stop_all():
    for server in _SERVERS:
        try:
            server.close()
            await server.wait_closed()
        except OSError:
            pass
    _SERVERS.clear()
    _BOUND_PORTS.clear()
    _BIND_ERRORS.clear()
    await telemt_stop_all()
