"""SulgX Telegram proxy layer.

SOCKS5 and HTTP CONNECT stay in this module and only accept Telegram
destinations. MTProto and WEB proxying are delegated to the telemt binary:
one shared telemt child serves classic MTProto for every inbound, and one
telemt child per WEB inbound serves that inbound token. The panel never
implements the MTProto or WEB wire protocols itself any more.
"""
import asyncio
import base64
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
    from cryptography.hazmat.primitives.ciphers import Cipher as _AES_CIPHER
    from cryptography.hazmat.primitives.ciphers.algorithms import AES as _AES_ALG
    from cryptography.hazmat.primitives.ciphers.modes import CTR as _AES_CTR
except Exception:
    _AES_CIPHER = None
    _AES_ALG = None
    _AES_CTR = None

_LOG = logging.getLogger("sulgx.telegram")

TG_NETWORKS = [
    ipaddress.ip_network("91.108.4.0/22"),
    ipaddress.ip_network("91.108.8.0/22"),
    ipaddress.ip_network("91.108.12.0/22"),
    ipaddress.ip_network("91.108.16.0/22"),
    ipaddress.ip_network("91.108.20.0/22"),
    ipaddress.ip_network("91.108.56.0/22"),
    ipaddress.ip_network("149.154.160.0/20"),
    ipaddress.ip_network("185.76.151.0/24"),
    ipaddress.ip_network("95.161.64.0/20"),
    ipaddress.ip_network("91.105.192.0/18"),
    ipaddress.ip_network("2001:67c:4e8::/48"),
    ipaddress.ip_network("2001:b28:f23c::/48"),
    ipaddress.ip_network("2001:b28:f23d::/48"),
    ipaddress.ip_network("2001:b28:f23f::/48"),
    ipaddress.ip_network("2a0a:f280::/32"),
]

TELEMT_VERSION = "3.5.17"
_TELEMT_DEFAULT_BIN = "/usr/local/bin/telemt"
_TELEMT_DEFAULT_DIR = "/data/telemt"
_TELEMT_LOG_MAX = 500
_TELEMT_BACKOFF = (1, 2, 5, 10, 30)
_TELEMT_MAX_FAILURES = 5
_TELEMT_FAILURE_WINDOW = 60.0
_TELEMT_BOOT_LOG_MAX = 40
_TELEMT_DECOY_HTML = "<!doctype html><html><head><meta charset=\"utf-8\"><title>OK</title></head><body>OK</body></html>"
_HTTP_METHODS = (b"CONNECT ", b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ", b"PATCH ")
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


def is_telegram_ip(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    for net in TG_NETWORKS:
        if ip in net:
            return True
    return False


def _telegram_targets(ips):
    targets = []
    for ip in ips or []:
        if is_telegram_ip(ip):
            targets.append(ip)
    targets.sort(key=lambda item: ipaddress.ip_address(item).version)
    return targets


async def _connect_telegram(targets, port):
    for target_ip in targets:
        try:
            return await asyncio.wait_for(asyncio.open_connection(target_ip, port), timeout=10)
        except (OSError, asyncio.TimeoutError):
            continue
    return None, None


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
    for method in _HTTP_METHODS:
        if prefix.startswith(method):
            return True
        if len(prefix) >= 3 and len(prefix) < len(method) and method.startswith(prefix):
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
    for method in _HTTP_METHODS:
        if method.startswith(prefix):
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
    while len(prefix) < 8:
        try:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            chunk = await asyncio.wait_for(reader.read(8 - len(prefix)), timeout=remaining)
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
    _STATS["mtproxy_connections"] += 1
    upstream_reader = None
    upstream_writer = None
    sid = None
    entry = None
    total_bytes = 0
    up_flushed = 0
    down_flushed = 0
    link_uid = ""
    try:
        if _MTPROXY_QUOTA_OK is not None:
            if not await _MTPROXY_QUOTA_OK():
                writer.close()
                return
        port = telemt_mtproto_port()
        if port is None:
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
        if link_uid and _COUNT_TRAFFIC is not None:
            if not await _COUNT_TRAFFIC(link_uid, 0):
                writer.close()
                return
        if link_uid and _SESSION_ALLOWED is not None:
            _peer = writer.get_extra_info("peername")
            _cip = _peer[0] if _peer else ""
            if not _SESSION_ALLOWED(link_uid, _cip):
                writer.close()
                return
        try:
            upstream_reader, upstream_writer = await asyncio.wait_for(
                asyncio.open_connection("127.0.0.1", port), timeout=10
            )
        except (OSError, asyncio.TimeoutError):
            writer.close()
            return
        peer = writer.get_extra_info("peername")
        sid = "mtproxy-" + os.urandom(6).hex()
        entry = {"id": sid, "username": link_uid, "protocol": "mtproto", "client_ip": peer[0] if peer else "", "started_at": datetime.now(timezone.utc).isoformat(), "bytes_up": 0, "bytes_down": 0, "bytes_flushed": 0, "writer": writer}
        ACTIVE_PROXY[sid] = entry

        async def _count(n, direction):
            nonlocal total_bytes, up_flushed, down_flushed
            total_bytes += n
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
        pass
    finally:
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
    try:
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
        if upstream_writer is not None:
            try:
                upstream_writer.close()
            except OSError:
                pass
        try:
            writer.close()
        except OSError:
            pass


async def _handle_multi(reader, writer):
    prefix = await _peek_prefix(reader)
    if _looks_http(prefix):
        while b" " not in prefix and len(prefix) < 16:
            try:
                chunk = await asyncio.wait_for(reader.read(16 - len(prefix)), timeout=5.0)
            except (asyncio.TimeoutError, ConnectionError, OSError):
                break
            if not chunk:
                break
            prefix += bytes(chunk)
        if b" " not in prefix:
            try:
                writer.close()
            except OSError:
                pass
            return
        if prefix.split(b" ", 1)[0].upper() == b"CONNECT":
            await _handle_http_proxy(_PrefixedReader(reader, prefix), writer)
            return
        await _handle_panel_forward(_PrefixedReader(reader, prefix), writer)
        return
    if _looks_socks5(prefix):
        await _handle_socks5(_PrefixedReader(reader, prefix), writer)
        return
    await _handle_mtproto_relay(reader, writer, prefix)


async def _handle_socks5(reader, writer):
    _STATS["socks_connections"] += 1
    link = None
    total_bytes = 0
    up_flushed = 0
    down_flushed = 0
    sid = None
    entry = None
    try:
        greeting = await _read_exact(reader, 2)
        if greeting[0] != 0x05:
            writer.close()
            return
        nmethods = greeting[1]
        methods = await _read_exact(reader, nmethods)
        if 0x02 in methods:
            writer.write(b"\x05\x02")
        else:
            writer.write(b"\x05\xff")
            await writer.drain()
            writer.close()
            return
        await writer.drain()
        auth_head = await _read_exact(reader, 2)
        if auth_head[0] != 0x01:
            writer.close()
            return
        ulen = auth_head[1]
        username = (await _read_exact(reader, ulen)).decode("utf-8", "ignore")
        plen = (await _read_exact(reader, 1))[0]
        password = (await _read_exact(reader, plen)).decode("utf-8", "ignore")
        if _AUTH_LOOKUP is not None:
            link = _AUTH_LOOKUP(username, password)
        if link is None:
            writer.write(b"\x01\x01")
            await writer.drain()
            writer.close()
            return
        if _SESSION_ALLOWED is not None:
            peer = writer.get_extra_info("peername")
            cip = peer[0] if peer else ""
            if not _SESSION_ALLOWED(username, cip):
                writer.write(b"\x01\x01")
                await writer.drain()
                writer.close()
                return
        writer.write(b"\x01\x00")
        await writer.drain()
        req = await _read_exact(reader, 4)
        if req[0] != 0x05:
            writer.close()
            return
        cmd = req[1]
        atyp = req[3]
        if cmd != 0x01:
            writer.write(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
            await writer.drain()
            writer.close()
            return
        if atyp == 0x01:
            addr_bytes = await _read_exact(reader, 4)
            host = socket.inet_ntoa(addr_bytes)
            ips = [host]
        elif atyp == 0x03:
            dlen = (await _read_exact(reader, 1))[0]
            host = (await _read_exact(reader, dlen)).decode("utf-8", "ignore")
            loop = asyncio.get_running_loop()
            try:
                infos = await asyncio.wait_for(loop.getaddrinfo(host, None, proto=socket.IPPROTO_TCP), timeout=10.0)
            except (OSError, asyncio.TimeoutError):
                writer.write(b"\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00")
                await writer.drain()
                writer.close()
                return
            ips = list({info[4][0] for info in infos})
        elif atyp == 0x04:
            addr_bytes = await _read_exact(reader, 16)
            host = socket.inet_ntop(socket.AF_INET6, addr_bytes)
            ips = [host]
        else:
            writer.write(b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")
            await writer.drain()
            writer.close()
            return
        port = struct.unpack(">H", await _read_exact(reader, 2))[0]
        targets = _telegram_targets(ips)
        if not targets:
            writer.write(b"\x05\x02\x00\x01\x00\x00\x00\x00\x00\x00")
            await writer.drain()
            writer.close()
            return
        uid = link.get("uid", "")
        if _COUNT_TRAFFIC is not None:
            if not await _COUNT_TRAFFIC(uid, 0):
                writer.write(b"\x05\x02\x00\x01\x00\x00\x00\x00\x00\x00")
                await writer.drain()
                writer.close()
                return
        target_reader, target_writer = await _connect_telegram(targets, port)
        if target_writer is None:
            writer.write(b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00")
            await writer.drain()
            writer.close()
            return
        bound = target_writer.get_extra_info("sockname")
        if bound and ":" in str(bound[0]):
            reply = b"\x05\x00\x00\x04" + socket.inet_pton(socket.AF_INET6, bound[0]) + struct.pack(">H", bound[1])
        elif bound:
            reply = b"\x05\x00\x00\x01" + socket.inet_aton(bound[0]) + struct.pack(">H", bound[1])
        else:
            reply = b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        writer.write(reply)
        await writer.drain()

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

        await asyncio.gather(_relay(reader, target_writer, "up"), _relay(target_reader, writer, "down"))
        try:
            target_writer.close()
        except OSError:
            pass
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
            writer.close()
        except OSError:
            pass

async def _handle_http_proxy(reader, writer):
    _STATS["http_connections"] += 1
    link = None
    total_bytes = 0
    up_flushed = 0
    down_flushed = 0
    sid = None
    entry = None
    target_writer = None
    try:
        try:
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=10.0)
        except (asyncio.IncompleteReadError, asyncio.TimeoutError, asyncio.LimitOverrunError, ConnectionError, OSError):
            writer.close()
            return
        text = head.decode("iso-8859-1", "ignore")
        lines = text.split("\r\n")
        parts = lines[0].split(" ")
        if len(parts) < 2 or parts[0].upper() != "CONNECT":
            writer.write(b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            await writer.drain()
            writer.close()
            return
        target = parts[1].strip()
        if ":" not in target:
            writer.write(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            await writer.drain()
            writer.close()
            return
        host, port_text = target.rsplit(":", 1)
        try:
            port = int(port_text)
        except ValueError:
            writer.write(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            await writer.drain()
            writer.close()
            return
        if port < 1 or port > 65535:
            writer.write(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            await writer.drain()
            writer.close()
            return
        headers = {}
        for line in lines[1:]:
            if ":" in line:
                key, val = line.split(":", 1)
                headers[key.strip().lower()] = val.strip()
        username = ""
        password = ""
        auth = headers.get("proxy-authorization", "") or headers.get("authorization", "")
        if auth.lower().startswith("basic "):
            try:
                decoded = base64.b64decode(auth[6:].strip()).decode("utf-8", "ignore")
                if ":" in decoded:
                    username, password = decoded.split(":", 1)
            except (ValueError, TypeError):
                username = ""
                password = ""
        if _AUTH_LOOKUP is not None:
            link = _AUTH_LOOKUP(username, password)
        if link is None:
            writer.write(b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"SulgX\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            await writer.drain()
            writer.close()
            return
        if _SESSION_ALLOWED is not None:
            peer = writer.get_extra_info("peername")
            cip = peer[0] if peer else ""
            if not _SESSION_ALLOWED(username, cip):
                writer.write(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                await writer.drain()
                writer.close()
                return
        uid = link.get("uid", "")
        if _COUNT_TRAFFIC is not None and not await _COUNT_TRAFFIC(uid, 0):
            writer.write(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            await writer.drain()
            writer.close()
            return
        if host.startswith("[") and host.endswith("]"):
            host = host[1:-1]
        loop = asyncio.get_running_loop()
        try:
            infos = await asyncio.wait_for(loop.getaddrinfo(host, None, proto=socket.IPPROTO_TCP), timeout=10.0)
            ips = list({info[4][0] for info in infos})
        except (OSError, asyncio.TimeoutError):
            writer.write(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            await writer.drain()
            writer.close()
            return
        targets = _telegram_targets(ips)
        if not targets:
            writer.write(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            await writer.drain()
            writer.close()
            return
        target_reader, target_writer = await _connect_telegram(targets, port)
        if target_writer is None:
            writer.write(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            await writer.drain()
            writer.close()
            return
        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await writer.drain()
        peer = writer.get_extra_info("peername")
        sid = "http-" + os.urandom(6).hex()
        entry = {"id": sid, "username": username, "protocol": "http-proxy", "client_ip": peer[0] if peer else "", "started_at": datetime.now(timezone.utc).isoformat(), "bytes_up": 0, "bytes_down": 0, "bytes_flushed": 0, "writer": writer}
        ACTIVE_PROXY[sid] = entry
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
        await asyncio.gather(_relay(reader, target_writer, "up"), _relay(target_reader, writer, "down"))
        try:
            target_writer.close()
        except OSError:
            pass
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
        if target_writer is not None:
            try:
                target_writer.close()
            except OSError:
                pass
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


def _random_bearer():
    return secrets.token_hex(24)


def _toml_escape(value):
    return str(value).replace("\\", "\\\\").replace('"', '\\"')


def _telemt_username(uid):
    name = str(uid)
    if _TELEMT_USERNAME_RE.match(name):
        return name
    return "u" + hashlib.sha256(name.encode("utf-8")).hexdigest()[:40]


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


def _mtproto_config_text(api_port, token, port, bootstrap_secret, users=None):
    lines = [
        "[general]",
        "use_middle_proxy = false",
        'log_level = "normal"',
        "",
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
        "[censorship]",
        'tls_domain = "www.google.com"',
        "mask = true",
        "tls_emulation = true",
        "",
        "[censorship.tls_fetch]",
        "total_budget_ms = 5000",
        "attempt_timeout_ms = 2000",
        "",
        "[access.users]",
        'bootstrap = "' + bootstrap_secret + '"',
    ]
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
        "[[web.vhosts.profiles]]",
        'user = "' + _toml_escape(username) + '"',
        'secret_mode = "dd"',
        "max_sessions = " + str(fields["max_sessions"]),
        "max_streams = " + str(fields["max_streams"]),
        "max_streams_per_session = 64",
        "",
        "[censorship]",
        'tls_domain = "www.google.com"',
        "mask = true",
        "",
        "[censorship.tls_fetch]",
        "total_budget_ms = 5000",
        "attempt_timeout_ms = 2000",
        "",
        "[access.users]",
        '"' + _toml_escape(username) + '" = "' + fields["secret_hex"] + '"',
    ]
    return "\n".join(lines) + "\n"


def _web_root_vhost(fields, enabled):
    return {
        "host": fields["host"],
        "base_path": "" if enabled else fields["web_token"],
        "public_addr": _telemt_public_addr(fields["public_ip"]),
        "decoy": {"mode": "static_directory", "directory": _ensure_decoy_dir(), "index": "index.html"},
        "profiles": [{"user": _telemt_username(fields["uid"]), "secret_mode": "dd", "max_sessions": fields["max_sessions"], "max_streams": fields["max_streams"], "max_streams_per_session": 64}],
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
        entry["config_text"] = _mtproto_config_text(entry["api_port"], entry["token"], entry["port"], str(fields.get("bootstrap_secret") or ""), users=_TELEMT_MTPROTO_USERS)
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


async def telemt_start_mtproto():
    global _TELEMT_MTPROTO
    if not telemt_available():
        return {"enabled": False, "port": 0, "api_port": 0, "error": "telemt binary not found at " + _telemt_binary()}
    async with _telemt_lock("mtproto"):
        entry = _TELEMT_MTPROTO
        if entry is not None and entry.get("proc") is not None and entry["proc"].returncode is None and entry.get("ready"):
            return {"enabled": True, "port": entry["port"], "api_port": entry["api_port"], "error": ""}
        if entry is not None:
            await _stop_entry(entry)
        base = _telemt_dir()
        run_dir = os.path.join(base, "mtproto")
        os.makedirs(run_dir, exist_ok=True)
        config_path = os.path.join(run_dir, "config.toml")
        port = _free_loopback_port()
        api_port = _free_loopback_port()
        token = _random_bearer()
        fields = {"bootstrap_secret": secrets.token_hex(16)}
        config_text = _mtproto_config_text(api_port, token, port, fields["bootstrap_secret"])
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
    entry["config_text"] = _mtproto_config_text(entry["api_port"], entry["token"], entry["port"], str((entry.get("fields") or {}).get("bootstrap_secret") or ""), users=_TELEMT_MTPROTO_USERS)
    _write_text(entry["config_path"], entry["config_text"])


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


async def _telemt_mtproto_upsert_api(entry, username, body):
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
    _LOG.warning("telemt MTProto upsert failed for user %s: %s", username, _telemt_api_error(payload))
    return False


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


async def telemt_mtproto_upsert_user(uid, secret_hex, variant="dd", domain="www.google.com", max_conns=0, limit_bytes=0, expires_at=None):
    if not _valid_secret_hex(secret_hex):
        _LOG.warning("telemt MTProto upsert refused for uid %s: secret must be 32 hex characters", uid)
        return False
    body = {"secret": secret_hex.lower()}
    try:
        if max_conns and int(max_conns) > 0:
            body["max_tcp_conns"] = int(max_conns)
        if limit_bytes and int(limit_bytes) > 0:
            body["data_quota_bytes"] = int(limit_bytes)
    except (TypeError, ValueError):
        return False
    expires_text = None
    if expires_at is not None:
        expires_text = _rfc3339(expires_at)
        if expires_text is None:
            return False
        body["expiration_rfc3339"] = expires_text
    username = _telemt_username(uid)
    async with _telemt_lock("mtproto-upsert"):
        _TELEMT_MTPROTO_USERS[username] = {"uid": str(uid), "secret_hex": secret_hex.lower(), "max_conns": int(max_conns or 0), "limit_bytes": int(limit_bytes or 0), "expires_at": expires_text}
        entry = _TELEMT_MTPROTO
        if entry is None or not entry.get("ready"):
            started = await telemt_start_mtproto()
            if not started.get("enabled"):
                return False
            entry = _TELEMT_MTPROTO
            return await _telemt_mtproto_wait_live(entry, username)
        try:
            _write_mtproto_config(entry)
        except OSError:
            pass
        if await _telemt_mtproto_upsert_api(entry, username, body):
            return await _telemt_mtproto_wait_live(entry, username)
        _LOG.warning("telemt MTProto API upsert failed for user %s; restarting the MTProto child so the user is live from its config", username)
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
            return await _restart_mtproto_entry(entry)
        path = "/v1/users/" + _url_path_quote(username, safe="")
        status, payload = None, {}
        for attempt in range(5):
            status, payload = await _telemt_api_async(entry["api_port"], entry["token"], "DELETE", path)
            if status in (200, 202) and payload.get("ok"):
                return True
            if status == 404:
                return True
            if status == 409:
                if _telemt_error_code(payload) == "reload_in_progress":
                    await asyncio.sleep(1.0)
                    continue
                status, payload = await _telemt_api_async(entry["api_port"], entry["token"], "POST", path + "/disable")
                if status in (200, 202) and payload.get("ok"):
                    _LOG.warning("telemt refused to delete the last MTProto user %s; disabled it instead", uid)
                    return True
                return False
            break
        _LOG.warning("telemt MTProto remove failed for user %s: %s; restarting the MTProto child so the user is gone from its config", uid, _telemt_api_error(payload))
        return await _restart_mtproto_entry(entry)


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


async def telemt_start_web(uid, token, secret_hex, host, max_sessions=8, max_streams=512, public_ip=None, root_enabled=False):
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
            if fields.get("web_token") == token and fields.get("secret_hex") == secret_hex.lower() and fields.get("host") == host and fields.get("public_ip") == resolved_ip and fields.get("max_sessions") == max_sessions and fields.get("max_streams") == max_streams and bool(fields.get("root_enabled")) == bool(root_enabled):
                return {"enabled": True, "port": entry["port"], "api_port": entry["api_port"], "error": ""}
        if entry is not None:
            await _stop_entry(entry)
            _TELEMT_WEB.pop(key, None)
        base = _telemt_dir()
        run_dir = os.path.join(base, _telemt_username(key))
        os.makedirs(run_dir, exist_ok=True)
        config_path = os.path.join(run_dir, "config.toml")
        port = _free_loopback_port()
        api_port = _free_loopback_port()
        bearer = _random_bearer()
        fields = {"uid": key, "web_token": token, "secret_hex": secret_hex.lower(), "host": host, "public_ip": resolved_ip, "max_sessions": max_sessions, "max_streams": max_streams, "root_enabled": bool(root_enabled)}
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


async def _web_patch_root(entry, enabled):
    status, payload = await _telemt_api_async(entry["api_port"], entry["token"], "GET", "/v1/config")
    if status != 200 or not payload.get("ok"):
        entry["root_error"] = "telemt config read failed: " + _telemt_api_error(payload)
        _LOG.warning("telemt WEB root PATCH aborted for uid %s: config read failed: %s", entry["key"], _telemt_api_error(payload))
        return False
    try:
        vhosts = list(((payload.get("data") or {}).get("web") or {}).get("vhosts") or [])
    except (AttributeError, TypeError):
        entry["root_error"] = "telemt config has no web vhosts"
        _LOG.warning("telemt WEB root PATCH aborted for uid %s: config has no web vhosts", entry["key"])
        return False
    fields = entry["fields"]
    target_base = "" if enabled else fields["web_token"]
    replaced = False
    new_vhosts = []
    for vhost in vhosts:
        if isinstance(vhost, dict) and str(vhost.get("host", "")).lower() == fields["host"]:
            item = dict(vhost)
            item["base_path"] = target_base
            new_vhosts.append(item)
            replaced = True
        else:
            new_vhosts.append(vhost)
    if not replaced:
        new_vhosts.append(_web_root_vhost(fields, enabled))
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
        if status == 409 and _telemt_error_code(payload) == "reload_in_progress":
            await asyncio.sleep(1.0)
            continue
        break
    if not patched:
        entry["root_error"] = "telemt config PATCH failed: " + _telemt_api_error(payload)
        _LOG.warning("telemt WEB root PATCH failed for uid %s: %s", entry["key"], _telemt_api_error(payload))
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
        entry["root_error"] = "telemt config PATCH failed: reload id missing"
        _LOG.warning("telemt WEB root PATCH failed for uid %s: reload id missing", entry["key"])
        return False
    deadline = time.monotonic() + 30.0
    while time.monotonic() < deadline:
        status, payload = await _telemt_api_async(entry["api_port"], entry["token"], "GET", "/v1/system/reload/" + str(reload_id))
        if status == 200 and payload.get("ok"):
            state = (payload.get("data") or {}).get("state")
            if state == "succeeded":
                entry["root_error"] = ""
                return True
            if state in ("failed", "rolled_back"):
                entry["root_error"] = "telemt config reload " + str(state) + ": " + _telemt_api_error(payload)
                _LOG.warning("telemt WEB root reload %s for uid %s: %s", state, entry["key"], _telemt_api_error(payload))
                return False
        await asyncio.sleep(0.5)
    entry["root_error"] = "telemt config reload timed out after 30s (reload stayed in preparing state)"
    _LOG.warning("telemt WEB root reload timed out for uid %s", entry["key"])
    return False


async def _web_restart_with_root(key, enabled):
    entry = _TELEMT_WEB.get(key)
    if entry is None:
        return False
    entry["fields"]["root_enabled"] = bool(enabled)
    await _stop_entry(entry)
    _TELEMT_WEB.pop(key, None)
    fresh = _new_telemt_entry("web", key, entry["run_dir"], entry["config_path"], entry["port"], entry["api_port"], entry["token"])
    fresh["fields"] = entry["fields"]
    fresh["root_error"] = ""
    _TELEMT_WEB[key] = fresh
    fresh["task"] = asyncio.create_task(_supervise_entry(fresh))
    ready = await _wait_entry_ready(fresh, timeout=30.0)
    if not ready:
        fresh["root_error"] = "telemt WEB child did not become ready within 30s after restart: " + str(fresh.get("error") or "")
        return False
    base_path, base_err = await telemt_web_base_path(key)
    if base_err:
        fresh["root_error"] = "telemt WEB child is ready but its root vhost could not be verified: " + str(base_err)
        return False
    if bool(enabled) and base_path != "":
        fresh["root_error"] = "telemt WEB child is ready but its vhost base_path is still " + repr(base_path) + " instead of root"
        return False
    if not bool(enabled) and base_path == "":
        fresh["root_error"] = "telemt WEB child is ready but its vhost is still at the root instead of its token path"
        return False
    fresh["root_error"] = ""
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


async def telemt_web_set_root(uid, enabled):
    key = str(uid)
    entry = _TELEMT_WEB.get(key)
    if entry is None:
        return False
    async with _telemt_lock("web:" + key):
        entry = _TELEMT_WEB.get(key)
        if entry is None:
            return False
        if not entry.get("ready"):
            entry["root_error"] = "telemt WEB child is not ready yet, root vhost cannot be enabled"
            return False
        fields = entry["fields"]
        if bool(fields.get("root_enabled")) == bool(enabled):
            return True
        if await _web_patch_root(entry, bool(enabled)):
            fields["root_enabled"] = bool(enabled)
            return True
        _LOG.warning("telemt WEB root PATCH path failed for uid %s; restarting child with root vhost", key)
        return await _web_restart_with_root(key, bool(enabled))


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
    mtproto = {"enabled": False, "port": 0, "api_port": 0, "error": error or "telemt MTProto child is not running", "healthy": False}
    entry = _TELEMT_MTPROTO
    if entry is not None and entry.get("proc") is not None and entry["proc"].returncode is None:
        status, payload = await _telemt_api_async(entry["api_port"], entry["token"], "GET", "/v1/health", timeout=5.0)
        healthy = status == 200 and bool(payload.get("ok"))
        mtproto = {"enabled": True, "port": entry["port"], "api_port": entry["api_port"], "error": "" if healthy else (entry.get("error") or "telemt MTProto API did not answer"), "healthy": healthy}
    elif entry is not None and entry.get("error"):
        mtproto["error"] = entry["error"]
    web = {}
    for key in list(_TELEMT_WEB.keys()):
        web[key] = await telemt_web_status(key)
    return {"available": available, "mtproto": mtproto, "web": web, "error": error}


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
            server = await asyncio.start_server(_handle_multi, "0.0.0.0", port)
            _SERVERS.append(server)
            _BOUND_PORTS.add(port)
            _BIND_ERRORS.pop(port, None)
            bound.append(port)
        except OSError as exc:
            failed[port] = _bind_error_text(port, exc)
            _BIND_ERRORS[port] = _bind_error_text(port, exc)
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
            server = await asyncio.start_server(_handle_multi, "0.0.0.0", port)
            _SERVERS.append(server)
            _BOUND_PORTS.add(port)
            _BIND_ERRORS.pop(port, None)
            bound.append(port)
        except OSError as exc:
            failed[port] = _bind_error_text(port, exc)
            _BIND_ERRORS[port] = _bind_error_text(port, exc)
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
