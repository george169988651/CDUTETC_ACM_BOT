"""链接抓取模块：带 SSRF 防护与资源限制的正文抓取。

设计要点：
- 仅允许 HTTP/HTTPS，拒绝带用户名/密码的 URL。
- 每次连接前解析并校验目标主机全部地址：回环、私网、链路本地、保留地址、
  组播、未指定地址一律拒绝（IPv4 + IPv6）。
- 用 socket 直连「已校验的 IP」发起请求，而不是让请求库独立二次解析，
  从机制上规避 DNS 重绑定 / TOCTOU（检查时解析结果 ≠ 实际连接地址）。
  HTTPS 时 SNI 与证书校验仍使用原始域名。
- 手动跟随重定向，每跳重新解析与校验；跳数上限由配置控制。
- 流式读取，限制读取与解压后响应体大小，超限立即中止；
  Content-Length 仅用于提前拒绝，不作为唯一保护。
- 可选域名白名单（推荐配置），抓取目标与跳转目标统一校验。
- 失败抛 FetchError（含原因），由上层决定如何提示，绝不返回可入库的空正文。
"""

import asyncio
import ipaddress
import logging
import socket
import ssl
import zlib
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

import config

logger = logging.getLogger(__name__)

_ALLOWED_SCHEMES = ("http", "https")
_ALLOWED_CTYPES = {
    "text/html", "text/plain", "text/markdown",
    "application/xhtml+xml", "application/xml", "text/xml", "application/json",
}
_UA = "Mozilla/5.0 (compatible; CDUTETC-ACM-Bot/1.0; +https://q.qq.com)"
_MAX_HEADER_BYTES = 65536

_sem = asyncio.Semaphore(config.FETCH_CONCURRENCY)


class FetchError(Exception):
    """抓取失败（含安全拒绝），携带用户可读原因。"""


# ---------- 安全校验 ----------


def _is_public_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """非公网地址一律拒绝：回环/私网/链路本地/保留/组播/未指定。"""
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


def _parse_url(url: str) -> tuple[str, str, int] | None:
    """解析 URL，仅接受无凭据的 http/https，返回 (scheme, host, port)。"""
    try:
        parsed = urlparse(url)
    except ValueError:
        return None
    if parsed.scheme not in _ALLOWED_SCHEMES:
        return None
    if parsed.username or parsed.password:
        return None
    host = parsed.hostname or ""
    if not host:
        return None
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return parsed.scheme, host, port


async def _resolve_public_ip(host: str) -> str:
    """解析主机名并校验所有地址均为公网；返回第一个可用 IP。

    域名白名单（若配置）在此检查；白名单校验在解析之前，避免先做 DNS。
    """
    if config.FETCH_ALLOWED_DOMAINS and host not in config.FETCH_ALLOWED_DOMAINS:
        raise FetchError(f"域名不在抓取白名单: {host}")
    try:
        infos = await asyncio.get_running_loop().getaddrinfo(
            host, None, type=socket.SOCK_STREAM
        )
    except socket.gaierror:
        raise FetchError(f"无法解析域名: {host}") from None
    public: list[str] = []
    for info in infos:
        try:
            ip = ipaddress.ip_address(info[4][0])
        except ValueError:
            continue
        if not _is_public_ip(ip):
            raise FetchError(f"目标地址非公网，已拒绝连接: {ip}（域名 {host}）")
        public.append(str(ip))
    if not public:
        raise FetchError(f"目标主机无可用地址: {host}")
    return public[0]


# ---------- 底层 HTTP/1.1 流式读取 ----------


async def _connect(host: str, ip: str, port: int, scheme: str):
    """直连已校验 IP；HTTPS 用原始 host 做 SNI 与证书校验。"""
    ctx = ssl.create_default_context() if scheme == "https" else None
    try:
        return await asyncio.wait_for(
            asyncio.open_connection(
                host=ip, port=port, ssl=ctx, server_hostname=host if ctx else None
            ),
            timeout=config.FETCH_TIMEOUT,
        )
    except (OSError, asyncio.TimeoutError) as e:
        raise FetchError(f"连接失败（{host}:{port}）: {e}") from e


async def _read_headers(reader) -> tuple[int, dict[str, str]]:
    data = b""
    while b"\r\n\r\n" not in data:
        try:
            chunk = await asyncio.wait_for(reader.read(4096), timeout=config.FETCH_TIMEOUT)
        except asyncio.TimeoutError:
            raise FetchError("读取响应头超时") from None
        if not chunk:
            raise FetchError("响应头读取失败（连接提前关闭）")
        data += chunk
        if len(data) > _MAX_HEADER_BYTES:
            raise FetchError("响应头过大")
    header_block, _, rest = data.partition(b"\r\n\r\n")
    lines = header_block.split(b"\r\n")
    parts = lines[0].split(b" ")
    if len(parts) < 2 or not parts[1].isdigit():
        raise FetchError("响应状态行非法")
    status = int(parts[1])
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if b":" in line:
            k, _, v = line.partition(b":")
            headers[k.decode("latin-1").strip().lower()] = v.decode("latin-1").strip()
    return status, headers, rest


async def _read_body(reader, headers: dict[str, str], initial: bytes) -> bytes:
    limit = config.FETCH_MAX_BYTES
    te = headers.get("transfer-encoding", "").lower()
    cl_raw = headers.get("content-length")

    if cl_raw is not None:
        if not cl_raw.isdigit():
            raise FetchError("非法 Content-Length")
        if int(cl_raw) > limit:
            raise FetchError(f"响应体过大（Content-Length={cl_raw}）已提前拒绝")

    if "chunked" in te:
        return await _read_chunked(reader, initial, limit)
    return await _read_fixed(reader, initial, limit, int(cl_raw) if cl_raw else None)


async def _read_fixed(reader, initial: bytes, limit: int, expected: int | None) -> bytes:
    parts = [initial]
    total = len(initial)
    while True:
        if expected is not None and total >= expected:
            break
        try:
            chunk = await asyncio.wait_for(reader.read(65536), timeout=config.FETCH_TIMEOUT)
        except asyncio.TimeoutError:
            raise FetchError("读取响应体超时") from None
        if not chunk:
            break  # EOF（Connection: close 收尾）
        total += len(chunk)
        if total > limit:
            raise FetchError(f"响应体超过大小上限（{limit} 字节），已中止")
        parts.append(chunk)
    return b"".join(parts)


async def _read_chunked(reader, initial: bytes, limit: int) -> bytes:
    buf = initial
    parts: list[bytes] = []
    total = 0
    while True:
        while b"\r\n" not in buf:
            try:
                chunk = await asyncio.wait_for(reader.read(65536), timeout=config.FETCH_TIMEOUT)
            except asyncio.TimeoutError:
                raise FetchError("读取响应体超时") from None
            if not chunk:
                raise FetchError("chunked 响应不完整")
            buf += chunk
            if len(buf) > 65536 + 64:
                raise FetchError("chunk 头过大")
        line, _, buf = buf.partition(b"\r\n")
        size_str = line.split(b";")[0].strip()
        if not size_str or not all(c in b"0123456789abcdefABCDEF" for c in size_str):
            raise FetchError("非法 chunk 大小")
        size = int(size_str, 16)
        if size == 0:
            break
        total += size
        if total > limit:
            raise FetchError(f"响应体超过大小上限（{limit} 字节），已中止")
        while len(buf) < size + 2:
            try:
                chunk = await asyncio.wait_for(reader.read(65536), timeout=config.FETCH_TIMEOUT)
            except asyncio.TimeoutError:
                raise FetchError("读取响应体超时") from None
            if not chunk:
                raise FetchError("chunked 响应不完整")
            buf += chunk
        parts.append(buf[:size])
        buf = buf[size + 2:]
    return b"".join(parts)


def _decompress_gzip(data: bytes) -> bytes:
    """边解压边限制解压后大小，防止压缩炸弹。"""
    limit = config.FETCH_MAX_BYTES
    d = zlib.decompressobj(16 + zlib.MAX_WBITS)
    out: list[bytes] = []
    total = 0
    for i in range(0, len(data), 65536):
        piece = d.decompress(data[i : i + 65536])
        total += len(piece)
        if total > limit:
            raise FetchError(f"解压后响应体超过大小上限（{limit} 字节），已中止")
        out.append(piece)
    tail = d.flush()
    total += len(tail)
    if total > limit:
        raise FetchError(f"解压后响应体超过大小上限（{limit} 字节），已中止")
    out.append(tail)
    return b"".join(out)


async def _request_once(url: str) -> tuple[int, dict[str, str], bytes]:
    """对单个 URL 发一次 GET（直连已校验 IP），返回 (status, headers, body)。"""
    parsed = _parse_url(url)
    if parsed is None:
        raise FetchError("仅支持无账号密码的 http/https 链接")
    scheme, host, port = parsed
    ip = await _resolve_public_ip(host)
    reader, writer = await _connect(host, ip, port, scheme)
    try:
        req = (
            f"GET {url} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: {_UA}\r\n"
            "Accept: text/html,text/plain,application/json,application/xml;q=0.9,*/*;q=0.1\r\n"
            "Accept-Encoding: gzip\r\n"
            "Connection: close\r\n\r\n"
        )
        writer.write(req.encode("ascii", "ignore"))
        await writer.drain()
        status, headers, rest = await _read_headers(reader)
        body = await _read_body(reader, headers, rest)
        if headers.get("content-encoding", "").lower() == "gzip":
            body = _decompress_gzip(body)
        return status, headers, body
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


# ---------- 公开入口 ----------


def _extract_text(body: bytes, content_type: str, source_url: str) -> str:
    ctype = (content_type or "").split(";")[0].strip().lower()
    if ctype not in _ALLOWED_CTYPES:
        raise FetchError(f"不支持的响应类型: {ctype or '未知'}")
    text = body.decode("utf-8", errors="replace")
    if ctype in ("text/html", "application/xhtml+xml"):
        soup = BeautifulSoup(text, "html.parser")
        for tag in soup(["script", "style", "noscript", "iframe"]):
            tag.decompose()
        text = soup.get_text("\n", strip=True)
    if len(text) > config.FETCH_TEXT_LIMIT:
        text = text[: config.FETCH_TEXT_LIMIT]
    logger.info("抓取成功: %s（%d 字符）", source_url, len(text))
    return text


async def fetch_text(url: str) -> str:
    """抓取网页正文文本（含手动重定向跟随与逐跳校验）。

    Args:
        url: 初始链接。

    Returns:
        正文纯文本（已截断到 FETCH_TEXT_LIMIT）。

    Raises:
        FetchError: 任何抓取失败 / 安全拒绝，带用户可读原因。
    """
    text, _ = await fetch_text_with_headers(url)
    return text


async def fetch_text_with_headers(url: str) -> tuple[str, dict[str, str]]:
    """抓取网页正文，同时返回响应头（含 ETag / Last-Modified）。

    用于公共来源变化检测：上游（crawler）可结合 ETag、Last-Modified
    与正文哈希判断“是否实质变化”，只有实质变化才调模型生成草稿。

    Returns:
        (正文纯文本, 响应头 dict，键名小写)。

    Raises:
        FetchError: 任何抓取失败 / 安全拒绝，带用户可读原因。
    """
    async with _sem:
        current = url
        for hop in range(config.FETCH_MAX_REDIRECTS + 1):
            parsed = _parse_url(current)
            if parsed is None:
                raise FetchError("仅支持无账号密码的 http/https 链接")
            status, headers, body = await _request_once(current)
            if status in (301, 302, 303, 307, 308):
                location = headers.get("location")
                if not location:
                    raise FetchError("重定向响应缺少 Location")
                current = urljoin(current, location)
                logger.info("跟随重定向(%d/%d): %s", hop + 1, config.FETCH_MAX_REDIRECTS, current)
                continue
            if status >= 400:
                raise FetchError(f"HTTP 状态码 {status}")
            text = _extract_text(body, headers.get("content-type", ""), current)
            return text, headers
        raise FetchError(f"重定向次数超过上限（{config.FETCH_MAX_REDIRECTS}）")
