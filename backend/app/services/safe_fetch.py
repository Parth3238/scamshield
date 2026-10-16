"""SSRF-safe URL fetcher for ScamShield.

Every user-supplied URL is validated before any network request, and again
after every redirect. Only public http/https targets on ports 80/443 are
allowed.
"""

from __future__ import annotations

import ipaddress
import socket
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

import httpx

# How we stop DNS rebinding (TOCTOU): each hostname is resolved exactly ONCE
# per redirect hop, EVERY returned IP is checked against the block-list, and
# the request is then sent to one of those already-validated IPs (never back
# through the hostname, so a later answer of 127.0.0.1 is never used). The
# original hostname still travels in the HTTP Host header and, for HTTPS, as
# the TLS SNI name, with certificate verification left ON against that name.
# Still out of scope: a compromised site proxying to internal hosts, and
# anything an outbound firewall/DNS filter would need to enforce.
#
# Certificate verification is NEVER disabled anywhere in this module.

ALLOWED_SCHEMES = {"http", "https"}
ALLOWED_PORTS = {80, 443}
DEFAULT_PORTS = {"http": 80, "https": 443}
MAX_REDIRECTS = 5
MAX_BODY_BYTES = 1024 * 1024  # 1 MB
REQUEST_TIMEOUT = 5.0
REDIRECT_STATUSES = {301, 302, 303, 307, 308}


class SafeFetchError(Exception):
    """Base class for all safe_fetch errors."""


class BlockedURLError(SafeFetchError):
    """Raised when a URL fails the SSRF allow-list (scheme/port/IP)."""


class TooManyRedirectsError(SafeFetchError):
    """Raised when redirect hops exceed the maximum."""


class ResponseTooLargeError(SafeFetchError):
    """Raised when the response body exceeds the size limit."""


class FetchTimeoutError(SafeFetchError):
    """Raised when a request times out."""


@dataclass
class FetchResult:
    final_url: str
    status_code: int
    redirect_chain: list[str] = field(default_factory=list)
    body: str = ""
    elapsed_seconds: float = 0.0


def _parse_int_part(part: str) -> int | None:
    """Parse one IPv4 part allowing decimal, hex (0x) and octal (leading 0)."""
    s = part.strip().lower()
    if not s:
        return None
    try:
        if s.startswith("0x"):
            return int(s, 16)
        if len(s) > 1 and s.startswith("0") and s.isdigit():
            # Leading zero means octal in classic inet_aton behaviour.
            # Guard against invalid octal digits like '8' or '9'.
            if any(c in "89" for c in s):
                return None
            return int(s, 8)
        if s.isdigit():
            return int(s, 10)
        # Bare hex without dots is handled as single-number below.
        return int(s, 16) if all(c in "0123456789abcdef" for c in s) else None
    except ValueError:
        return None


def _tricky_ipv4_to_ip(host: str) -> ipaddress.IPv4Address | None:
    """Convert decimal/hex/octal IPv4 forms (e.g. '2130706433') to an IP.

    Returns None when the host is not such a numeric form. This covers the
    bypass where 127.0.0.1 is written as a single decimal integer, hex, or
    octal, which ipaddress.ip_address() and Windows getaddrinfo() reject.
    """
    h = host.strip().lower().rstrip(".")
    if not h or ":" in h:
        return None  # IPv6 or empty: not our case.
    # Single-number form: decimal, 0x-hex, or 0-octal.
    if "." not in h:
        try:
            if h.startswith("0x"):
                value = int(h, 16)
            elif len(h) > 1 and h.startswith("0") and h.isdigit():
                if any(c in "89" for c in h):
                    return None
                value = int(h, 8)
            elif h.isdigit():
                value = int(h, 10)
            else:
                return None
        except ValueError:
            return None
        if 0 <= value <= 0xFFFFFFFF:
            return ipaddress.IPv4Address(value)
        return None
    # Dotted forms with 2-4 parts, each part decimal/hex/octal.
    parts = h.split(".")
    if len(parts) > 4:
        return None
    nums: list[int] = []
    for p in parts:
        n = _parse_int_part(p)
        if n is None or n < 0:
            return None
        nums.append(n)
    try:
        if len(nums) == 2:
            a, b = nums
            if not (0 <= a <= 255 and 0 <= b <= 0xFFFFFF):
                return None
            return ipaddress.IPv4Address(
                bytes([a, (b >> 16) & 0xFF, (b >> 8) & 0xFF, b & 0xFF])
            )
        if len(nums) == 3:
            a, b, c = nums
            if not (0 <= a <= 255 and 0 <= b <= 255 and 0 <= c <= 0xFFFF):
                return None
            return ipaddress.IPv4Address(bytes([a, b, (c >> 8) & 0xFF, c & 0xFF]))
        if len(nums) == 4:
            if not all(0 <= n <= 255 for n in nums):
                return None
            return ipaddress.IPv4Address(bytes(nums))
    except (ipaddress.AddressValueError, ValueError):
        return None
    return None


def _is_blocked_ip(ip: ipaddress._BaseAddress) -> bool:
    """True when the IP must never be fetched (private/loopback/etc)."""
    return bool(
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


def _check_ip_list(ips: list[ipaddress._BaseAddress], url: str) -> None:
    for ip in ips:
        if _is_blocked_ip(ip):
            raise BlockedURLError(f"blocked IP {ip} for URL {url!r}")


# Resolver: hostname -> list of IP strings. Swappable so tests can inject
# a fake without touching real DNS.
Resolver = Callable[[str], list[str]]


def default_resolver(hostname: str) -> list[str]:
    """Resolve a hostname to IP strings using the system resolver."""
    try:
        infos = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError, OverflowError) as exc:
        raise BlockedURLError(f"cannot resolve host {hostname!r}: {exc}") from exc
    if not infos:
        raise BlockedURLError(f"cannot resolve host {hostname!r}")
    return [sockaddr[0] for _, _, _, _, sockaddr in infos]


def validate_url(url: str, resolver: Resolver = default_resolver):
    """Validate scheme, port and resolved IPs.

    Returns (parsed_url, pinned_ips): pinned_ips is the list of validated IP
    strings to connect to for a DNS hostname, or None for IP literals (which
    need no DNS and are already pinned). Raises BlockedURLError when anything
    is disallowed.
    """
    try:
        parsed = urlparse(url)
    except Exception as exc:
        raise BlockedURLError(f"unparseable URL {url!r}: {exc}") from exc

    scheme = (parsed.scheme or "").lower()
    if scheme not in ALLOWED_SCHEMES:
        raise BlockedURLError(f"blocked scheme {scheme!r} for URL {url!r}")

    host = parsed.hostname
    if not host:
        raise BlockedURLError(f"missing hostname for URL {url!r}")
    host = host.strip().rstrip(".")

    try:
        raw_port = parsed.port
    except ValueError as exc:
        raise BlockedURLError(f"invalid port for URL {url!r}: {exc}") from exc
    port = raw_port if raw_port is not None else DEFAULT_PORTS[scheme]
    if port not in ALLOWED_PORTS:
        raise BlockedURLError(f"blocked port {port} for URL {url!r}")

    # 1) Tricky numeric IPv4 forms (decimal/hex/octal) first, because
    # ipaddress and getaddrinfo on some platforms reject them even though
    # browsers/servers may still interpret them as IPs.
    tricky = _tricky_ipv4_to_ip(host)
    if tricky is not None:
        _check_ip_list([tricky], url)
        # Public numeric IP: accept without DNS (getaddrinfo would fail
        # for these forms on Windows). Private ones already raised above.
        return parsed, None

    # 2) Standard IP literals (covers normal IPv4 and all IPv6).
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is not None:
        _check_ip_list([literal], url)
        return parsed, None

    # 3) DNS hostnames: resolve ONCE and check EVERY address (IPv4 + IPv6).
    # The caller must connect to one of the returned IPs, never resolve again.
    ip_strings = resolver(host)
    if not ip_strings:
        raise BlockedURLError(f"cannot resolve host {host!r}")
    resolved: list[ipaddress._BaseAddress] = []
    for ip_str in ip_strings:
        try:
            resolved.append(ipaddress.ip_address(ip_str))
        except ValueError as exc:
            raise BlockedURLError(f"unparseable DNS IP {ip_str!r}: {exc}") from exc
    _check_ip_list(resolved, url)
    return parsed, [str(ip) for ip in resolved]


def _wire_request(parsed, pinned_ip: str | None):
    """Build the on-the-wire (url, headers, extensions) for one hop.

    pinned_ip is None for IP literals (request the URL unchanged). For DNS
    hostnames it is one already-validated IP: the URL host is swapped to it
    while the original hostname is kept in the Host header and, for HTTPS,
    as the TLS SNI name so certificate verification still checks the real
    name. Verification is never turned off.
    """
    scheme = (parsed.scheme or "").lower()
    host = (parsed.hostname or "").strip().rstrip(".")
    if pinned_ip is None:
        return parsed.geturl(), {}, {}
    ip_host = f"[{pinned_ip}]" if ":" in pinned_ip else pinned_ip
    userinfo = ""
    if parsed.username:
        userinfo = parsed.username
        if parsed.password:
            userinfo += f":{parsed.password}"
        userinfo += "@"
    explicit_port = parsed.port is not None
    netloc = userinfo + ip_host + (f":{parsed.port}" if explicit_port else "")
    wire_url = parsed._replace(netloc=netloc).geturl()
    if parsed.port is None or parsed.port == DEFAULT_PORTS[scheme]:
        host_header = host
    else:
        host_header = f"{host}:{parsed.port}"
    headers = {"host": host_header}
    # sni_hostname makes TLS verify the cert against the original hostname
    # even though the socket goes to the pinned IP.
    extensions = {"sni_hostname": host} if scheme == "https" else {}
    return wire_url, headers, extensions


def safe_fetch(
    url: str,
    *,
    transport: httpx.BaseTransport | None = None,
    resolver: Resolver = default_resolver,
    timeout: float = REQUEST_TIMEOUT,
    max_redirects: int = MAX_REDIRECTS,
    max_bytes: int = MAX_BODY_BYTES,
) -> FetchResult:
    """Fetch a URL with SSRF protection. Follows redirects manually.

    Each redirect target is resolved once, fully validated, and then
    contacted at a validated IP (see module comment). Responses are streamed
    so a body larger than max_bytes aborts early instead of loading into
    memory. Pass transport=httpx.MockTransport(...) in tests to avoid real
    internet, and resolver=<fake> to avoid real DNS.
    """
    start = time.monotonic()
    redirect_chain: list[str] = []
    current_url = url

    with httpx.Client(follow_redirects=False, timeout=timeout, transport=transport) as client:
        for attempt in range(max_redirects + 1):
            parsed, pinned_ips = validate_url(current_url, resolver=resolver)
            redirect_chain.append(current_url)
            # Literals are already pinned; hostnames try each validated IP
            # from this single resolution, never resolving again.
            candidates: list[str | None] = list(pinned_ips) if pinned_ips else [None]
            connect_error: httpx.ConnectError | None = None

            candidates: list[str | None] = list(pinned_ips) if pinned_ips else [None]
            connect_error: httpx.ConnectError | None = None
            followed_redirect = False

            try:
                for candidate in candidates:
                    wire_url, req_headers, req_ext = _wire_request(parsed, candidate)
                    try:
                        with client.stream(
                            "GET", wire_url, headers=req_headers, extensions=req_ext
                        ) as response:
                            status = response.status_code
                            location = response.headers.get("location")

                            if status in REDIRECT_STATUSES and location:
                                if attempt == max_redirects:
                                    raise TooManyRedirectsError(
                                        f"more than {max_redirects} redirects starting from {url!r}"
                                    )
                                # Discard any redirect body, then follow manually so
                                # the next loop iteration re-validates the target.
                                response.close()
                                current_url = urljoin(current_url, location)
                                followed_redirect = True
                                break

                            # Early reject when the server announces a huge body.
                            length = response.headers.get("content-length")
                            if length is not None:
                                try:
                                    if int(length) > max_bytes:
                                        raise ResponseTooLargeError(
                                            f"content-length {length} exceeds {max_bytes} bytes"
                                        )
                                except ValueError:
                                    pass

                            chunks: list[bytes] = []
                            total = 0
                            for chunk in response.iter_bytes(chunk_size=8192):
                                total += len(chunk)
                                if total > max_bytes:
                                    raise ResponseTooLargeError(
                                        f"body exceeds {max_bytes} bytes for {current_url!r}"
                                    )
                                chunks.append(chunk)
                            body = b"".join(chunks).decode("utf-8", errors="replace")
                            elapsed = time.monotonic() - start
                            return FetchResult(
                                final_url=current_url,
                                status_code=status,
                                redirect_chain=list(redirect_chain),
                                body=body,
                                elapsed_seconds=elapsed,
                            )
                    except httpx.ConnectError as exc:
                        # Try the next already-validated IP from the same
                        # resolution. The name is never resolved again.
                        connect_error = exc
                        continue
                else:
                    # No break: every validated IP failed to connect.
                    if connect_error is not None:
                        if isinstance(connect_error, httpx.TimeoutException):
                            raise FetchTimeoutError(
                                f"timeout fetching {current_url!r}: {connect_error}"
                            ) from connect_error
                        raise SafeFetchError(
                            f"fetch failed for {current_url!r}: {connect_error}"
                        ) from connect_error
            except httpx.TimeoutException as exc:
                raise FetchTimeoutError(f"timeout fetching {current_url!r}: {exc}") from exc
            except (ResponseTooLargeError, TooManyRedirectsError, BlockedURLError):
                raise
            except httpx.HTTPError as exc:
                raise SafeFetchError(f"fetch failed for {current_url!r}: {exc}") from exc

            if followed_redirect:
                continue

    # Unreachable in practice: the loop returns or raises above.
    raise TooManyRedirectsError(f"more than {max_redirects} redirects from {url!r}")
