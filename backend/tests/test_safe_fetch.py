import socket
from unittest.mock import patch

import httpx
import pytest

from app.services.safe_fetch import (
    MAX_BODY_BYTES,
    BlockedURLError,
    ResponseTooLargeError,
    TooManyRedirectsError,
    safe_fetch,
)

PUBLIC_IP = "93.184.216.34"  # example.com (public, safe for tests)
_real_getaddrinfo = socket.getaddrinfo


def _fake_getaddrinfo(host, port, *args, **kwargs):
    # Public test hosts resolve to a public IP without real internet.
    # Everything else uses the real resolver (IP literals need no internet).
    if host in ("public.test", "example.com"):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (PUBLIC_IP, 0))]
    return _real_getaddrinfo(host, port, *args, **kwargs)


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost",
        "http://127.0.0.1",
        "http://0.0.0.0",
        "http://10.0.0.1",
        "http://192.168.1.1",
        "http://169.254.169.254",
        "http://[::1]",
        "http://2130706433",
    ],
)
def test_blocked_private_hosts(url):
    with pytest.raises(BlockedURLError):
        safe_fetch(url)


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "ftp://example.com",
    ],
)
def test_blocked_schemes(url):
    with pytest.raises(BlockedURLError):
        safe_fetch(url)


def test_blocked_port():
    with pytest.raises(BlockedURLError):
        safe_fetch("http://example.com:22")


def test_redirect_to_private_is_blocked():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": "http://127.0.0.1/"}, text="redir")

    transport = httpx.MockTransport(handler)
    with patch("socket.getaddrinfo", side_effect=_fake_getaddrinfo):
        with pytest.raises(BlockedURLError):
            safe_fetch("http://public.test/start", transport=transport)


def test_more_than_5_redirects_raises():
    def handler(request: httpx.Request) -> httpx.Response:
        # Infinite redirect loop: /r0 -> /r1 -> /r2 -> ...
        path = request.url.path
        try:
            n = int(path.replace("/r", "") or 0)
        except ValueError:
            n = 0
        return httpx.Response(
            302, headers={"location": f"http://public.test/r{n + 1}"}, text="redir"
        )

    transport = httpx.MockTransport(handler)
    with patch("socket.getaddrinfo", side_effect=_fake_getaddrinfo):
        with pytest.raises(TooManyRedirectsError):
            safe_fetch("http://public.test/r0", transport=transport)


def test_response_bigger_than_1mb_raises():
    big = b"x" * (MAX_BODY_BYTES + 1024)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=big)

    transport = httpx.MockTransport(handler)
    with patch("socket.getaddrinfo", side_effect=_fake_getaddrinfo):
        with pytest.raises(ResponseTooLargeError):
            safe_fetch("http://public.test/big", transport=transport)


def test_normal_public_url():
    seen: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        # Wired to the validated IP, with the original name in Host.
        seen["url"] = str(request.url)
        seen["host"] = request.headers.get("host", "")
        return httpx.Response(200, text="hello safe")

    transport = httpx.MockTransport(handler)
    with patch("socket.getaddrinfo", side_effect=_fake_getaddrinfo):
        result = safe_fetch("http://public.test/ok", transport=transport)

    assert seen["url"] == f"http://{PUBLIC_IP}/ok"
    assert seen["host"] == "public.test"
    assert result.status_code == 200
    assert result.final_url == "http://public.test/ok"
    assert result.redirect_chain == ["http://public.test/ok"]
    assert result.body == "hello safe"


def test_single_redirect_chain():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/start":
            return httpx.Response(
                302, headers={"location": "http://public.test/final"}, text="redir"
            )
        return httpx.Response(200, text="done")

    transport = httpx.MockTransport(handler)
    with patch("socket.getaddrinfo", side_effect=_fake_getaddrinfo):
        result = safe_fetch("http://public.test/start", transport=transport)

    assert result.status_code == 200
    assert result.final_url == "http://public.test/final"
    assert result.redirect_chain == [
        "http://public.test/start",
        "http://public.test/final",
    ]
    assert result.body == "done"


def test_rebinding_second_answer_never_used():
    # Malicious DNS: public IP now, 127.0.0.1 a moment later. The fetch must
    # go to the first (validated) answer and resolve only once per hop.
    from unittest.mock import Mock

    from app.services import safe_fetch as sf

    seen: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["host"] = request.url.host
        return httpx.Response(200, text="pinned")

    resolver = Mock(side_effect=[[PUBLIC_IP], ["127.0.0.1"]])
    transport = httpx.MockTransport(handler)
    result = sf.safe_fetch(
        "http://evil.test/page", transport=transport, resolver=resolver
    )

    assert result.status_code == 200
    assert result.body == "pinned"
    assert seen["host"] == PUBLIC_IP
    assert resolver.call_count == 1
    assert resolver.call_args[0] == ("evil.test",)


def test_mixed_public_and_private_ips_blocked():
    from app.services import safe_fetch as sf

    for answers in ([PUBLIC_IP, "10.0.0.1"], ["10.0.0.1", PUBLIC_IP]):
        def handler(request: httpx.Request) -> httpx.Response:  # pragma: no cover
            raise AssertionError("must never connect when any IP is blocked")

        transport = httpx.MockTransport(handler)
        with pytest.raises(BlockedURLError):
            sf.safe_fetch(
                "http://mixed.test/", transport=transport, resolver=lambda h: answers
            )


def test_host_header_and_sni_use_original_hostname():
    from app.services import safe_fetch as sf

    seen: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url_host"] = request.url.host
        seen["host_header"] = request.headers.get("host", "")
        seen["sni"] = request.extensions.get("sni_hostname")
        return httpx.Response(200, text="ok")

    transport = httpx.MockTransport(handler)
    result = sf.safe_fetch(
        "https://public.test/secure",
        transport=transport,
        resolver=lambda h: [PUBLIC_IP],
    )

    assert result.status_code == 200
    assert seen["url_host"] == PUBLIC_IP
    assert seen["host_header"] == "public.test"
    assert seen["sni"] == "public.test"


def test_http_has_no_sni_but_keeps_host_header():
    from app.services import safe_fetch as sf

    seen: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["sni"] = request.extensions.get("sni_hostname")
        seen["host_header"] = request.headers.get("host", "")
        return httpx.Response(200, text="ok")

    transport = httpx.MockTransport(handler)
    sf.safe_fetch(
        "http://public.test/plain", transport=transport, resolver=lambda h: [PUBLIC_IP]
    )

    assert seen["sni"] is None
    assert seen["host_header"] == "public.test"


def test_ipv6_resolution_works():
    from app.services import safe_fetch as sf

    ipv6 = "2606:2800:220:1:248:1893:25c8:1946"
    seen: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url_host"] = request.url.host
        seen["raw_path"] = request.url.path
        seen["host_header"] = request.headers.get("host", "")
        return httpx.Response(200, text="v6 ok")

    transport = httpx.MockTransport(handler)
    result = sf.safe_fetch(
        "http://v6.test/page", transport=transport, resolver=lambda h: [ipv6]
    )

    assert result.status_code == 200
    assert result.body == "v6 ok"
    assert seen["url_host"] == ipv6
    assert seen["host_header"] == "v6.test"
    assert result.final_url == "http://v6.test/page"


def test_failover_tries_next_validated_ip_without_reresolving():
    from unittest.mock import Mock

    from app.services import safe_fetch as sf

    ips = [PUBLIC_IP, "93.184.216.35"]
    seen_hosts: list[str] = []
    attempts = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        seen_hosts.append(request.url.host)
        attempts["n"] += 1
        if attempts["n"] == 1:
            raise httpx.ConnectError("first IP down", request=request)
        return httpx.Response(200, text="second works")

    resolver = Mock(return_value=ips)
    transport = httpx.MockTransport(handler)
    result = sf.safe_fetch(
        "http://flaky.test/", transport=transport, resolver=resolver
    )

    assert result.status_code == 200
    assert result.body == "second works"
    assert seen_hosts == ips
    assert resolver.call_count == 1
