"""Pinned HTTP policy tests; all network replies and TLS streams are local stubs."""

import asyncio
import ssl
import time
from collections.abc import AsyncIterator

import httpcore
import httpx
import pytest
from pydantic import ValidationError

from mail_triage.transport import (
    ConnectorError,
    ControlledTransport,
    EndpointPolicy,
    build_client,
)


def endpoint(**changes: object) -> EndpointPolicy:
    values: dict[str, object] = {
        "origin": "https://service.example.test:8443",
        "pinned_ip": "192.0.2.10",
        "allow_private_ip": True,
    }
    values.update(changes)
    return EndpointPolicy.model_validate(values)


class ReplyStream(httpx.AsyncByteStream):
    def __init__(self, chunks: list[bytes], delay: float = 0) -> None:
        self.chunks = chunks
        self.delay = delay
        self.closed = False
        self.iterated = False

    async def __aiter__(self) -> AsyncIterator[bytes]:
        self.iterated = True
        for chunk in self.chunks:
            if self.delay:
                await asyncio.sleep(self.delay)
            yield chunk

    async def aclose(self) -> None:
        self.closed = True


@pytest.mark.parametrize(
    "origin",
    [
        "http://service.example.test",
        "https://user:password@service.example.test",
        "https://service.example.test/",
        "https://service.example.test/path",
        "https://service.example.test?query",
        "https://service.example.test?",
        "https://service.example.test#fragment",
        "https://service.example.test#",
        "https://service.example.test\\attacker.test",
        "https://service.example.test\n",
        "https://service.example.test:0",
        "https://service.example.test:65536",
        "https://*.example.test",
        "https://\u2603.example.test",
    ],
)
def test_origin_requires_explicit_credential_free_https_origin(origin: str) -> None:
    with pytest.raises(ValidationError):
        endpoint(origin=origin)


@pytest.mark.parametrize(
    "pin",
    [
        "127.0.0.1",
        "169.254.169.254",
        "224.0.0.1",
        "0.0.0.0",
        "::1",
        "fe80::1",
        "ff02::1",
        "::",
        "::ffff:127.0.0.1",
        "::ffff:169.254.169.254",
        "10.0.0.0/8",
        "service.example.test",
        "2001:4860:4860::8888%en0",
    ],
)
def test_forbidden_or_nonliteral_pins_stay_forbidden_with_private_opt_in(pin: str) -> None:
    with pytest.raises(ValidationError):
        endpoint(pinned_ip=pin)


def test_non_global_pin_needs_explicit_exception_and_policy_is_frozen() -> None:
    with pytest.raises(ValidationError):
        endpoint(allow_private_ip=False)
    assert endpoint(pinned_ip="10.20.30.40").pinned_ip == "10.20.30.40"
    assert endpoint(pinned_ip="8.8.8.8", allow_private_ip=False).pinned_ip == "8.8.8.8"
    policy = endpoint()
    with pytest.raises(ValidationError):
        policy.pinned_ip = "127.0.0.1"
    with pytest.raises(ValidationError):
        ControlledTransport(policy.model_copy(update={"pinned_ip": "127.0.0.1"}), set())


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("connect_timeout", 0.09),
        ("connect_timeout", 31),
        ("read_timeout", 31),
        ("total_timeout", 0.09),
        ("total_timeout", 61),
        ("read_timeout", float("nan")),
        ("max_request_bytes", 0),
        ("max_request_bytes", 16 * 1024 * 1024 + 1),
        ("max_response_bytes", 0),
        ("max_response_bytes", 8 * 1024 * 1024 + 1),
    ],
)
def test_timeouts_and_byte_caps_have_bounded_configuration(field: str, value: object) -> None:
    with pytest.raises(ValidationError):
        endpoint(**{field: value})


def test_physical_ip_host_sni_timeouts_and_buffered_logical_response() -> None:
    calls: list[httpx.Request] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(200, json={"stub": True})

    async def run() -> None:
        async with build_client(
            endpoint(), {("POST", "/analyze")}, httpx.MockTransport(handler)
        ) as client:
            response = await client.post(
                "/analyze",
                content=b"authored payload",
                headers={"Host": "attacker.test", "Accept-Encoding": "gzip"},
                extensions={"sni_hostname": "attacker.test", "timeout": {"read": None}},
            )
            assert response.json() == {"stub": True}
            assert str(response.url) == "https://service.example.test:8443/analyze"
            assert response.is_stream_consumed
            assert not client.follow_redirects
            assert not client.trust_env

    asyncio.run(run())
    assert len(calls) == 1
    request = calls[0]
    assert request.url.host == "192.0.2.10"
    assert request.url.port == 8443
    assert request.headers["host"] == "service.example.test:8443"
    assert request.headers["accept-encoding"] == "identity"
    assert request.headers["content-length"] == str(len(b"authored payload"))
    assert request.extensions["sni_hostname"] == "service.example.test"
    assert request.extensions["timeout"] == {"connect": 5, "read": 5, "write": 5, "pool": 5}


def test_percent_encoded_route_is_compared_as_exact_raw_path() -> None:
    raw_path = "/users/user%2Fpart/messages/message%2Fpart/$value"
    calls: list[bytes] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.raw_path)
        return httpx.Response(200, content=b"synthetic MIME")

    async def run() -> None:
        async with build_client(
            endpoint(), {("GET", raw_path)}, httpx.MockTransport(handler)
        ) as client:
            assert (await client.get(raw_path)).content == b"synthetic MIME"
            with pytest.raises(ConnectorError, match="^policy_violation$"):
                await client.get(raw_path.replace("%2F", "/"))

    asyncio.run(run())
    assert calls == [raw_path.encode()]


@pytest.mark.parametrize(
    ("method", "url"),
    [
        ("GET", "https://attacker.test:8443/analyze"),
        ("GET", "http://service.example.test:8443/analyze"),
        ("GET", "https://user:secret@service.example.test:8443/analyze"),
        ("GET", "https://service.example.test:9443/analyze"),
        ("GET", "https://service.example.test:8443/analyze?target=http://127.0.0.1"),
        ("GET", "https://service.example.test:8443/analyze#fragment"),
        ("GET", "https://service.example.test:8443/other"),
        ("POST", "https://service.example.test:8443/analyze"),
    ],
)
def test_request_policy_rejects_before_inner_transport(method: str, url: str) -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200)

    async def run() -> None:
        async with build_client(
            endpoint(), {("GET", "/analyze")}, httpx.MockTransport(handler)
        ) as client:
            with pytest.raises(ConnectorError) as error:
                await client.request(method, url)
            assert error.value.code == "policy_violation"
            assert str(error.value) == "policy_violation"

    asyncio.run(run())
    assert calls == 0


@pytest.mark.parametrize("streamed", [False, True])
def test_request_body_bound_enforced_before_network(streamed: bool) -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200)

    async def chunks() -> AsyncIterator[bytes]:
        yield b"12345"
        yield b"67890"
        yield b"!"

    async def run() -> None:
        async with build_client(
            endpoint(max_request_bytes=10),
            {("POST", "/analyze")},
            httpx.MockTransport(handler),
        ) as client:
            with pytest.raises(ConnectorError, match="^request_too_large$"):
                await client.post("/analyze", content=chunks() if streamed else b"1234567890!")

    asyncio.run(run())
    assert calls == 0


@pytest.mark.parametrize(
    ("status", "headers", "chunks", "expected"),
    [
        (302, {"location": "http://169.254.169.254/private"}, [], "redirect_rejected"),
        (200, {"content-encoding": "gzip"}, [b"not decoded"], "compression_rejected"),
        (200, {"content-length": "11"}, [], "response_too_large"),
        (200, {"content-length": "1"}, [b"12345", b"67890", b"!"], "response_too_large"),
        (200, {}, [b"12345", b"67890", b"!"], "response_too_large"),
        (200, {"content-length": "nonsense"}, [], "policy_violation"),
    ],
)
def test_redirect_compression_and_response_caps_fail_closed(
    status: int,
    headers: dict[str, str],
    chunks: list[bytes],
    expected: str,
) -> None:
    calls = 0
    stream = ReplyStream(chunks)

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(status, headers=headers, stream=stream)

    async def run() -> None:
        async with build_client(
            endpoint(max_response_bytes=10),
            {("GET", "/analyze")},
            httpx.MockTransport(handler),
        ) as client:
            with pytest.raises(ConnectorError) as error:
                await client.get("/analyze")
            assert error.value.code == expected

    asyncio.run(run())
    assert calls == 1
    assert stream.closed
    if headers.get("content-length") == "11" or expected in {
        "redirect_rejected",
        "compression_rejected",
    }:
        assert not stream.iterated


def test_already_buffered_mock_response_still_has_byte_cap() -> None:
    async def run() -> None:
        async with build_client(
            endpoint(max_response_bytes=10),
            {("GET", "/analyze")},
            httpx.MockTransport(lambda request: httpx.Response(200, content=b"x" * 11)),
        ) as client:
            with pytest.raises(ConnectorError, match="^response_too_large$"):
                await client.get("/analyze")

    asyncio.run(run())


@pytest.mark.parametrize("delayed_stage", ["inner", "response_stream", "request_stream"])
def test_total_deadline_covers_real_async_iteration(delayed_stage: str) -> None:
    calls = 0
    stream = ReplyStream([b"{}"], delay=0.2 if delayed_stage == "response_stream" else 0)

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if delayed_stage == "inner":
            await asyncio.sleep(0.2)
        return httpx.Response(200, stream=stream)

    async def request_chunks() -> AsyncIterator[bytes]:
        await asyncio.sleep(0.2)
        yield b"{}"

    async def run() -> None:
        async with build_client(
            endpoint(total_timeout=0.1),
            {("POST", "/analyze")},
            httpx.MockTransport(handler),
        ) as client:
            with pytest.raises(ConnectorError, match="^timeout$"):
                await client.post(
                    "/analyze",
                    content=request_chunks() if delayed_stage == "request_stream" else b"{}",
                )

    started = time.monotonic()
    asyncio.run(run())
    assert time.monotonic() - started < 0.5
    assert calls == (0 if delayed_stage == "request_stream" else 1)
    if delayed_stage == "response_stream":
        assert stream.closed


@pytest.mark.parametrize("kind", ["read", "connect", "tls"])
def test_transport_failures_are_sanitized_and_never_retried(kind: str) -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if kind == "read":
            raise httpx.ReadTimeout("SYNTHETIC_SECRET https://user:secret@private.test")
        if kind == "tls":
            try:
                raise ssl.SSLCertVerificationError("SYNTHETIC_SECRET certificate failure")
            except ssl.SSLError as exc:
                raise httpx.ConnectError("SYNTHETIC_SECRET") from exc
        raise httpx.ConnectError("SYNTHETIC_SECRET gateway failure")

    async def run() -> None:
        async with build_client(
            endpoint(), {("GET", "/analyze")}, httpx.MockTransport(handler)
        ) as client:
            with pytest.raises(ConnectorError) as error:
                await client.get("/analyze", headers={"Authorization": "Bearer SYNTHETIC_SECRET"})
            assert (
                error.value.code
                == {"read": "timeout", "connect": "network_error", "tls": "tls_error"}[kind]
            )
            assert "SYNTHETIC_SECRET" not in str(error.value)
            assert "private.test" not in repr(error.value)

    asyncio.run(run())
    assert calls == 1


def test_default_transport_keeps_tls_verification_and_disables_environment_and_retries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    def factory(**kwargs: object) -> httpx.MockTransport:
        captured.update(kwargs)
        return httpx.MockTransport(lambda request: httpx.Response(200))

    monkeypatch.setattr(httpx, "AsyncHTTPTransport", factory)
    ControlledTransport(endpoint(), {("GET", "/analyze")})
    assert captured == {"verify": True, "retries": 0, "trust_env": False}


def test_httpcore_uses_original_tls_hostname_and_required_verification_with_pinned_tcp() -> None:
    observed: dict[str, object] = {}

    class FakeStream(httpcore.AsyncNetworkStream):
        async def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
            return b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}"

        async def write(self, buffer: bytes, timeout: float | None = None) -> None:
            observed["written"] = bytes(observed.get("written", b"")) + buffer

        async def aclose(self) -> None:
            observed["closed"] = True

        async def start_tls(
            self,
            ssl_context: ssl.SSLContext,
            server_hostname: str | None = None,
            timeout: float | None = None,
        ) -> httpcore.AsyncNetworkStream:
            observed["tls_hostname"] = server_hostname
            observed["check_hostname"] = ssl_context.check_hostname
            observed["verify_mode"] = ssl_context.verify_mode
            return self

        def get_extra_info(self, info: str) -> object:
            return None

    class FakeBackend(httpcore.AsyncNetworkBackend):
        async def connect_tcp(
            self,
            host: str,
            port: int,
            timeout: float | None = None,
            local_address: str | None = None,
            socket_options: object = None,
        ) -> httpcore.AsyncNetworkStream:
            observed["tcp_host"] = host
            observed["tcp_port"] = port
            return FakeStream()

    async def run() -> None:
        inner = httpx.AsyncHTTPTransport(verify=True, retries=0, trust_env=False)
        # Exercise the installed httpx/httpcore TLS forwarding contract without sockets.
        inner._pool._network_backend = FakeBackend()
        async with build_client(endpoint(), {("GET", "/analyze")}, inner) as client:
            assert (await client.get("/analyze")).json() == {}

    asyncio.run(run())
    assert observed["tcp_host"] == "192.0.2.10"
    assert observed["tcp_port"] == 8443
    assert observed["tls_hostname"] == "service.example.test"
    assert observed["check_hostname"] is True
    assert observed["verify_mode"] == ssl.CERT_REQUIRED
    assert b"host: service.example.test:8443\r\n" in observed["written"].lower()
    assert observed["closed"] is True


def test_closing_client_closes_inner_transport() -> None:
    class Closable(httpx.AsyncBaseTransport):
        closed = False

        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            return httpx.Response(200)

        async def aclose(self) -> None:
            self.closed = True

    inner = Closable()

    async def run() -> None:
        async with build_client(endpoint(), {("GET", "/analyze")}, inner):
            assert not inner.closed

    asyncio.run(run())
    assert inner.closed
