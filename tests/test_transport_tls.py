"""Real TLS records over MemoryBIO; no sockets, DNS, or external service traffic.

Only the TCP byte carrier is replaced. ControlledTransport constructs its normal
httpx/httpcore pool and SSL context; tests append an ephemeral fixture CA to that
context without disabling hostname or certificate verification.
"""

from __future__ import annotations

import asyncio
import shutil
import ssl
import subprocess
from pathlib import Path

import httpcore
import httpx
import pytest

from mail_triage.transport import ConnectorError, ControlledTransport, EndpointPolicy, build_client


@pytest.fixture(scope="module")
def tls_certificate(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, Path]:
    """Generate a short-lived, synthetic key only in pytest's temporary directory."""
    openssl = shutil.which("openssl")
    assert openssl is not None, "The offline TLS regression tests require openssl."
    directory = tmp_path_factory.mktemp("memory-tls")
    certificate, key = directory / "certificate.pem", directory / "key.pem"
    subprocess.run(
        [
            openssl,
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "2",
            "-subj",
            "/CN=service.example.test",
            "-addext",
            "subjectAltName=DNS:service.example.test",
            "-keyout",
            str(key),
            "-out",
            str(certificate),
        ],
        check=True,
        capture_output=True,
    )
    return certificate, key


class TLSCarrier(httpcore.AsyncNetworkStream):
    """An encrypted, in-memory byte carrier, not an HTTP response mock."""

    def __init__(self, server_context: ssl.SSLContext, reply: bytes, delay: float = 0) -> None:
        self.client_in, self.client_out = ssl.MemoryBIO(), ssl.MemoryBIO()
        self.server_in, self.server_out = ssl.MemoryBIO(), ssl.MemoryBIO()
        self.server = server_context.wrap_bio(self.server_in, self.server_out, server_side=True)
        self.client: ssl.SSLObject | None = None
        self.reply = reply
        self.delay = delay
        self.request = bytearray()
        self.closed = False
        self.reply_sent = False
        self.tls_hostname: str | None = None
        self.context: ssl.SSLContext | None = None

    def pump(self) -> None:
        if self.client_out.pending:
            self.server_in.write(self.client_out.read())
        if self.server_out.pending:
            self.client_in.write(self.server_out.read())

    async def start_tls(
        self,
        ssl_context: ssl.SSLContext,
        server_hostname: str | None = None,
        timeout: float | None = None,
    ) -> httpcore.AsyncNetworkStream:
        self.context, self.tls_hostname = ssl_context, server_hostname
        self.client = ssl_context.wrap_bio(
            self.client_in, self.client_out, server_hostname=server_hostname
        )
        completed = [False, False]
        for _ in range(20):
            for index, peer in enumerate((self.client, self.server)):
                if not completed[index]:
                    try:
                        peer.do_handshake()
                        completed[index] = True
                    except ssl.SSLWantReadError:
                        pass
                self.pump()
            if all(completed):
                return self
        raise AssertionError("Fixture TLS handshake did not converge")

    async def write(self, buffer: bytes, timeout: float | None = None) -> None:
        assert self.client is not None
        self.client.write(buffer)
        self.pump()
        while True:
            try:
                self.request.extend(self.server.read(65536))
            except ssl.SSLWantReadError:
                break

    async def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        assert self.client is not None
        if self.delay:
            await asyncio.sleep(self.delay)
        if not self.reply_sent:
            self.server.write(self.reply)
            self.reply_sent = True
            self.pump()
        try:
            return self.client.read(max_bytes)
        except ssl.SSLWantReadError:
            return b""

    async def aclose(self) -> None:
        self.closed = True

    def get_extra_info(self, info: str) -> object:
        return self.client if info == "ssl_object" else None


class TLSBackend(httpcore.AsyncNetworkBackend):
    def __init__(self, carrier: TLSCarrier) -> None:
        self.carrier = carrier
        self.destinations: list[tuple[str, int]] = []

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: object = None,
    ) -> httpcore.AsyncNetworkStream:
        self.destinations.append((host, port))
        return self.carrier


def tls_client(
    monkeypatch: pytest.MonkeyPatch,
    certificate: tuple[Path, Path],
    *,
    trust_fixture: bool = True,
    hostname: str = "service.example.test",
    response: bytes = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
    delay: float = 0,
    max_response_bytes: int = 1024,
    total_timeout: float = 1,
) -> tuple[httpx.AsyncClient, TLSBackend, list[ssl.SSLContext]]:
    cert, key = certificate
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(cert, key)
    contexts: list[ssl.SSLContext] = []
    original_factory = ssl.create_default_context

    def factory(*args: object, **kwargs: object) -> ssl.SSLContext:
        context = original_factory(*args, **kwargs)
        if trust_fixture:
            context.load_verify_locations(cafile=str(cert))
        contexts.append(context)
        return context

    monkeypatch.setattr(ssl, "create_default_context", factory)
    policy = EndpointPolicy(
        origin=f"https://{hostname}:8443",
        pinned_ip="192.0.2.10",
        allow_private_ip=True,
        max_response_bytes=max_response_bytes,
        total_timeout=total_timeout,
    )
    # No inner transport override: exercise the production construction path.
    client = build_client(policy, {("POST", "/analyze")})
    transport = client._transport
    assert isinstance(transport, ControlledTransport)
    assert isinstance(transport._inner, httpx.AsyncHTTPTransport)
    backend = TLSBackend(TLSCarrier(server_context, response, delay))
    transport._inner._pool._network_backend = backend
    return client, backend, contexts


def test_real_tls_preserves_mime_and_verifies_logical_hostname(
    monkeypatch: pytest.MonkeyPatch, tls_certificate: tuple[Path, Path]
) -> None:
    mime = b"From: authored@example.test\r\nSubject: synthetic\r\n\r\nexact\x00bytes\r\n"
    client, backend, contexts = tls_client(monkeypatch, tls_certificate)

    async def run() -> None:
        async with client:
            response = await client.post("/analyze", content=mime)
            assert response.json() == {}
            assert response.url.host == "service.example.test"

    asyncio.run(run())
    carrier = backend.carrier
    assert backend.destinations == [("192.0.2.10", 8443)]
    assert carrier.context in contexts
    assert carrier.context is not None and carrier.context.verify_mode == ssl.CERT_REQUIRED
    assert carrier.context.check_hostname
    assert carrier.tls_hostname == "service.example.test"
    assert carrier.client is not None and carrier.client.version() in {"TLSv1.2", "TLSv1.3"}
    headers, body = bytes(carrier.request).split(b"\r\n\r\n", 1)
    assert b"host: service.example.test:8443" in headers.lower()
    assert body == mime
    assert carrier.closed


@pytest.mark.parametrize("failure", ["untrusted", "wrong_hostname"])
def test_real_tls_rejects_untrusted_or_mismatched_cert_before_sending_body(
    monkeypatch: pytest.MonkeyPatch, tls_certificate: tuple[Path, Path], failure: str
) -> None:
    client, backend, _ = tls_client(
        monkeypatch,
        tls_certificate,
        trust_fixture=failure != "untrusted",
        hostname="wrong.example.test" if failure == "wrong_hostname" else "service.example.test",
    )

    async def run() -> None:
        async with client:
            with pytest.raises(ConnectorError, match="^tls_error$"):
                await client.post("/analyze", content=b"SYNTHETIC_BODY")

    asyncio.run(run())
    assert backend.destinations == [("192.0.2.10", 8443)]
    assert backend.carrier.request == b""


@pytest.mark.parametrize(
    ("reply", "limit", "delay", "expected"),
    [
        (
            b"HTTP/1.1 302 Found\r\nLocation: https://other.example.test\r\n"
            b"Content-Length: 0\r\n\r\n",
            1024,
            0,
            "redirect_rejected",
        ),
        (b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\n123456789", 8, 0, "response_too_large"),
        (b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}", 1024, 0.3, "timeout"),
    ],
)
def test_real_tls_reply_keeps_redirect_size_and_deadline_guards(
    monkeypatch: pytest.MonkeyPatch,
    tls_certificate: tuple[Path, Path],
    reply: bytes,
    limit: int,
    delay: float,
    expected: str,
) -> None:
    client, backend, _ = tls_client(
        monkeypatch,
        tls_certificate,
        response=reply,
        max_response_bytes=limit,
        delay=delay,
        total_timeout=0.1,
    )

    async def run() -> None:
        async with client:
            with pytest.raises(ConnectorError, match=f"^{expected}$"):
                await client.post("/analyze", content=b"synthetic")

    asyncio.run(run())
    assert backend.destinations == [("192.0.2.10", 8443)]
    assert backend.carrier.closed
