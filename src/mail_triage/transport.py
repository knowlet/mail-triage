"""Explicit, pinned HTTPS egress with bounded requests and inert buffered replies."""

from __future__ import annotations

import asyncio
import ipaddress
import re
import ssl
from urllib.parse import urlsplit

import httpx
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class ConnectorError(Exception):
    """A static failure code safe to report without upstream URLs or credentials."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _address(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    if "%" in value:
        raise ValueError("IP scope identifiers are not supported.")
    return ipaddress.ip_address(value)


def _effective_address(
    value: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    if isinstance(value, ipaddress.IPv6Address) and value.ipv4_mapped is not None:
        return value.ipv4_mapped
    return value


class EndpointPolicy(BaseModel):
    """Operator-owned service origin and exact IP pin; never derived from email."""

    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)

    origin: str
    pinned_ip: str
    allow_private_ip: bool = False
    connect_timeout: float = Field(default=5, ge=0.1, le=30)
    read_timeout: float = Field(default=5, ge=0.1, le=30)
    total_timeout: float = Field(default=15, ge=0.1, le=60)
    max_request_bytes: int = Field(default=8 * 1024 * 1024, ge=1, le=16 * 1024 * 1024)
    max_response_bytes: int = Field(default=5 * 1024 * 1024, ge=1, le=8 * 1024 * 1024)

    @field_validator("origin")
    @classmethod
    def validate_origin(cls, value: str) -> str:
        if any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in value):
            raise ValueError("Origin cannot contain whitespace or controls.")
        if "\\" in value:
            raise ValueError("Origin cannot contain a backslash.")
        parsed = urlsplit(value)
        if (
            parsed.scheme != "https"
            or not parsed.netloc
            or parsed.path
            or "?" in value
            or "#" in value
            or parsed.username is not None
            or parsed.password is not None
        ):
            raise ValueError("An explicit HTTPS origin without credentials or path is required.")
        if parsed.port is not None and not 1 <= parsed.port <= 65535:
            raise ValueError("Origin port is invalid.")
        try:
            url = httpx.URL(value)
        except httpx.InvalidURL:
            raise ValueError("Origin hostname is invalid.") from None
        if not url.host or "%" in url.host:
            raise ValueError("Origin hostname is invalid.")
        try:
            _address(url.host)
        except ValueError:
            labels = url.raw_host.decode("ascii").rstrip(".").split(".")
            if (
                any(
                    not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                    for label in labels
                )
                or len(url.raw_host) > 253
            ):
                raise ValueError("Origin hostname is invalid.") from None
        return "https://" + url.netloc.decode("ascii")

    @field_validator("pinned_ip")
    @classmethod
    def validate_pin(cls, value: str) -> str:
        return str(_address(value))

    @model_validator(mode="after")
    def validate_destination(self) -> EndpointPolicy:
        address = _effective_address(_address(self.pinned_ip))
        if (
            address.is_loopback
            or address.is_link_local
            or address.is_multicast
            or address.is_unspecified
        ):
            raise ValueError(
                "Loopback, link-local, multicast and unspecified destinations are forbidden."
            )
        if not address.is_global and not self.allow_private_ip:
            raise ValueError("A non-global exact IP pin requires allow_private_ip.")
        return self


def _has_tls_cause(error: BaseException) -> bool:
    seen: set[int] = set()
    current: BaseException | None = error
    while current is not None and id(current) not in seen:
        if isinstance(current, ssl.SSLError):
            return True
        seen.add(id(current))
        current = current.__cause__ or current.__context__
    return False


def _declared_length(headers: httpx.Headers) -> int | None:
    values = headers.get_list("content-length")
    if not values:
        return None
    if len(values) != 1 or not values[0].isascii() or not values[0].isdecimal():
        raise ConnectorError("policy_violation")
    return int(values[0])


class ControlledTransport(httpx.AsyncBaseTransport):
    """Validate the logical request, then connect only to its operator-selected IP."""

    def __init__(
        self,
        policy: EndpointPolicy,
        allowed_routes: set[tuple[str, str]],
        *,
        inner: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        # Revalidate even if a caller used model_construct/model_copy to bypass validators.
        self.policy = EndpointPolicy.model_validate(policy.model_dump())
        self._origin = httpx.URL(self.policy.origin)
        routes: set[tuple[str, bytes]] = set()
        for method, path in allowed_routes:
            if (
                not re.fullmatch(r"[A-Z]+", method)
                or not path.startswith("/")
                or path.startswith("//")
                or any(char in path for char in "?#\\")
                or any(ord(char) <= 32 or ord(char) >= 127 for char in path)
            ):
                raise ValueError(
                    "Routes require an uppercase method and exact ASCII absolute path."
                )
            routes.add((method, path.encode("ascii")))
        self._routes = frozenset(routes)
        self._inner = (
            inner
            if inner is not None
            else httpx.AsyncHTTPTransport(
                verify=True,
                retries=0,
                trust_env=False,
            )
        )

    def _validate_request(self, request: httpx.Request) -> None:
        url = request.url
        if (
            url.scheme != "https"
            or url.raw_host != self._origin.raw_host
            or url.port != self._origin.port
            or url.userinfo
            or url.query
            or url.fragment
            or (request.method, url.raw_path) not in self._routes
        ):
            raise ConnectorError("policy_violation")

    async def _request_body(self, request: httpx.Request) -> bytes:
        length = _declared_length(request.headers)
        if length is not None and length > self.policy.max_request_bytes:
            raise ConnectorError("request_too_large")
        if not isinstance(request.stream, httpx.AsyncByteStream):
            raise ConnectorError("policy_violation")
        chunks: list[bytes] = []
        total = 0
        async for chunk in request.stream:
            total += len(chunk)
            if total > self.policy.max_request_bytes:
                raise ConnectorError("request_too_large")
            chunks.append(chunk)
        return b"".join(chunks)

    async def _response_body(self, response: httpx.Response) -> bytes:
        if 300 <= response.status_code < 400:
            raise ConnectorError("redirect_rejected")
        encoding = response.headers.get("content-encoding", "identity").strip().lower()
        if encoding != "identity":
            raise ConnectorError("compression_rejected")
        length = _declared_length(response.headers)
        if length is not None and length > self.policy.max_response_bytes:
            raise ConnectorError("response_too_large")
        # MockTransport may return an already-buffered response. Apply the same cap.
        if response.is_stream_consumed:
            body = response.content
            if len(body) > self.policy.max_response_bytes:
                raise ConnectorError("response_too_large")
            return body
        chunks: list[bytes] = []
        total = 0
        async for chunk in response.aiter_raw():
            total += len(chunk)
            if total > self.policy.max_response_bytes:
                raise ConnectorError("response_too_large")
            chunks.append(chunk)
        return b"".join(chunks)

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self._validate_request(request)
        deadline = asyncio.get_running_loop().time() + self.policy.total_timeout
        response: httpx.Response | None = None
        try:
            async with asyncio.timeout(self.policy.total_timeout):
                body = await self._request_body(request)
                headers = request.headers.copy()
                headers.pop("content-length", None)
                headers.pop("transfer-encoding", None)
                headers["host"] = self._origin.netloc.decode("ascii")
                headers["accept-encoding"] = "identity"
                physical = httpx.Request(
                    request.method,
                    request.url.copy_with(host=self.policy.pinned_ip),
                    headers=headers,
                    content=body,
                    extensions={
                        "sni_hostname": self._origin.raw_host.decode("ascii"),
                        "timeout": {
                            "connect": self.policy.connect_timeout,
                            "read": self.policy.read_timeout,
                            "write": self.policy.read_timeout,
                            "pool": self.policy.connect_timeout,
                        },
                    },
                )
                response = await self._inner.handle_async_request(physical)
                content = await self._response_body(response)
                await response.aclose()
                return httpx.Response(
                    response.status_code,
                    headers=response.headers,
                    content=content,
                    request=request,
                )
        except ConnectorError:
            raise
        except (TimeoutError, httpx.TimeoutException):
            raise ConnectorError("timeout") from None
        except Exception as exc:
            raise ConnectorError("tls_error" if _has_tls_cause(exc) else "network_error") from None
        finally:
            if response is not None and not response.is_closed:
                # Cleanup may not extend the request's total deadline. Closing the
                # client also closes the underlying pool after any failed exchange.
                try:
                    remaining = max(0, deadline - asyncio.get_running_loop().time())
                    async with asyncio.timeout(remaining):
                        await response.aclose()
                except Exception:
                    pass

    async def aclose(self) -> None:
        await self._inner.aclose()


def build_client(
    policy: EndpointPolicy,
    routes: set[tuple[str, str]],
    inner: httpx.AsyncBaseTransport | None = None,
) -> httpx.AsyncClient:
    """Create an isolated client; constructing it does not make a connection."""
    transport = ControlledTransport(policy, routes, inner=inner)
    selected = transport.policy
    return httpx.AsyncClient(
        base_url=selected.origin,
        transport=transport,
        trust_env=False,
        follow_redirects=False,
        max_redirects=0,
        headers={"accept-encoding": "identity"},
        timeout=httpx.Timeout(
            connect=selected.connect_timeout,
            read=selected.read_timeout,
            write=selected.read_timeout,
            pool=selected.connect_timeout,
        ),
    )
