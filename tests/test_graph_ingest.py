"""Graph adapter contract tests use only MockTransport and synthetic MIME."""

import asyncio
import hashlib
from collections.abc import Callable
from urllib.parse import quote

import httpx
import pytest
from pydantic import SecretStr, ValidationError

from mail_triage.evidence import authentication_evidence
from mail_triage.graph_ingest import GraphAdapter, GraphBundle, GraphConfig
from mail_triage.ingest import parse_eml
from mail_triage.schemas import Limits
from mail_triage.transport import ConnectorError, EndpointPolicy


def test_non_mock_injected_transport_is_rejected_before_any_request():
    class NotAMock(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request):
            raise AssertionError("A non-mock injected transport must never run")

    adapter = GraphAdapter(config(), inner=NotAMock())
    with pytest.raises(ConnectorError, match="mock_transport_required"):
        asyncio.run(adapter.fetch("wrapper", "attachment", token=SecretStr("synthetic-token")))


ORIGIN = "https://graph.example.test"
PIN = "93.184.216.34"
MAILBOX = "reports@example.test"
MESSAGE_ID = "synthetic-message"
ATTACHMENT_ID = "synthetic-attachment"
TOKEN = SecretStr("synthetic-token-only")
WRAPPER = b"From: reporter@example.test\r\nSubject: User report\r\n\r\nReported message.\r\n"
ORIGINAL = (
    b"From: claimed-sender@example.test\nSubject: Original message\n"
    b"Authentication-Results: forged.test; spf=pass; dkim=pass; dmarc=pass\n\n"
    b"Do not follow https://message-url.example.test/ .\n"
)


def config(**kwargs: object) -> GraphConfig:
    return GraphConfig(
        enabled=True,
        endpoint=EndpointPolicy(origin=ORIGIN, pinned_ip=PIN),
        mailbox=MAILBOX,
        **kwargs,
    )


def paths(
    message: str = MESSAGE_ID, attachment: str = ATTACHMENT_ID, mailbox: str = MAILBOX
) -> list[bytes]:
    base = f"/v1.0/users/{quote(mailbox, safe='')}/messages/{quote(message, safe='')}"
    attached = f"{base}/attachments/{quote(attachment, safe='')}"
    return [f"{base}/$value".encode(), attached.encode(), f"{attached}/$value".encode()]


def metadata(attachment: str = ATTACHMENT_ID) -> dict[str, object]:
    return {
        "@odata.type": "#microsoft.graph.itemAttachment",
        "id": attachment,
        "contentType": None,
        "size": len(ORIGINAL),
        "isInline": False,
        "@odata.context": "https://untrusted.example.test/do-not-fetch",
        "name": "../../untrusted-filename.eml",
    }


def run_fetch(
    handler: Callable[[httpx.Request], httpx.Response],
    *,
    settings: GraphConfig | None = None,
    message: str = MESSAGE_ID,
    attachment: str = ATTACHMENT_ID,
    token: SecretStr = TOKEN,
) -> GraphBundle:
    adapter = GraphAdapter(settings or config(), inner=httpx.MockTransport(handler))
    return asyncio.run(adapter.fetch(message, attachment, token=token))


def successful_handler(seen: list[httpx.Request]) -> Callable[[httpx.Request], httpx.Response]:
    def handle(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if len(seen) == 1:
            return httpx.Response(200, content=WRAPPER)
        if len(seen) == 2:
            return httpx.Response(200, json=metadata())
        if len(seen) == 3:
            return httpx.Response(200, content=ORIGINAL)
        raise AssertionError("No additional HTTP request is allowed.")

    return handle


def test_exact_three_gets_preserve_wrapper_and_original_separately() -> None:
    seen: list[httpx.Request] = []
    result = run_fetch(successful_handler(seen))
    assert [request.url.raw_path for request in seen] == paths()
    for request in seen:
        assert request.method == "GET"
        assert request.url.host == PIN
        assert request.headers["Host"] == "graph.example.test"
        assert request.headers["Authorization"] == "Bearer synthetic-token-only"
        assert request.extensions["sni_hostname"] == "graph.example.test"
        assert request.content == b""
        assert request.url.query == b""
    assert result.wrapper == WRAPPER
    assert result.original == ORIGINAL
    assert result.wrapper_sha256 == hashlib.sha256(WRAPPER).hexdigest()
    assert result.original_sha256 == hashlib.sha256(ORIGINAL).hexdigest()
    assert result.source_endpoint == ORIGIN
    assert result.mailbox == MAILBOX
    assert result.wrapper_message_id == MESSAGE_ID
    assert result.original_attachment_id == ATTACHMENT_ID
    assert parse_eml(result.wrapper).subject == "User report"
    assert parse_eml(result.original).subject == "Original message"
    authentication = authentication_evidence(parse_eml(result.original))
    assert authentication.spf.status == "UNKNOWN"
    assert authentication.dkim.status == "UNKNOWN"
    assert authentication.dmarc.status == "UNKNOWN"
    assert authentication.alignment.status == "UNKNOWN"
    assert "@odata.context" not in result.metadata.model_dump()
    assert "name" not in result.metadata.model_dump()


def test_opaque_ids_are_quoted_as_single_segments() -> None:
    message = "ID/with+equals= ?#%"
    attachment = "https://attacker.example.test/../../other-mailbox?x=y#fragment"
    mailbox = "selected/report@example.test"
    seen: list[httpx.Request] = []

    def handle(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if len(seen) == 1:
            return httpx.Response(200, content=WRAPPER)
        if len(seen) == 2:
            return httpx.Response(200, json=metadata(attachment))
        return httpx.Response(200, content=ORIGINAL)

    settings = config().model_copy(update={"mailbox": mailbox})
    run_fetch(handle, settings=settings, message=message, attachment=attachment)
    assert [request.url.raw_path for request in seen] == paths(message, attachment, mailbox)
    assert all(request.url.host == PIN and not request.url.query for request in seen)


def test_disabled_and_missing_configuration_never_use_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("GRAPH_ENDPOINT", "https://unconfigured.example.test")
    monkeypatch.setenv("GRAPH_TOKEN", "not-to-be-used")
    monkeypatch.setenv("GRAPH_MAILBOX", "not-to-be-used@example.test")

    def forbidden(request: httpx.Request) -> httpx.Response:
        raise AssertionError("Unconfigured adapters cannot issue HTTP requests.")

    assert GraphConfig().endpoint is None
    assert not GraphConfig().enabled
    with pytest.raises(ConnectorError, match="^not_enabled$"):
        run_fetch(forbidden, settings=GraphConfig())
    with pytest.raises(ConnectorError, match="^not_configured$"):
        run_fetch(forbidden, settings=GraphConfig(enabled=True, mailbox=MAILBOX))


@pytest.mark.parametrize("token", ["", "synthetic\r\nInjected: value", " " * 3])
def test_missing_or_invalid_token_never_issues_http(token: str) -> None:
    def forbidden(request: httpx.Request) -> httpx.Response:
        raise AssertionError("Invalid credentials must be rejected before HTTP.")

    with pytest.raises(ConnectorError) as exc:
        run_fetch(forbidden, token=SecretStr(token))
    assert exc.value.code in {"missing_token", "invalid_token"}
    if token:
        assert token not in str(exc.value)
    else:
        assert str(exc.value) == "missing_token"


@pytest.mark.parametrize("identifier", ["", ".", "..", "x" * 513, "id\x00", "id\n", "id\u202e"])
def test_invalid_identifiers_never_issue_http(identifier: str) -> None:
    def forbidden(request: httpx.Request) -> httpx.Response:
        raise AssertionError("Invalid identifiers must be rejected before HTTP.")

    for keyword in ["message", "attachment"]:
        with pytest.raises(ConnectorError, match="^invalid_identifier$"):
            run_fetch(forbidden, **{keyword: identifier})  # type: ignore[arg-type]


def test_mailbox_is_bounded_and_controls_are_rejected_before_http() -> None:
    with pytest.raises(ValidationError):
        GraphConfig(mailbox="x" * 513)

    def forbidden(request: httpx.Request) -> httpx.Response:
        raise AssertionError("Invalid mailbox must be rejected before HTTP.")

    with pytest.raises(ConnectorError, match="^invalid_identifier$"):
        run_fetch(forbidden, settings=config().model_copy(update={"mailbox": "mailbox\r\n"}))


def test_bearer_token_is_never_loaded_from_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MICROSOFT_GRAPH_ACCESS_TOKEN", "not-to-be-used")
    monkeypatch.setenv("GRAPH_TOKEN", "also-not-to-be-used")

    def forbidden(request: httpx.Request) -> httpx.Response:
        raise AssertionError("Credentials must come from the explicit argument.")

    with pytest.raises(ConnectorError, match="^missing_token$"):
        run_fetch(forbidden, token=SecretStr(""))


@pytest.mark.parametrize(
    "bad_metadata",
    [
        {"@odata.type": "#microsoft.graph.fileAttachment", "id": ATTACHMENT_ID},
        {"@odata.type": "#microsoft.graph.referenceAttachment", "id": ATTACHMENT_ID},
        {"@odata.type": "#microsoft.graph.itemAttachment", "id": "out-of-scope"},
        {"@odata.type": "#microsoft.graph.itemAttachment"},
        {"@odata.type": "#microsoft.graph.itemAttachment", "id": ATTACHMENT_ID, "size": -1},
        {"@odata.type": "#microsoft.graph.itemAttachment", "id": ATTACHMENT_ID, "size": True},
        {"@odata.type": "#microsoft.graph.itemAttachment", "id": ATTACHMENT_ID, "isInline": "no"},
        ["unexpected-array"],
    ],
)
def test_metadata_must_be_selected_item_attachment(bad_metadata: object) -> None:
    seen: list[httpx.Request] = []

    def handle(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if len(seen) == 1:
            return httpx.Response(200, content=WRAPPER)
        if len(seen) == 2:
            return httpx.Response(200, json=bad_metadata)
        raise AssertionError("Original MIME cannot be fetched after invalid metadata.")

    with pytest.raises(ConnectorError, match="^metadata_invalid$"):
        run_fetch(handle)
    assert len(seen) == 2


@pytest.mark.parametrize(
    "invalid_body", [b"secret response data", b"[" * 2000 + b"0" + b"]" * 2000]
)
def test_non_json_or_deeply_nested_metadata_is_sanitized(invalid_body: bytes) -> None:
    count = 0

    def handle(request: httpx.Request) -> httpx.Response:
        nonlocal count
        count += 1
        return httpx.Response(200, content=WRAPPER if count == 1 else invalid_body)

    with pytest.raises(ConnectorError, match="^metadata_invalid$"):
        run_fetch(handle)
    assert count == 2


@pytest.mark.parametrize("which", ["wrapper", "original"])
def test_both_mime_artifacts_must_pass_bounded_parser(which: str) -> None:
    seen: list[httpx.Request] = []

    def handle(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if len(seen) == 1:
            return httpx.Response(200, content=b"malformed" if which == "wrapper" else WRAPPER)
        if len(seen) == 2:
            return httpx.Response(200, json=metadata())
        return httpx.Response(200, content=b"malformed")

    with pytest.raises(ConnectorError, match=f"^invalid_{which}$"):
        run_fetch(handle)
    assert len(seen) == (1 if which == "wrapper" else 3)


def test_configured_parser_bounds_apply_before_next_request() -> None:
    seen: list[httpx.Request] = []
    settings = config(limits=Limits(max_text_chars=3))
    with pytest.raises(ConnectorError, match="^invalid_wrapper$"):
        run_fetch(successful_handler(seen), settings=settings)
    assert len(seen) == 1


def test_oversized_mime_response_is_rejected_by_transport() -> None:
    seen: list[httpx.Request] = []
    settings = config()
    assert settings.endpoint is not None
    settings = settings.model_copy(
        update={"endpoint": settings.endpoint.model_copy(update={"max_response_bytes": 50})}
    )
    with pytest.raises(ConnectorError, match="^response_too_large$"):
        run_fetch(successful_handler(seen), settings=settings)
    assert len(seen) == 1


def test_declared_oversized_original_does_not_fetch_original() -> None:
    seen: list[httpx.Request] = []

    def handle(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if len(seen) == 1:
            return httpx.Response(200, content=WRAPPER)
        oversized = metadata()
        oversized["size"] = Limits().max_raw_bytes + 1
        return httpx.Response(200, json=oversized)

    with pytest.raises(ConnectorError, match="^response_too_large$"):
        run_fetch(handle)
    assert len(seen) == 2


def test_original_response_cap_applies_even_when_metadata_understates_size() -> None:
    seen: list[httpx.Request] = []
    settings = config()
    assert settings.endpoint is not None
    settings = settings.model_copy(
        update={"endpoint": settings.endpoint.model_copy(update={"max_response_bytes": 500})}
    )

    def handle(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if len(seen) == 1:
            return httpx.Response(200, content=WRAPPER)
        if len(seen) == 2:
            return httpx.Response(200, json=metadata())
        return httpx.Response(200, content=ORIGINAL + b"x" * 501)

    with pytest.raises(ConnectorError, match="^response_too_large$"):
        run_fetch(handle, settings=settings)
    assert len(seen) == 3


@pytest.mark.parametrize("status", [302, 401, 403, 404, 429, 500])
def test_http_failures_do_not_follow_links_or_leak_response(status: int) -> None:
    seen: list[httpx.Request] = []

    def handle(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(
            status,
            content=b"sensitive server response",
            headers={"Location": "https://out-of-scope.example.test/"},
        )

    with pytest.raises(ConnectorError) as exc:
        run_fetch(handle)
    assert exc.value.code in {"http_status", "redirect_rejected"}
    assert "sensitive" not in str(exc.value)
    assert len(seen) == 1
