"""Mock-only Assemblyline GET contract tests; no server or mailbox is contacted."""

import asyncio
import hashlib
import ssl
import time

import httpx
import pytest
from pydantic import SecretStr, ValidationError

from mail_triage import assemblyline_results as module
from mail_triage.assemblyline_results import PollingPolicy, poll_submission
from mail_triage.transport import EndpointPolicy

SID = "authored-fixture-sid"
INPUT_HASH = hashlib.sha256(b"Authored fixture email bytes.").hexdigest()
KEY = "authored-fixture-api-key"


@pytest.fixture
def endpoint():
    return EndpointPolicy(
        origin="https://assemblyline.example.invalid", pinned_ip="10.4.5.6", allow_private_ip=True
    )


@pytest.fixture
def policy():
    return PollingPolicy(enabled=True, interval_seconds=1, deadline_seconds=10, max_polls=3)


@pytest.fixture
def fake_wait(monkeypatch):
    waits = []

    async def advance(seconds, cancel, **kwargs):
        waits.append(seconds)

    monkeypatch.setattr(module, "_wait_interval", advance)
    return waits


def envelope(data):
    return httpx.Response(
        200, json={"api_status_code": 200, "api_error_message": "", "api_response": data}
    )


def full_data():
    return {
        "sid": SID,
        "state": "completed",
        "max_score": 1234,
        "files": [{"name": "original.eml", "sha256": INPUT_HASH, "size": 29}],
        # Total files can exceed the count of original submitted files.
        "file_count": 2,
        "error_count": 0,
        "results": {
            INPUT_HASH + ".AuthoredService.v1.config": {
                "sha256": INPUT_HASH,
                "partial": False,
                "response": {"service_name": "AuthoredService", "service_version": "1"},
                "result": {"score": 1234},
            }
        },
        "errors": {},
        "missing_result_keys": [],
        "missing_error_keys": [],
        "missing_file_keys": [],
        "file_infos": {},
        "file_tree": {},
    }


def execute(endpoint, policy, handler, **overrides):
    arguments = {
        "endpoint": endpoint,
        "username": "authored-user",
        "sid": SID,
        "input_sha256": INPUT_HASH,
        "credential": SecretStr(KEY),
        "policy": policy,
        "inner": httpx.MockTransport(handler),
        **overrides,
    }
    return asyncio.run(poll_submission(**arguments))


def test_disabled_policy_preserves_valid_identity_and_makes_no_requests(endpoint):
    calls = []
    result = execute(endpoint, PollingPolicy(), lambda request: calls.append(request))
    assert result.status == "NOT_RUN"
    assert result.reason == "disabled"
    assert result.sid == SID
    assert result.input_sha256 == INPUT_HASH
    assert result.source_origin == endpoint.origin
    assert result.pinned_ip == endpoint.pinned_ip
    assert result.execution_mode == "NOT_RUN"
    assert result.requests == calls == []


@pytest.mark.parametrize("field", ["sid", "input_sha256", "source_origin", "pinned_ip"])
@pytest.mark.parametrize("enabled", [False, True])
def test_known_credentials_are_redacted_even_from_disabled_and_early_error_context(
    endpoint, policy, field, enabled
):
    value = {
        "sid": SID,
        "input_sha256": INPUT_HASH,
        "source_origin": endpoint.origin,
        "pinned_ip": endpoint.pinned_ip,
    }[field]
    calls = []
    result = execute(
        endpoint,
        policy if enabled else PollingPolicy(),
        lambda request: calls.append(request),
        credential=SecretStr(value),
        username="invalid\r\nusername" if enabled else "authored-user",
    )
    assert result.status == ("ERROR" if enabled else "NOT_RUN")
    assert getattr(result, field) is None
    assert value not in result.model_dump_json()
    assert calls == []


def test_completion_false_then_true_reads_full_once_using_only_bound_get_routes(
    endpoint, policy, fake_wait
):
    calls = []
    response_hashes = []

    def scripted(request):
        calls.append(request)
        assert request.method == "GET"
        assert request.content == b""
        assert request.url.host == endpoint.pinned_ip
        assert request.headers["Host"] == "assemblyline.example.invalid"
        assert request.headers["X-USER"] == "authored-user"
        assert request.headers["X-APIKEY"] == KEY
        if "/is_completed/" in request.url.path:
            response = envelope(len(calls) == 3)
        else:
            assert request.url.path == f"/api/v4/submission/full/{SID}/"
            data = full_data()
            data["returned_url"] = "https://never-fetch.example.invalid/"
            response = envelope(data)
        response_hashes.append(hashlib.sha256(response.content).hexdigest())
        return response

    result = execute(endpoint, policy, scripted)
    assert result.status == "COMPLETED", result.reason
    assert result.execution_mode == "MOCK"
    assert result.polls == 3
    assert fake_wait == [1, 1]
    assert len(result.requests) == len(calls) == 4
    assert [item.operation for item in result.requests] == ["completion"] * 3 + ["full"]
    assert [item.response_sha256 for item in result.requests] == response_hashes
    assert all(item.http_status == 200 and item.observed_at for item in result.requests)
    assert result.analysis.raw_max_score == 1234  # A raw external score, not a probability.
    assert result.analysis.file_count == 2
    assert result.analysis.untrusted_service_names == ["AuthoredService"]
    assert KEY not in result.model_dump_json()
    assert "never-fetch" not in result.model_dump_json()


@pytest.mark.parametrize("value", ["true", 1, {"completed": True}, "completed", None])
def test_completion_requires_a_boolean_envelope(endpoint, policy, value):
    calls = []

    def scripted(request):
        calls.append(request)
        return envelope(value)

    result = execute(endpoint, policy, scripted)
    assert result.status == "ERROR"
    assert result.reason == "invalid_response"
    assert result.analysis is None
    assert len(calls) == 1


@pytest.mark.parametrize(
    "partial",
    [
        "missing_result_keys",
        "missing_error_keys",
        "missing_file_keys",
        "errors",
        "error_count",
        "partial_result",
        "submitted",
        "failed",
    ],
)
def test_completed_poll_does_not_hide_partial_results_or_service_errors(endpoint, policy, partial):
    data = full_data()
    if partial.startswith("missing_"):
        data[partial] = ["authored-missing-key"]
    elif partial == "errors":
        data["errors"] = {"authored-error-key": {"untrusted_body": "discard this"}}
    elif partial == "error_count":
        data["error_count"] = 1
    elif partial == "partial_result":
        next(iter(data["results"].values()))["partial"] = True
    else:
        data["state"] = partial
    result = execute(
        endpoint,
        policy,
        lambda request: envelope(True) if "/is_completed/" in request.url.path else envelope(data),
    )
    assert result.status == "PARTIAL", result.reason
    assert result.reason == "partial_external_analysis"
    assert result.analysis is not None
    assert "discard this" not in result.model_dump_json()


@pytest.mark.parametrize(
    "mismatch", ["sid", "top_hash", "multiple_originals", "child_only", "stale_schema"]
)
def test_full_result_must_bind_the_sid_and_single_original_file_hash(endpoint, policy, mismatch):
    data = full_data()
    if mismatch == "sid":
        data["sid"] = "a-different-submission"
    elif mismatch in {"top_hash", "child_only"}:
        data["files"][0]["sha256"] = "a" * 64
        data["file_infos"] = {INPUT_HASH: {"sha256": INPUT_HASH}}
        data["file_tree"] = {INPUT_HASH: {"children": {}}}
    elif mismatch == "multiple_originals":
        data["files"].append({"sha256": "a" * 64})
    else:
        data["submission"] = {"sid": data.pop("sid"), "max_score": data.pop("max_score")}
    result = execute(
        endpoint,
        policy,
        lambda request: envelope(True) if "/is_completed/" in request.url.path else envelope(data),
    )
    assert result.status == "ERROR"
    assert result.reason == (
        "invalid_response" if mismatch == "stale_schema" else "identity_mismatch"
    )
    assert result.analysis is None
    assert len(result.requests) == 2


def test_maximum_poll_count_stops_without_result_fetch_or_real_wait(endpoint, policy, fake_wait):
    calls = []

    def scripted(request):
        calls.append(request)
        return envelope(False)

    result = execute(endpoint, policy, scripted)
    assert result.status == "TIMED_OUT"
    assert result.reason == "poll_limit_reached"
    assert result.polls == len(calls) == 3
    assert fake_wait == [1, 1]
    assert all("/is_completed/" in request.url.path for request in calls)
    assert result.analysis is None


@pytest.mark.parametrize("status", [401, 403, 404, 429, 500])
def test_http_errors_do_not_become_incomplete_or_retry_and_never_echo_body(
    endpoint, policy, status
):
    calls = []

    def scripted(request):
        calls.append(request)
        return httpx.Response(status, text=KEY + " sensitive response")

    result = execute(endpoint, policy, scripted)
    assert result.status == "ERROR"
    expected = (
        "authentication_rejected"
        if status in {401, 403}
        else "submission_unavailable"
        if status == 404
        else "service_rejected"
    )
    assert result.reason == expected
    assert len(calls) == 1
    assert result.requests[0].response_sha256
    assert KEY not in result.model_dump_json()
    assert "sensitive response" not in result.model_dump_json()


@pytest.mark.parametrize("failure", ["tls", "network", "timeout", "redirect", "oversized"])
def test_transport_boundaries_apply_without_retry(endpoint, policy, failure):
    calls = []

    def scripted(request):
        calls.append(request)
        if failure == "tls":
            raise httpx.ConnectError("sensitive TLS details", request=request) from ssl.SSLError(
                "x"
            )
        if failure == "network":
            raise httpx.ConnectError("sensitive network details", request=request)
        if failure == "timeout":
            raise httpx.ReadTimeout("sensitive timeout details", request=request)
        if failure == "redirect":
            return httpx.Response(302, headers={"location": "https://never-fetch.example.invalid"})
        return httpx.Response(200, content=b"x" * (module.MAX_RESPONSE_BYTES + 1))

    result = execute(endpoint, policy, scripted)
    assert result.status == ("TIMED_OUT" if failure == "timeout" else "ERROR")
    assert len(calls) == 1
    assert result.analysis is None
    assert "sensitive" not in result.model_dump_json()


@pytest.mark.parametrize(
    "field,value",
    [
        ("sid", "../escape"),
        ("sid", "x%2fy"),
        ("input_sha256", "invalid"),
        ("username", "x\r\nX-APIKEY: leaked"),
    ],
)
def test_invalid_inputs_cannot_select_a_route_or_inject_headers(endpoint, policy, field, value):
    calls = []
    result = execute(endpoint, policy, lambda request: calls.append(request), **{field: value})
    assert result.status == "ERROR"
    assert result.reason == "input_rejected"
    assert calls == []


def test_policy_limits_and_revalidation(endpoint, policy):
    for update in (
        {"interval_seconds": 0.99},
        {"max_polls": 61},
        {"deadline_seconds": 301},
        {"deadline_seconds": float("nan")},
    ):
        with pytest.raises(ValidationError):
            PollingPolicy(**{**policy.model_dump(), **update})
    invalid = policy.model_copy(update={"max_polls": 0})
    calls = []
    result = execute(endpoint, invalid, lambda request: calls.append(request))
    assert result.status == "ERROR"
    assert result.reason == "configuration_rejected"
    assert calls == []


def test_only_mock_transport_may_be_injected(endpoint, policy):
    class TrapTransport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request):
            raise AssertionError("Rejected transport must not execute.")

    result = execute(endpoint, policy, lambda request: envelope(True), inner=TrapTransport())
    assert result.status == "ERROR"
    assert result.reason == "configuration_rejected"
    assert result.execution_mode == "NOT_RUN"
    assert result.requests == []


@pytest.mark.parametrize("escaped", [False, True])
def test_projected_service_names_cannot_echo_supplied_credentials(endpoint, policy, escaped):
    data = full_data()
    next(iter(data["results"].values()))["response"]["service_name"] = KEY

    def scripted(request):
        if "/is_completed/" in request.url.path:
            return envelope(True)
        response = envelope(data)
        if escaped:
            return httpx.Response(
                200,
                content=response.content.replace(b"authored", b"\\u0061uthored"),
                headers={"content-type": "application/json"},
            )
        return response

    result = execute(endpoint, policy, scripted)
    assert result.status == "ERROR"
    assert result.reason == "invalid_response"
    assert result.analysis is None
    assert KEY not in result.model_dump_json()


def test_raw_negative_score_is_preserved_without_normalization(endpoint, policy):
    data = full_data()
    data["max_score"] = -1000
    result = execute(
        endpoint,
        policy,
        lambda request: envelope(True) if "/is_completed/" in request.url.path else envelope(data),
    )
    assert result.status == "COMPLETED"
    assert result.analysis.raw_max_score == -1000


def test_known_credential_cannot_be_echoed_as_a_numeric_raw_score(endpoint, policy):
    data = full_data()
    data["max_score"] = 123456789
    result = execute(
        endpoint,
        policy,
        lambda request: envelope(True) if "/is_completed/" in request.url.path else envelope(data),
        credential=SecretStr("123456789"),
    )
    assert result.status == "ERROR"
    assert result.reason == "invalid_response"
    assert result.analysis is None
    assert "123456789" not in result.model_dump_json()


def test_already_cancelled_event_makes_no_requests(endpoint, policy):
    cancel = asyncio.Event()
    cancel.set()
    calls = []
    result = execute(endpoint, policy, lambda request: calls.append(request), cancel=cancel)
    assert result.status == "CANCELLED"
    assert result.reason == "cancelled"
    assert result.requests == calls == []


def test_cancellation_during_inflight_get_stops_it_and_never_fetches_results(endpoint, policy):
    async def scenario():
        cancel = asyncio.Event()
        started = asyncio.Event()
        request_stopped = asyncio.Event()
        calls = []

        async def scripted(request):
            calls.append(request)
            started.set()
            try:
                await asyncio.Event().wait()
            finally:
                request_stopped.set()

        task = asyncio.create_task(
            poll_submission(
                endpoint,
                "authored-user",
                SID,
                INPUT_HASH,
                SecretStr(KEY),
                policy,
                inner=httpx.MockTransport(scripted),
                cancel=cancel,
            )
        )
        await started.wait()
        cancel.set()
        result = await task
        assert result.status == "CANCELLED"
        assert request_stopped.is_set()
        assert len(calls) == len(result.requests) == 1
        assert result.requests[0].response_sha256 is None
        assert result.analysis is None

    asyncio.run(scenario())


def test_cancellation_between_poll_and_result_fetch_prevents_second_get(endpoint, policy):
    cancel = asyncio.Event()
    calls = []

    def scripted(request):
        calls.append(request)
        cancel.set()
        return envelope(True)

    result = execute(endpoint, policy, scripted, cancel=cancel)
    assert result.status == "CANCELLED"
    assert len(calls) == 1
    assert result.analysis is None


def test_cancellation_during_poll_interval_stops_before_another_get(endpoint, policy, monkeypatch):
    cancel = asyncio.Event()
    wait = module._wait_interval
    calls = []

    async def cancel_during_wait(seconds, event, **kwargs):
        cancel.set()
        await wait(seconds, event, **kwargs)

    monkeypatch.setattr(module, "_wait_interval", cancel_during_wait)

    def scripted(request):
        calls.append(request)
        return envelope(False)

    result = execute(endpoint, policy, scripted, cancel=cancel)
    assert result.status == "CANCELLED"
    assert len(calls) == 1
    assert result.analysis is None


def test_cancellation_during_client_cleanup_does_not_accept_a_completed_result(endpoint, policy):
    cancel = asyncio.Event()

    class CancellingCleanupMock(httpx.MockTransport):
        async def aclose(self):
            cancel.set()
            await super().aclose()

    def scripted(request):
        return envelope(True) if "/is_completed/" in request.url.path else envelope(full_data())

    result = execute(
        endpoint, policy, scripted, cancel=cancel, inner=CancellingCleanupMock(scripted)
    )
    assert result.status == "CANCELLED"
    assert result.analysis is None


def test_external_task_cancellation_propagates_and_closes_client(endpoint, policy):
    async def scenario():
        started = asyncio.Event()

        class ClosingMock(httpx.MockTransport):
            closed = False

            async def aclose(self):
                self.closed = True
                await super().aclose()

        async def scripted(request):
            started.set()
            await asyncio.Event().wait()

        inner = ClosingMock(scripted)
        task = asyncio.create_task(
            poll_submission(
                endpoint,
                "authored-user",
                SID,
                INPUT_HASH,
                SecretStr(KEY),
                policy,
                inner=inner,
                cancel=asyncio.Event(),
            )
        )
        await started.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert inner.closed

    asyncio.run(scenario())


@pytest.mark.parametrize("slow_stage", ["request", "cleanup"])
def test_whole_poll_deadline_includes_request_wait_and_client_cleanup(endpoint, policy, slow_stage):
    class SlowMock(httpx.MockTransport):
        async def aclose(self):
            if slow_stage == "cleanup":
                await asyncio.sleep(0.5)
            await super().aclose()

    async def scripted(request):
        if slow_stage == "request":
            await asyncio.sleep(0.5)
        return envelope(True) if "/is_completed/" in request.url.path else envelope(full_data())

    limited = PollingPolicy(**{**policy.model_dump(), "deadline_seconds": 0.1})
    result = execute(endpoint, limited, scripted, inner=SlowMock(scripted))
    assert result.status == "TIMED_OUT"
    assert result.reason == "deadline_exceeded"
    assert result.analysis is None


@pytest.mark.parametrize("with_cancel_event", [False, True])
def test_poll_deadline_also_bounds_stream_cleanup_after_an_active_get_is_cancelled(
    endpoint, policy, with_cancel_event
):
    class SlowCloseStream(httpx.AsyncByteStream):
        async def __aiter__(self):
            await asyncio.Event().wait()
            yield b"unreachable"

        async def aclose(self):
            await asyncio.sleep(1)

    def scripted(request):
        return httpx.Response(
            200, stream=SlowCloseStream(), headers={"content-type": "application/json"}
        )

    limited = PollingPolicy(**{**policy.model_dump(), "deadline_seconds": 0.1})
    start = time.monotonic()
    result = execute(
        endpoint, limited, scripted, cancel=asyncio.Event() if with_cancel_event else None
    )
    elapsed = time.monotonic() - start
    assert result.status == "TIMED_OUT"
    assert result.reason == "deadline_exceeded"
    assert elapsed < 0.75  # One-second stream cleanup cannot extend the 0.1-second budget.
    assert len(result.requests) == 1
    assert result.requests[0].response_sha256 is None


def test_external_task_cancel_during_explicit_cancel_cleanup_still_propagates(endpoint, policy):
    async def scenario():
        started = asyncio.Event()
        closing = asyncio.Event()
        cancel = asyncio.Event()

        class SlowCloseStream(httpx.AsyncByteStream):
            async def __aiter__(self):
                started.set()
                await asyncio.Event().wait()
                yield b"unreachable"

            async def aclose(self):
                closing.set()
                await asyncio.sleep(1)

        def scripted(request):
            return httpx.Response(
                200, stream=SlowCloseStream(), headers={"content-type": "application/json"}
            )

        task = asyncio.create_task(
            poll_submission(
                endpoint,
                "authored-user",
                SID,
                INPUT_HASH,
                SecretStr(KEY),
                policy,
                inner=httpx.MockTransport(scripted),
                cancel=cancel,
            )
        )
        await started.wait()
        cancel.set()
        await closing.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(scenario())
