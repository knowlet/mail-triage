"""Bounded GET-only Assemblyline completion polling and untrusted result projection.

Current official contracts, checked 2026-10-14:
https://github.com/CybercentreCanada/assemblyline-ui/blob/master/assemblyline_ui/api/v4/submission.py
https://github.com/CybercentreCanada/assemblyline-base/blob/master/assemblyline/odm/models/submission.py
https://github.com/CybercentreCanada/assemblyline-base/blob/master/assemblyline/odm/models/result.py
The older nested-submission example in the route docstring is not the current
wire format: the implementation returns the top-level ODM submission record.
"""

from __future__ import annotations

import asyncio
import hashlib
import re
from collections.abc import Coroutine
from contextlib import suppress
from datetime import UTC, datetime
from typing import Annotated, Literal

import httpx
from pydantic import BaseModel, ConfigDict, Field, SecretStr

from mail_triage.transport import ConnectorError, EndpointPolicy, build_client

Sid = Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]{1,128}$")]
Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
Counter = Annotated[int, Field(ge=0, le=100_000)]
Score = Annotated[int, Field(ge=-(2**63), le=2**63 - 1)]
ResultKey = Annotated[str, Field(min_length=1, max_length=1_024)]
MAX_RESPONSE_BYTES = 1024 * 1024
PollingStatus = Literal["NOT_RUN", "COMPLETED", "PARTIAL", "TIMED_OUT", "CANCELLED", "ERROR"]
PollingReason = Literal[
    "disabled",
    "completed_external_analysis",
    "partial_external_analysis",
    "poll_limit_reached",
    "deadline_exceeded",
    "cancelled",
    "input_rejected",
    "configuration_rejected",
    "credential_rejected",
    "authentication_rejected",
    "submission_unavailable",
    "service_rejected",
    "transport_rejected",
    "response_too_large",
    "invalid_response",
    "identity_mismatch",
]


class _Record(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True, allow_inf_nan=False)


class PollingPolicy(_Record):
    enabled: bool = False
    interval_seconds: float = Field(default=2, ge=1, le=30)
    deadline_seconds: float = Field(default=60, ge=0.1, le=300)
    max_polls: int = Field(default=30, ge=1, le=60)


class ReadProvenance(_Record):
    operation: Literal["completion", "full"]
    route: str = Field(min_length=1, max_length=192)
    requested_at: datetime
    observed_at: datetime | None = None
    http_status: Annotated[int, Field(ge=100, le=599)] | None = None
    response_sha256: Digest | None = None


class SubmissionProjection(_Record):
    """External execution state and raw counters; never a safety/probability verdict."""

    state: Literal["submitted", "completed", "failed"]
    raw_max_score: Score
    file_count: Counter
    error_count: Counter
    result_count: Counter
    returned_error_count: Counter
    missing_result_count: Counter
    missing_error_count: Counter
    missing_file_count: Counter
    partial_result_count: Counter
    untrusted_service_names: list[str] = Field(default_factory=list, max_length=128)


class PollingReport(_Record):
    status: PollingStatus
    reason: PollingReason
    execution_mode: Literal["MOCK", "LIVE", "NOT_RUN"] = "NOT_RUN"
    sid: Sid | None = None
    input_sha256: Digest | None = None
    source_origin: str | None = Field(default=None, max_length=2_048)
    pinned_ip: str | None = Field(default=None, max_length=45)
    started_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    finished_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    polls: int = Field(default=0, ge=0, le=60)
    requests: list[ReadProvenance] = Field(default_factory=list, max_length=61)
    analysis: SubmissionProjection | None = None


class _WireRecord(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True, allow_inf_nan=False)


class _CompletionResponse(_WireRecord):
    api_status_code: Literal[200]
    api_error_message: Literal[""]
    api_response: bool


class _SubmittedFile(_WireRecord):
    sha256: Digest


class _ServiceResponse(_WireRecord):
    service_name: str = Field(
        min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9_. -]*$"
    )


class _ServiceResult(_WireRecord):
    partial: bool = False
    response: _ServiceResponse | None = None


class _FullData(_WireRecord):
    sid: Sid
    state: Literal["submitted", "completed", "failed"]
    max_score: Score
    files: list[_SubmittedFile] = Field(min_length=1, max_length=16)
    file_count: Counter
    error_count: Counter
    results: dict[ResultKey, _ServiceResult] = Field(max_length=4_096)
    errors: dict[ResultKey, object] = Field(max_length=4_096)
    missing_result_keys: list[ResultKey] = Field(max_length=4_096)
    missing_error_keys: list[ResultKey] = Field(max_length=4_096)
    missing_file_keys: list[ResultKey] = Field(max_length=4_096)


class _FullResponse(_WireRecord):
    api_status_code: Literal[200]
    api_error_message: Literal[""]
    api_response: _FullData


class _PollingCancelled(Exception):
    pass


class _ReadRejected(Exception):
    def __init__(self, reason: PollingReason) -> None:
        self.reason = reason
        super().__init__(reason)


async def _cancellable[T](
    operation: Coroutine[object, object, T],
    cancel: asyncio.Event | None,
    *,
    deadline: float | None = None,
) -> T:
    task = asyncio.create_task(operation)
    stop = asyncio.create_task(cancel.wait()) if cancel is not None else None

    async def settle(pending: asyncio.Task[object]) -> None:
        current = asyncio.current_task()
        cancellations = current.cancelling() if current is not None else 0
        if not pending.done():
            pending.cancel()
        try:
            # A request's own cleanup budget must not outlive the polling budget.
            async with asyncio.timeout_at(deadline):
                await pending
        except asyncio.CancelledError:
            # Ignore the child's cancellation, never a new cancellation of this caller.
            if current is not None and current.cancelling() > cancellations:
                raise
        except Exception:
            # The primary request outcome is handled by the caller, not cleanup.
            pass

    try:
        if stop is not None:
            done, _ = await asyncio.wait({task, stop}, return_when=asyncio.FIRST_COMPLETED)
            if stop in done:
                raise _PollingCancelled
        # Parent cancellation must reach this scope immediately, before child cleanup.
        return await asyncio.shield(task)
    finally:
        try:
            await settle(task)
        finally:
            if stop is not None:
                await settle(stop)


async def _wait_interval(
    seconds: float, cancel: asyncio.Event | None, *, deadline: float | None = None
) -> None:
    """One bounded polling interval; tests replace this helper with a fake wait."""
    await _cancellable(asyncio.sleep(seconds), cancel, deadline=deadline)


def _credential(credential: SecretStr) -> str:
    if not isinstance(credential, SecretStr):
        raise _ReadRejected("credential_rejected")
    key = credential.get_secret_value()
    if not 1 <= len(key) <= 4_096 or any(not 33 <= ord(char) <= 126 for char in key):
        raise _ReadRejected("credential_rejected")
    return key


def _project(data: _FullData, sid: str, input_hash: str, key: str) -> SubmissionProjection:
    # This application submits exactly one original EML. A descendant hash does not bind identity.
    if data.sid != sid or len(data.files) != 1 or data.files[0].sha256 != input_hash:
        raise _ReadRejected("identity_mismatch")
    names = sorted({item.response.service_name for item in data.results.values() if item.response})
    if len(names) > 128 or any(key in name for name in names):
        raise _ReadRejected("invalid_response")
    projection = SubmissionProjection(
        state=data.state,
        raw_max_score=data.max_score,
        file_count=data.file_count,
        error_count=data.error_count,
        result_count=len(data.results),
        returned_error_count=len(data.errors),
        missing_result_count=len(data.missing_result_keys),
        missing_error_count=len(data.missing_error_keys),
        missing_file_count=len(data.missing_file_keys),
        partial_result_count=sum(item.partial for item in data.results.values()),
        untrusted_service_names=names,
    )
    if key in projection.model_dump_json():
        raise _ReadRejected("invalid_response")
    return projection


async def poll_submission(
    endpoint: EndpointPolicy,
    username: str,
    sid: str,
    input_sha256: str,
    credential: SecretStr,
    policy: PollingPolicy,
    *,
    inner: httpx.AsyncBaseTransport | None = None,
    cancel: asyncio.Event | None = None,
) -> PollingReport:
    """Poll one known submission, then fetch its result once; never submit or retry.

    Explicit cancel events produce CANCELLED. External task cancellation propagates
    after client cleanup, preserving standard asyncio cancellation semantics.
    """
    started = datetime.now(UTC)
    requests: list[ReadProvenance] = []
    polls = 0
    mode: Literal["MOCK", "LIVE", "NOT_RUN"] = "NOT_RUN"
    safe_sid = sid if isinstance(sid, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,128}", sid) else None
    safe_hash = (
        input_sha256
        if isinstance(input_sha256, str) and re.fullmatch(r"[0-9a-f]{64}", input_sha256)
        else None
    )
    checked_endpoint: EndpointPolicy | None = None
    with suppress(ValueError, TypeError, AttributeError):
        checked_endpoint = EndpointPolicy.model_validate(endpoint.model_dump())
    known_key = credential.get_secret_value() if isinstance(credential, SecretStr) else ""

    def redact(value: str | None) -> str | None:
        return None if known_key and value is not None and known_key in value else value

    def report(
        status: PollingStatus,
        reason: PollingReason,
        analysis: SubmissionProjection | None = None,
    ) -> PollingReport:
        return PollingReport(
            status=status,
            reason=reason,
            execution_mode=mode,
            sid=redact(safe_sid),
            input_sha256=redact(safe_hash),
            source_origin=redact(checked_endpoint.origin if checked_endpoint else None),
            pinned_ip=redact(checked_endpoint.pinned_ip if checked_endpoint else None),
            started_at=started,
            finished_at=datetime.now(UTC),
            polls=polls,
            requests=requests,
            analysis=analysis,
        )

    if not policy.enabled:
        return report("NOT_RUN", "disabled")
    try:
        try:
            checked_policy = PollingPolicy.model_validate(policy.model_dump())
        except (ValueError, TypeError, AttributeError):
            raise _ReadRejected("configuration_rejected") from None
        if checked_endpoint is None:
            raise _ReadRejected("configuration_rejected")
        if (
            safe_sid is None
            or safe_hash is None
            or not isinstance(username, str)
            or not re.fullmatch(r"[A-Za-z0-9_.@-]{1,128}", username)
        ):
            raise _ReadRejected("input_rejected")
        key = _credential(credential)
        if any(
            key in value
            for value in (safe_sid, safe_hash, checked_endpoint.origin, checked_endpoint.pinned_ip)
        ):
            safe_sid = None if key in safe_sid else safe_sid
            safe_hash = None if key in safe_hash else safe_hash
            if key in checked_endpoint.origin or key in checked_endpoint.pinned_ip:
                checked_endpoint = None
            raise _ReadRejected("credential_rejected")
        if inner is not None and not isinstance(inner, httpx.MockTransport):
            raise _ReadRejected("configuration_rejected")
        if cancel is not None and cancel.is_set():
            return report("CANCELLED", "cancelled")
        completion_path = f"/api/v4/submission/is_completed/{safe_sid}/"
        full_path = f"/api/v4/submission/full/{safe_sid}/"
        deadline = asyncio.get_running_loop().time() + checked_policy.deadline_seconds

        async def read(
            client: httpx.AsyncClient, path: str, operation: Literal["completion", "full"]
        ) -> bytes:
            if cancel is not None and cancel.is_set():
                raise _PollingCancelled
            requests.append(
                ReadProvenance(operation=operation, route=path, requested_at=datetime.now(UTC))
            )
            response = await _cancellable(
                client.get(
                    path,
                    headers={"X-USER": username, "X-APIKEY": key, "Accept": "application/json"},
                ),
                cancel,
                deadline=deadline,
            )
            requests[-1] = ReadProvenance(
                operation=operation,
                route=path,
                requested_at=requests[-1].requested_at,
                observed_at=datetime.now(UTC),
                http_status=response.status_code,
                response_sha256=hashlib.sha256(response.content).hexdigest(),
            )
            if response.status_code in {401, 403}:
                raise _ReadRejected("authentication_rejected")
            if response.status_code == 404:
                raise _ReadRejected("submission_unavailable")
            if response.status_code != 200:
                raise _ReadRejected("service_rejected")
            if len(response.content) > MAX_RESPONSE_BYTES:
                raise _ReadRejected("response_too_large")
            if (
                response.headers.get("content-type", "").split(";", 1)[0].lower()
                != "application/json"
            ):
                raise _ReadRejected("invalid_response")
            return response.content

        analysis: SubmissionProjection | None = None
        async with asyncio.timeout_at(deadline):
            client = build_client(
                checked_endpoint, {("GET", completion_path), ("GET", full_path)}, inner=inner
            )
            try:
                mode = "MOCK" if inner is not None else "LIVE"
                for index in range(checked_policy.max_polls):
                    if cancel is not None and cancel.is_set():
                        raise _PollingCancelled
                    polls += 1
                    response = _CompletionResponse.model_validate_json(
                        await read(client, completion_path, "completion")
                    )
                    if response.api_response:
                        full = _FullResponse.model_validate_json(
                            await read(client, full_path, "full")
                        )
                        analysis = _project(full.api_response, safe_sid, safe_hash, key)
                        break
                    if index + 1 < checked_policy.max_polls:
                        await _wait_interval(
                            checked_policy.interval_seconds, cancel, deadline=deadline
                        )
            finally:
                async with asyncio.timeout_at(deadline):
                    await client.aclose()
        if cancel is not None and cancel.is_set():
            return report("CANCELLED", "cancelled")
        if analysis is None:
            return report("TIMED_OUT", "poll_limit_reached")
        partial = (
            analysis.state != "completed"
            or analysis.file_count < 1
            or any(
                (
                    analysis.error_count,
                    analysis.returned_error_count,
                    analysis.missing_result_count,
                    analysis.missing_error_count,
                    analysis.missing_file_count,
                    analysis.partial_result_count,
                )
            )
        )
        return report(
            "PARTIAL" if partial else "COMPLETED",
            "partial_external_analysis" if partial else "completed_external_analysis",
            analysis,
        )
    except _PollingCancelled:
        return report("CANCELLED", "cancelled")
    except TimeoutError:
        return report("TIMED_OUT", "deadline_exceeded")
    except _ReadRejected as exc:
        return report("ERROR", exc.reason)
    except ConnectorError as exc:
        if exc.code == "timeout":
            return report("TIMED_OUT", "deadline_exceeded")
        reason: PollingReason = (
            "response_too_large" if exc.code == "response_too_large" else "transport_rejected"
        )
        return report("ERROR", reason)
    except (ValueError, TypeError, AttributeError):
        return report("ERROR", "invalid_response")
    except (httpx.HTTPError, OSError, RuntimeError):
        return report("ERROR", "transport_rejected")
