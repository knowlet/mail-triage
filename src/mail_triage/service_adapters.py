"""Explicit service submissions; external replies never establish identity or safety."""

from __future__ import annotations

import base64
import hashlib
import json
import os
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Literal, Self
from urllib.parse import urlsplit

import httpx
from pydantic import BaseModel, ConfigDict, Field, SecretStr, model_validator

from mail_triage.transport import ConnectorError, EndpointPolicy, build_client

MAX_INPUT_BYTES = 5 * 1024 * 1024
MAX_SERVICE_RESPONSE_BYTES = 1024 * 1024
Service = Literal["assemblyline", "sublime"]
Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
ExternalId = Annotated[str, Field(pattern=r"^[A-Za-z0-9_.:-]{1,128}$")]
Reason = Literal[
    "disabled",
    "input_rejected",
    "configuration_rejected",
    "credential_rejected",
    "duplicate_submission_blocked",
    "claim_storage_failed",
    "transport_rejected",
    "request_failed_outcome_unknown",
    "request_timeout_outcome_unknown",
    "authentication_rejected",
    "service_rejected",
    "response_too_large",
    "invalid_response",
    "untrusted_response_observed_no_safety_or_identity_verdict",
]


class SettingsRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class AssemblylineConfig(SettingsRecord):
    enabled: bool = False
    endpoint: EndpointPolicy | None = None
    username: Annotated[str, Field(pattern=r"^[A-Za-z0-9_.@-]{1,128}$")] | None = None

    @model_validator(mode="after")
    def enabled_requires_configuration(self) -> Self:
        if self.enabled and (self.endpoint is None or self.username is None):
            raise ValueError("Enabled Assemblyline requires an endpoint and username.")
        return self


class SublimeRule(SettingsRecord):
    """Operator-authored rule source, never a URL, file path, or automatic rule feed."""

    name: str = Field(min_length=1, max_length=128)
    source: str = Field(min_length=1, max_length=8_000)
    severity: Annotated[str, Field(pattern=r"^[A-Za-z][A-Za-z_-]{0,31}$")] | None = None


class SublimeConfig(SettingsRecord):
    enabled: bool = False
    endpoint: EndpointPolicy | None = None
    selected_rules: list[SublimeRule] = Field(default_factory=list, max_length=16)

    @model_validator(mode="after")
    def explicit_self_hosted_configuration(self) -> Self:
        if self.endpoint is not None:
            host = (urlsplit(self.endpoint.origin).hostname or "").lower().rstrip(".")
            public_hosts = ("analyzer.sublime.security", "platform.sublime.security")
            if any(host == public or host.endswith("." + public) for public in public_hosts):
                raise ValueError("Public Sublime analyzer endpoints are not supported.")
        if self.enabled and (self.endpoint is None or not self.selected_rules):
            raise ValueError("Enabled Sublime requires an endpoint and explicit rule sources.")
        if len({rule.name for rule in self.selected_rules}) != len(self.selected_rules):
            raise ValueError("Selected rule names must be unique.")
        return self


class ConnectorResult(SettingsRecord):
    status: Literal["NOT_RUN", "OBSERVED", "ERROR"]
    service: Service
    execution_mode: Literal["MOCK", "LIVE", "NOT_RUN"] = "NOT_RUN"
    reason: Reason
    input_sha256: Digest | None = None
    response_sha256: Digest | None = None
    source_origin: str | None = Field(default=None, max_length=2_048)
    observed_at: datetime | None = None
    external_id: ExternalId | None = None


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


class SubmissionClaims:
    """Durable at-most-once intent per case, including uncertain request outcomes.

    A claim is never automatically removed, even if writing or the POST fails.
    There is no retry/reset method. Records contain only hashes, static service
    identifiers and time, never credentials, rule source or email bytes.
    """

    def __init__(self, directory: Path) -> None:
        self.directory = directory

    def reserve(
        self, *, service: Service, endpoint: EndpointPolicy, input_sha256: str, rules: object
    ) -> str:
        endpoint_hash = hashlib.sha256(
            _canonical({"origin": endpoint.origin, "pinned_ip": endpoint.pinned_ip})
        ).hexdigest()
        rules_hash = hashlib.sha256(_canonical(rules)).hexdigest()
        identity = {
            "service": service,
            "endpoint_sha256": endpoint_hash,
            "input_sha256": input_sha256,
            "rules_sha256": rules_hash,
        }
        key = hashlib.sha256(_canonical(identity)).hexdigest()
        record = _canonical(
            {"schema_version": "1.0", **identity, "created_at": datetime.now(UTC).isoformat()}
        )
        parent_fd: int | None = None
        directory_fd: int | None = None
        file_fd: int | None = None
        try:
            parent_fd = os.open(self.directory.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            with suppress(FileExistsError):
                os.mkdir(self.directory.name, mode=0o700, dir_fd=parent_fd)
            directory_fd = os.open(
                self.directory.name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=parent_fd,
            )
            try:
                file_fd = os.open(
                    key + ".json",
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    0o600,
                    dir_fd=directory_fd,
                )
            except FileExistsError:
                raise ConnectorError("duplicate_submission") from None
            with os.fdopen(file_fd, "wb") as stream:
                file_fd = None
                stream.write(record)
                stream.flush()
                os.fsync(stream.fileno())
            os.fsync(directory_fd)
            # Persist the new directory's entry before any remote submission.
            os.fsync(parent_fd)
            return key
        except ConnectorError:
            raise
        except OSError:
            raise ConnectorError("claim_storage_failed") from None
        finally:
            if file_fd is not None:
                os.close(file_fd)
            if directory_fd is not None:
                os.close(directory_fd)
            if parent_fd is not None:
                os.close(parent_fd)


class _ResponseRecord(BaseModel):
    # Only the bounded fields below are interpreted; all other external data is discarded.
    model_config = ConfigDict(extra="ignore", strict=True)


class _AssemblylineData(_ResponseRecord):
    sid: ExternalId


class _AssemblylineResponse(_ResponseRecord):
    api_status_code: Literal[200]
    api_error_message: Literal[""]
    api_response: _AssemblylineData


class _RuleEcho(_ResponseRecord):
    name: str = Field(min_length=1, max_length=128)
    source: str = Field(min_length=1, max_length=8_000)


class _RuleResult(_ResponseRecord):
    success: bool
    matched: bool
    rule: _RuleEcho


class _SublimeResponse(_ResponseRecord):
    rule_results: list[_RuleResult] = Field(max_length=16)
    query_results: list[dict[str, object]] = Field(max_length=16)


def _credential_value(credential: SecretStr) -> str:
    if not isinstance(credential, SecretStr):
        raise ValueError("Explicit SecretStr credential required.")
    value = credential.get_secret_value()
    if not 1 <= len(value) <= 4_096 or any(not 33 <= ord(char) <= 126 for char in value):
        raise ValueError("Invalid credential format.")
    return value


async def _submit(
    *,
    service: Service,
    endpoint: EndpointPolicy,
    raw: bytes,
    credential: SecretStr,
    claims: SubmissionClaims,
    inner: httpx.AsyncBaseTransport | None,
    username: str | None = None,
    rules: list[dict[str, object]] | None = None,
) -> ConnectorResult:
    input_hash = hashlib.sha256(raw).hexdigest()
    mode: Literal["MOCK", "LIVE", "NOT_RUN"] = "NOT_RUN"
    response_hash: str | None = None
    observed_at: datetime | None = None

    def result(status: Literal["OBSERVED", "ERROR"], reason: Reason) -> ConnectorResult:
        return ConnectorResult(
            status=status,
            service=service,
            execution_mode=mode,
            reason=reason,
            input_sha256=input_hash,
            response_sha256=response_hash,
            source_origin=endpoint.origin,
            observed_at=observed_at,
        )

    try:
        key = _credential_value(credential)
    except ValueError:
        return result("ERROR", "credential_rejected")
    if inner is not None and not isinstance(inner, httpx.MockTransport):
        return result("ERROR", "configuration_rejected")
    path = "/api/v4/submit/" if service == "assemblyline" else "/v0/messages/analyze"
    try:
        async with build_client(endpoint, {("POST", path)}, inner=inner) as client:
            correlation = claims.reserve(
                service=service, endpoint=endpoint, input_sha256=input_hash, rules=rules or []
            )
            mode = "MOCK" if inner is not None else "LIVE"
            if service == "assemblyline":
                response = await client.post(
                    path,
                    headers={
                        "X-USER": username or "",
                        "X-APIKEY": key,
                        "Accept": "application/json",
                    },
                    files={"bin": ("original.eml", raw, "message/rfc822")},
                    data={
                        "json": json.dumps(
                            {"metadata": {"sha256": input_hash, "correlation_id": correlation}}
                        )
                    },
                )
            else:
                response = await client.post(
                    path,
                    headers={"Authorization": "Bearer " + key, "Accept": "application/json"},
                    json={
                        "raw_message": base64.b64encode(raw).decode("ascii"),
                        "rules": rules,
                        "queries": [],
                    },
                )
        response_hash = hashlib.sha256(response.content).hexdigest()
        observed_at = datetime.now(UTC)
        if response.status_code in {401, 403}:
            return result("ERROR", "authentication_rejected")
        if response.status_code != 200:
            return result("ERROR", "service_rejected")
        if len(response.content) > MAX_SERVICE_RESPONSE_BYTES:
            return result("ERROR", "response_too_large")
        if response.headers.get("content-type", "").split(";", 1)[0].lower() != "application/json":
            return result("ERROR", "invalid_response")
        external_id: str | None = None
        if service == "assemblyline":
            parsed = _AssemblylineResponse.model_validate_json(response.content)
            external_id = parsed.api_response.sid
            if key in external_id:
                return result("ERROR", "invalid_response")
        else:
            parsed_sublime = _SublimeResponse.model_validate_json(response.content)
            expected = {rule["name"]: rule["source"] for rule in rules or []}
            observed = parsed_sublime.rule_results
            if (
                len(observed) != len(expected)
                or len({item.rule.name for item in observed}) != len(observed)
                or parsed_sublime.query_results
                or any(
                    not item.success or expected.get(item.rule.name) != item.rule.source
                    for item in observed
                )
            ):
                return result("ERROR", "invalid_response")
        return result(
            "OBSERVED", "untrusted_response_observed_no_safety_or_identity_verdict"
        ).model_copy(update={"external_id": external_id})
    except ConnectorError as exc:
        reasons: dict[str, Reason] = {
            "duplicate_submission": "duplicate_submission_blocked",
            "claim_storage_failed": "claim_storage_failed",
            "timeout": "request_timeout_outcome_unknown",
            "network_error": "request_failed_outcome_unknown",
            "response_too_large": "response_too_large",
        }
        return result("ERROR", reasons.get(exc.code, "transport_rejected"))
    except httpx.TimeoutException:
        return result("ERROR", "request_timeout_outcome_unknown")
    except (httpx.HTTPError, OSError, RuntimeError):
        return result("ERROR", "request_failed_outcome_unknown")
    except (ValueError, TypeError):
        return result("ERROR", "invalid_response")


class AssemblylineAdapter:
    def __init__(
        self, config: AssemblylineConfig, *, inner: httpx.AsyncBaseTransport | None = None
    ) -> None:
        if inner is not None and not isinstance(inner, httpx.MockTransport):
            raise ValueError("Only MockTransport may replace live service egress.")
        self.config = config
        self.inner = inner

    async def analyze(
        self, raw: bytes, *, credential: SecretStr, claims: SubmissionClaims
    ) -> ConnectorResult:
        if not self.config.enabled:
            return ConnectorResult(status="NOT_RUN", service="assemblyline", reason="disabled")
        if not isinstance(raw, bytes) or not 1 <= len(raw) <= MAX_INPUT_BYTES:
            return ConnectorResult(status="ERROR", service="assemblyline", reason="input_rejected")
        try:
            config = AssemblylineConfig.model_validate(self.config.model_dump())
        except ValueError:
            return ConnectorResult(
                status="ERROR", service="assemblyline", reason="configuration_rejected"
            )
        assert config.endpoint is not None
        return await _submit(
            service="assemblyline",
            endpoint=config.endpoint,
            username=config.username,
            raw=raw,
            credential=credential,
            claims=claims,
            inner=self.inner,
        )


class SublimeAdapter:
    def __init__(
        self, config: SublimeConfig, *, inner: httpx.AsyncBaseTransport | None = None
    ) -> None:
        if inner is not None and not isinstance(inner, httpx.MockTransport):
            raise ValueError("Only MockTransport may replace live service egress.")
        self.config = config
        self.inner = inner

    async def analyze(
        self, raw: bytes, *, credential: SecretStr, claims: SubmissionClaims
    ) -> ConnectorResult:
        if not self.config.enabled:
            return ConnectorResult(status="NOT_RUN", service="sublime", reason="disabled")
        if not isinstance(raw, bytes) or not 1 <= len(raw) <= MAX_INPUT_BYTES:
            return ConnectorResult(status="ERROR", service="sublime", reason="input_rejected")
        try:
            config = SublimeConfig.model_validate(self.config.model_dump())
        except ValueError:
            return ConnectorResult(
                status="ERROR", service="sublime", reason="configuration_rejected"
            )
        assert config.endpoint is not None
        return await _submit(
            service="sublime",
            endpoint=config.endpoint,
            rules=[rule.model_dump(exclude_none=True) for rule in config.selected_rules],
            raw=raw,
            credential=credential,
            claims=claims,
            inner=self.inner,
        )
