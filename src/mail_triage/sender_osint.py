"""Bounded MISP lookups of operator-selected indicators, never a safety verdict."""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import re
from datetime import UTC, datetime
from typing import Annotated, Literal, Self, TypedDict

import httpx
import idna
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator, model_validator

from mail_triage.transport import ConnectorError, EndpointPolicy, build_client


class Record(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True, allow_inf_nan=False)


class Indicator(Record):
    """Explicit selection does not prove that this is the actual sending host/domain."""

    kind: Literal["domain", "ip"]
    value: str = Field(min_length=1, max_length=253)

    @model_validator(mode="after")
    def canonical(self) -> Self:
        if self.kind == "ip":
            if "%" in self.value:
                raise ValueError("Scoped IPs are unsupported")
            normalized = str(ipaddress.ip_address(self.value))
        else:
            normalized = idna.encode(self.value.rstrip("."), uts46=True).decode().lower()
            if "." not in normalized or len(normalized) > 253:
                raise ValueError("A fully qualified domain is required")
            try:
                ipaddress.ip_address(normalized)
            except ValueError:
                pass
            else:
                raise ValueError("Use an IP indicator for IP addresses")
        object.__setattr__(self, "value", normalized)
        return self


class Source(Record):
    source_id: Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]{1,64}$")]
    endpoint: EndpointPolicy


class OsintConfig(Record):
    enabled: bool = False
    sources: list[Source] = Field(default_factory=list, max_length=4)
    indicators: list[Indicator] = Field(default_factory=list, max_length=8)
    max_age_seconds: int = Field(default=7 * 86400, ge=1, le=365 * 86400)
    min_interval_seconds: float = Field(default=1.0, ge=1.0, le=60.0)
    max_attributes: int = Field(default=100, ge=1, le=1000)

    @model_validator(mode="after")
    def valid_selection(self) -> Self:
        if self.enabled and (not self.sources or not self.indicators):
            raise ValueError("Enabled OSINT requires sources and selected indicators")
        if len({s.source_id for s in self.sources}) != len(self.sources):
            raise ValueError("Source IDs must be unique")
        if len({(s.endpoint.origin, s.endpoint.pinned_ip) for s in self.sources}) != len(
            self.sources
        ):
            raise ValueError("Source endpoints must be unique")
        if len({(i.kind, i.value) for i in self.indicators}) != len(self.indicators):
            raise ValueError("Indicators must be unique")
        return self


class OsintCredentials(Record):
    keys: dict[str, SecretStr] = Field(default_factory=dict, max_length=4)

    @field_validator("keys")
    @classmethod
    def safe_keys(cls, value: dict[str, SecretStr]) -> dict[str, SecretStr]:
        for secret in value.values():
            if not re.fullmatch(r"[!-~]{1,512}", secret.get_secret_value()):
                raise ValueError("Invalid credential")
        return value


class Attribute(Record):
    uuid: Annotated[str, Field(pattern=r"^[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$")]
    attribute_type: Literal["domain", "hostname", "ip-src", "ip-dst"]
    value: str = Field(min_length=1, max_length=253)
    source_updated_at: datetime
    update_recency: Literal["CURRENT", "STALE", "FUTURE"]
    to_ids: bool


class _LookupFields(TypedDict):
    source_id: str
    source_origin: str
    indicator: Indicator
    queried_at: datetime


class Lookup(Record):
    source_id: str
    source_origin: str
    indicator: Indicator
    queried_at: datetime
    status: Literal["OBSERVED", "MISSING", "ERROR"]
    reason: str
    response_sha256: str | None = None
    attributes: list[Attribute] = Field(default_factory=list)
    possibly_truncated: bool = False


class OsintEvidence(Record):
    schema_version: Literal["1.0"] = "1.0"
    status: Literal["NOT_RUN", "OBSERVED", "UNKNOWN", "ERROR"]
    execution_mode: Literal["NOT_RUN", "MOCK", "LIVE"] = "NOT_RUN"
    input_sha256: str
    reason: str
    lookups: list[Lookup] = Field(default_factory=list)
    conflicting_to_ids: list[Indicator] = Field(default_factory=list)
    limitations: list[str] = Field(
        default_factory=lambda: [
            "Operator-selected indicators are unverified associations with this message.",
            "MISP to_ids is a detection-use flag, not a malicious/benign or phishing verdict.",
            "MISP timestamps are last-update times, not observation or validity times.",
            "Missing matches, stale data and conflicting claims do not establish safety.",
            "No DNS resolution, sender authentication or gateway statistics are performed.",
        ]
    )


def _attributes(
    raw: bytes, indicator: Indicator, config: OsintConfig, now: datetime
) -> list[Attribute]:
    # Fail closed on malformed known fields, duplicate keys and oversized item lists.
    from mail_triage.connector_cli import _json

    payload = _json(raw)
    if not isinstance(payload, dict) or not isinstance(payload.get("response"), dict):
        raise ValueError("Invalid MISP envelope")
    items = payload["response"].get("Attribute")
    if not isinstance(items, list) or len(items) > config.max_attributes:
        raise ValueError("Invalid MISP attributes")
    result: list[Attribute] = []
    allowed = {"domain", "hostname"} if indicator.kind == "domain" else {"ip-src", "ip-dst"}
    for item in items:
        if not isinstance(item, dict):
            raise ValueError("Invalid attribute")
        kind = item.get("type")
        if kind not in allowed:
            continue
        value = item.get("value")
        if not isinstance(value, str):
            raise ValueError("Invalid attribute value")
        if Indicator(kind=indicator.kind, value=value).value != indicator.value:
            continue  # MISP search can return non-exact matches; never attribute those to sender.
        deleted = item.get("deleted")
        if type(deleted) is not bool:
            raise ValueError("Invalid deleted flag")
        if deleted:
            continue
        stamp = item.get("timestamp")
        if not isinstance(stamp, str) or not re.fullmatch(r"[0-9]{1,11}", stamp):
            raise ValueError("Invalid MISP timestamp")
        updated = datetime.fromtimestamp(int(stamp), UTC)
        age = (now - updated).total_seconds()
        uuid = item.get("uuid")
        flag = item.get("to_ids")
        if not isinstance(uuid, str) or type(flag) is not bool:
            raise ValueError("Invalid MISP identity or flag")
        result.append(
            Attribute(
                uuid=uuid,
                attribute_type=kind,
                value=indicator.value,
                source_updated_at=updated,
                update_recency="FUTURE"
                if age < 0
                else "STALE"
                if age > config.max_age_seconds
                else "CURRENT",
                to_ids=flag,
            )
        )
    return result


async def lookup_sender(
    config: OsintConfig,
    credentials: OsintCredentials,
    *,
    input_sha256: str,
    allow_egress: bool = False,
    inner: httpx.AsyncBaseTransport | None = None,
) -> OsintEvidence:
    """Sequential, rate-limited, bounded run; cancellation propagates, no automatic retries.

    `inner` is solely a test injection point. MOCK results still require explicit opt-in.
    No email bytes, addresses, URLs, headers or credentials are included in query JSON.
    """
    config = OsintConfig.model_validate(config.model_dump())
    credentials = OsintCredentials.model_validate(credentials.model_dump())
    if not re.fullmatch(r"[a-f0-9]{64}", input_sha256):
        raise ValueError("Invalid input digest")
    if not config.enabled or not allow_egress:
        return OsintEvidence(
            status="NOT_RUN", input_sha256=input_sha256, reason="disabled_or_egress_not_authorized"
        )
    if set(credentials.keys) != {source.source_id for source in config.sources}:
        raise ConnectorError("explicit_osint_credentials_required")
    lookups: list[Lookup] = []
    last_started: float | None = None
    loop = asyncio.get_running_loop()
    for source in config.sources:
        # Reuse existing TLS/IP/route/byte/deadline protections, with tighter OSINT caps.
        endpoint = source.endpoint.model_copy(
            update={
                "max_request_bytes": min(source.endpoint.max_request_bytes, 4096),
                "max_response_bytes": min(source.endpoint.max_response_bytes, 1024 * 1024),
            }
        )
        async with build_client(endpoint, {("POST", "/attributes/restSearch")}, inner) as client:
            for indicator in config.indicators:
                if last_started is not None:
                    await asyncio.sleep(
                        max(0, config.min_interval_seconds - (loop.time() - last_started))
                    )
                last_started = loop.time()
                now = datetime.now(UTC)
                fields = _LookupFields(
                    source_id=source.source_id,
                    source_origin=endpoint.origin,
                    indicator=indicator,
                    queried_at=now,
                )
                digest: str | None = None
                try:
                    response = await client.post(
                        "/attributes/restSearch",
                        headers={
                            "Authorization": credentials.keys[source.source_id].get_secret_value(),
                            "Accept": "application/json",
                        },
                        json={
                            "returnFormat": "json",
                            "value": indicator.value,
                            "type": ["domain", "hostname"]
                            if indicator.kind == "domain"
                            else ["ip-src", "ip-dst"],
                            "limit": config.max_attributes,
                            "page": 1,
                            "deleted": False,
                        },
                    )
                    digest = hashlib.sha256(response.content).hexdigest()
                    if response.status_code != 200:
                        lookups.append(
                            Lookup(
                                **fields,
                                status="ERROR",
                                reason="service_rejected",
                                response_sha256=digest,
                            )
                        )
                        continue
                    attrs = _attributes(response.content, indicator, config, now)
                    payload = json.loads(response.content)
                    lookups.append(
                        Lookup(
                            **fields,
                            status="OBSERVED" if attrs else "MISSING",
                            reason="untrusted_attributes"
                            if attrs
                            else "no_exact_current_or_historical_match",
                            attributes=attrs,
                            response_sha256=digest,
                            possibly_truncated=len(payload["response"]["Attribute"])
                            >= config.max_attributes,
                        )
                    )
                except ConnectorError as exc:
                    lookups.append(Lookup(**fields, status="ERROR", reason=exc.code))
                except (ValueError, TypeError, OverflowError, RecursionError):
                    lookups.append(
                        Lookup(
                            **fields,
                            status="ERROR",
                            reason="invalid_response",
                            response_sha256=digest,
                        )
                    )
    conflicts = []
    for indicator in config.indicators:
        flags = {
            attr.to_ids
            for lookup in lookups
            if lookup.indicator == indicator
            for attr in lookup.attributes
            if attr.update_recency == "CURRENT"
        }
        if len(flags) > 1:
            conflicts.append(indicator)
    observed = any(item.attributes for item in lookups)
    failed = any(item.status == "ERROR" for item in lookups)
    return OsintEvidence(
        status="OBSERVED" if observed else "ERROR" if failed else "UNKNOWN",
        execution_mode="MOCK" if inner is not None else "LIVE",
        input_sha256=input_sha256,
        reason="untrusted_evidence_only",
        lookups=lookups,
        conflicting_to_ids=conflicts,
    )
