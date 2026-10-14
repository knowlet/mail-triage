"""Explicit, read-only Graph ingestion of a wrapper and one selected original.

No account discovery, token acquisition, mailbox listing, or environment defaults
occur here. Graph supplies MIME bytes; it does not attest SMTP authentication.
The itemAttachment MIME contract is documented at:
https://learn.microsoft.com/en-us/graph/api/attachment-get?view=graph-rest-1.0
"""

from __future__ import annotations

import asyncio
import hashlib
import re
import unicodedata
from typing import Literal
from urllib.parse import quote

import httpx
from pydantic import BaseModel, ConfigDict, Field, SecretStr, ValidationError

from mail_triage.ingest import IngestError, parse_eml
from mail_triage.schemas import Limits
from mail_triage.transport import ConnectorError, EndpointPolicy, build_client


class GraphConfig(BaseModel):
    """A mailbox and endpoint must be explicitly supplied before use."""

    model_config = ConfigDict(extra="forbid")

    enabled: bool = False
    endpoint: EndpointPolicy | None = None
    mailbox: str = Field(default="", max_length=512)
    limits: Limits = Field(default_factory=Limits)


class GraphAttachmentMetadata(BaseModel):
    """Selected inert metadata; arbitrary response fields/URLs are not retained."""

    model_config = ConfigDict(extra="forbid", strict=True)

    attachment_type: Literal["#microsoft.graph.itemAttachment"]
    attachment_id: str = Field(min_length=1, max_length=512)
    content_type: str | None = Field(default=None, max_length=256)
    declared_size: int | None = Field(default=None, ge=0, le=2**31 - 1)
    is_inline: bool | None = None


class GraphBundle(BaseModel):
    """Exact returned MIME bytes and separate identities, never merged evidence."""

    model_config = ConfigDict(extra="forbid")

    wrapper: bytes = Field(repr=False)
    original: bytes = Field(repr=False)
    wrapper_sha256: str
    original_sha256: str
    mailbox: str
    wrapper_message_id: str
    original_attachment_id: str
    source_endpoint: str
    metadata: GraphAttachmentMetadata


def _segment(value: str) -> str:
    # Quote each opaque ID individually. Literal dot segments must be rejected:
    # urllib.quote intentionally leaves the unreserved dot character unquoted.
    if (
        not value
        or len(value) > 512
        or value in {".", ".."}
        or any(unicodedata.category(char).startswith("C") for char in value)
    ):
        raise ConnectorError("invalid_identifier")
    return quote(value, safe="")


def _metadata(
    response: httpx.Response, attachment_id: str, limits: Limits
) -> GraphAttachmentMetadata:
    if len(response.content) > 64 * 1024:
        raise ConnectorError("metadata_too_large")
    try:
        data = response.json()
        if not isinstance(data, dict) or data.get("id") != attachment_id:
            raise ConnectorError("metadata_invalid")
        metadata = GraphAttachmentMetadata.model_validate(
            {
                "attachment_type": data.get("@odata.type"),
                "attachment_id": data.get("id"),
                "content_type": data.get("contentType"),
                "declared_size": data.get("size"),
                "is_inline": data.get("isInline"),
            }
        )
        if metadata.content_type is not None and any(
            unicodedata.category(char).startswith("C") for char in metadata.content_type
        ):
            raise ConnectorError("metadata_invalid")
        if metadata.declared_size is not None and metadata.declared_size > limits.max_raw_bytes:
            raise ConnectorError("response_too_large")
        return metadata
    except ConnectorError:
        raise
    except (ValueError, ValidationError, TypeError, RecursionError):
        raise ConnectorError("metadata_invalid") from None


class GraphAdapter:
    """Fetch only three selected resources from one policy-controlled origin."""

    def __init__(
        self, config: GraphConfig, *, inner: httpx.AsyncBaseTransport | None = None
    ) -> None:
        self.config = config
        self.inner = inner

    async def fetch(
        self,
        wrapper_message_id: str,
        original_attachment_id: str,
        *,
        token: SecretStr,
    ) -> GraphBundle:
        if not self.config.enabled:
            raise ConnectorError("not_enabled")
        if self.inner is not None and not isinstance(self.inner, httpx.MockTransport):
            raise ConnectorError("mock_transport_required")
        endpoint = self.config.endpoint
        if endpoint is None or not self.config.mailbox:
            raise ConnectorError("not_configured")
        mailbox = _segment(self.config.mailbox)
        message = _segment(wrapper_message_id)
        attachment = _segment(original_attachment_id)
        if not isinstance(token, SecretStr) or not token.get_secret_value():
            raise ConnectorError("missing_token")
        credential = token.get_secret_value()
        if len(credential) > 16 * 1024 or not re.fullmatch(r"[A-Za-z0-9._~+/\-]+=*", credential):
            raise ConnectorError("invalid_token")
        message_path = f"/v1.0/users/{mailbox}/messages/{message}"
        wrapper_path = f"{message_path}/$value"
        metadata_path = f"{message_path}/attachments/{attachment}"
        original_path = f"{metadata_path}/$value"
        routes = {("GET", path) for path in (wrapper_path, metadata_path, original_path)}
        headers = {"Authorization": f"Bearer {credential}"}

        async def get(client: httpx.AsyncClient, path: str, accept: str) -> httpx.Response:
            response = await client.get(
                endpoint.origin + path, headers={**headers, "Accept": accept}
            )
            if response.status_code != 200:
                raise ConnectorError("http_status")
            return response

        try:
            async with asyncio.timeout(endpoint.total_timeout):
                async with build_client(endpoint, routes, inner=self.inner) as client:
                    wrapper_response = await get(client, wrapper_path, "message/rfc822")
                    wrapper = wrapper_response.content
                    self._validate_message(wrapper, "invalid_wrapper")
                    metadata_response = await get(client, metadata_path, "application/json")
                    metadata = _metadata(
                        metadata_response, original_attachment_id, self.config.limits
                    )
                    original_response = await get(client, original_path, "message/rfc822")
                    original = original_response.content
                    self._validate_message(original, "invalid_original")
        except ConnectorError:
            raise
        except TimeoutError:
            raise ConnectorError("timeout") from None
        except httpx.HTTPError:
            raise ConnectorError("network_error") from None

        return GraphBundle(
            wrapper=wrapper,
            original=original,
            wrapper_sha256=hashlib.sha256(wrapper).hexdigest(),
            original_sha256=hashlib.sha256(original).hexdigest(),
            mailbox=self.config.mailbox,
            wrapper_message_id=wrapper_message_id,
            original_attachment_id=original_attachment_id,
            source_endpoint=endpoint.origin,
            metadata=metadata,
        )

    def _validate_message(self, raw: bytes, error_code: str) -> None:
        try:
            parse_eml(raw, self.config.limits)
        except IngestError:
            raise ConnectorError(error_code) from None
