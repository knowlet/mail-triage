"""Versioned evidence contracts; observations never imply authentication or safety."""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class Record(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Limits(Record):
    max_raw_bytes: int = Field(default=5 * 1024 * 1024, ge=1)
    max_parts: int = Field(default=100, ge=1)
    max_depth: int = Field(default=12, ge=1)
    max_header_bytes: int = Field(default=128 * 1024, ge=1)
    max_line_bytes: int = Field(default=32 * 1024, ge=1)
    max_decoded_bytes: int = Field(default=5 * 1024 * 1024, ge=1)
    max_text_chars: int = Field(default=100_000, ge=1)


class Header(Record):
    name: str
    value: str


class MimePart(Record):
    part_id: str
    media_type: str
    disposition: str | None = None
    filename: str | None = None
    decoded_bytes: int
    sha256: str
    is_attachment: bool


class TextSegment(Record):
    part_id: str
    kind: Literal["plain", "html_source"]
    text: str


class ParsedEmail(Record):
    headers: list[Header]
    subject: str
    from_addresses: list[str]
    reply_to_addresses: list[str]
    parts: list[MimePart]
    text_segments: list[TextSegment]
    warnings: list[str] = Field(default_factory=list)


class Provenance(Record):
    sha256: str
    raw_bytes: int
    source_name: str
    source_kind: Literal["local_eml", "graph_original"] = "local_eml"
    ingested_at: datetime
    original_artifact: str = "original.eml"


class Check(Record):
    status: Literal["OBSERVED", "UNKNOWN", "NOT_RUN", "ERROR"]
    reason: str
    observations: list[str] = Field(default_factory=list)


class AuthenticationEvidence(Record):
    spf: Check
    dkim: Check
    dmarc: Check
    alignment: Check
    untrusted_authentication_results: list[str]
    trust_boundary: str


class Finding(Record):
    code: str
    description: str
    evidence: list[str] = Field(default_factory=list)


class ContentEvidence(Record):
    status: Literal["OBSERVED"] = "OBSERVED"
    method: str = "deterministic offline heuristics v1"
    findings: list[Finding]
    limitations: list[str]


class ReputationEvidence(Record):
    sender_osint: Check
    gateway_reputation: Check
    gateway_spam_rate: Check
    assemblyline: Check
    sublime: Check
    outlook_ingestion: Check


class Report(Record):
    schema_version: Literal["1.0"] = "1.0"
    application_version: str = "0.1.0"
    disposition: Literal["REVIEW_REQUIRED"] = "REVIEW_REQUIRED"
    provenance: Provenance
    limits: Limits
    message: ParsedEmail
    authentication: AuthenticationEvidence
    content: ContentEvidence
    reputation: ReputationEvidence
    model_stages: dict[str, Check]
    warnings: list[str]
