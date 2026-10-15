"""Strict v1 wire contracts. None of these records is proof until verified."""

from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, SecretStr, model_validator

Token = Annotated[str, Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_.:-]+$")]
Identity = Annotated[str, Field(min_length=1, max_length=512, pattern=r"^[\x21-\x7e]+$")]
Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
Domain = Annotated[str, Field(min_length=1, max_length=253)]
Timestamp = Annotated[int, Field(ge=0, le=253402300799)]
Outcome = Literal[
    "PASS", "FAIL", "SOFTFAIL", "NEUTRAL", "NONE", "TEMPERROR", "PERMERROR", "UNKNOWN"
]
Alignment = Literal["PASS", "FAIL", "UNKNOWN"]

PROFILE = "rfc7489-psl-private-v1"
PSL_SHA256 = "b69315c085d53972724b8f2df111ffc329b0c84fe0a47d62c8c91655cc774a38"


class StrictRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True, hide_input_in_errors=True)


class MessageIdentity(StrictRecord):
    """Out-of-band original identity, NOT the untrusted RFC Message-ID header."""

    tenant_id: Identity
    mailbox_id: Identity
    message_id: Identity


class OriginalBinding(StrictRecord):
    identity: MessageIdentity
    representation: Literal["original-mime-bytes"]
    sha256: Digest
    raw_bytes: Annotated[int, Field(ge=1, le=5 * 1024 * 1024)]


class SPFResult(StrictRecord):
    result: Outcome
    smtp_peer_ip: Annotated[str, Field(min_length=2, max_length=45)] | None
    identity: Literal["mailfrom", "helo"]
    domain: Domain | None
    null_mail_from: bool

    @model_validator(mode="after")
    def validate_identity(self) -> Self:
        if self.identity == "mailfrom" and self.null_mail_from:
            raise ValueError("Null reverse-path requires the HELO identity.")
        if self.result != "UNKNOWN" and (self.domain is None or self.smtp_peer_ip is None):
            raise ValueError("An evaluated SPF result requires its tested domain and SMTP peer.")
        return self


class DKIMSignature(StrictRecord):
    signature_id: Token
    result: Literal["PASS", "FAIL", "TEMPERROR", "PERMERROR", "UNKNOWN"]
    domain: Domain
    selector: Token


class DKIMResults(StrictRecord):
    complete: bool
    signatures: Annotated[list[DKIMSignature], Field(max_length=32)]

    @model_validator(mode="after")
    def unique_signatures(self) -> Self:
        if len({s.signature_id for s in self.signatures}) != len(self.signatures):
            raise ValueError("Duplicate signature identity.")
        return self


class DMARCResult(StrictRecord):
    result: Literal["PASS", "FAIL", "NONE", "TEMPERROR", "PERMERROR", "UNKNOWN"]
    policy_domain: Domain | None
    policy: Literal["none", "quarantine", "reject"] | None
    policy_record_sha256: Digest | None
    aspf: Literal["s", "r"]
    adkim: Literal["s", "r"]

    @model_validator(mode="after")
    def evaluated_policy(self) -> Self:
        fields = (self.policy_domain, self.policy, self.policy_record_sha256)
        if self.result in {"PASS", "FAIL"} and any(v is None for v in fields):
            raise ValueError("DMARC pass/fail requires evaluated policy provenance.")
        if self.result == "NONE" and any(v is not None for v in fields):
            raise ValueError("No-policy result must not claim a policy.")
        return self


class AlignmentClaim(StrictRecord):
    profile: Literal["rfc7489-psl-private-v1"]
    psl_sha256: Digest
    spf: Alignment
    dkim: Alignment


class IngressAssertionV1(StrictRecord):
    schema_version: Literal["mail-triage.ingress-assertion/1"]
    audience: Token
    event_id: Annotated[str, Field(min_length=16, max_length=128, pattern=r"^[A-Za-z0-9_-]+$")]
    issued_at: Timestamp
    expires_at: Timestamp
    received_at: Timestamp
    boundary_id: Token
    verifier_version: Token
    evidence_origin: Literal["smtp-session-and-cryptographic-verifier"]
    internal_auth_headers_sanitized: bool
    original: OriginalBinding
    header_from_domain: Domain
    spf: SPFResult
    dkim: DKIMResults
    dmarc: DMARCResult
    alignment: AlignmentClaim


class SignedEnvelopeV1(StrictRecord):
    schema_version: Literal["mail-triage.ingress-envelope/1"]
    algorithm: Literal["HMAC-SHA256"]
    issuer_id: Token
    key_id: Token
    payload: Annotated[str, Field(min_length=1, max_length=48000, pattern=r"^[A-Za-z0-9_-]+$")]
    mac: Digest


class KeyGrant(StrictRecord):
    issuer_id: Token
    key_id: Token
    tenant_id: Identity
    mailbox_ids: Annotated[list[Identity], Field(min_length=1, max_length=32)]
    audience: Token
    boundary_id: Token
    verifier_version: Token
    not_before: Timestamp
    not_after: Timestamp

    @model_validator(mode="after")
    def valid_window(self) -> Self:
        if self.not_after <= self.not_before:
            raise ValueError("Invalid key validity window.")
        if len(set(self.mailbox_ids)) != len(self.mailbox_ids):
            raise ValueError("Duplicate mailbox grant.")
        return self


class IngressTrustPolicy(StrictRecord):
    schema_version: Literal["mail-triage.ingress-trust/1"]
    grants: Annotated[list[KeyGrant], Field(min_length=1, max_length=32)]
    max_issuance_age_seconds: Annotated[int, Field(ge=1, le=86400)] = 900
    max_lifetime_seconds: Annotated[int, Field(ge=1, le=86400)] = 900
    max_receive_age_seconds: Annotated[int, Field(ge=1, le=90 * 86400)] = 30 * 86400
    clock_skew_seconds: Annotated[int, Field(ge=0, le=300)] = 60

    @model_validator(mode="after")
    def unique_grants(self) -> Self:
        if len({(g.issuer_id, g.key_id) for g in self.grants}) != len(self.grants):
            raise ValueError("Ambiguous issuer/key grant.")
        return self


class KeySecret(StrictRecord):
    issuer_id: Token
    key_id: Token
    key_hex: SecretStr


class IngressSecrets(StrictRecord):
    keys: Annotated[list[KeySecret], Field(min_length=1, max_length=32)]


class VerifiedResults(StrictRecord):
    spf: Outcome = "UNKNOWN"
    dkim: Outcome = "UNKNOWN"
    dmarc: Outcome = "UNKNOWN"
    spf_alignment: Alignment = "UNKNOWN"
    dkim_alignment: Alignment = "UNKNOWN"
    alignment: Alignment = "UNKNOWN"


class IngressAssessment(StrictRecord):
    """Report output, not an importable trust token. Reverify the signed envelope."""

    schema_version: Literal["mail-triage.ingress-assessment/1"] = "mail-triage.ingress-assessment/1"
    status: Literal["MISSING", "REJECTED", "ACCEPTED"]
    reason_code: Token
    checked_at: Timestamp
    envelope_sha256: Digest | None = None
    results: VerifiedResults = Field(default_factory=VerifiedResults)
    envelope: SignedEnvelopeV1 | None = None
    assertion: IngressAssertionV1 | None = None
