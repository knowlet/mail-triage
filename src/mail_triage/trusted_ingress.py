"""Offline verification of independently signed ingress evidence; never header trust."""

import base64
import hashlib
import hmac
import ipaddress
import json
import os
import time
from collections.abc import Mapping
from importlib import resources
from pathlib import Path
from typing import cast

import idna
import tldextract
from pydantic import ValidationError

from mail_triage.ingress_contract import (
    PSL_SHA256,
    Alignment,
    IngressAssertionV1,
    IngressAssessment,
    IngressSecrets,
    IngressTrustPolicy,
    MessageIdentity,
    Outcome,
    SignedEnvelopeV1,
    VerifiedResults,
)
from mail_triage.schemas import Check, Report

MAX_ENVELOPE_BYTES = 65536
MAX_PAYLOAD_BYTES = 32768
_EXTRACT = tldextract.TLDExtract(
    suffix_list_urls=(), cache_dir=None, include_psl_private_domains=True
)


class EvidenceRejected(ValueError):
    """Only fixed, non-sensitive reason codes cross this boundary."""


def strict_object(raw: bytes, limit: int = MAX_ENVELOPE_BYTES) -> dict[str, object]:
    if not raw or len(raw) > limit:
        raise EvidenceRejected("invalid_size")

    def pairs(items: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in items:
            if key in result:
                raise EvidenceRejected("duplicate_json_key")
            result[key] = value
        return result

    def invalid_constant(_value: str) -> None:
        raise EvidenceRejected("invalid_json_constant")

    try:
        value = json.loads(
            raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=invalid_constant
        )
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise EvidenceRejected("invalid_json") from exc
    if not isinstance(value, dict):
        raise EvidenceRejected("invalid_json_object")
    return cast(dict[str, object], value)


def load_keys(raw: bytes) -> dict[tuple[str, str], bytes]:
    """Explicit stdin only in the CLI. No ambient credential source or defaults."""
    secrets = IngressSecrets.model_validate(strict_object(raw, 16384))
    result: dict[tuple[str, str], bytes] = {}
    for item in secrets.keys:
        identity = (item.issuer_id, item.key_id)
        text = item.key_hex.get_secret_value()
        if identity in result or len(text) != 64 or any(c not in "0123456789abcdef" for c in text):
            raise EvidenceRejected("invalid_key_material")
        result[identity] = bytes.fromhex(text)
    return result


def normalize_domain(value: str) -> str:
    """IDNA2008 A-label comparison. No URLs, whitespace, IPs or suffix guessing."""
    if not value or value != value.strip() or any(c in value for c in "/:@[]\\"):
        raise EvidenceRejected("invalid_domain")
    try:
        normalized = (
            idna.encode(value.removesuffix(".").lower(), uts46=False, std3_rules=True)
            .decode("ascii")
            .lower()
        )
        if "." not in normalized or len(normalized) > 253:
            raise ValueError("Not a qualified domain")
        try:
            ipaddress.ip_address(normalized)
        except ValueError:
            return normalized
    except (ValueError, UnicodeError) as exc:
        raise EvidenceRejected("invalid_domain") from exc
    raise EvidenceRejected("invalid_domain")


def organizational_domain(value: str) -> str | None:
    normalized = normalize_domain(value)
    parts = _EXTRACT(normalized)
    # Unlike PSL's implicit '*' fallback, unknown suffixes fail closed here.
    if not parts.suffix or not parts.domain:
        return None
    return f"{parts.domain}.{parts.suffix}"


def domain_alignment(identity: str, author: str, mode: str) -> Alignment:
    left, right = normalize_domain(identity), normalize_domain(author)
    if mode == "s":
        return "PASS" if left == right else "FAIL"
    if mode != "r":
        raise EvidenceRejected("unsupported_alignment_mode")
    left_org, right_org = organizational_domain(left), organizational_domain(right)
    if left_org is None or right_org is None:
        return "UNKNOWN"
    return "PASS" if left_org == right_org else "FAIL"


def mac_input(envelope: SignedEnvelopeV1) -> bytes:
    """All routing/algorithm fields are protected; payload bytes are not reserialized."""
    return b"mail-triage.ingress.mac.v1\x00" + "\x00".join(
        (
            envelope.schema_version,
            envelope.algorithm,
            envelope.issuer_id,
            envelope.key_id,
            envelope.payload,
        )
    ).encode("ascii")


def _decode_payload(envelope: SignedEnvelopeV1) -> bytes:
    try:
        raw = base64.b64decode(
            envelope.payload + "=" * (-len(envelope.payload) % 4), altchars=b"-_", validate=True
        )
    except ValueError as exc:
        raise EvidenceRejected("invalid_payload_encoding") from exc
    if (
        len(raw) > MAX_PAYLOAD_BYTES
        or base64.urlsafe_b64encode(raw).rstrip(b"=").decode() != envelope.payload
    ):
        raise EvidenceRejected("invalid_payload_encoding")
    return raw


class ReplayLedger:
    """Single-host durable, exclusive claim. Never automatically reset or prune."""

    def __init__(self, directory: Path):
        self.directory = directory

    def consume(self, issuer: str, event: str, envelope_hash: str) -> None:
        name = hashlib.sha256((issuer + "\x00" + event).encode("ascii")).hexdigest() + ".json"
        directory = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            info = os.fstat(directory)
            if info.st_uid != os.getuid() or info.st_mode & 0o077:
                raise EvidenceRejected("unsafe_replay_ledger")
            try:
                descriptor = os.open(
                    name,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    0o600,
                    dir_fd=directory,
                )
            except FileExistsError as exc:
                raise EvidenceRejected("replayed_event") from exc
            with os.fdopen(descriptor, "wb") as stream:
                stream.write((json.dumps({"envelope_sha256": envelope_hash}) + "\n").encode())
                stream.flush()
                os.fsync(stream.fileno())
            os.fsync(directory)
        finally:
            os.close(directory)


def _or_alignment(values: list[Alignment], complete: bool = True) -> Alignment:
    if "PASS" in values:
        return "PASS"
    if not complete or "UNKNOWN" in values:
        return "UNKNOWN"
    return "FAIL"


def _authenticated_alignment(
    result: Outcome, domain: str | None, author: str, mode: str
) -> Alignment:
    if result in {"TEMPERROR", "PERMERROR", "UNKNOWN"}:
        return "UNKNOWN"
    if result != "PASS":
        return "FAIL"
    if domain is None:
        raise EvidenceRejected("missing_authenticated_domain")
    return domain_alignment(domain, author, mode)


def evaluate_results(assertion: IngressAssertionV1) -> VerifiedResults:
    """Recompute DMARC-eligible authenticated alignment, not mere domain resemblance."""
    spf = assertion.spf
    spf_alignment = _authenticated_alignment(
        spf.result, spf.domain, assertion.header_from_domain, assertion.dmarc.aspf
    )
    if spf.identity == "helo" and not spf.null_mail_from:
        spf_alignment = "FAIL"  # HELO pass cannot replace a non-null MAIL FROM for DMARC.
    signatures = assertion.dkim.signatures
    dkim_alignment = _or_alignment(
        [
            _authenticated_alignment(
                s.result, s.domain, assertion.header_from_domain, assertion.dmarc.adkim
            )
            for s in signatures
        ],
        complete=assertion.dkim.complete,
    )
    dkim: Outcome
    outcomes = {s.result for s in signatures}
    if "PASS" in outcomes:
        dkim = "PASS"
    elif not assertion.dkim.complete or "UNKNOWN" in outcomes:
        dkim = "UNKNOWN"
    elif "TEMPERROR" in outcomes:
        dkim = "TEMPERROR"
    elif "PERMERROR" in outcomes:
        dkim = "PERMERROR"
    else:
        dkim = "FAIL" if signatures else "NONE"
    alignment = _or_alignment([spf_alignment, dkim_alignment])
    if (assertion.alignment.spf, assertion.alignment.dkim) != (spf_alignment, dkim_alignment):
        raise EvidenceRejected("alignment_claim_mismatch")
    dmarc = assertion.dmarc
    if dmarc.result == "PASS" and alignment != "PASS":
        raise EvidenceRejected("dmarc_pass_without_aligned_authentication")
    if dmarc.result == "FAIL" and alignment != "FAIL":
        raise EvidenceRejected("dmarc_fail_inconsistent_with_evidence")
    if dmarc.policy_domain is not None:
        domain = normalize_domain(dmarc.policy_domain)
        author = normalize_domain(assertion.header_from_domain)
        if domain != author and domain != organizational_domain(author):
            raise EvidenceRejected("unrelated_dmarc_policy_domain")
    return VerifiedResults(
        spf=spf.result,
        dkim=dkim,
        dmarc=dmarc.result,
        spf_alignment=spf_alignment,
        dkim_alignment=dkim_alignment,
        alignment=alignment,
    )


def verify_ingress(
    raw: bytes,
    report: Report,
    evidence: bytes | None,
    *,
    expected: MessageIdentity,
    policy: IngressTrustPolicy,
    keys: Mapping[tuple[str, str], bytes],
    ledger: ReplayLedger,
    now: int | None = None,
) -> IngressAssessment:
    """Only a fully verified, unconsumed envelope can produce non-UNKNOWN results."""
    checked_at = int(time.time()) if now is None else now
    if evidence is None:
        return IngressAssessment(
            status="MISSING", reason_code="missing_evidence", checked_at=checked_at
        )
    if len(evidence) > MAX_ENVELOPE_BYTES:
        return IngressAssessment(
            status="REJECTED", reason_code="invalid_size", checked_at=checked_at
        )
    evidence_hash = hashlib.sha256(evidence).hexdigest()
    try:
        envelope = SignedEnvelopeV1.model_validate(strict_object(evidence))
        grants = [
            g
            for g in policy.grants
            if (g.issuer_id, g.key_id) == (envelope.issuer_id, envelope.key_id)
        ]
        if len(grants) != 1:
            raise EvidenceRejected("unknown_issuer_or_key")
        grant = grants[0]
        key = keys.get((envelope.issuer_id, envelope.key_id))
        if key is None or len(key) != 32:
            raise EvidenceRejected("unavailable_key")
        expected_mac = hmac.new(key, mac_input(envelope), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(envelope.mac, expected_mac):
            raise EvidenceRejected("invalid_mac")
        assertion = IngressAssertionV1.model_validate(
            strict_object(_decode_payload(envelope), MAX_PAYLOAD_BYTES)
        )
        if (
            assertion.audience != grant.audience
            or assertion.original.identity != expected
            or expected.tenant_id != grant.tenant_id
            or expected.mailbox_id not in grant.mailbox_ids
            or assertion.boundary_id != grant.boundary_id
            or assertion.verifier_version != grant.verifier_version
        ):
            raise EvidenceRejected("source_or_message_identity_mismatch")
        original = assertion.original
        if (
            original.sha256 != hashlib.sha256(raw).hexdigest()
            or original.raw_bytes != len(raw)
            or report.provenance.sha256 != original.sha256
            or report.provenance.raw_bytes != original.raw_bytes
        ):
            raise EvidenceRejected("original_mime_mismatch")
        if not assertion.internal_auth_headers_sanitized:
            raise EvidenceRejected("unattested_ingress_boundary")
        if not (
            grant.not_before <= assertion.issued_at < grant.not_after
            and grant.not_before <= checked_at < grant.not_after
            and assertion.issued_at <= checked_at + policy.clock_skew_seconds
            and checked_at - assertion.issued_at <= policy.max_issuance_age_seconds
            and assertion.issued_at
            < assertion.expires_at
            <= assertion.issued_at + policy.max_lifetime_seconds
            and checked_at < assertion.expires_at
            and assertion.received_at <= assertion.issued_at + policy.clock_skew_seconds
            and assertion.received_at <= checked_at + policy.clock_skew_seconds
            and checked_at - assertion.received_at <= policy.max_receive_age_seconds
        ):
            raise EvidenceRejected("invalid_evidence_or_key_time")
        if (
            assertion.alignment.psl_sha256 != PSL_SHA256
            or hashlib.sha256(
                resources.files("tldextract").joinpath(".tld_set_snapshot").read_bytes()
            ).hexdigest()
            != PSL_SHA256
        ):
            raise EvidenceRejected("unsupported_psl_snapshot")
        # Reparse the exact bytes: callers cannot substitute a different ParsedEmail.
        from mail_triage.ingest import parse_eml

        message = parse_eml(raw, report.limits)
        if (
            len([h for h in message.headers if h.name.lower() == "from"]) != 1
            or len(message.from_addresses) != 1
        ):
            raise EvidenceRejected("ambiguous_author_identity")
        _local, separator, author = message.from_addresses[0].rpartition("@")
        if not separator or normalize_domain(author) != normalize_domain(
            assertion.header_from_domain
        ):
            raise EvidenceRejected("author_domain_mismatch")
        if assertion.spf.smtp_peer_ip is not None:
            if "%" in assertion.spf.smtp_peer_ip:
                raise EvidenceRejected("invalid_smtp_peer_ip")
            ipaddress.ip_address(assertion.spf.smtp_peer_ip)
        if assertion.spf.domain is not None:
            normalize_domain(assertion.spf.domain)
        for signature in assertion.dkim.signatures:
            normalize_domain(signature.domain)
        results = evaluate_results(assertion)
        ledger.consume(envelope.issuer_id, assertion.event_id, evidence_hash)
        return IngressAssessment(
            status="ACCEPTED",
            reason_code="verified_ingress_evidence",
            checked_at=checked_at,
            envelope_sha256=evidence_hash,
            results=results,
            envelope=envelope,
            assertion=assertion,
        )
    except EvidenceRejected as exc:
        reason = str(exc)
    except (ValueError, ValidationError, UnicodeError, RecursionError):
        reason = "invalid_evidence"
    except OSError:
        reason = "evidence_storage_unavailable"
    return IngressAssessment(
        status="REJECTED",
        reason_code=reason,
        checked_at=checked_at,
        envelope_sha256=evidence_hash,
    )


def build_ingress_report(
    raw: bytes,
    source_name: str,
    evidence: bytes | None,
    *,
    expected: MessageIdentity,
    policy: IngressTrustPolicy,
    keys: Mapping[tuple[str, str], bytes],
    ledger: ReplayLedger,
    now: int | None = None,
) -> Report:
    """Fresh report only. Ordinary triage/Graph ingestion do not call this implicitly."""
    from mail_triage.cli import build_report

    report = build_report(raw, source_name)
    assessment = verify_ingress(
        raw, report, evidence, expected=expected, policy=policy, keys=keys, ledger=ledger, now=now
    )
    report.schema_version = "1.1"
    report.authentication.trusted_ingress = assessment
    report.authentication.trust_boundary = (
        "All MIME headers, including Authentication-Results, Received, Return-Path, "
        "Received-SPF and ARC assertions, remain untrusted observations. Only the separate "
        "MAC-verified, identity/hash-bound, fresh and replay-checked ingress envelope can "
        "supply authenticated results. ACCEPTED authenticates the evidence source, not "
        "message safety. SPF/DKIM/DMARC PASS never changes REVIEW_REQUIRED."
    )
    if assessment.status == "ACCEPTED":
        for name in ("spf", "dkim", "dmarc", "alignment"):
            result = getattr(assessment.results, name)
            previous: Check = getattr(report.authentication, name)
            setattr(
                report.authentication,
                name,
                Check(
                    status="UNKNOWN" if result == "UNKNOWN" else "OBSERVED",
                    reason=(
                        f"Trusted ingress {name.upper()} result: {result}. "
                        "See typed trusted_ingress evidence."
                    ),
                    observations=previous.observations,
                ),
            )
        report.warnings[1] = (
            "Original bytes are bound to authenticated ingress evidence. This application "
            "did not perform SMTP-time SPF, DKIM cryptography or live DMARC DNS evaluation."
        )
    else:
        report.warnings.append(f"Trusted ingress evidence not accepted: {assessment.reason_code}.")
    return report
