"""Offline observations, kept independent from authenticated or external evidence."""

import re
from pathlib import PurePosixPath

from .schemas import (
    AuthenticationEvidence,
    Check,
    ContentEvidence,
    Finding,
    ParsedEmail,
    ReputationEvidence,
)

_DKIM_DOMAIN = re.compile(r"(?:^|;)\s*d\s*=\s*([^;\s]+)", re.IGNORECASE)
_URGENCY = re.compile(
    r"\b(?:urgent|immediately|action required|final warning|expires|"
    r"within \d{1,4} (?:minutes?|hours?))\b",
    re.IGNORECASE,
)
_CREDENTIALS = re.compile(
    r"\b(?:password|credentials|verify your account|sign in|log in|login|"
    r"one[- ]time code|security code)\b",
    re.IGNORECASE,
)
_ACTIVE_HTML = re.compile(
    r"<\s*(?:script|iframe|object|embed|form)\b|"
    r"\bon[a-z]+\s*=|javascript\s*:",
    re.IGNORECASE,
)
_URL = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
_RISKY_EXTENSIONS = {
    ".exe",
    ".scr",
    ".js",
    ".vbs",
    ".bat",
    ".cmd",
    ".ps1",
    ".msi",
    ".jar",
    ".hta",
    ".lnk",
    ".iso",
    ".img",
    ".docm",
    ".xlsm",
    ".pptm",
}


def authentication_evidence(message: ParsedEmail) -> AuthenticationEvidence:
    """A local MIME file provides claims, never an authenticated SMTP context."""
    claims = [h.value for h in message.headers if h.name.casefold() == "authentication-results"]
    dkim_domains = [
        match.group(1)
        for header in message.headers
        if header.name.casefold() == "dkim-signature"
        for match in _DKIM_DOMAIN.finditer(header.value)
    ]
    received_count = sum(h.name.casefold() == "received" for h in message.headers)
    return AuthenticationEvidence(
        spf=Check(
            status="UNKNOWN",
            reason=(
                "Original SMTP peer and envelope sender are unavailable. "
                "No SPF DNS evaluation or authenticated ingress was performed."
            ),
            observations=[
                f"{received_count} untrusted Received header(s); "
                "they do not establish the original SMTP peer."
            ],
        ),
        dkim=Check(
            status="UNKNOWN",
            reason=(
                "DKIM signatures were not cryptographically verified. "
                "DNS keys were not fetched; signature metadata is untrusted."
            ),
            observations=[f"Unverified DKIM-Signature d= claim: {d!r}" for d in dkim_domains],
        ),
        dmarc=Check(
            status="UNKNOWN",
            reason=(
                "DMARC requires a verified, aligned SPF pass OR a verified, aligned "
                "DKIM pass and policy evaluation. Those trusted results are unavailable."
            ),
        ),
        alignment=Check(
            status="UNKNOWN",
            reason=(
                "Verified SPF/DKIM identities are unavailable. Relaxed alignment also "
                "requires organizational-domain/public-suffix rules; literal header "
                "domains do not establish DMARC alignment."
            ),
        ),
        untrusted_authentication_results=claims,
        trust_boundary=(
            "All local .eml headers, including Authentication-Results and Received, "
            "are attacker-controlled observations. An allowlisted authserv-id alone "
            "cannot establish trust. Authenticated ingress and removal of forged "
            "internal assertions are required before trusting authentication results."
        ),
    )


def _domains(addresses: list[str]) -> set[str]:
    """Compare only literal case-insensitive domains; do not infer organizations."""
    return {
        domain.casefold()
        for address in addresses
        for _, separator, domain in [address.rpartition("@")]
        if separator and domain and not any(char.isspace() for char in domain)
    }


def _matches(pattern: re.Pattern[str], sources: list[tuple[str, str]]) -> list[str]:
    return list(
        dict.fromkeys(
            f"{source}: {match.group(0)!r}"
            for source, value in sources
            for match in pattern.finditer(value)
        )
    )


def content_evidence(message: ParsedEmail) -> ContentEvidence:
    """Collect fallible review cues without deciding maliciousness or safety."""
    sources = [("subject", message.subject)] + [
        (f"part {segment.part_id}", segment.text) for segment in message.text_segments
    ]
    findings: list[Finding] = []

    def add(code: str, description: str, evidence: list[str]) -> None:
        if evidence:
            findings.append(Finding(code=code, description=description, evidence=evidence))

    add(
        "content.urgency_language",
        "Urgency-related wording was observed.",
        _matches(_URGENCY, sources),
    )
    add(
        "content.credential_language",
        "Account or credential-related wording was observed.",
        _matches(_CREDENTIALS, sources),
    )
    from_domains = _domains(message.from_addresses)
    reply_domains = _domains(message.reply_to_addresses)
    mismatches = sorted(reply_domains - from_domains) if from_domains else []
    add(
        "content.reply_to_domain_mismatch",
        "Reply-To has a literal domain different from the From domains; this is not "
        "proof of impersonation or a DMARC alignment result.",
        [f"From domains: {sorted(from_domains)!r}; differing Reply-To domains: {mismatches!r}"]
        if mismatches
        else [],
    )
    add(
        "content.risky_attachment_extension",
        "An attachment filename has an extension associated with executable or active "
        "content. File type and maliciousness have not been established.",
        [
            f"part {part.part_id}: filename={part.filename!r}; sha256={part.sha256}"
            for part in message.parts
            if part.is_attachment
            and part.filename
            and PurePosixPath(part.filename.rstrip(" .")).suffix.casefold() in _RISKY_EXTENSIONS
        ],
    )
    add(
        "content.html_active_syntax",
        "Potentially active HTML syntax was observed as inert source text. "
        "No HTML was rendered or executed.",
        _matches(
            _ACTIVE_HTML,
            [
                (f"part {segment.part_id}", segment.text)
                for segment in message.text_segments
                if segment.kind == "html_source"
            ],
        ),
    )
    add(
        "content.url_observed",
        "URL-like strings were observed. None were fetched or assigned a reputation.",
        _matches(_URL, sources),
    )
    return ContentEvidence(
        findings=findings,
        limitations=[
            "Heuristics are fallible review cues, not a malicious/benign verdict or score.",
            "Literal domain differences do not establish ownership or impersonation.",
            "Quoted text, legitimate urgency and account instructions can trigger findings.",
            "Text and filenames are untrusted; URLs and attachments were not opened or executed.",
            "A lack of findings does not demonstrate that a message is safe.",
        ],
    )


def reputation_evidence() -> ReputationEvidence:
    """Do not manufacture telemetry or silently invoke external integrations."""
    return ReputationEvidence(
        sender_osint=Check(
            status="NOT_RUN", reason="No OSINT provider or permitted egress configured."
        ),
        gateway_reputation=Check(
            status="NOT_RUN",
            reason="No gateway reputation provider or trusted sending gateway identity configured.",
        ),
        gateway_spam_rate=Check(
            status="UNKNOWN",
            reason="No named telemetry source, spam numerator, message denominator "
            "or time window available.",
        ),
        assemblyline=Check(
            status="NOT_RUN",
            reason="File-triage adapter disabled. No submission or credentials configured; "
            "Assemblyline services may make external requests and are not sender reputation.",
        ),
        sublime=Check(
            status="NOT_RUN",
            reason="Optional analysis adapter is disabled. No explicit endpoint, selected rules "
            "or data-egress authorization configured; no default public endpoint is used.",
        ),
        outlook_ingestion=Check(
            status="NOT_RUN",
            reason="Local .eml only. Reporting-mailbox ingestion is an adapter boundary; "
            "no mailbox, Graph access, tenant consent or native reporting webhook configured.",
        ),
    )


def model_stages() -> dict[str, Check]:
    return {
        "pydantic_ai": Check(
            status="NOT_RUN",
            reason="Optional typed content review is disabled; no model or egress configured. "
            "Model claims require validation against existing evidence IDs.",
        ),
        "dspy": Check(
            status="NOT_RUN",
            reason="DSPy is reserved for offline labeled-data and held-out evaluation. "
            "No live email optimization or evaluation dataset configured.",
        ),
    }
