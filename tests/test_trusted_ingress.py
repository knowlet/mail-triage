"""Synthetic evidence only: no enterprise tenant, actual SMTP/DNS or secret discovery."""

import base64
import copy
import hashlib
import hmac
import io
import json
import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from mail_triage.cli import build_report, main
from mail_triage.ingress_contract import (
    PROFILE,
    PSL_SHA256,
    IngressAssertionV1,
    IngressTrustPolicy,
    MessageIdentity,
    SignedEnvelopeV1,
)
from mail_triage.reporting import render_html, write_case
from mail_triage.schemas import Report
from mail_triage.trusted_ingress import (
    EvidenceRejected,
    ReplayLedger,
    build_ingress_report,
    domain_alignment,
    load_keys,
    mac_input,
    normalize_domain,
    strict_object,
)

NOW = 1_800_000_000
# PUBLIC, SYNTHETIC fixture key. Not a deployable credential.
KEY = bytes(range(32))
KEYS = {("synthetic-gateway", "fixture-1"): KEY}
IDENTITY = MessageIdentity(
    tenant_id="synthetic-tenant", mailbox_id="reports@example.org", message_id="original-object-123"
)
RAW = (
    b"From: Sender <sender@example.com>\r\n"
    b"Message-ID: <reused@example.com>\r\n"
    b"Authentication-Results: trusted.internal; spf=pass; dkim=pass; dmarc=pass\r\n"
    b"Received: from forged.example by trusted.internal\r\n"
    b"Return-Path: <attacker@evil.net>\r\n"
    b"Received-SPF: pass\r\n"
    b"ARC-Authentication-Results: i=1; trusted.internal; dmarc=pass\r\n"
    b"DKIM-Signature: v=1; d=forged.example; s=forged; b=YWJj\r\n"
    b"Content-Type: text/plain; charset=utf-8\r\n\r\nSynthetic only.\r\n"
)
_AUTO = object()


def policy_data() -> dict[str, Any]:
    return {
        "schema_version": "mail-triage.ingress-trust/1",
        "grants": [
            {
                "issuer_id": "synthetic-gateway",
                "key_id": "fixture-1",
                "tenant_id": IDENTITY.tenant_id,
                "mailbox_ids": [IDENTITY.mailbox_id],
                "audience": "mail-triage",
                "boundary_id": "smtp-edge",
                "verifier_version": "synthetic-mta-1",
                "not_before": NOW - 3600,
                "not_after": NOW + 3600,
            }
        ],
    }


def payload(raw: bytes = RAW) -> dict[str, Any]:
    return {
        "schema_version": "mail-triage.ingress-assertion/1",
        "audience": "mail-triage",
        "event_id": "synthetic-event-0001",
        "issued_at": NOW - 30,
        "expires_at": NOW + 300,
        "received_at": NOW - 60,
        "boundary_id": "smtp-edge",
        "verifier_version": "synthetic-mta-1",
        "evidence_origin": "smtp-session-and-cryptographic-verifier",
        "internal_auth_headers_sanitized": True,
        "original": {
            "identity": IDENTITY.model_dump(),
            "representation": "original-mime-bytes",
            "sha256": hashlib.sha256(raw).hexdigest(),
            "raw_bytes": len(raw),
        },
        "header_from_domain": "example.com",
        "spf": {
            "result": "PASS",
            "smtp_peer_ip": "203.0.113.9",
            "identity": "mailfrom",
            "domain": "example.com",
            "null_mail_from": False,
        },
        "dkim": {"complete": True, "signatures": []},
        "dmarc": {
            "result": "PASS",
            "policy_domain": "example.com",
            "policy": "reject",
            "policy_record_sha256": hashlib.sha256(b"v=DMARC1;p=reject;aspf=s;adkim=s").hexdigest(),
            "aspf": "s",
            "adkim": "s",
        },
        "alignment": {"profile": PROFILE, "psl_sha256": PSL_SHA256, "spf": "PASS", "dkim": "FAIL"},
    }


def signed(
    data: dict[str, Any] | None = None,
    *,
    key: bytes = KEY,
    body: bytes | None = None,
    **fields: Any,
) -> bytes:
    """Independent producer, deliberately not calling production mac_input()."""
    body = (
        body
        if body is not None
        else json.dumps(data or payload(), sort_keys=True, separators=(",", ":")).encode()
    )
    envelope = {
        "schema_version": "mail-triage.ingress-envelope/1",
        "algorithm": "HMAC-SHA256",
        "issuer_id": "synthetic-gateway",
        "key_id": "fixture-1",
        "payload": base64.urlsafe_b64encode(body).rstrip(b"=").decode(),
        "mac": "0" * 64,
    }
    envelope.update(fields)
    protected = b"mail-triage.ingress.mac.v1\0" + "\0".join(
        envelope[k] for k in ("schema_version", "algorithm", "issuer_id", "key_id", "payload")
    ).encode("ascii")
    envelope["mac"] = hmac.new(key, protected, hashlib.sha256).hexdigest()
    return json.dumps(envelope).encode()


def review(
    tmp_path: Path,
    data: dict[str, Any] | None = None,
    *,
    evidence: Any = _AUTO,
    raw: bytes = RAW,
    expected: MessageIdentity = IDENTITY,
    policy: IngressTrustPolicy | None = None,
    keys: Any = KEYS,
    ledger: ReplayLedger | None = None,
    now: int = NOW,
) -> Report:
    directory = tmp_path / "ledger"
    directory.mkdir(mode=0o700, exist_ok=True)
    return build_ingress_report(
        raw,
        "synthetic.eml",
        signed(data) if evidence is _AUTO else evidence,
        expected=expected,
        policy=policy or IngressTrustPolicy.model_validate(policy_data()),
        keys=keys,
        ledger=ledger or ReplayLedger(directory),
        now=now,
    )


def rejected(report: Report, reason: str | None = None) -> None:
    assessment = report.authentication.trusted_ingress
    assert assessment is not None and assessment.status == "REJECTED"
    if reason is not None:
        assert assessment.reason_code == reason
    assert set(assessment.results.model_dump().values()) == {"UNKNOWN"}
    assert assessment.assertion is None and assessment.envelope is None
    for name in ("spf", "dkim", "dmarc", "alignment"):
        assert getattr(report.authentication, name).status == "UNKNOWN"
    assert report.disposition == "REVIEW_REQUIRED"


def test_signed_spf_pass_and_untrusted_header_isolation(tmp_path: Path) -> None:
    report = review(tmp_path)
    trusted = report.authentication.trusted_ingress
    assert trusted is not None and trusted.status == "ACCEPTED"
    assert trusted.results.spf == trusted.results.dmarc == trusted.results.alignment == "PASS"
    assert trusted.results.dkim == "NONE" and trusted.results.dkim_alignment == "FAIL"
    assert report.disposition == "REVIEW_REQUIRED"
    assert "trusted.internal" in report.authentication.untrusted_authentication_results[0]
    assert "forged.example" in report.authentication.dkim.observations[0]
    assert any(h.name == "Return-Path" and "evil.net" in h.value for h in report.message.headers)
    assert report.authentication.spf.status == "OBSERVED"
    assert "source" in render_html(report) and "ACCEPTED" in render_html(report)
    assert KEY.hex() not in report.model_dump_json()
    out = tmp_path / "case"
    write_case(out, RAW, report)
    assert (out / "original.eml").read_bytes() == RAW
    assert (out.stat().st_mode & 0o777) == 0o700
    assert all((p.stat().st_mode & 0o777) == 0o600 for p in out.iterdir())
    loaded = Report.model_validate_json((out / "report.json").read_bytes())
    assert loaded.authentication.trusted_ingress == trusted


def test_missing_and_graph_origin_do_not_promote_headers(tmp_path: Path) -> None:
    report = review(tmp_path, evidence=None)
    assert report.authentication.trusted_ingress.status == "MISSING"
    assert set(report.authentication.trusted_ingress.results.model_dump().values()) == {"UNKNOWN"}
    ordinary = build_report(RAW, "graph.eml")
    ordinary.provenance.source_kind = "graph_original"
    assert ordinary.authentication.trusted_ingress is None
    for name in ("spf", "dkim", "dmarc", "alignment"):
        assert getattr(ordinary.authentication, name).status == "UNKNOWN"


@pytest.mark.parametrize(
    "domain,author,mode,result",
    [
        ("example.com", "example.com", "s", "PASS"),
        ("EXAMPLE.COM.", "example.com", "s", "PASS"),
        ("mail.example.com", "example.com", "s", "FAIL"),
        ("a.example.com", "b.example.com", "r", "PASS"),
        ("a.example.co.uk", "b.example.co.uk", "r", "PASS"),
        ("example.co.uk", "evil.co.uk", "r", "FAIL"),
        ("example.com.attacker.net", "example.com", "r", "FAIL"),
        ("evil-example.com", "example.com", "r", "FAIL"),
        ("tenant1.github.io", "tenant2.github.io", "r", "FAIL"),
        ("a.tenant.github.io", "b.tenant.github.io", "r", "PASS"),
        ("a.b.ck", "c.b.ck", "r", "FAIL"),
        ("a.www.ck", "b.www.ck", "r", "PASS"),
        ("a.city.kawasaki.jp", "b.city.kawasaki.jp", "r", "PASS"),
        ("a.foo.kawasaki.jp", "b.foo.kawasaki.jp", "r", "FAIL"),
        ("co.uk", "co.uk", "r", "UNKNOWN"),
        ("x.unknowninvalidtld", "x.unknowninvalidtld", "r", "UNKNOWN"),
        ("x.unknowninvalidtld", "x.unknowninvalidtld", "s", "PASS"),
        ("bücher.de", "xn--bcher-kva.de", "s", "PASS"),
        ("ß.de", "ss.de", "s", "FAIL"),
    ],
)
def test_alignment_domain_rules(domain: str, author: str, mode: str, result: str) -> None:
    assert domain_alignment(domain, author, mode) == result


@pytest.mark.parametrize(
    "domain",
    [
        "",
        " example.com",
        "example.com ",
        "example.com\n",
        "https://example.com",
        "user@example.com",
        "127.0.0.1",
        "[::1]",
        "a..com",
        "a_.com",
        "-a.com",
        "a-.com",
        "a" * 64 + ".com",
        "xn--0.com",
        "localhost",
        "a/com",
        "a\\com",
        "a:443.com",
    ],
)
def test_invalid_domains(domain: str) -> None:
    with pytest.raises(EvidenceRejected):
        normalize_domain(domain)


def signature(
    domain: str = "example.com", *, result: str = "PASS", name: str = "signature-1"
) -> dict[str, Any]:
    return {"signature_id": name, "result": result, "domain": domain, "selector": "synthetic"}


@pytest.mark.parametrize(
    "scenario",
    [
        "dkim_only",
        "multiple",
        "partial_with_pass",
        "negative",
        "failed_aligned_signature",
        "null_helo",
        "nonnull_helo",
        "no_policy",
        "monitoring_policy",
        "unknown",
        "dkim_temperror_with_spf_pass",
    ],
)
def test_mechanism_combinations(tmp_path: Path, scenario: str) -> None:
    p = payload()
    if scenario in {"dkim_only", "multiple", "partial_with_pass"}:
        p["spf"]["result"] = "FAIL"
        p["alignment"].update(spf="FAIL", dkim="PASS")
        p["dkim"]["signatures"] = [signature()]
        if scenario == "multiple":
            p["dkim"]["signatures"].insert(0, signature("evil.net", name="unaligned-first"))
        if scenario == "partial_with_pass":
            p["dkim"]["complete"] = False
    elif scenario in {"negative", "failed_aligned_signature"}:
        p["spf"]["result"] = p["dmarc"]["result"] = p["alignment"]["spf"] = "FAIL"
        if scenario == "failed_aligned_signature":
            p["dkim"]["signatures"] = [signature(result="FAIL")]
    elif scenario in {"null_helo", "nonnull_helo"}:
        p["spf"].update(identity="helo", null_mail_from=scenario == "null_helo")
        if scenario == "nonnull_helo":
            p["dmarc"]["result"] = p["alignment"]["spf"] = "FAIL"
    elif scenario == "no_policy":
        p["dmarc"].update(result="NONE", policy=None, policy_domain=None, policy_record_sha256=None)
    elif scenario == "monitoring_policy":
        p["dmarc"]["policy"] = "none"
    elif scenario == "unknown":
        p["spf"].update(result="UNKNOWN", domain=None)
        p["dkim"]["complete"] = False
        p["dmarc"]["result"] = "UNKNOWN"
        p["alignment"].update(spf="UNKNOWN", dkim="UNKNOWN")
    elif scenario == "dkim_temperror_with_spf_pass":
        p["dkim"]["signatures"] = [signature(result="TEMPERROR")]
        p["alignment"]["dkim"] = "UNKNOWN"
    report = review(tmp_path, p)
    a = report.authentication.trusted_ingress
    assert a.status == "ACCEPTED"
    assert a.results.spf == p["spf"]["result"]
    assert a.results.dmarc == p["dmarc"]["result"]
    assert a.results.spf_alignment == p["alignment"]["spf"]
    assert a.results.dkim_alignment == p["alignment"]["dkim"]
    assert report.disposition == "REVIEW_REQUIRED"


@pytest.mark.parametrize(
    "spf,align,dmarc",
    [
        ("SOFTFAIL", "FAIL", "FAIL"),
        ("NEUTRAL", "FAIL", "FAIL"),
        ("NONE", "FAIL", "FAIL"),
        ("TEMPERROR", "UNKNOWN", "TEMPERROR"),
        ("PERMERROR", "UNKNOWN", "PERMERROR"),
    ],
)
def test_spf_nonpasses_preserved(tmp_path: Path, spf: str, align: str, dmarc: str) -> None:
    p = payload()
    p["spf"]["result"], p["alignment"]["spf"], p["dmarc"]["result"] = spf, align, dmarc
    a = review(tmp_path, p).authentication.trusted_ingress
    assert a.status == "ACCEPTED" and a.results.spf == spf and a.results.dmarc == dmarc


@pytest.mark.parametrize(
    "path,value",
    [
        ("schema_version", "mail-triage.ingress-assertion/2"),
        ("trusted", True),
        ("audience", "another-app"),
        ("boundary_id", "forged-boundary"),
        ("verifier_version", "unknown-verifier"),
        ("evidence_origin", "authentication-results-header"),
        ("internal_auth_headers_sanitized", False),
        ("internal_auth_headers_sanitized", 1),
        ("internal_auth_headers_sanitized", "true"),
        ("original.identity.tenant_id", "other-tenant"),
        ("original.identity.mailbox_id", "other@example.org"),
        ("original.identity.message_id", "other-object"),
        ("original.sha256", "0" * 64),
        ("original.raw_bytes", len(RAW) + 1),
        ("original.raw_bytes", str(len(RAW))),
        ("original.raw_bytes", True),
        ("original.representation", "wrapper-mime-bytes"),
        ("header_from_domain", "attacker.net"),
        ("spf.result", "pass"),
        ("spf.result", "POLICY"),
        ("spf.domain", None),
        ("spf.domain", "https://example.com"),
        ("spf.smtp_peer_ip", "peer.example.com"),
        ("spf.smtp_peer_ip", "fe80::1%eth0"),
        ("spf.null_mail_from", True),
        ("spf.null_mail_from", 0),
        ("dkim.complete", "true"),
        ("dkim.signatures", [signature()] * 33),
        ("dkim.signatures", [signature(), signature()]),
        ("dmarc.result", "FAIL"),
        ("dmarc.policy", None),
        ("dmarc.policy_domain", None),
        ("dmarc.policy_domain", "evil.net"),
        ("dmarc.policy_record_sha256", None),
        ("dmarc.aspf", "relaxed"),
        ("alignment.spf", "FAIL"),
        ("alignment.dkim", "PASS"),
        ("alignment.psl_sha256", "0" * 64),
        ("alignment.profile", "last-two-labels"),
        ("event_id", "../bad-event"),
        ("event_id", "short"),
        ("issued_at", "1800000000"),
        ("issued_at", True),
        ("issued_at", -1),
        ("issued_at", NOW + 61),
        ("issued_at", NOW - 901),
        ("expires_at", NOW),
        ("expires_at", NOW + 2000),
        ("received_at", NOW + 61),
        ("received_at", NOW - 30 * 86400 - 1),
    ],
)
def test_signed_invalid_assertions_fail_closed(tmp_path: Path, path: str, value: Any) -> None:
    p = payload()
    obj = p
    parts = path.split(".")
    for part in parts[:-1]:
        obj = obj[part]
    obj[parts[-1]] = value
    rejected(review(tmp_path, p))
    assert not list((tmp_path / "ledger").iterdir())


@pytest.mark.parametrize(
    "field,value",
    [
        ("schema_version", "mail-triage.ingress-envelope/2"),
        ("algorithm", "none"),
        ("issuer_id", "unknown"),
        ("key_id", "unknown"),
        ("key_id", "fixture-1\n"),
        ("mac", "0" * 64),
        ("trusted", True),
        ("payload", "!!!!"),
        ("payload", ""),
        ("jku", "https://evil.invalid/key"),
    ],
)
def test_bad_envelopes(tmp_path: Path, field: str, value: Any) -> None:
    envelope = json.loads(signed())
    envelope[field] = value
    rejected(review(tmp_path, evidence=json.dumps(envelope).encode()))


@pytest.mark.parametrize(
    "evidence",
    [
        b"",
        b"[]",
        b"null",
        b"{",
        b"\xff",
        b"x" * 65537,
        b'{"a":1,"a":2}',
        b'{"x":NaN}',
        b"[" * 1200 + b"]" * 1200,
    ],
)
def test_malformed_wire_inputs(tmp_path: Path, evidence: bytes) -> None:
    rejected(review(tmp_path, evidence=evidence))


def test_duplicate_signed_json_and_noncanonical_base64(tmp_path: Path) -> None:
    body = json.dumps(payload()).encode()
    rejected(review(tmp_path, evidence=signed(body=body[:-1] + b', "audience":"mail-triage"}')))
    rejected(review(tmp_path, evidence=signed(payload="e30=")))


def test_wrong_key_and_missing_key(tmp_path: Path) -> None:
    rejected(review(tmp_path, evidence=signed(key=b"x" * 32)), "invalid_mac")
    rejected(review(tmp_path, keys={}), "unavailable_key")
    rejected(
        review(tmp_path, keys={("synthetic-gateway", "fixture-1"): b"short"}), "unavailable_key"
    )


@pytest.mark.parametrize(
    "raw",
    [
        RAW + b"x",
        RAW.replace(b"\r\n", b"\n"),
        RAW.replace(b"Synthetic", b"Malicious"),
        b"From: reporter@example.org\r\n\r\nWrapper, not original.\r\n",
    ],
)
def test_exact_mime_bytes_not_message_id(tmp_path: Path, raw: bytes) -> None:
    rejected(review(tmp_path, raw=raw), "original_mime_mismatch")


@pytest.mark.parametrize("part", ["tenant_id", "mailbox_id", "message_id"])
def test_independent_context_binding(tmp_path: Path, part: str) -> None:
    expected = IDENTITY.model_copy(update={part: "other-context"})
    rejected(review(tmp_path, expected=expected), "source_or_message_identity_mismatch")


def test_key_grant_scope_rotation_and_expiry(tmp_path: Path) -> None:
    for field, value in [
        ("tenant_id", "other"),
        ("mailbox_ids", ["other@example.org"]),
        ("not_before", NOW + 1),
        ("not_after", NOW),
    ]:
        config = policy_data()
        config["grants"][0][field] = value
        rejected(review(tmp_path, policy=IngressTrustPolicy.model_validate(config)))
    config = policy_data()
    grant = copy.deepcopy(config["grants"][0])
    grant["key_id"] = "fixture-2"
    config["grants"].append(grant)
    pol = IngressTrustPolicy.model_validate(config)
    assert review(tmp_path, policy=pol).authentication.trusted_ingress.status == "ACCEPTED"
    rejected(
        review(
            tmp_path,
            evidence=signed(key_id="fixture-2"),
            policy=pol,
            keys={**KEYS, ("synthetic-gateway", "fixture-2"): KEY},
        ),
        "replayed_event",
    )


def test_replay_across_instances_and_concurrent_acceptance(tmp_path: Path) -> None:
    (tmp_path / "ledger").mkdir(mode=0o700)
    with ThreadPoolExecutor(max_workers=2) as pool:
        reports = list(pool.map(lambda _: review(tmp_path), range(2)))
    assert sorted(r.authentication.trusted_ingress.status for r in reports) == [
        "ACCEPTED",
        "REJECTED",
    ]
    rejected(review(tmp_path), "replayed_event")
    assert len(list((tmp_path / "ledger").iterdir())) == 1


def test_invalid_input_cannot_poison_replay(tmp_path: Path) -> None:
    rejected(review(tmp_path, evidence=signed(key=b"x" * 32)))
    assert not list((tmp_path / "ledger").iterdir())
    assert review(tmp_path).authentication.trusted_ingress.status == "ACCEPTED"


@pytest.mark.parametrize("kind", ["missing", "public", "symlink", "not_directory"])
def test_unsafe_or_unavailable_ledger(tmp_path: Path, kind: str) -> None:
    path = tmp_path / "unsafe"
    if kind == "public":
        path.mkdir(mode=0o755)
    elif kind == "symlink":
        target = tmp_path / "target"
        target.mkdir(mode=0o700)
        path.symlink_to(target, target_is_directory=True)
    elif kind == "not_directory":
        path.write_text("not a directory")
    rejected(review(tmp_path, ledger=ReplayLedger(path)))


def test_fsync_failure_does_not_return_acceptance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(os, "fsync", lambda *_: (_ for _ in ()).throw(OSError("synthetic failure")))
    rejected(review(tmp_path), "evidence_storage_unavailable")
    assert len(list((tmp_path / "ledger").iterdir())) == 1


@pytest.mark.parametrize(
    "header",
    [
        b"",
        b"From: a@example.com\r\nFrom: b@example.com\r\n",
        b"From: a@example.com, b@example.com\r\n",
    ],
)
def test_ambiguous_from_cannot_authenticate(tmp_path: Path, header: bytes) -> None:
    raw = header + b"Subject: synthetic\r\n\r\nbody\r\n"
    rejected(review(tmp_path, payload(raw), raw=raw), "ambiguous_author_identity")


def test_relaxed_full_pipeline_and_idna(tmp_path: Path) -> None:
    p = payload()
    p["spf"]["domain"] = "mx.example.com"
    p["dmarc"]["aspf"] = "r"
    assert review(tmp_path, p).authentication.trusted_ingress.results.dmarc == "PASS"
    raw = RAW.replace(b"sender@example.com", b"sender@xn--bcher-kva.de")
    p = payload(raw)
    p["event_id"] = "synthetic-event-0002"
    p["header_from_domain"] = p["spf"]["domain"] = p["dmarc"]["policy_domain"] = "bücher.de"
    assert review(tmp_path, p, raw=raw).authentication.trusted_ingress.status == "ACCEPTED"


def test_incomplete_dkim_not_false_failure(tmp_path: Path) -> None:
    p = payload()
    p["spf"]["result"] = "FAIL"
    p["alignment"].update(spf="FAIL", dkim="UNKNOWN")
    p["dkim"]["complete"] = False
    p["dmarc"]["result"] = "UNKNOWN"
    result = review(tmp_path, p).authentication.trusted_ingress
    assert result.status == "ACCEPTED" and result.results.alignment == "UNKNOWN"
    p["dmarc"]["result"] = "FAIL"
    rejected(review(tmp_path, p), "dmarc_fail_inconsistent_with_evidence")


def test_pass_claim_requires_authenticated_aligned_pass(tmp_path: Path) -> None:
    p = payload()
    p["spf"]["result"] = p["alignment"]["spf"] = "FAIL"
    rejected(review(tmp_path, p), "dmarc_pass_without_aligned_authentication")


def test_strict_json_types_and_key_redaction() -> None:
    config = policy_data()
    config["grants"].append(config["grants"][0])
    with pytest.raises(ValidationError):
        IngressTrustPolicy.model_validate(config)
    secrets = {
        "keys": [{"issuer_id": "synthetic-gateway", "key_id": "fixture-1", "key_hex": KEY.hex()}]
    }
    assert load_keys(json.dumps(secrets).encode()) == KEYS
    for value in ["short", "x" * 64, KEY.hex() + "\n"]:
        secrets["keys"][0]["key_hex"] = value
        with pytest.raises(EvidenceRejected, match="invalid_key_material"):
            load_keys(json.dumps(secrets).encode())
    with pytest.raises(EvidenceRejected):
        strict_object(b'{"a":{"b":1,"b":2}}')
    envelope = SignedEnvelopeV1.model_validate_json(signed())
    assert hmac.new(KEY, mac_input(envelope), hashlib.sha256).hexdigest() == envelope.mac
    assert IngressAssertionV1.model_validate(payload()).original.identity == IDENTITY


def test_legacy_report_readable() -> None:
    data = build_report(RAW, "synthetic.eml").model_dump(mode="json")
    data["schema_version"] = "1.0"
    data["authentication"].pop("trusted_ingress")
    assert Report.model_validate(data).authentication.trusted_ingress is None


@pytest.mark.parametrize(
    "mode,exit_code", [("valid", 0), ("bad_mac", 3), ("missing_file", 3), ("invalid_secret", 2)]
)
def test_cli_end_to_end(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    mode: str,
    exit_code: int,
) -> None:
    import mail_triage.trusted_ingress as ingress

    monkeypatch.setattr(ingress.time, "time", lambda: NOW)
    (tmp_path / "message.eml").write_bytes(RAW)
    (tmp_path / "policy.json").write_text(json.dumps(policy_data()))
    (tmp_path / "evidence.json").write_bytes(signed(key=KEY if mode != "bad_mac" else b"x" * 32))
    (tmp_path / "ledger").mkdir(mode=0o700)
    credentials = {
        "keys": [
            {
                "issuer_id": "synthetic-gateway",
                "key_id": "fixture-1",
                "key_hex": KEY.hex() if mode != "invalid_secret" else "secret-do-not-echo",
            }
        ]
    }
    monkeypatch.setattr("sys.stdin", io.TextIOWrapper(io.BytesIO(json.dumps(credentials).encode())))
    args = [
        "trusted-ingress",
        str(tmp_path / "message.eml"),
        "--evidence",
        str(tmp_path / ("absent.json" if mode == "missing_file" else "evidence.json")),
        "--trust-policy",
        str(tmp_path / "policy.json"),
        "--tenant-id",
        IDENTITY.tenant_id,
        "--mailbox-id",
        IDENTITY.mailbox_id,
        "--original-id",
        IDENTITY.message_id,
        "--replay-dir",
        str(tmp_path / "ledger"),
        "--out",
        str(tmp_path / "case"),
        "--secrets-stdin",
    ]
    assert main(args) == exit_code
    captured = capsys.readouterr()
    assert KEY.hex() not in captured.out + captured.err
    assert "secret-do-not-echo" not in captured.out + captured.err
    if exit_code != 2:
        report = Report.model_validate_json((tmp_path / "case/report.json").read_bytes())
        assert report.disposition == "REVIEW_REQUIRED"
        if exit_code == 3:
            rejected(report)
        assert (tmp_path / "case/original.eml").read_bytes() == RAW


def test_missing_smtp_context_can_preserve_dkim_only_evidence(tmp_path: Path) -> None:
    p = payload()
    p["spf"].update(result="UNKNOWN", domain=None, smtp_peer_ip=None)
    p["dkim"]["signatures"] = [signature()]
    p["alignment"].update(spf="UNKNOWN", dkim="PASS")
    a = review(tmp_path, p).authentication.trusted_ingress
    assert a.status == "ACCEPTED" and a.results.spf == "UNKNOWN"
    assert a.results.dkim == a.results.dmarc == "PASS"
    p["spf"]["result"] = "PASS"
    rejected(review(tmp_path, p))


def test_authorized_alias_cannot_relabel_existing_mac(tmp_path: Path) -> None:
    config = policy_data()
    other = copy.deepcopy(config["grants"][0])
    other["issuer_id"] = "other-authorized-gateway"
    config["grants"].append(other)
    envelope = json.loads(signed())
    envelope["issuer_id"] = other["issuer_id"]
    rejected(
        review(
            tmp_path,
            evidence=json.dumps(envelope).encode(),
            policy=IngressTrustPolicy.model_validate(config),
            keys={**KEYS, (other["issuer_id"], "fixture-1"): KEY},
        ),
        "invalid_mac",
    )


def test_envelope_whitespace_cannot_bypass_replay(tmp_path: Path) -> None:
    assert review(tmp_path).authentication.trusted_ingress.status == "ACCEPTED"
    rejected(
        review(tmp_path, evidence=json.dumps(json.loads(signed()), indent=4).encode()),
        "replayed_event",
    )


def test_payload_tamper_is_rejected_before_claims(tmp_path: Path) -> None:
    envelope = json.loads(signed())
    altered = payload()
    altered["spf"]["result"] = "FAIL"
    envelope["payload"] = (
        base64.urlsafe_b64encode(json.dumps(altered).encode()).rstrip(b"=").decode()
    )
    rejected(review(tmp_path, evidence=json.dumps(envelope).encode()), "invalid_mac")


def test_unknown_suffix_stays_unknown_in_accepted_evidence(tmp_path: Path) -> None:
    raw = RAW.replace(b"sender@example.com", b"sender@a.unknowninvalidtld")
    p = payload(raw)
    p["header_from_domain"] = p["spf"]["domain"] = p["dmarc"]["policy_domain"] = (
        "a.unknowninvalidtld"
    )
    p["dmarc"].update(result="UNKNOWN", aspf="r")
    p["alignment"]["spf"] = "UNKNOWN"
    a = review(tmp_path, p, raw=raw).authentication.trusted_ingress
    assert a.status == "ACCEPTED" and a.results.spf == "PASS"
    assert a.results.dmarc == a.results.alignment == "UNKNOWN"


def test_psl_package_tamper_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from mail_triage import trusted_ingress

    class ChangedSnapshot:
        def joinpath(self, _name: str) -> "ChangedSnapshot":
            return self

        def read_bytes(self) -> bytes:
            return b"unapproved suffixes"

    monkeypatch.setattr(trusted_ingress.resources, "files", lambda _: ChangedSnapshot())
    rejected(review(tmp_path), "unsupported_psl_snapshot")


@pytest.mark.parametrize(
    "name,model",
    [
        ("ingress-envelope-v1", SignedEnvelopeV1),
        ("ingress-assertion-v1", IngressAssertionV1),
        ("ingress-trust-v1", IngressTrustPolicy),
    ],
)
def test_published_wire_schemas_are_current(name: str, model: Any) -> None:
    schema = model.model_json_schema()
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    schema["$id"] = f"urn:mail-triage:{name}"
    path = Path(__file__).resolve().parents[1] / "docs/schemas" / f"{name}.json"
    assert json.loads(path.read_text()) == schema
