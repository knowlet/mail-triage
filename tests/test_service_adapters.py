"""Service wire-contract tests with authored bytes and mock transports only."""

import asyncio
import base64
import hashlib
import json
import os
import stat
from email import policy
from email.parser import BytesParser

import httpx
import pytest
from pydantic import SecretStr, ValidationError

from mail_triage.service_adapters import (
    MAX_INPUT_BYTES,
    MAX_SERVICE_RESPONSE_BYTES,
    AssemblylineAdapter,
    AssemblylineConfig,
    SublimeAdapter,
    SublimeConfig,
    SublimeRule,
    SubmissionClaims,
)
from mail_triage.transport import EndpointPolicy

RAW = b"From: author@example.test\r\nSubject: Authored fixture\r\n\r\nSynthetic body.\r\n"
SECRET = "fixture-key:synthetic-secret"
CREDENTIAL = SecretStr(SECRET)
AL_REPLY = {
    "api_response": {"sid": "synthetic-submission"},
    "api_status_code": 200,
    "api_error_message": "",
}
SUBLIME_REPLY = {
    "rule_results": [
        {
            "rule": {"name": "synthetic-review", "source": "type.inbound"},
            "success": True,
            "matched": False,
        }
    ],
    "query_results": [],
}


def endpoint(origin="https://analysis.example.test", **options):
    return EndpointPolicy(
        origin=origin, pinned_ip="192.168.50.20", allow_private_ip=True, **options
    )


def selected_rule(**updates):
    return SublimeRule(name="synthetic-review", source="type.inbound", severity="low", **updates)


def adapter_for(service, handler, **endpoint_options):
    transport = httpx.MockTransport(handler)
    if service == "assemblyline":
        return AssemblylineAdapter(
            AssemblylineConfig(
                enabled=True, endpoint=endpoint(**endpoint_options), username="synthetic-reviewer"
            ),
            inner=transport,
        )
    return SublimeAdapter(
        SublimeConfig(
            enabled=True, endpoint=endpoint(**endpoint_options), selected_rules=[selected_rule()]
        ),
        inner=transport,
    )


def analyze(adapter, claims, raw=RAW, credential=CREDENTIAL):
    return asyncio.run(adapter.analyze(raw, credential=credential, claims=claims))


@pytest.mark.parametrize("service", ["assemblyline", "sublime"])
def test_disabled_defaults_do_not_build_requests_or_create_intents(tmp_path, service):
    def forbidden(request):
        pytest.fail("Disabled adapters must not reach HTTP.")

    cls, config = (
        (AssemblylineAdapter, AssemblylineConfig())
        if service == "assemblyline"
        else (SublimeAdapter, SublimeConfig())
    )
    claims = SubmissionClaims(tmp_path / "claims")
    result = analyze(cls(config, inner=httpx.MockTransport(forbidden)), claims)
    assert result.status == "NOT_RUN"
    assert result.execution_mode == "NOT_RUN"
    assert result.reason == "disabled"
    assert not claims.directory.exists()


@pytest.mark.parametrize(
    ("cls", "values"),
    [
        (AssemblylineConfig, {"enabled": True}),
        (AssemblylineConfig, {"enabled": True, "endpoint": endpoint()}),
        (AssemblylineConfig, {"apikey": "must-not-be-in-config"}),
        (SublimeConfig, {"enabled": True}),
        (SublimeConfig, {"enabled": True, "endpoint": endpoint(), "selected_rules": []}),
        (SublimeConfig, {"rule_ids": ["not-rule-sources"]}),
    ],
)
def test_enabled_requires_explicit_nonsecret_configuration(cls, values):
    with pytest.raises(ValidationError):
        cls(**values)


@pytest.mark.parametrize(
    "host",
    [
        "analyzer.sublime.security",
        "ANALYZER.SUBLIME.SECURITY",
        "analyzer.sublime.security.",
        "platform.sublime.security",
        "subdomain.analyzer.sublime.security",
    ],
)
def test_sublime_public_service_hosts_are_rejected(host):
    with pytest.raises(ValidationError):
        SublimeConfig(
            enabled=True,
            endpoint=endpoint("https://" + host),
            selected_rules=[selected_rule()],
        )


def test_assemblyline_fixed_multipart_preserves_exact_bytes_and_prior_intent(tmp_path, monkeypatch):
    claims = SubmissionClaims(tmp_path / "claims")
    expected_hash = hashlib.sha256(RAW).hexdigest()
    response_bytes = json.dumps(AL_REPLY).encode()
    synchronized = []
    real_fsync = os.fsync

    def sync(fd):
        info = os.fstat(fd)
        synchronized.append((info.st_dev, info.st_ino))
        real_fsync(fd)

    monkeypatch.setattr(os, "fsync", sync)

    def handler(request):
        records = list(claims.directory.glob("*.json"))
        assert len(records) == 1  # Durable intent exists before the request is dispatched.
        stored = json.loads(records[0].read_text())
        assert stored["input_sha256"] == expected_hash
        persisted = [records[0].stat(), claims.directory.stat(), tmp_path.stat()]
        assert synchronized == [(info.st_dev, info.st_ino) for info in persisted]
        assert stat.S_IMODE(records[0].stat().st_mode) == 0o600
        assert stat.S_IMODE(claims.directory.stat().st_mode) == 0o700
        assert SECRET not in records[0].read_text()
        assert "Synthetic body" not in records[0].read_text()
        assert "synthetic-reviewer" not in records[0].read_text()
        assert request.method == "POST"
        assert request.url.path == "/api/v4/submit/"
        assert request.url.host == "192.168.50.20"
        assert request.headers["host"] == "analysis.example.test"
        assert request.headers["x-user"] == "synthetic-reviewer"
        assert request.headers["x-apikey"] == SECRET
        assert not request.url.query and SECRET not in str(request.url)
        message = BytesParser(policy=policy.default).parsebytes(
            b"Content-Type: "
            + request.headers["content-type"].encode()
            + b"\r\n\r\n"
            + request.content
        )
        parts = {
            part.get_param("name", header="Content-Disposition"): part
            for part in message.iter_parts()
        }
        assert set(parts) == {"bin", "json"}
        assert parts["bin"].get_filename() == "original.eml"
        # message/rfc822 is parsed as a child tree. Check the wire octets without
        # reserializing that tree, which would alter provenance-sensitive bytes.
        boundary = b"--" + message.get_boundary().encode()
        bin_wire = next(
            chunk for chunk in request.content.split(boundary) if b'name="bin";' in chunk
        )
        assert bin_wire.split(b"\r\n\r\n", 1)[1].removesuffix(b"\r\n") == RAW
        metadata = json.loads(parts["json"].get_payload(decode=True))["metadata"]
        assert metadata == {"sha256": expected_hash, "correlation_id": records[0].stem}
        return httpx.Response(
            200, content=response_bytes, headers={"content-type": "application/json"}
        )

    result = analyze(adapter_for("assemblyline", handler), claims)
    assert result.status == "OBSERVED"
    assert result.execution_mode == "MOCK"
    assert result.external_id == "synthetic-submission"
    assert result.input_sha256 == expected_hash
    assert result.response_sha256 == hashlib.sha256(response_bytes).hexdigest()
    assert result.observed_at is not None
    assert result.source_origin == "https://analysis.example.test"
    assert "no_safety_or_identity_verdict" in result.reason
    assert SECRET not in result.model_dump_json()


def test_sublime_exact_raw_base64_selected_sources_and_bearer_header(tmp_path):
    def handler(request):
        assert request.url.path == "/v0/messages/analyze"
        assert request.headers["authorization"] == "Bearer " + SECRET
        assert not request.url.query and SECRET not in str(request.url)
        payload = json.loads(request.content)
        assert payload == {
            "raw_message": base64.b64encode(RAW).decode(),
            "rules": [{"name": "synthetic-review", "source": "type.inbound", "severity": "low"}],
            "queries": [],
        }
        assert base64.b64decode(payload["raw_message"]) == RAW
        return httpx.Response(200, json=SUBLIME_REPLY)

    result = analyze(adapter_for("sublime", handler), SubmissionClaims(tmp_path / "claims"))
    assert result.status == "OBSERVED"
    assert result.execution_mode == "MOCK"
    assert result.external_id is None
    assert SECRET not in result.model_dump_json()


@pytest.mark.parametrize("service", ["assemblyline", "sublime"])
def test_new_instances_cannot_repeat_a_durable_submission(tmp_path, service):
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(200, json=AL_REPLY if service == "assemblyline" else SUBLIME_REPLY)

    first = analyze(adapter_for(service, handler), SubmissionClaims(tmp_path / "claims"))
    second = analyze(adapter_for(service, handler), SubmissionClaims(tmp_path / "claims"))
    assert first.status == "OBSERVED"
    assert second.status == "ERROR"
    assert second.reason == "duplicate_submission_blocked"
    assert len(calls) == 1
    assert len(list((tmp_path / "claims").glob("*.json"))) == 1


@pytest.mark.parametrize("service", ["assemblyline", "sublime"])
def test_timeout_is_uncertain_and_no_retry_occurs_even_after_restart(tmp_path, service):
    calls = []

    def handler(request):
        calls.append(request)
        raise httpx.ReadTimeout("Never persist " + SECRET, request=request)

    first = analyze(adapter_for(service, handler), SubmissionClaims(tmp_path / "claims"))
    second = analyze(adapter_for(service, handler), SubmissionClaims(tmp_path / "claims"))
    assert first.status == second.status == "ERROR"
    assert first.reason == "request_timeout_outcome_unknown"
    assert second.reason == "duplicate_submission_blocked"
    assert len(calls) == 1
    assert SECRET not in first.model_dump_json() + second.model_dump_json()


@pytest.mark.parametrize("service", ["assemblyline", "sublime"])
@pytest.mark.parametrize("status", [401, 403])
def test_authentication_errors_never_store_response_body_or_credentials(tmp_path, service, status):
    def handler(request):
        return httpx.Response(status, json={"error": SECRET, "body": RAW.decode()})

    result = analyze(adapter_for(service, handler), SubmissionClaims(tmp_path / "claims"))
    assert result.status == "ERROR"
    assert result.reason == "authentication_rejected"
    assert result.response_sha256
    serialized = result.model_dump_json()
    assert SECRET not in serialized and "Synthetic body" not in serialized
    assert result.external_id is None


@pytest.mark.parametrize(
    ("service", "reply"),
    [
        ("assemblyline", {}),
        ("assemblyline", {"sid": "wrong-level"}),
        ("assemblyline", {**AL_REPLY, "api_status_code": 403}),
        ("assemblyline", {**AL_REPLY, "api_error_message": "upstream error"}),
        ("assemblyline", {**AL_REPLY, "api_response": {"sid": "x" * 129}}),
        ("assemblyline", {**AL_REPLY, "api_response": {"sid": SECRET}}),
        ("sublime", {}),
        ("sublime", {"rule_results": [], "query_results": []}),
        ("sublime", {"rule_results": {}, "query_results": []}),
        ("sublime", {"rule_results": [True], "query_results": []}),
        (
            "sublime",
            {
                "rule_results": [{"success": True, "matched": "true", "rule": {}}],
                "query_results": [],
            },
        ),
        (
            "sublime",
            {
                "rule_results": [{"success": True, "matched": True, "rule": {"name": "x" * 129}}],
                "query_results": [],
            },
        ),
        ("sublime", {"rule_results": [], "query_results": [False]}),
    ],
)
def test_malformed_or_unbounded_response_projections_fail_closed(tmp_path, service, reply):
    def handler(request):
        return httpx.Response(200, json=reply)

    result = analyze(adapter_for(service, handler), SubmissionClaims(tmp_path / "claims"))
    assert result.status == "ERROR"
    assert result.reason == "invalid_response"
    assert result.external_id is None
    assert SECRET not in result.model_dump_json()


@pytest.mark.parametrize(
    "results",
    [
        [],
        [
            {
                "rule": {"name": "synthetic-review", "source": "type.inbound"},
                "success": False,
                "matched": False,
            }
        ],
        [
            {
                "rule": {"name": "synthetic-review", "source": "type.inbound"},
                "success": True,
            }
        ],
        SUBLIME_REPLY["rule_results"] * 2,
        [
            {
                "rule": {"name": "unrequested", "source": "type.inbound"},
                "success": True,
                "matched": False,
            }
        ],
        [
            {
                "rule": {"name": "synthetic-review", "source": "type.outbound"},
                "success": True,
                "matched": False,
            }
        ],
    ],
)
def test_sublime_requires_success_for_each_exact_selected_rule_once(tmp_path, results):
    def handler(request):
        return httpx.Response(200, json={"rule_results": results, "query_results": []})

    result = analyze(adapter_for("sublime", handler), SubmissionClaims(tmp_path / "claims"))
    assert result.status == "ERROR"
    assert result.reason == "invalid_response"


def test_real_http_transport_cannot_be_injected_and_labeled_mock():
    transport = httpx.AsyncHTTPTransport(trust_env=False)
    try:
        with pytest.raises(ValueError, match="Only MockTransport"):
            AssemblylineAdapter(AssemblylineConfig(), inner=transport)
        with pytest.raises(ValueError, match="Only MockTransport"):
            SublimeAdapter(SublimeConfig(), inner=transport)
    finally:
        asyncio.run(transport.aclose())


@pytest.mark.parametrize("service", ["assemblyline", "sublime"])
def test_response_size_and_invalid_json_are_bounded(tmp_path, service):
    for index, response in enumerate(
        [
            httpx.Response(
                200,
                content=b"x" * (MAX_SERVICE_RESPONSE_BYTES + 1),
                headers={"content-type": "application/json"},
            ),
            httpx.Response(200, content=b"{broken", headers={"content-type": "application/json"}),
        ]
    ):
        result = analyze(
            adapter_for(service, lambda request, response=response: response),
            SubmissionClaims(tmp_path / str(index)),
        )
        assert result.status == "ERROR"
        assert result.reason == ("response_too_large" if index == 0 else "invalid_response")


@pytest.mark.parametrize("service", ["assemblyline", "sublime"])
@pytest.mark.parametrize("raw", [b"", b"x" * (MAX_INPUT_BYTES + 1)])
def test_input_rejection_never_posts_or_creates_claims(tmp_path, service, raw):
    def forbidden(request):
        pytest.fail("Rejected input must not reach HTTP.")

    claims = SubmissionClaims(tmp_path / "claims")
    result = analyze(adapter_for(service, forbidden), claims, raw=raw)
    assert result.reason == "input_rejected"
    assert not claims.directory.exists()


@pytest.mark.parametrize("credential", [SecretStr(""), SecretStr("bad\r\nheader"), None])
def test_invalid_credentials_do_not_reach_transport_or_intent_storage(tmp_path, credential):
    def forbidden(request):
        pytest.fail("Invalid credentials must not reach HTTP.")

    claims = SubmissionClaims(tmp_path / "claims")
    result = analyze(adapter_for("sublime", forbidden), claims, credential=credential)
    assert result.reason == "credential_rejected"
    assert not claims.directory.exists()


@pytest.mark.parametrize("service", ["assemblyline", "sublime"])
def test_failed_claim_storage_or_symlink_directory_prevents_post(tmp_path, service):
    def forbidden(request):
        pytest.fail("A failed durable intent must prevent HTTP.")

    invalid = tmp_path / "not-a-directory"
    invalid.write_text("authored fixture")
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "link"
    link.symlink_to(target, target_is_directory=True)
    for directory in (invalid, link):
        result = analyze(adapter_for(service, forbidden), SubmissionClaims(directory))
        assert result.reason == "claim_storage_failed"
    assert not list(target.iterdir())


def test_different_payload_endpoint_or_selected_rules_have_distinct_intents(tmp_path):
    def handler(request):
        rules = json.loads(request.content)["rules"]
        return httpx.Response(
            200,
            json={
                "rule_results": [
                    {"rule": rule, "success": True, "matched": False} for rule in rules
                ],
                "query_results": [],
            },
        )

    claims = SubmissionClaims(tmp_path / "claims")
    variants = [
        (endpoint(), [selected_rule()], RAW),
        (endpoint(), [selected_rule()], RAW + b"Different."),
        (endpoint("https://other.example.test"), [selected_rule()], RAW),
        (endpoint(), [SublimeRule(name="different", source="type.outbound")], RAW),
    ]
    for policy_config, rules, raw in variants:
        adapter = SublimeAdapter(
            SublimeConfig(enabled=True, endpoint=policy_config, selected_rules=rules),
            inner=httpx.MockTransport(handler),
        )
        assert analyze(adapter, claims, raw=raw).status == "OBSERVED"
    assert len(list(claims.directory.glob("*.json"))) == 4


def test_concurrent_instances_reserve_one_post_only(tmp_path):
    calls = []

    async def handler(request):
        calls.append(request)
        await asyncio.sleep(0)
        return httpx.Response(200, json=AL_REPLY)

    async def run():
        return await asyncio.gather(
            *[
                adapter_for("assemblyline", handler).analyze(
                    RAW, credential=SecretStr(SECRET), claims=SubmissionClaims(tmp_path / "claims")
                )
                for _ in range(2)
            ]
        )

    results = asyncio.run(run())
    assert sorted(result.status for result in results) == ["ERROR", "OBSERVED"]
    assert len(calls) == 1
