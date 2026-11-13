"""Synthetic OSINT contracts. Network calls are prohibited by conftest."""

import asyncio
import hashlib
import json
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from pydantic import SecretStr, ValidationError

from mail_triage.cli import build_report, main
from mail_triage.osint_cli import apply_osint
from mail_triage.reporting import render_html
from mail_triage.schemas import Report
from mail_triage.sender_osint import (
    Indicator,
    OsintConfig,
    OsintCredentials,
    Source,
    lookup_sender,
)
from mail_triage.transport import ConnectorError, EndpointPolicy

DIGEST = "a" * 64
KEY = "synthetic-secret-do-not-print"


def config(**updates):
    base = OsintConfig(
        enabled=True,
        sources=[
            Source(
                source_id="local",
                endpoint=EndpointPolicy(
                    origin="https://misp.example", pinned_ip="192.0.2.1", allow_private_ip=True
                ),
            )
        ],
        indicators=[Indicator(kind="domain", value="sender.example")],
    )
    return OsintConfig.model_validate({**base.model_dump(), **updates})


def attr(**updates):
    return {
        "uuid": "00000000-0000-4000-8000-000000000001",
        "type": "domain",
        "value": "sender.example",
        "timestamp": str(int(datetime.now(UTC).timestamp())),
        "to_ids": True,
        "deleted": False,
        **updates,
    }


def run(items=None, *, settings=None, status=200, body=None, allow=True):
    requests = []

    def handler(request):
        requests.append(request)
        return (
            httpx.Response(status, json={"response": {"Attribute": items or []}})
            if body is None
            else httpx.Response(status, content=body)
        )

    selected = settings or config()
    result = asyncio.run(
        lookup_sender(
            selected,
            OsintCredentials(keys={s.source_id: SecretStr(KEY) for s in selected.sources}),
            input_sha256=DIGEST,
            allow_egress=allow,
            inner=httpx.MockTransport(handler),
        )
    )
    return result, requests


def test_success_is_bounded_exact_and_untrusted():
    result, requests = run([attr(), attr(value="other.example")])
    assert result.status == "OBSERVED"
    assert result.execution_mode == "MOCK"
    assert len(requests) == 1
    request = requests[0]
    assert request.url.host == "192.0.2.1"
    assert request.url.path == "/attributes/restSearch"
    assert request.method == "POST"
    assert request.headers["authorization"] == KEY
    payload = json.loads(request.content)
    assert payload == {
        "returnFormat": "json",
        "value": "sender.example",
        "type": ["domain", "hostname"],
        "page": 1,
        "limit": 100,
        "deleted": False,
    }
    lookup = result.lookups[0]
    assert lookup.source_origin == "https://misp.example"
    assert lookup.queried_at.tzinfo is not None
    assert len(lookup.response_sha256) == 64
    assert len(lookup.attributes) == 1
    assert lookup.attributes[0].update_recency == "CURRENT"
    assert KEY not in result.model_dump_json()


@pytest.mark.parametrize("enabled,allow", [(False, True), (True, False), (False, False)])
def test_default_offline(enabled, allow):
    result, requests = run(settings=config(enabled=enabled), allow=allow)
    assert result.status == "NOT_RUN"
    assert result.execution_mode == "NOT_RUN"
    assert requests == []


def test_missing_does_not_mean_safe():
    result, _ = run()
    assert result.status == "UNKNOWN"
    assert result.lookups[0].status == "MISSING"
    assert "safety" in " ".join(result.limitations)


@pytest.mark.parametrize(
    "age,freshness", [(10, "CURRENT"), (8 * 86400, "STALE"), (-3600, "FUTURE")]
)
def test_source_update_age(age, freshness):
    stamp = str(int((datetime.now(UTC) - timedelta(seconds=age)).timestamp()))
    result, _ = run([attr(timestamp=stamp)])
    assert result.lookups[0].attributes[0].update_recency == freshness
    assert result.status == "OBSERVED"


def test_conflicting_current_flags_preserved_without_verdict():
    result, _ = run([attr(), attr(to_ids=False)])
    assert result.conflicting_to_ids == [Indicator(kind="domain", value="sender.example")]
    assert [x.to_ids for x in result.lookups[0].attributes] == [True, False]
    assert "disposition" not in result.model_dump()


def test_stale_flags_do_not_create_current_conflict():
    result, _ = run([attr(), attr(to_ids=False, timestamp="1")])
    assert result.conflicting_to_ids == []


@pytest.mark.parametrize(
    "item", [attr(deleted=True), attr(type="url"), attr(value="other.example")]
)
def test_deleted_and_unrelated_are_not_evidence(item):
    result, _ = run([item])
    assert result.status == "UNKNOWN"


@pytest.mark.parametrize(
    "patch",
    [
        {"timestamp": 1},
        {"timestamp": "NaN"},
        {"timestamp": "999999999999999999999999"},
        {"timestamp": None},
        {"to_ids": "false"},
        {"to_ids": 1},
        {"to_ids": None},
        {"deleted": "false"},
        {"value": None},
        {"value": "http://bad.example"},
        {"uuid": None},
        {"uuid": "a" * 129},
    ],
)
def test_malformed_attributes_fail_closed(patch):
    result, _ = run([attr(**patch)])
    assert result.status == "ERROR"
    assert result.lookups[0].attributes == []
    assert result.lookups[0].reason == "invalid_response"


@pytest.mark.parametrize(
    "body",
    [
        b"{}",
        b"[]",
        b"null",
        b"not json",
        b'{"response": []}',
        b'{"response":{"Attribute":{}}}',
        b'{"response":{"Attribute":[]},"response":{"Attribute":[]}}',
    ],
)
def test_malformed_envelope(body):
    result, _ = run(body=body)
    assert result.status == "ERROR"


@pytest.mark.parametrize("status", [401, 403, 429, 500, 503])
def test_service_failure_no_retry_or_secret_leak(status):
    result, requests = run(status=status, body=KEY.encode())
    assert result.status == "ERROR"
    assert len(requests) == 1
    assert result.lookups[0].reason == "service_rejected"
    assert KEY not in result.model_dump_json()


def test_redirect_rejected():
    result, requests = run(status=302)
    assert result.lookups[0].reason == "redirect_rejected"
    assert len(requests) == 1


def test_response_cap():
    result, _ = run(body=b"x" * (1024 * 1024 + 1))
    assert result.lookups[0].reason == "response_too_large"


def test_truncation_not_silent():
    result, _ = run([attr()], settings=config(max_attributes=1))
    assert result.lookups[0].possibly_truncated is True
    bad, _ = run([attr(), attr()], settings=config(max_attributes=1))
    assert bad.status == "ERROR"


@pytest.mark.parametrize(
    "value,canonical",
    [("EXAMPLE.ORG.", "example.org"), ("bücher.example", "xn--bcher-kva.example")],
)
def test_domain_normalization(value, canonical):
    assert Indicator(kind="domain", value=value).value == canonical


@pytest.mark.parametrize("kind,value", [("ip", "192.0.2.1"), ("ip", "2001:db8::1")])
def test_ip_lookup(kind, value):
    result, requests = run(
        [attr(type="ip-src", value=value)],
        settings=config(indicators=[{"kind": kind, "value": value}]),
    )
    assert result.status == "OBSERVED"
    assert json.loads(requests[0].content)["type"] == ["ip-src", "ip-dst"]


@pytest.mark.parametrize(
    "kind,value",
    [
        ("ip", "fe80::1%eth0"),
        ("domain", "localhost"),
        ("domain", "192.0.2.1"),
        ("domain", "x@example.org"),
        ("ip", "not-an-ip"),
    ],
)
def test_invalid_indicators(kind, value):
    with pytest.raises(ValueError):
        Indicator(kind=kind, value=value)


@pytest.mark.parametrize(
    "patch",
    [
        {"enabled": "true"},
        {"max_attributes": True},
        {"min_interval_seconds": 0.0},
        {"min_interval_seconds": float("nan")},
        {"sources": []},
        {"indicators": []},
    ],
)
def test_configuration_rejected(patch):
    with pytest.raises(ValueError):
        config(**patch)


def test_credentials_required_before_dispatch():
    with pytest.raises(ConnectorError, match="explicit_osint_credentials_required"):
        asyncio.run(
            lookup_sender(config(), OsintCredentials(), input_sha256=DIGEST, allow_egress=True)
        )
    with pytest.raises(ValidationError):
        OsintCredentials(keys={"local": SecretStr("bad\nkey")})


def test_rate_limit_and_cancel_prevents_later_dispatch():
    async def execute():
        started = []

        async def handler(request):
            started.append(asyncio.get_running_loop().time())
            return httpx.Response(200, json={"response": {"Attribute": []}})

        settings = config(
            indicators=[
                {"kind": "domain", "value": "one.example"},
                {"kind": "domain", "value": "two.example"},
            ]
        )
        await lookup_sender(
            settings,
            OsintCredentials(keys={"local": SecretStr(KEY)}),
            input_sha256=DIGEST,
            allow_egress=True,
            inner=httpx.MockTransport(handler),
        )
        assert len(started) == 2
        assert started[1] - started[0] >= 0.99
        started.clear()
        task = asyncio.create_task(
            lookup_sender(
                settings,
                OsintCredentials(keys={"local": SecretStr(KEY)}),
                input_sha256=DIGEST,
                allow_egress=True,
                inner=httpx.MockTransport(handler),
            )
        )
        await asyncio.sleep(0.02)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert len(started) == 1

    asyncio.run(execute())


def test_timeout_is_evidence_error():
    async def handler(request):
        await asyncio.sleep(1)
        return httpx.Response(200)

    selected = config()
    endpoint = selected.sources[0].endpoint.model_copy(update={"total_timeout": 0.1})
    selected = config(sources=[Source(source_id="local", endpoint=endpoint).model_dump()])
    result = asyncio.run(
        lookup_sender(
            selected,
            OsintCredentials(keys={"local": SecretStr(KEY)}),
            input_sha256=DIGEST,
            allow_egress=True,
            inner=httpx.MockTransport(handler),
        )
    )
    assert result.lookups[0].reason == "timeout"


def test_report_integration_preserves_unknown_and_review():
    raw = b"From: sender@sender.example\r\n\r\nsynthetic"
    report = build_report(raw, "synthetic.eml")
    evidence, _ = run([attr(to_ids=False)])
    evidence = evidence.model_copy(update={"input_sha256": hashlib.sha256(raw).hexdigest()})
    apply_osint(report, evidence)
    assert report.schema_version == "1.2"
    assert report.disposition == "REVIEW_REQUIRED"
    assert report.authentication.spf.status == "UNKNOWN"
    assert report.reputation.gateway_spam_rate.status == "UNKNOWN"
    assert report.reputation.sender_osint.status == "OBSERVED"
    assert Report.model_validate_json(report.model_dump_json()) == report
    assert "sender.example" in render_html(report)
    assert "MOCK OSINT · EXPLICIT CONNECTOR REPORT" in render_html(report)
    assert not any(w.startswith("No DNS, URL retrieval") for w in report.warnings)
    with pytest.raises(ValueError, match="provenance"):
        apply_osint(report, evidence.model_copy(update={"input_sha256": DIGEST}))


def test_cli_requires_explicit_switches():
    with pytest.raises(SystemExit):
        main(["sender-osint", "synthetic.eml", "--config", "config.json", "--out", "case"])


def test_two_sources_conflict_and_partial_failure():
    settings = config(
        sources=[
            Source(
                source_id="first",
                endpoint=EndpointPolicy(
                    origin="https://first.example", pinned_ip="192.0.2.1", allow_private_ip=True
                ),
            ).model_dump(),
            Source(
                source_id="second",
                endpoint=EndpointPolicy(
                    origin="https://second.example", pinned_ip="192.0.2.2", allow_private_ip=True
                ),
            ).model_dump(),
        ]
    )
    for fail in [False, True]:

        def handler(request, fail=fail):
            second = request.url.host == "192.0.2.2"
            if second and fail:
                return httpx.Response(503, content=KEY.encode())
            return httpx.Response(200, json={"response": {"Attribute": [attr(to_ids=not second)]}})

        evidence = asyncio.run(
            lookup_sender(
                settings,
                OsintCredentials(keys={"first": SecretStr(KEY), "second": SecretStr(KEY)}),
                input_sha256=DIGEST,
                allow_egress=True,
                inner=httpx.MockTransport(handler),
            )
        )
        assert evidence.status == "OBSERVED"
        assert [x.source_id for x in evidence.lookups] == ["first", "second"]
        assert evidence.lookups[1].status == ("ERROR" if fail else "OBSERVED")
        assert len(evidence.conflicting_to_ids) == (0 if fail else 1)
        assert KEY not in evidence.model_dump_json()


def test_cli_mock_case_and_credential_redaction(tmp_path, monkeypatch, capsys):
    import io
    import sys

    import mail_triage.osint_cli as cli

    raw = b"From: synthetic@sender.example\r\n\r\nsynthetic fixture only"
    eml = tmp_path / "input.eml"
    eml.write_bytes(raw)
    cfg = tmp_path / "settings.json"
    cfg.write_text(config().model_dump_json())
    calls = []

    async def mocked(settings, credentials, **kwargs):
        def handler(request):
            calls.append(request)
            return httpx.Response(200, json={"response": {"Attribute": [attr()]}})

        return await lookup_sender(
            settings, credentials, **kwargs, inner=httpx.MockTransport(handler)
        )

    monkeypatch.setattr(cli, "lookup_sender", mocked)
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps({"keys": {"local": KEY}})))
    out = tmp_path / "case"
    command = [
        "sender-osint",
        str(eml),
        "--config",
        str(cfg),
        "--out",
        str(out),
        "--allow-egress",
        "--secrets-stdin",
    ]
    assert main(command) == 0
    captured = capsys.readouterr()
    assert KEY not in captured.out + captured.err
    assert '"execution_mode": "MOCK"' in captured.out
    assert len(calls) == 1
    assert (out / "original.eml").read_bytes() == raw
    result = Report.model_validate_json((out / "report.json").read_bytes())
    assert result.sender_osint_evidence.lookups[0].status == "OBSERVED"
    assert KEY not in (out / "report.json").read_text() + (out / "report.html").read_text()
    assert main(command) == 2  # output rejection occurs before credentials/query
    assert len(calls) == 1
    assert "output_unavailable" in capsys.readouterr().err


def test_missing_deleted_flag_rejected():
    item = attr()
    del item["deleted"]
    result, _ = run([item])
    assert result.status == "ERROR"
    assert len(result.lookups[0].response_sha256) == 64


def test_legacy_report_without_new_field_loads_and_default_stays_offline():
    report = build_report(b"From: synthetic@sender.example\r\n\r\nhello", "synthetic.eml")
    data = json.loads(report.model_dump_json())
    del data["sender_osint_evidence"]
    for version in ["1.0", "1.1"]:
        data["schema_version"] = version
        loaded = Report.model_validate_json(json.dumps(data))
        assert loaded.sender_osint_evidence is None
        assert loaded.reputation.sender_osint.status == "NOT_RUN"
    assert report.schema_version == "1.1"
    assert report.sender_osint_evidence is None


def test_invalid_uuid_and_duplicate_configuration():
    result, _ = run([attr(uuid=KEY)])
    assert result.status == "ERROR"
    assert KEY not in result.model_dump_json()
    selected = config()
    with pytest.raises(ValueError):
        config(sources=[selected.sources[0].model_dump()] * 2)
    with pytest.raises(ValueError):
        config(indicators=[selected.indicators[0].model_dump()] * 2)
