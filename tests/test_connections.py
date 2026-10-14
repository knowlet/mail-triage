"""End-to-end connector orchestration with local HTTP mocks, never live services."""

import asyncio
import hashlib
import io
import json
import stat
from pathlib import Path

import httpx
import pytest
from pydantic import SecretStr

from mail_triage.cli import main
from mail_triage.connections import ExplicitCredentials, ingest_graph_case
from mail_triage.contract_demo import (
    DEMO_ATTACHMENT_ID,
    DEMO_MESSAGE_ID,
    DEMO_TOKEN,
    FIXTURE_SHA256,
    demo_settings,
    demo_transport,
    demo_wrapper,
)
from mail_triage.model_adapter import ModelConfig
from mail_triage.schemas import Report
from mail_triage.service_adapters import AssemblylineConfig, SublimeConfig
from mail_triage.transport import ConnectorError

FIXTURE = Path(__file__).parent.parent / "fixtures" / "synthetic-phish.eml"


def credentials():
    dummy = SecretStr(DEMO_TOKEN)
    return ExplicitCredentials(
        graph_token=dummy, assemblyline_key=dummy, sublime_key=dummy, model_key=dummy
    )


def execute(output, *, settings=None, secrets=None, inner=None):
    return asyncio.run(
        ingest_graph_case(
            settings or demo_settings(),
            secrets or credentials(),
            message_id=DEMO_MESSAGE_ID,
            attachment_id=DEMO_ATTACHMENT_ID,
            output=output,
            inner=inner if inner is not None else demo_transport(FIXTURE.read_bytes(), []),
        )
    )


def test_six_request_mock_contract_preserves_independent_byte_identities_and_unknown_auth(tmp_path):
    raw = FIXTURE.read_bytes()
    calls = []
    output = tmp_path / "case"
    result = execute(output, inner=demo_transport(raw, calls))
    assert result.status == "COMPLETED"
    assert result.execution_mode == result.model.backend_kind == "MOCK"
    assert result.assemblyline.execution_mode == result.sublime.execution_mode == "MOCK"
    assert len(calls) == 6
    assert [item["method"] for item in calls] == ["GET", "GET", "GET", "POST", "POST", "POST"]
    assert (output / "original.eml").read_bytes() == raw
    assert (output / "wrapper.eml").read_bytes() == demo_wrapper(raw)
    assert result.graph.original_sha256 == FIXTURE_SHA256
    assert result.graph.wrapper_sha256 == hashlib.sha256(demo_wrapper(raw)).hexdigest()
    assert result.graph.wrapper_sha256 != result.graph.original_sha256
    assert result.graph.attachment_metadata.attachment_id == DEMO_ATTACHMENT_ID
    report = Report.model_validate_json((output / "report.json").read_bytes())
    assert report.provenance.source_kind == "graph_original"
    assert report.provenance.sha256 == FIXTURE_SHA256
    assert report.message.subject != "Synthetic user report wrapper"
    for name in ("spf", "dkim", "dmarc", "alignment"):
        assert getattr(report.authentication, name).status == "UNKNOWN"
    assert report.reputation.gateway_spam_rate.status == "UNKNOWN"
    assert report.model_stages["dspy"].status == "NOT_RUN"
    assert report.disposition == "REVIEW_REQUIRED"
    html = (output / "report.html").read_text()
    assert "GRAPH ORIGINAL" in html and "MOCK" in html
    assert "&lt;script&gt;" in html and "<script>" not in html
    assert "<img" not in html and '<a href="https:' not in html
    assert report.content.findings
    assert result.model.opinion.finding_ids[0] in [f.code for f in report.content.findings]
    # Secrets and raw upstream bodies are not part of typed connector evidence.
    for name in ("connectors.json", "graph-provenance.json", "report.json", "report.html"):
        assert DEMO_TOKEN not in (output / name).read_text()
        assert stat.S_IMODE((output / name).stat().st_mode) == 0o600
    assert stat.S_IMODE(output.stat().st_mode) == 0o700
    assert len(list((output / "submissions").glob("*.json"))) == 2


def test_mock_demo_cli_outputs_actual_json_and_inert_request_log(tmp_path, capsys):
    output = tmp_path / "demo"
    assert main(["connect-demo", "--out", str(output)]) == 0
    summary = json.loads(capsys.readouterr().out)
    assert summary["execution_mode"] == summary["model_backend"] == "MOCK"
    assert summary["status"] == "COMPLETED"
    assert summary["authentication"] == "UNKNOWN"
    records = json.loads((output / "mock-requests.json").read_bytes())
    assert len(records) == 6
    assert all(item["execution_mode"] == "MOCK" for item in records)
    assert "Authorization" not in json.dumps(records) and DEMO_TOKEN not in json.dumps(records)
    assert main(["connect-demo", "--out", str(output)]) == 2
    assert json.loads(capsys.readouterr().err)["error"] == "output_already_exists"


def test_pipeline_needs_explicit_egress_when_no_mock_and_never_discovers_credentials(tmp_path):
    with pytest.raises(ConnectorError, match="egress_not_authorized"):
        asyncio.run(
            ingest_graph_case(
                demo_settings(), credentials(), message_id="x", attachment_id="y", output=tmp_path
            )
        )


@pytest.mark.parametrize("field", ["graph_token", "assemblyline_key", "sublime_key", "model_key"])
def test_all_enabled_credentials_checked_before_any_request(tmp_path, field):
    calls = []
    secrets = credentials().model_copy(update={field: None})
    with pytest.raises(ConnectorError, match="explicit_credentials_required"):
        execute(
            tmp_path / "case", secrets=secrets, inner=demo_transport(FIXTURE.read_bytes(), calls)
        )
    assert calls == []
    assert not (tmp_path / "case").exists()


def test_disabled_post_stages_are_not_run_not_simulated_success(tmp_path):
    settings = demo_settings().model_copy(
        update={
            "assemblyline": AssemblylineConfig(),
            "sublime": SublimeConfig(),
            "model": ModelConfig(),
        }
    )
    calls = []
    result = execute(
        tmp_path / "case", settings=settings, inner=demo_transport(FIXTURE.read_bytes(), calls)
    )
    assert len(calls) == 3
    assert result.assemblyline.status == result.sublime.status == result.model.status == "NOT_RUN"
    assert result.model.backend_kind == "UNCONFIGURED"


def test_service_timeout_is_partial_preserves_bytes_and_intent_and_runs_other_stages(tmp_path):
    calls = []
    normal = demo_transport(FIXTURE.read_bytes(), calls)
    failed_posts = []

    async def timeout(request):
        if request.headers["host"] == "assemblyline.example.invalid":
            failed_posts.append(request)
            # The claim must exist durably before bytes can be submitted.
            assert len(list((tmp_path / "case" / "submissions").glob("*.json"))) == 1
            raise httpx.ReadTimeout("do not persist " + DEMO_TOKEN)
        return await normal.handle_async_request(request)

    result = execute(tmp_path / "case", inner=httpx.MockTransport(timeout))
    assert result.status == "PARTIAL"
    assert result.assemblyline.status == "ERROR"
    assert result.sublime.status == result.model.status == "OBSERVED"
    assert result.assemblyline.reason == "request_timeout_outcome_unknown"
    assert len(failed_posts) == 1
    assert (tmp_path / "case" / "original.eml").read_bytes() == FIXTURE.read_bytes()
    assert DEMO_TOKEN not in (tmp_path / "case" / "connectors.json").read_text()


@pytest.mark.parametrize("kind", ["directory", "symlink", "missing_parent"])
def test_output_conflicts_fail_before_graph_requests(tmp_path, kind):
    calls = []
    output = tmp_path / "case"
    code = "output_already_exists"
    if kind == "directory":
        output.mkdir()
    elif kind == "symlink":
        output.symlink_to(tmp_path / "absent")
    else:
        output = tmp_path / "absent" / "case"
        code = "output_parent_missing"
    with pytest.raises(ConnectorError, match=code):
        execute(output, inner=demo_transport(FIXTURE.read_bytes(), calls))
    assert calls == []


def graph_args(config, output):
    return [
        "graph-ingest",
        "--config",
        str(config),
        "--message-id",
        DEMO_MESSAGE_ID,
        "--attachment-id",
        DEMO_ATTACHMENT_ID,
        "--out",
        str(output),
        "--allow-egress",
        "--secrets-stdin",
    ]


def test_graph_cli_passes_explicit_config_and_stdin_to_mocked_orchestration(
    tmp_path, monkeypatch, capsys
):
    from mail_triage import connector_cli

    config = tmp_path / "config.json"
    config.write_text(demo_settings().model_dump_json())
    secrets = {name: DEMO_TOKEN for name in ExplicitCredentials.model_fields}
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(secrets)))

    async def local_only(settings, values, **kwargs):
        assert kwargs.pop("allow_egress") is True
        assert values.graph_token.get_secret_value() == DEMO_TOKEN
        return await ingest_graph_case(
            settings, values, inner=demo_transport(FIXTURE.read_bytes(), []), **kwargs
        )

    monkeypatch.setattr(connector_cli, "ingest_graph_case", local_only)
    assert main(graph_args(config, tmp_path / "case")) == 0
    assert json.loads(capsys.readouterr().out)["execution_mode"] == "MOCK"


@pytest.mark.parametrize(
    "bad", ["not-json", '{"graph":{},"graph":{}}', '{"graph":{"token":"private"}}', "[" * 1100]
)
def test_config_errors_are_sanitized_before_reading_secrets(tmp_path, monkeypatch, capsys, bad):
    config = tmp_path / "config.json"
    config.write_text(bad)

    class Unreadable:
        def read(self, count):
            raise AssertionError("Must validate config before requesting secret input")

    monkeypatch.setattr("sys.stdin", Unreadable())
    assert main(graph_args(config, tmp_path / "case")) == 2
    assert json.loads(capsys.readouterr().err) == {"error": "configuration_rejected"}


@pytest.mark.parametrize(
    "bad",
    [
        "not-json-private",
        "x" * 17000,
        '{"graph_token": "private", "unknown":"private"}',
        '{"graph_token":"private","graph_token":"private2"}',
    ],
)
def test_stdin_secrets_invalid_oversized_or_duplicate_rejected_without_echo(
    tmp_path, monkeypatch, capsys, bad
):
    config = tmp_path / "config.json"
    config.write_text(demo_settings().model_dump_json())
    monkeypatch.setattr("sys.stdin", io.StringIO(bad))
    assert main(graph_args(config, tmp_path / "case")) == 2
    assert json.loads(capsys.readouterr().err) == {"error": "credentials_rejected"}


def test_live_cli_requires_both_opt_in_flags_without_reading_config(tmp_path):
    args = graph_args(tmp_path / "missing.json", tmp_path / "case")
    with pytest.raises(SystemExit) as exc:
        main(args[:-2])
    assert exc.value.code == 2
