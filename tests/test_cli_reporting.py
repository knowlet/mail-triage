"""Real offline end-to-end tests, with authored message data and no model mocks."""

import hashlib
import json
from html.parser import HTMLParser
from pathlib import Path

import pytest

from mail_triage.cli import build_report, main
from mail_triage.reporting import render_html, write_case
from mail_triage.schemas import Report

FIXTURE = Path(__file__).parent.parent / "fixtures" / "synthetic-phish.eml"


def test_end_to_end_preserves_bytes_and_untrusted_auth(tmp_path: Path) -> None:
    output = tmp_path / "case"
    assert main(["triage", str(FIXTURE), "--out", str(output)]) == 0
    raw = FIXTURE.read_bytes()
    assert (output / "original.eml").read_bytes() == raw
    report = Report.model_validate_json((output / "report.json").read_text())
    assert report.provenance.sha256 == hashlib.sha256(raw).hexdigest()
    assert report.provenance.raw_bytes == len(raw)
    assert report.authentication.spf.status == "UNKNOWN"
    assert report.authentication.dkim.status == "UNKNOWN"
    assert report.authentication.dmarc.status == "UNKNOWN"
    assert report.authentication.alignment.status == "UNKNOWN"
    assert "spf=pass" in report.authentication.untrusted_authentication_results[0]
    assert report.model_stages["pydantic_ai"].status == "NOT_RUN"
    assert report.model_stages["dspy"].status == "NOT_RUN"
    assert report.reputation.assemblyline.status == "NOT_RUN"
    assert report.reputation.sublime.status == "NOT_RUN"
    assert report.reputation.outlook_ingestion.status == "NOT_RUN"
    assert report.reputation.gateway_spam_rate.status == "UNKNOWN"
    assert report.disposition == "REVIEW_REQUIRED"
    assert any(p.filename == "../../invoice.docm" for p in report.message.parts)
    assert sorted(p.name for p in output.iterdir()) == [
        "original.eml",
        "report.html",
        "report.json",
    ]
    assert output.stat().st_mode & 0o777 == 0o700
    assert all(p.stat().st_mode & 0o777 == 0o600 for p in output.iterdir())


class SafetyInspector(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.tags: list[str] = []
        self.attributes: list[tuple[str, str | None]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags.append(tag)
        self.attributes.extend(attrs)


def test_report_html_has_no_executable_message_markup_or_links() -> None:
    report = build_report(FIXTURE.read_bytes(), "<script>alert(1)</script>.eml")
    report.message.subject = '<img src=x onerror="alert(1)">'
    page = render_html(report)
    inspector = SafetyInspector()
    inspector.feed(page)
    assert not {"script", "img", "iframe", "object", "a", "form"}.intersection(inspector.tags)
    assert not any(k.startswith("on") or k in {"src", "href"} for k, _ in inspector.attributes)
    assert "default-src 'none'" in page
    assert "&lt;script&gt;" in page
    assert "&lt;img src=x" in page
    assert "tracking.example.invalid" in page


def test_existing_output_is_never_overwritten(tmp_path: Path) -> None:
    output = tmp_path / "existing"
    output.mkdir()
    marker = output / "marker"
    marker.write_text("preserve")
    assert main(["triage", str(FIXTURE), "--out", str(output)]) == 2
    assert marker.read_text() == "preserve"
    assert list(output.iterdir()) == [marker]
    assert not list(tmp_path.glob(".mail-triage-*"))


def test_oversized_cli_input_creates_no_case(tmp_path: Path) -> None:
    source = tmp_path / "oversized.eml"
    with source.open("wb") as stream:
        stream.truncate(5 * 1024 * 1024 + 1)
    output = tmp_path / "rejected"
    assert main(["triage", str(source), "--out", str(output)]) == 2
    assert not output.exists()


def test_terminal_summary_is_json_and_does_not_echo_message_content(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    assert main(["triage", str(FIXTURE), "--out", "case"]) == 0
    output = capsys.readouterr().out
    summary = json.loads(output)
    assert summary["disposition"] == "REVIEW_REQUIRED"
    assert summary["authentication"] == "UNKNOWN"
    assert summary["output_directory"] == "case"
    assert str(tmp_path) not in output
    assert "Ignore previous instructions" not in output
    assert "../../invoice.docm" not in output


def test_case_writer_rejects_mismatched_provenance_before_writing(tmp_path: Path) -> None:
    raw = FIXTURE.read_bytes()
    report = build_report(raw, "fixture.eml")
    output = tmp_path / "case"
    with pytest.raises(ValueError, match="provenance"):
        write_case(output, raw + b"modified", report)
    assert not output.exists()
    assert not list(tmp_path.glob(".mail-triage-*"))
