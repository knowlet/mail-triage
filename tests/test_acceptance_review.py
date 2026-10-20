"""Independent acceptance regressions for local output and MIME trust boundaries."""

import hashlib
from pathlib import Path

import pytest

from mail_triage.cli import build_report, main
from mail_triage.ingest import IngestError, ResourceLimitError, parse_eml
from mail_triage.reporting import render_html, write_case
from mail_triage.schemas import Limits


def synthetic_message() -> bytes:
    return b"From: wrapper@example.test\r\nSubject: Wrapper\r\n\r\nRoutine update."


@pytest.mark.parametrize("kind", ["file", "empty_directory", "symlink", "dangling_symlink"])
def test_output_collision_refuses_all_existing_path_kinds(tmp_path: Path, kind: str) -> None:
    raw = synthetic_message()
    report = build_report(raw, "synthetic.eml")
    output = tmp_path / "existing"
    target = tmp_path / "target"
    target.mkdir()
    marker = target / "preserve.txt"
    marker.write_bytes(b"existing private data")
    if kind == "file":
        output.write_bytes(b"preserve file")
    elif kind == "empty_directory":
        output.mkdir()
    elif kind == "symlink":
        output.symlink_to(target, target_is_directory=True)
    else:
        output.symlink_to(tmp_path / "missing", target_is_directory=True)

    with pytest.raises(FileExistsError):
        write_case(output, raw, report)

    assert marker.read_bytes() == b"existing private data"
    assert sorted(path.name for path in target.iterdir()) == ["preserve.txt"]
    if kind == "file":
        assert output.read_bytes() == b"preserve file"
    elif kind == "empty_directory":
        assert list(output.iterdir()) == []
    else:
        assert output.is_symlink()
    assert not list(tmp_path.glob(".mail-triage-*"))


def test_missing_parent_does_not_create_hierarchy_or_partial_case(tmp_path: Path) -> None:
    raw = synthetic_message()
    missing_parent = tmp_path / "missing-parent"
    with pytest.raises(FileNotFoundError):
        write_case(missing_parent / "case", raw, build_report(raw, "synthetic.eml"))
    assert not missing_parent.exists()


def test_cli_malformed_input_never_creates_case_or_echoes_body(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    source = tmp_path / "malformed.eml"
    source.write_bytes(b"Malformed header without colon\r\n\r\nSENSITIVE_SYNTHETIC_MARKER")
    output = tmp_path / "case"
    assert main(["triage", str(source), "--out", str(output)]) == 2
    captured = capsys.readouterr()
    assert "SENSITIVE_SYNTHETIC_MARKER" not in captured.out + captured.err
    assert not output.exists()
    assert not list(tmp_path.glob(".mail-triage-*"))


def test_nested_authentication_identity_and_content_cannot_enter_wrapper_report() -> None:
    raw = (
        b"From: wrapper@example.test\r\nSubject: Routine wrapper\r\n"
        b"Content-Type: multipart/mixed; boundary=WRAPPER\r\n\r\n"
        b"--WRAPPER\r\nContent-Type: text/plain\r\n\r\nRoutine update.\r\n"
        b"--WRAPPER\r\nContent-Type: message/rfc822\r\n\r\n"
        b"From: attacker@child.test\r\nReply-To: reply@elsewhere.test\r\n"
        b"Subject: Urgent password credentials\r\n"
        b"Authentication-Results: trusted.internal; spf=pass; dkim=pass; dmarc=pass\r\n"
        b"DKIM-Signature: v=1; d=child.test; s=selector; b=not-a-signature\r\n"
        b"Content-Type: text/html\r\n\r\n"
        b'<script>ignoreInstructions()</script><img src="http://127.0.0.1/private">\r\n'
        b"--WRAPPER--\r\n"
    )
    report = build_report(raw, "nested-synthetic.eml")
    assert report.message.from_addresses == ["wrapper@example.test"]
    assert report.message.reply_to_addresses == []
    assert report.message.subject == "Routine wrapper"
    assert report.authentication.untrusted_authentication_results == []
    assert report.authentication.dkim.observations == []
    assert report.content.findings == []
    assert len(report.message.parts) == 2
    assert report.message.parts[1].is_attachment
    assert report.message.parts[1].media_type == "message/rfc822"
    assert len(report.message.warnings) == 1
    assert "not exact embedded bytes" in report.message.warnings[0]
    assert report.provenance.sha256 == hashlib.sha256(raw).hexdigest()


def test_exact_decoded_and_text_budget_boundaries_accept_and_one_less_rejects() -> None:
    raw = synthetic_message()
    body_size = len(b"Routine update.")
    parsed = parse_eml(raw, Limits(max_decoded_bytes=body_size, max_text_chars=body_size))
    assert parsed.parts[0].decoded_bytes == body_size
    with pytest.raises(ResourceLimitError, match="max_decoded_bytes"):
        parse_eml(raw, Limits(max_decoded_bytes=body_size - 1))
    with pytest.raises(ResourceLimitError, match="max_text_chars"):
        parse_eml(raw, Limits(max_text_chars=body_size - 1))


def test_attachment_header_defect_is_rejected_even_when_body_is_excluded() -> None:
    raw = (
        b"Subject: Synthetic\r\nContent-Type: multipart/mixed; boundary=B\r\n\r\n"
        b"--B\r\nContent-Type: text/plain\r\n\r\nBody.\r\n"
        b'--B\r\nContent-Type: text/plain; charset="unterminated\r\n'
        b"Content-Disposition: attachment; filename=test.txt\r\n\r\nattachment\r\n"
        b"--B--\r\n"
    )
    with pytest.raises(IngestError):
        parse_eml(raw)


def test_report_visibly_escapes_terminal_and_bidi_controls() -> None:
    report = build_report(synthetic_message(), "synthetic.eml")
    report.message.subject = "Subject\x1b[31m\u202econtrol"
    page = render_html(report)
    assert "\x1b" not in page
    assert "\u202e" not in page
    assert "\\u001b[31m\\u202econtrol" in page
