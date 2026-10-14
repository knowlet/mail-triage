"""Offline .eml ingestion; no credentials, connections, or email actions."""

import argparse
import hashlib
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

from mail_triage.evidence import (
    authentication_evidence,
    content_evidence,
    model_stages,
    reputation_evidence,
)
from mail_triage.ingest import IngestError, parse_eml, read_eml
from mail_triage.reporting import write_case
from mail_triage.schemas import Limits, Provenance, Report


def build_report(raw: bytes, source_name: str, limits: Limits | None = None) -> Report:
    selected_limits = limits or Limits()
    message = parse_eml(raw, selected_limits)
    return Report(
        provenance=Provenance(
            sha256=hashlib.sha256(raw).hexdigest(),
            raw_bytes=len(raw),
            source_name=source_name,
            ingested_at=datetime.now(UTC),
        ),
        limits=selected_limits,
        message=message,
        authentication=authentication_evidence(message),
        content=content_evidence(message),
        reputation=reputation_evidence(),
        model_stages=model_stages(),
        warnings=[
            "All local email headers, body content, filenames and model output are untrusted.",
            "Original bytes are preserved; authentication and identity have not been verified.",
            "No DNS, URL retrieval, external intelligence, mailbox access or model call ran.",
            "Attachments are inventoried and hashed; no extraction, execution or scanning ran.",
            "Synthetic examples demonstrate mechanics and do not measure detection accuracy.",
            *message.warnings,
        ],
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="command", required=True)
    triage = subcommands.add_parser("triage", help="Review one local regular .eml file offline")
    triage.add_argument("input", type=Path)
    triage.add_argument("--out", type=Path, required=True, help="New private case directory")
    args = parser.parse_args(argv)
    limits = Limits()
    try:
        raw = read_eml(args.input, limits)
        report = build_report(raw, args.input.name, limits)
        write_case(args.out, raw, report)
    except IngestError as exc:
        # Ingest errors contain controlled diagnostics; encode controls before display.
        print(json.dumps({"error": "input_rejected", "detail": str(exc)}), file=sys.stderr)
        return 2
    except FileExistsError:
        print(json.dumps({"error": "output_already_exists"}), file=sys.stderr)
        return 2
    except OSError as exc:
        # Do not echo attacker-controlled filenames or message content to the terminal.
        print(json.dumps({"error": "case_write_failed", "errno": exc.errno}), file=sys.stderr)
        return 2
    except ValueError:
        print(json.dumps({"error": "invalid_input"}), file=sys.stderr)
        return 2
    print(
        json.dumps(
            {
                "disposition": report.disposition,
                "sha256": report.provenance.sha256,
                "raw_bytes": report.provenance.raw_bytes,
                "content_finding_ids": [item.code for item in report.content.findings],
                "authentication": "UNKNOWN",
                "external_integrations": "NOT_RUN",
                "model_stages": "NOT_RUN",
                "gateway_spam_rate": "UNKNOWN",
                "output_directory": str(args.out),
            },
            indent=2,
            ensure_ascii=True,
        )
    )
    return 0
