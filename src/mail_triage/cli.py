"""Offline .eml triage and explicitly selected, opt-in connector commands."""

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
    from mail_triage.ingress_cli import add_ingress_arguments

    ingress = subcommands.add_parser(
        "trusted-ingress", help="Verify separately signed, identity-bound ingress evidence offline"
    )
    add_ingress_arguments(ingress)
    triage = subcommands.add_parser("triage", help="Review one local regular .eml file offline")
    triage.add_argument("input", type=Path)
    triage.add_argument("--out", type=Path, required=True, help="New private case directory")
    demo = subcommands.add_parser("connect-demo", help="Local mocks of all connector contracts")
    demo.add_argument("--out", type=Path, required=True, help="New private case directory")
    demo.add_argument(
        "--assemblyline-poll",
        action="store_true",
        help="Also demonstrate bounded mock result polling",
    )
    graph = subcommands.add_parser("graph-ingest", help="Opt-in read-only selected Graph report")
    graph.add_argument("--config", type=Path, required=True, help="Non-secret JSON configuration")
    graph.add_argument("--message-id", required=True, help="Explicit reporting wrapper ID")
    graph.add_argument("--attachment-id", required=True, help="Explicit original itemAttachment ID")
    graph.add_argument("--out", type=Path, required=True, help="New private case directory")
    graph.add_argument("--allow-egress", action="store_true", required=True)
    graph.add_argument("--secrets-stdin", action="store_true", required=True)
    readback = subcommands.add_parser(
        "assemblyline-readback",
        help="GET-only results for an existing saved Assemblyline submission",
    )
    readback.add_argument(
        "--config", type=Path, required=True, help="Non-secret JSON configuration"
    )
    readback.add_argument(
        "--case", type=Path, required=True, help="Existing private case directory"
    )
    readback.add_argument("--allow-egress", action="store_true", required=True)
    readback.add_argument("--secrets-stdin", action="store_true", required=True)
    osint = subcommands.add_parser(
        "sender-osint", help="Opt-in MISP evidence for selected indicators"
    )
    osint.add_argument("input", type=Path)
    osint.add_argument("--config", type=Path, required=True)
    osint.add_argument("--out", type=Path, required=True)
    osint.add_argument("--allow-egress", action="store_true", required=True)
    osint.add_argument("--secrets-stdin", action="store_true", required=True)
    args = parser.parse_args(argv)
    if args.command == "sender-osint":
        from mail_triage.osint_cli import osint_main

        return osint_main(args)
    if args.command == "trusted-ingress":
        from mail_triage.ingress_cli import ingress_main

        return ingress_main(args)
    if args.command != "triage":
        from mail_triage.connector_cli import connector_main

        return connector_main(args)
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
