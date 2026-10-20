"""Explicit sender intelligence command; ordinary triage never performs OSINT network I/O."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys

from mail_triage.cli import build_report
from mail_triage.connector_cli import _json
from mail_triage.ingest import IngestError, read_eml
from mail_triage.reporting import write_case
from mail_triage.schemas import Check, Limits
from mail_triage.sender_osint import OsintConfig, OsintCredentials, OsintEvidence, lookup_sender
from mail_triage.transport import ConnectorError


def apply_osint(report: object, evidence: OsintEvidence) -> None:
    from mail_triage.schemas import Report

    if not isinstance(report, Report) or report.provenance.sha256 != evidence.input_sha256:
        raise ValueError("OSINT provenance mismatch")
    report.schema_version = "1.2"
    report.sender_osint_evidence = evidence
    report.reputation.sender_osint = Check(
        status=evidence.status,
        reason="Untrusted MISP evidence only; no sender identity or message safety conclusion.",
        observations=[
            f"Execution: {evidence.execution_mode}; {len(evidence.lookups)} bounded lookups.",
            f"Conflicting current to_ids flags: {len(evidence.conflicting_to_ids)}.",
            *[
                f"{item.source_id}: {item.indicator.value}: {item.status} ({item.reason})"
                for item in evidence.lookups
            ],
        ],
    )
    if evidence.execution_mode != "NOT_RUN":
        report.warnings = [w for w in report.warnings if not w.startswith("No DNS, URL retrieval")]
        report.warnings.append(
            "Selected MISP lookups ran; no DNS, URL retrieval, mailbox or model calls."
        )
    report.warnings.extend(evidence.limitations)


def osint_main(args: argparse.Namespace) -> int:
    try:
        if not args.allow_egress or not args.secrets_stdin:
            raise ConnectorError("explicit_egress_and_stdin_required")
        config = OsintConfig.model_validate(
            _json(read_eml(args.config, Limits(max_raw_bytes=65536)))
        )
        raw = read_eml(args.input, Limits())
        report = build_report(raw, args.input.name)
        # Reject existing destinations before any query. write_case repeats no-clobber checks.
        if args.out.exists() or args.out.is_symlink() or not args.out.parent.is_dir():
            raise ConnectorError("output_unavailable")
        secrets = sys.stdin.read(16385)
        if len(secrets.encode()) > 16384:
            raise ConnectorError("credentials_rejected")
        credentials = OsintCredentials.model_validate(_json(secrets))
        evidence = asyncio.run(
            lookup_sender(
                config,
                credentials,
                input_sha256=report.provenance.sha256,
                allow_egress=args.allow_egress,
            )
        )
        apply_osint(report, evidence)
        write_case(args.out, raw, report)
    except ConnectorError as exc:
        print(json.dumps({"error": exc.code}), file=sys.stderr)
        return 2
    except (ValueError, IngestError, RecursionError):
        print(json.dumps({"error": "input_or_configuration_rejected"}), file=sys.stderr)
        return 2
    except OSError:
        print(json.dumps({"error": "case_io_failed"}), file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print(json.dumps({"error": "cancelled"}), file=sys.stderr)
        return 130
    print(
        json.dumps(
            {
                "sender_osint": evidence.status,
                "execution_mode": evidence.execution_mode,
                "disposition": report.disposition,
                "output_directory": str(args.out),
            }
        )
    )
    return 3 if any(item.status == "ERROR" for item in evidence.lookups) else 0
