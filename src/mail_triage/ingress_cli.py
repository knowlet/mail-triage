"""Explicit offline ingress-evidence command; credentials enter only on stdin."""

import argparse
import json
import sys
from pathlib import Path

from mail_triage.ingest import IngestError, read_eml
from mail_triage.ingress_contract import IngressTrustPolicy, MessageIdentity
from mail_triage.reporting import write_case
from mail_triage.schemas import Limits
from mail_triage.trusted_ingress import (
    ReplayLedger,
    build_ingress_report,
    load_keys,
    strict_object,
)


def add_ingress_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("input", type=Path)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--trust-policy", type=Path, required=True)
    parser.add_argument("--tenant-id", required=True)
    parser.add_argument("--mailbox-id", required=True)
    parser.add_argument(
        "--original-id", required=True, help="Independent original object ID, not a MIME header"
    )
    parser.add_argument(
        "--replay-dir", type=Path, required=True, help="Existing private 0700 directory"
    )
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--secrets-stdin", action="store_true", required=True)


def ingress_main(args: argparse.Namespace) -> int:
    try:
        if args.out.exists() or args.out.is_symlink():
            raise FileExistsError
        # Reject invalid parents before accepting evidence consumes its durable replay token.
        # This is a preflight only: later write failures must not roll back consumed tokens.
        if not args.out.absolute().parent.is_dir():
            raise NotADirectoryError
        raw = read_eml(args.input, Limits())
        policy = IngressTrustPolicy.model_validate(
            strict_object(read_eml(args.trust_policy, Limits(max_raw_bytes=65536)))
        )
        expected = MessageIdentity(
            tenant_id=args.tenant_id, mailbox_id=args.mailbox_id, message_id=args.original_id
        )
        keys = load_keys(sys.stdin.buffer.read(16385))
        evidence_unavailable = False
        try:
            evidence = read_eml(args.evidence, Limits(max_raw_bytes=65536))
        except (IngestError, OSError):
            evidence = b""
            evidence_unavailable = True
        report = build_ingress_report(
            raw,
            args.input.name,
            evidence,
            expected=expected,
            policy=policy,
            keys=keys,
            ledger=ReplayLedger(args.replay_dir),
        )
        assessment = report.authentication.trusted_ingress
        assert assessment is not None
        if evidence_unavailable:
            assessment = assessment.model_copy(update={"reason_code": "evidence_input_unavailable"})
            report.authentication.trusted_ingress = assessment
            report.warnings[-1] = "Trusted ingress evidence input is unavailable or oversized."
        write_case(args.out, raw, report)
    except FileExistsError:
        print(json.dumps({"error": "output_already_exists"}), file=sys.stderr)
        return 2
    except (ValueError, OSError, RecursionError):
        # Never format secret values, input-controlled paths or validation input.
        print(json.dumps({"error": "ingress_input_or_configuration_rejected"}), file=sys.stderr)
        return 2
    print(
        json.dumps(
            {
                "disposition": report.disposition,
                "sha256": report.provenance.sha256,
                "ingress_evidence_status": assessment.status,
                "reason_code": assessment.reason_code,
                "authentication": assessment.results.model_dump(),
                "output_directory": str(args.out),
                "network": "NOT_RUN",
            },
            indent=2,
        )
    )
    return 0 if assessment.status == "ACCEPTED" else 3
