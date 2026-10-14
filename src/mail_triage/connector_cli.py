"""Explicit connector commands. Called lazily; default triage remains offline."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys

from mail_triage.connections import ConnectorSettings, ExplicitCredentials, ingest_graph_case
from mail_triage.contract_demo import run_demo
from mail_triage.ingest import IngestError, read_eml
from mail_triage.schemas import Limits
from mail_triage.transport import ConnectorError


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key")
        result[key] = value
    return result


def _json(raw: bytes | str) -> object:
    return json.loads(raw, object_pairs_hook=_unique_object)


def connector_main(args: argparse.Namespace) -> int:
    try:
        if args.command == "connect-demo":
            result = asyncio.run(run_demo(args.out))
        else:
            # Both switches are required by argparse and checked here for direct callers.
            if not args.allow_egress or not args.secrets_stdin:
                raise ConnectorError("explicit_egress_and_stdin_required")
            try:
                raw_config = read_eml(args.config, Limits(max_raw_bytes=64 * 1024))
                settings = ConnectorSettings.model_validate(_json(raw_config))
            except (ValueError, IngestError, RecursionError):
                raise ConnectorError("configuration_rejected") from None
            # Read only explicit stdin, at most 16 KiB plus one character. No environment,
            # keychain, token refresh, secret file or account discovery is performed.
            raw_secrets = sys.stdin.read(16 * 1024 + 1)
            if len(raw_secrets.encode("utf-8")) > 16 * 1024:
                raise ConnectorError("credentials_rejected")
            try:
                credentials = ExplicitCredentials.model_validate(_json(raw_secrets))
            except (ValueError, RecursionError):
                raise ConnectorError("credentials_rejected") from None
            result = asyncio.run(
                ingest_graph_case(
                    settings,
                    credentials,
                    message_id=args.message_id,
                    attachment_id=args.attachment_id,
                    output=args.out,
                    allow_egress=True,
                )
            )
    except ConnectorError as exc:
        print(json.dumps({"error": exc.code}), file=sys.stderr)
        return 2
    except (IngestError, ValueError, RecursionError):
        print(json.dumps({"error": "input_rejected"}), file=sys.stderr)
        return 2
    except OSError as exc:
        print(json.dumps({"error": "case_io_failed", "errno": exc.errno}), file=sys.stderr)
        return 2
    except ImportError:
        print(json.dumps({"error": "optional_models_dependencies_missing"}), file=sys.stderr)
        return 2
    print(
        json.dumps(
            {
                "execution_mode": result.execution_mode,
                "status": result.status,
                "wrapper_sha256": result.graph.wrapper_sha256,
                "original_sha256": result.graph.original_sha256,
                "authentication": "UNKNOWN",
                "gateway_spam_rate": "UNKNOWN",
                "assemblyline": result.assemblyline.status,
                "sublime": result.sublime.status,
                "pydantic_ai": result.model.status,
                "model_backend": result.model.backend_kind,
                "dspy_per_email": "NOT_RUN",
                "output_directory": str(args.out),
            },
            indent=2,
        )
    )
    return 3 if result.status == "PARTIAL" else 0
