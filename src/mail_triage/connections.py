"""Explicit connector orchestration. Normal local triage never imports this module."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Literal
from uuid import uuid4

import httpx
from pydantic import BaseModel, ConfigDict, Field, SecretStr

from mail_triage.assemblyline_results import PollingReport, poll_submission
from mail_triage.cli import build_report
from mail_triage.graph_ingest import GraphAdapter, GraphAttachmentMetadata, GraphBundle, GraphConfig
from mail_triage.ingest import read_eml
from mail_triage.model_adapter import ModelConfig, configured_review
from mail_triage.model_workflow import ModelReview
from mail_triage.reporting import render_html, write_case
from mail_triage.schemas import Check, Limits, Report
from mail_triage.service_adapters import (
    AssemblylineAdapter,
    AssemblylineConfig,
    ConnectorResult,
    SublimeAdapter,
    SublimeConfig,
    SubmissionClaims,
)
from mail_triage.transport import ConnectorError


class ConnectorSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")
    graph: GraphConfig = Field(default_factory=GraphConfig)
    assemblyline: AssemblylineConfig = Field(default_factory=AssemblylineConfig)
    sublime: SublimeConfig = Field(default_factory=SublimeConfig)
    model: ModelConfig = Field(default_factory=ModelConfig)


class ExplicitCredentials(BaseModel):
    """Only explicitly supplied process input; never environment/keychain discovery."""

    model_config = ConfigDict(extra="forbid")
    graph_token: SecretStr | None = None
    assemblyline_key: SecretStr | None = None
    sublime_key: SecretStr | None = None
    model_key: SecretStr | None = None


class GraphSource(BaseModel):
    model_config = ConfigDict(extra="forbid")
    execution_mode: Literal["MOCK", "CONFIGURED"]
    wrapper_sha256: str
    original_sha256: str
    mailbox: str
    wrapper_message_id: str
    original_attachment_id: str
    source_endpoint: str
    attachment_metadata: GraphAttachmentMetadata
    wrapper_artifact: str = "wrapper.eml"
    original_artifact: str = "original.eml"
    original_byte_source: str = "Graph itemAttachment /$value response, not MIME reserialization"


class ConnectorRun(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal["1.0"] = "1.0"
    execution_mode: Literal["MOCK", "CONFIGURED"]
    status: Literal["COMPLETED", "PARTIAL"]
    graph: GraphSource
    assemblyline: ConnectorResult
    sublime: ConnectorResult
    model: ModelReview
    assemblyline_analysis: PollingReport | None = None


class SavedAssemblylineSubmission(BaseModel):
    """Local receipt binding for GET-only recovery, not a trust attestation."""

    model_config = ConfigDict(extra="forbid")
    schema_version: Literal["1.0"] = "1.0"
    execution_mode: Literal["MOCK", "CONFIGURED"]
    endpoint_policy_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    receipt: ConnectorResult


def _save(path: Path, contents: bytes, *, replace: bool = False) -> None:
    """Fixed filenames within this run's new private case directory only."""
    if not replace:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(contents)
            stream.flush()
            os.fsync(stream.fileno())
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        return
    descriptor, name = tempfile.mkstemp(prefix=".update-", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(contents)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


def _source(bundle: GraphBundle, mock: bool) -> GraphSource:
    return GraphSource(
        execution_mode="MOCK" if mock else "CONFIGURED",
        wrapper_sha256=bundle.wrapper_sha256,
        original_sha256=bundle.original_sha256,
        mailbox=bundle.mailbox,
        wrapper_message_id=bundle.wrapper_message_id,
        original_attachment_id=bundle.original_attachment_id,
        source_endpoint=bundle.source_endpoint,
        attachment_metadata=bundle.metadata,
    )


def _endpoint_identity(config: AssemblylineConfig) -> str:
    if config.endpoint is None:
        raise ConnectorError("assemblyline_not_configured")
    return hashlib.sha256(
        json.dumps(
            {"origin": config.endpoint.origin, "pinned_ip": config.endpoint.pinned_ip},
            sort_keys=True,
        ).encode()
    ).hexdigest()


def _analysis_check(receipt: ConnectorResult, analysis: PollingReport | None) -> Check:
    if analysis is None or analysis.status == "NOT_RUN":
        return Check(status=receipt.status, reason=receipt.reason)
    observations = [
        f"Execution: {analysis.execution_mode}; readback: {analysis.status}",
        f"Completion checks: {analysis.polls}; bounded GET exchanges: {len(analysis.requests)}",
        "External analysis is untrusted and does not authenticate the sender.",
    ]
    if analysis.analysis is not None:
        observations.extend(
            [
                f"Raw external max_score: {analysis.analysis.raw_max_score}",
                "This score is neither a phishing probability nor a locally calibrated verdict.",
                f"Service errors: {analysis.analysis.error_count}; "
                f"partial results: {analysis.analysis.partial_result_count}",
            ]
        )
    return Check(
        status="OBSERVED" if analysis.status == "COMPLETED" else "ERROR",
        reason=f"Assemblyline readback: {analysis.reason}; receipt remains separate.",
        observations=observations,
    )


def _run_status(
    assemblyline: ConnectorResult,
    sublime: ConnectorResult,
    model: ModelReview,
    analysis: PollingReport | None,
) -> Literal["COMPLETED", "PARTIAL"]:
    if "ERROR" in (assemblyline.status, sublime.status, model.status):
        return "PARTIAL"
    if (
        sublime.reason == "cancelled_before_dispatch"
        or model.reason == "Skipped after cancellation."
    ):
        return "PARTIAL"
    if analysis is not None and analysis.status not in {"COMPLETED", "NOT_RUN"}:
        return "PARTIAL"
    return "COMPLETED"


def _persist_analysis(case: Path, analysis: PollingReport) -> None:
    contents = (analysis.model_dump_json(indent=2) + "\n").encode()
    # Each explicit readback retains its provenance; latest is a convenient atomic snapshot.
    _save(case / f"assemblyline-readback-{uuid4().hex}.json", contents)
    _save(case / "assemblyline-analysis.json", contents, replace=True)


async def resume_assemblyline_case(
    settings: ConnectorSettings,
    credentials: ExplicitCredentials,
    *,
    case: Path,
    allow_egress: bool = False,
    inner: httpx.MockTransport | None = None,
    cancel: asyncio.Event | None = None,
) -> PollingReport:
    """Read only a saved submission; this path cannot submit or resubmit anything."""
    if inner is not None and not isinstance(inner, httpx.MockTransport):
        raise ConnectorError("mock_transport_required")
    if inner is None and not allow_egress:
        raise ConnectorError("egress_not_authorized")
    config = settings.assemblyline
    if not config.enabled or not config.polling.enabled or config.endpoint is None:
        raise ConnectorError("assemblyline_polling_not_enabled")
    if credentials.assemblyline_key is None:
        raise ConnectorError("explicit_credentials_required")
    if case.is_symlink() or not case.is_dir():
        raise ConnectorError("case_rejected")
    try:
        saved = SavedAssemblylineSubmission.model_validate_json(
            read_eml(case / "assemblyline-submission.json", Limits(max_raw_bytes=64 * 1024))
        )
        original = read_eml(case / "original.eml", settings.graph.limits)
        report = Report.model_validate_json(
            read_eml(case / "report.json", Limits(max_raw_bytes=8 * 1024 * 1024))
        )
        run = (
            ConnectorRun.model_validate_json(
                read_eml(case / "connectors.json", Limits(max_raw_bytes=1024 * 1024))
            )
            if (case / "connectors.json").exists()
            else None
        )
    except (ValueError, RecursionError):
        raise ConnectorError("saved_case_rejected") from None
    receipt = saved.receipt
    expected_mode = "MOCK" if inner is not None else "CONFIGURED"
    if (
        saved.execution_mode != expected_mode
        or receipt.execution_mode != ("MOCK" if inner is not None else "LIVE")
        or saved.endpoint_policy_sha256 != _endpoint_identity(config)
        or receipt.service != "assemblyline"
        or receipt.status != "OBSERVED"
        or receipt.external_id is None
        or receipt.source_origin != config.endpoint.origin
        or receipt.input_sha256 != hashlib.sha256(original).hexdigest()
        or report.provenance.sha256 != receipt.input_sha256
        or (run is not None and run.assemblyline != receipt)
    ):
        raise ConnectorError("saved_case_identity_mismatch")
    analysis = await poll_submission(
        config.endpoint,
        config.username or "",
        receipt.external_id,
        receipt.input_sha256,
        credentials.assemblyline_key,
        config.polling,
        inner=inner,
        cancel=cancel,
    )
    _persist_analysis(case, analysis)
    report.reputation.assemblyline = _analysis_check(receipt, analysis)
    if run is not None:
        run.assemblyline_analysis = analysis
        run.status = _run_status(receipt, run.sublime, run.model, analysis)
        _save(
            case / "connectors.json", (run.model_dump_json(indent=2) + "\n").encode(), replace=True
        )
    _save(case / "report.json", (report.model_dump_json(indent=2) + "\n").encode(), replace=True)
    _save(case / "report.html", render_html(report).encode(), replace=True)
    return analysis


async def ingest_graph_case(
    settings: ConnectorSettings,
    credentials: ExplicitCredentials,
    *,
    message_id: str,
    attachment_id: str,
    output: Path,
    allow_egress: bool = False,
    inner: httpx.MockTransport | None = None,
    cancel: asyncio.Event | None = None,
) -> ConnectorRun:
    """Fetch one selected report, save both artifacts, and run explicit stages once.

    A mock transport is the only way to run this function without allow_egress.
    It is code-injected, never selected by email or configuration file content.
    """
    if inner is not None and not isinstance(inner, httpx.MockTransport):
        raise ConnectorError("mock_transport_required")
    if inner is None and not allow_egress:
        raise ConnectorError("egress_not_authorized")
    if cancel is not None and cancel.is_set():
        raise ConnectorError("cancelled")
    if output.exists() or output.is_symlink():
        raise ConnectorError("output_already_exists")
    if not output.parent.is_dir():
        raise ConnectorError("output_parent_missing")
    for enabled, secret in (
        (settings.graph.enabled, credentials.graph_token),
        (settings.assemblyline.enabled, credentials.assemblyline_key),
        (settings.sublime.enabled, credentials.sublime_key),
        (settings.model.enabled, credentials.model_key),
    ):
        if enabled and (secret is None or not secret.get_secret_value().strip()):
            raise ConnectorError("explicit_credentials_required")
    if not settings.graph.enabled:
        raise ConnectorError("graph_not_enabled")
    if credentials.graph_token is None:
        raise ConnectorError("explicit_credentials_required")

    bundle = await GraphAdapter(settings.graph, inner=inner).fetch(
        message_id, attachment_id, token=credentials.graph_token
    )
    mock = inner is not None
    mode: Literal["MOCK", "CONFIGURED"] = "MOCK" if mock else "CONFIGURED"
    source = _source(bundle, mock)
    report = build_report(bundle.original, "original.eml", settings.graph.limits)
    report.provenance.source_kind = "graph_original"
    report.reputation.outlook_ingestion = Check(
        status="OBSERVED",
        reason=f"{mode}: selected Graph wrapper and itemAttachment MIME fetched separately.",
        observations=[
            f"Wrapper SHA-256: {source.wrapper_sha256}",
            f"Original SHA-256: {source.original_sha256}",
            "Graph retrieval does not authenticate the original sender or its headers.",
        ],
    )
    report.warnings = [
        "All message data and external/model output remain untrusted; review is required.",
        "MOCK contract execution: no live tenant, service, model or real credentials used."
        if mock
        else "Explicit configured connectors ran; inspect each outcome in connectors.json.",
        "Authentication and gateway spam rate remain UNKNOWN without independent evidence.",
        "This application never executes/unpacks attachments or follows message URLs.",
        "Model input is limited to subject 998, text 8000, and 32 findings with 160-character "
        "descriptions and one 160-character evidence excerpt each.",
        *report.message.warnings,
    ]
    # Preserve bytes before any POST. A later timeout leaves the case and intent records intact.
    write_case(output, bundle.original, report)
    _save(output / "wrapper.eml", bundle.wrapper)
    _save(output / "graph-provenance.json", (source.model_dump_json(indent=2) + "\n").encode())
    if cancel is not None and cancel.is_set():
        raise ConnectorError("cancelled")
    claims = SubmissionClaims(output / "submissions")
    assemblyline = await AssemblylineAdapter(settings.assemblyline, inner=inner).analyze(
        bundle.original, credential=credentials.assemblyline_key or SecretStr(""), claims=claims
    )
    analysis: PollingReport | None = None
    if assemblyline.status == "OBSERVED" and assemblyline.external_id is not None:
        saved = SavedAssemblylineSubmission(
            execution_mode=mode,
            endpoint_policy_sha256=_endpoint_identity(settings.assemblyline),
            receipt=assemblyline,
        )
        # A durable SID must exist before any polling await or cancellation can occur.
        _save(
            output / "assemblyline-submission.json",
            (saved.model_dump_json(indent=2) + "\n").encode(),
        )
        report.reputation.assemblyline = _analysis_check(assemblyline, None)
        _save(
            output / "report.json", (report.model_dump_json(indent=2) + "\n").encode(), replace=True
        )
        _save(output / "report.html", render_html(report).encode(), replace=True)
        analysis = (
            await resume_assemblyline_case(
                settings,
                credentials,
                case=output,
                allow_egress=allow_egress,
                inner=inner,
                cancel=cancel,
            )
            if settings.assemblyline.polling.enabled
            else None
        )
    if (analysis is not None and analysis.status == "CANCELLED") or (
        cancel is not None and cancel.is_set()
    ):
        sublime = ConnectorResult(
            status="NOT_RUN", service="sublime", reason="cancelled_before_dispatch"
        )
        model = ModelReview(status="NOT_RUN", reason="Skipped after cancellation.")
    else:
        sublime = await SublimeAdapter(settings.sublime, inner=inner).analyze(
            bundle.original, credential=credentials.sublime_key or SecretStr(""), claims=claims
        )
        if cancel is not None and cancel.is_set():
            model = ModelReview(status="NOT_RUN", reason="Skipped after cancellation.")
        else:
            model = await configured_review(
                settings.model,
                subject=report.message.subject,
                body_text="\n".join(segment.text for segment in report.message.text_segments),
                findings=report.content.findings,
                credential=credentials.model_key,
                inner=inner,
            )
    report.reputation.assemblyline = _analysis_check(assemblyline, analysis)
    report.reputation.sublime = Check(status=sublime.status, reason=sublime.reason)
    report.model_stages["pydantic_ai"] = Check(
        status=model.status,
        reason=model.reason,
        observations=[f"Backend: {model.backend_kind}", *model.input_warnings]
        + ([model.opinion.model_dump_json()] if model.opinion else []),
    )
    run = ConnectorRun(
        execution_mode=mode,
        status=_run_status(assemblyline, sublime, model, analysis),
        graph=source,
        assemblyline=assemblyline,
        sublime=sublime,
        model=model,
        assemblyline_analysis=analysis,
    )
    _save(output / "connectors.json", (run.model_dump_json(indent=2) + "\n").encode())
    _save(output / "report.json", (report.model_dump_json(indent=2) + "\n").encode(), replace=True)
    _save(output / "report.html", render_html(report).encode(), replace=True)
    return run
