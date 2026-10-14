"""Explicit connector orchestration. Normal local triage never imports this module."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Literal

import httpx
from pydantic import BaseModel, ConfigDict, Field, SecretStr

from mail_triage.cli import build_report
from mail_triage.graph_ingest import GraphAdapter, GraphAttachmentMetadata, GraphBundle, GraphConfig
from mail_triage.model_adapter import ModelConfig, configured_review
from mail_triage.model_workflow import ModelReview
from mail_triage.reporting import render_html, write_case
from mail_triage.schemas import Check
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


async def ingest_graph_case(
    settings: ConnectorSettings,
    credentials: ExplicitCredentials,
    *,
    message_id: str,
    attachment_id: str,
    output: Path,
    allow_egress: bool = False,
    inner: httpx.MockTransport | None = None,
) -> ConnectorRun:
    """Fetch one selected report, save both artifacts, and run explicit stages once.

    A mock transport is the only way to run this function without allow_egress.
    It is code-injected, never selected by email or configuration file content.
    """
    if inner is not None and not isinstance(inner, httpx.MockTransport):
        raise ConnectorError("mock_transport_required")
    if inner is None and not allow_egress:
        raise ConnectorError("egress_not_authorized")
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
    claims = SubmissionClaims(output / "submissions")
    assemblyline = await AssemblylineAdapter(settings.assemblyline, inner=inner).analyze(
        bundle.original, credential=credentials.assemblyline_key or SecretStr(""), claims=claims
    )
    sublime = await SublimeAdapter(settings.sublime, inner=inner).analyze(
        bundle.original, credential=credentials.sublime_key or SecretStr(""), claims=claims
    )
    model = await configured_review(
        settings.model,
        subject=report.message.subject,
        body_text="\n".join(segment.text for segment in report.message.text_segments),
        findings=report.content.findings,
        credential=credentials.model_key,
        inner=inner,
    )
    report.reputation.assemblyline = Check(status=assemblyline.status, reason=assemblyline.reason)
    report.reputation.sublime = Check(status=sublime.status, reason=sublime.reason)
    report.model_stages["pydantic_ai"] = Check(
        status=model.status,
        reason=model.reason,
        observations=[f"Backend: {model.backend_kind}", *model.input_warnings]
        + ([model.opinion.model_dump_json()] if model.opinion else []),
    )
    run = ConnectorRun(
        execution_mode=mode,
        status="PARTIAL"
        if "ERROR" in (assemblyline.status, sublime.status, model.status)
        else "COMPLETED",
        graph=source,
        assemblyline=assemblyline,
        sublime=sublime,
        model=model,
    )
    _save(output / "connectors.json", (run.model_dump_json(indent=2) + "\n").encode())
    _save(output / "report.json", (report.model_dump_json(indent=2) + "\n").encode(), replace=True)
    _save(output / "report.html", render_html(report).encode(), replace=True)
    return run
