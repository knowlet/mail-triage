"""Runnable HTTP contract demonstration using authored MIME and local mocks only."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

import httpx
from pydantic import SecretStr

from mail_triage.assemblyline_results import PollingPolicy
from mail_triage.connections import (
    ConnectorRun,
    ConnectorSettings,
    ExplicitCredentials,
    _save,
    ingest_graph_case,
)
from mail_triage.graph_ingest import GraphConfig
from mail_triage.ingest import read_eml
from mail_triage.model_adapter import ModelConfig
from mail_triage.schemas import Limits
from mail_triage.service_adapters import AssemblylineConfig, SublimeConfig, SublimeRule
from mail_triage.transport import ConnectorError, EndpointPolicy

FIXTURE_SHA256 = "4e31d9fb762cc859cf266a509e293fadbbd1e4a77feb41c1080f494e4fa10fca"
DEMO_MESSAGE_ID = "synthetic-report"
DEMO_ATTACHMENT_ID = "original-attachment"
DEMO_TOKEN = "synthetic-token-not-a-credential"


def demo_settings(*, poll_assemblyline: bool = False) -> ConnectorSettings:
    def endpoint(service: str, suffix: int) -> EndpointPolicy:
        # Documentation-only addresses, never contacted by this demonstration.
        return EndpointPolicy(
            origin=f"https://{service}.example.invalid",
            pinned_ip=f"192.0.2.{suffix}",
            allow_private_ip=True,
        )

    return ConnectorSettings(
        graph=GraphConfig(
            enabled=True,
            mailbox="reports@example.invalid",
            endpoint=endpoint("graph", 10),
        ),
        assemblyline=AssemblylineConfig(
            enabled=True,
            username="synthetic-reviewer",
            endpoint=endpoint("assemblyline", 20),
            polling=PollingPolicy(
                enabled=poll_assemblyline, interval_seconds=1, deadline_seconds=5, max_polls=3
            ),
        ),
        sublime=SublimeConfig(
            enabled=True,
            endpoint=endpoint("sublime", 30),
            selected_rules=[SublimeRule(name="synthetic-review", source="type.inbound")],
        ),
        model=ModelConfig(
            enabled=True, model_name="synthetic-model", endpoint=endpoint("model", 40)
        ),
    )


def demo_wrapper(original: bytes) -> bytes:
    """An authored user-report wrapper, separate from the original MIME identity."""
    return (
        b"From: Reporter <reporter@example.invalid>\r\n"
        b"To: Triage <reports@example.invalid>\r\n"
        b"Subject: Synthetic user report wrapper\r\n"
        b"MIME-Version: 1.0\r\n"
        b'Content-Type: multipart/mixed; boundary="REPORT-CONTRACT-BOUNDARY"\r\n\r\n'
        b"--REPORT-CONTRACT-BOUNDARY\r\nContent-Type: text/plain\r\n\r\n"
        b"This authored wrapper is for a local mock contract demonstration.\r\n"
        b"--REPORT-CONTRACT-BOUNDARY\r\nContent-Type: message/rfc822\r\n"
        b'Content-Disposition: attachment; filename="reported.eml"\r\n\r\n'
        + original
        + b"\r\n--REPORT-CONTRACT-BOUNDARY--\r\n"
    )


def demo_transport(original: bytes, calls: list[dict[str, object]]) -> httpx.MockTransport:
    """Mock upstream replies; only inert request metadata is recorded for review."""

    def handler(request: httpx.Request) -> httpx.Response:
        host = request.headers["host"]
        calls.append(
            {
                "execution_mode": "MOCK",
                "method": request.method,
                "logical_host": host,
                "path": request.url.raw_path.decode("ascii"),
                "request_bytes": len(request.content),
                "requested_at": datetime.now(UTC).isoformat(),
            }
        )
        if host == "graph.example.invalid" and request.method == "GET":
            if request.url.path.endswith("/attachments/" + DEMO_ATTACHMENT_ID + "/$value"):
                return httpx.Response(200, content=original)
            if request.url.path.endswith("/attachments/" + DEMO_ATTACHMENT_ID):
                return httpx.Response(
                    200,
                    json={
                        "@odata.type": "#microsoft.graph.itemAttachment",
                        "id": DEMO_ATTACHMENT_ID,
                        "contentType": "message/rfc822",
                        "size": len(original),
                        "isInline": False,
                    },
                )
            if request.url.path.endswith("/messages/" + DEMO_MESSAGE_ID + "/$value"):
                return httpx.Response(200, content=demo_wrapper(original))
        if host == "assemblyline.example.invalid" and request.url.path == "/api/v4/submit/":
            return httpx.Response(
                200,
                json={
                    "api_status_code": 200,
                    "api_error_message": "",
                    "api_response": {"sid": "synthetic-submission"},
                },
            )
        if host == "assemblyline.example.invalid" and request.method == "GET":
            completion_path = "/api/v4/submission/is_completed/synthetic-submission/"
            if request.url.path == completion_path:
                # One real one-second asynchronous interval separates the two mock checks.
                checks = sum(item["path"] == completion_path for item in calls)
                return httpx.Response(
                    200,
                    json={
                        "api_status_code": 200,
                        "api_error_message": "",
                        "api_response": checks > 1,
                    },
                )
            if request.url.path == "/api/v4/submission/full/synthetic-submission/":
                digest = hashlib.sha256(original).hexdigest()
                return httpx.Response(
                    200,
                    json={
                        "api_status_code": 200,
                        "api_error_message": "",
                        "api_response": {
                            "sid": "synthetic-submission",
                            "state": "completed",
                            "max_score": 350,
                            "file_count": 1,
                            "error_count": 0,
                            "files": [
                                {"name": "original.eml", "sha256": digest, "size": len(original)}
                            ],
                            "results": {
                                "synthetic-result": {
                                    "sha256": digest,
                                    "partial": False,
                                    "result": {"score": 350},
                                    "response": {
                                        "service_name": "SyntheticStatic",
                                        "service_version": "1.0",
                                    },
                                }
                            },
                            "errors": {},
                            "missing_result_keys": [],
                            "missing_error_keys": [],
                            "missing_file_keys": [],
                        },
                    },
                )
        if host == "sublime.example.invalid" and request.url.path == "/v0/messages/analyze":
            rules = json.loads(request.content)["rules"]
            return httpx.Response(
                200,
                json={
                    "rule_results": [
                        {
                            "rule": {"name": rule["name"], "source": rule["source"]},
                            "success": True,
                            "matched": False,
                        }
                        for rule in rules
                    ],
                    "query_results": [],
                },
            )
        if host == "model.example.invalid" and request.url.path == "/v1/chat/completions":
            payload = json.loads(request.content)
            inputs = json.loads(payload["messages"][1]["content"])
            opinion = {
                "content_risk": "HIGH",
                "summary": "MOCK hypothesis from authored fixture; no real inference ran.",
                "finding_ids": [inputs["findings"][0]["code"]],
            }
            return httpx.Response(
                200,
                json={
                    "choices": [
                        {
                            "index": 0,
                            "finish_reason": "tool_calls",
                            "message": {
                                "role": "assistant",
                                "content": None,
                                "tool_calls": [
                                    {
                                        "id": "synthetic-output-1",
                                        "type": "function",
                                        "function": {
                                            "name": payload["tools"][0]["function"]["name"],
                                            "arguments": json.dumps(opinion),
                                        },
                                    }
                                ],
                            },
                        }
                    ]
                },
            )
        raise AssertionError("Unexpected mock contract route")

    return httpx.MockTransport(handler)


async def run_demo(output: Path, *, poll_assemblyline: bool = False) -> ConnectorRun:
    fixture = Path(__file__).resolve().parents[2] / "fixtures" / "synthetic-phish.eml"
    original = read_eml(fixture, Limits())
    if hashlib.sha256(original).hexdigest() != FIXTURE_SHA256:
        raise ConnectorError("authored_fixture_mismatch")
    calls: list[dict[str, object]] = []
    dummy = SecretStr(DEMO_TOKEN)
    result = await ingest_graph_case(
        demo_settings(poll_assemblyline=poll_assemblyline),
        ExplicitCredentials(
            graph_token=dummy, assemblyline_key=dummy, sublime_key=dummy, model_key=dummy
        ),
        message_id=DEMO_MESSAGE_ID,
        attachment_id=DEMO_ATTACHMENT_ID,
        output=output,
        inner=demo_transport(original, calls),
    )
    _save(output / "mock-requests.json", (json.dumps(calls, indent=2) + "\n").encode())
    return result
