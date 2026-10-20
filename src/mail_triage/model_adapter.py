"""Explicit self-hosted chat-completions inference through the bounded transport.

No provider SDK, environment credentials, public endpoint default, retrieval,
function tool, attachment content, or message-selected endpoint is used here.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Sequence
from typing import TYPE_CHECKING, Literal, Self

import httpx
from pydantic import BaseModel, ConfigDict, Field, SecretStr, model_validator

from mail_triage.model_workflow import REVIEW_INSTRUCTIONS, ModelReview, run_typed_review_async
from mail_triage.schemas import Finding
from mail_triage.transport import ConnectorError, EndpointPolicy, build_client

if TYPE_CHECKING:
    from pydantic_ai.models import Model


class ModelConfig(BaseModel):
    """Operator-owned configuration for one self-hosted inference origin."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    enabled: bool = False
    endpoint: EndpointPolicy | None = None
    model_name: str | None = Field(
        default=None, min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/-]*$"
    )

    @model_validator(mode="after")
    def required_when_enabled(self) -> Self:
        if self.enabled and (self.endpoint is None or self.model_name is None):
            raise ValueError("Enabled model review requires an explicit endpoint and model name.")
        return self


class _WireRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class _WireFunction(_WireRecord):
    name: str = Field(min_length=1, max_length=128)
    arguments: str = Field(min_length=2, max_length=4_096)


class _WireToolCall(_WireRecord):
    id: str = Field(min_length=1, max_length=128)
    type: Literal["function"]
    function: _WireFunction


class _WireMessage(_WireRecord):
    role: Literal["assistant"]
    content: None = None
    refusal: None = None
    tool_calls: list[_WireToolCall] = Field(min_length=1, max_length=1)


class _WireChoice(_WireRecord):
    index: Literal[0]
    finish_reason: Literal["tool_calls"]
    message: _WireMessage
    logprobs: None = None


class _WireResponse(BaseModel):
    # Protocol metadata is ignored; the sole message and output call are strict.
    model_config = ConfigDict(extra="ignore", strict=True)
    choices: list[_WireChoice] = Field(min_length=1, max_length=1)


def _bounded_inputs(
    subject: str, body_text: str, findings: Sequence[Finding]
) -> tuple[str, str, list[Finding], list[str]]:
    """Select deterministic, bounded excerpts without changing original evidence."""
    reduced = subject != subject[:998] or body_text != body_text[:8_000] or len(findings) > 32
    selected = []
    for item in findings[:32]:
        description = item.description[:160]
        evidence = [value[:160] for value in item.evidence[:1]]
        reduced = reduced or description != item.description or evidence != item.evidence
        selected.append(Finding(code=item.code, description=description, evidence=evidence))
    warnings = (
        ["Model input uses bounded text/evidence excerpts; original evidence is unchanged."]
        if reduced
        else []
    )
    return subject[:998], body_text[:8_000], selected, warnings


def _configured_model(
    client: httpx.AsyncClient,
    origin: str,
    model_name: str,
    credential: SecretStr,
    failures: list[str],
) -> Model:
    """Load the optional framework only after explicit configuration passes."""
    from pydantic_ai.messages import (
        ModelMessage,
        ModelRequest,
        ModelResponse,
        ToolCallPart,
        UserPromptPart,
    )
    from pydantic_ai.models import Model, ModelRequestParameters
    from pydantic_ai.settings import ModelSettings

    class ControlledChatModel(Model):
        def __init__(self) -> None:
            super().__init__(
                profile={
                    "supports_tools": True,
                    "supports_text_output": False,
                    "supported_native_tools": frozenset(),
                    # Suppress automatic model-context registry lookup.
                    "context_window": None,
                }
            )

        @property
        def model_name(self) -> str:
            return model_name

        @property
        def system(self) -> str:
            return "self_hosted_openai_compatible"

        async def request(
            self,
            messages: list[ModelMessage],
            model_settings: ModelSettings | None,
            model_request_parameters: ModelRequestParameters,
        ) -> ModelResponse:
            _, params = self.prepare_request(model_settings, model_request_parameters)
            if (
                params.function_tools
                or params.native_tools
                or len(params.output_tools) != 1
                or params.output_mode != "tool"
                or params.allow_text_output
                or len(messages) != 1
                or not isinstance(messages[0], ModelRequest)
                or len(messages[0].parts) != 1
                or not isinstance(messages[0].parts[0], UserPromptPart)
                or not isinstance(messages[0].parts[0].content, str)
            ):
                raise ValueError("Unsupported model request shape.")
            instructions = params.instruction_parts or []
            if (
                len(instructions) != 1
                or instructions[0].content.strip() != REVIEW_INSTRUCTIONS.strip()
            ):
                raise ValueError("Unsupported model instructions.")
            tool = params.output_tools[0]
            response: httpx.Response
            try:
                response = await client.post(
                    f"{origin}/v1/chat/completions",
                    headers={"Authorization": f"Bearer {credential.get_secret_value()}"},
                    json={
                        "model": model_name,
                        "messages": [
                            {"role": "system", "content": REVIEW_INSTRUCTIONS},
                            {"role": "user", "content": messages[0].parts[0].content},
                        ],
                        "tools": [
                            {
                                "type": "function",
                                "function": {
                                    "name": tool.name,
                                    "description": tool.description or "Bounded review output.",
                                    "parameters": tool.parameters_json_schema,
                                },
                            }
                        ],
                        "tool_choice": {"type": "function", "function": {"name": tool.name}},
                        "parallel_tool_calls": False,
                        "max_tokens": 512,
                        "stream": False,
                    },
                )
            except ConnectorError as exc:
                failures.append(exc.code)
                raise
            if response.status_code != 200:
                failures.append("http_error")
                raise ValueError("Model endpoint returned a non-success response.")
            try:
                parsed = _WireResponse.model_validate_json(response.content)
                call = parsed.choices[0].message.tool_calls[0]
                if call.function.name != tool.name:
                    raise ValueError("Unsupported output tool name.")
                # Validate JSON syntax here; schema and citation validation follow in the agent.
                if not isinstance(json.loads(call.function.arguments), dict):
                    raise ValueError("Output arguments must be an object.")
            except (ValueError, TypeError):
                failures.append("invalid_response")
                raise
            return ModelResponse(
                parts=[
                    ToolCallPart(call.function.name, call.function.arguments, tool_call_id=call.id)
                ],
                model_name=model_name,
                provider_name="self_hosted_openai_compatible",
                finish_reason="tool_call",
            )

    return ControlledChatModel()


async def configured_review(
    config: ModelConfig,
    *,
    subject: str,
    body_text: str,
    findings: Sequence[Finding],
    credential: SecretStr | None = None,
    inner: httpx.AsyncBaseTransport | None = None,
) -> ModelReview:
    """Run one explicitly enabled self-hosted review; HTTP mocks are labeled MOCK."""
    if not config.enabled:
        return ModelReview(status="NOT_RUN", reason="Configured model review is disabled.")
    if inner is not None and not isinstance(inner, httpx.MockTransport):
        return ModelReview(
            status="ERROR",
            reason="Only scripted MockTransport injection is supported; no request was made.",
        )
    if credential is None:
        return ModelReview(status="NOT_RUN", reason="Model credential was not explicitly supplied.")
    value = credential.get_secret_value()
    if not value or len(value) > 4_096 or any(ord(char) < 33 or ord(char) > 126 for char in value):
        return ModelReview(status="ERROR", reason="Model credential format is invalid.")
    if not findings:
        return ModelReview(
            status="NOT_RUN", reason="No deterministic findings are available for citation."
        )

    backend_kind: Literal["MOCK", "CONFIGURED"] = "MOCK" if inner is not None else "CONFIGURED"
    failures: list[str] = []
    warnings: list[str] = []
    try:
        # Revalidation protects callers that used model_construct or mutated nested input.
        checked = ModelConfig.model_validate(config.model_dump())
        assert checked.endpoint is not None and checked.model_name is not None
        bounded_subject, bounded_body, bounded_findings, warnings = _bounded_inputs(
            subject, body_text, findings
        )
        async with asyncio.timeout(checked.endpoint.total_timeout):
            async with build_client(
                checked.endpoint, routes={("POST", "/v1/chat/completions")}, inner=inner
            ) as client:
                model = _configured_model(
                    client, checked.endpoint.origin, checked.model_name, credential, failures
                )
                result = await run_typed_review_async(
                    subject=bounded_subject,
                    body_text=bounded_body,
                    findings=bounded_findings,
                    model=model,
                )
        if result.status == "ERROR" and failures:
            allowed = {
                "policy_violation",
                "request_too_large",
                "redirect_rejected",
                "compression_rejected",
                "response_too_large",
                "timeout",
                "tls_error",
                "network_error",
                "http_error",
                "invalid_response",
            }
            code = failures[-1] if failures[-1] in allowed else "network_error"
            result.reason = f"Configured model request failed ({code}); no hypothesis accepted."
        if result.opinion is not None:
            # Inspect decoded fields as well as serialization so JSON escapes cannot hide a key.
            opinion_strings = [
                result.opinion.summary,
                result.opinion.content_risk,
                *result.opinion.finding_ids,
            ]
            if value in result.opinion.model_dump_json() or any(
                value in item for item in opinion_strings
            ):
                return ModelReview(
                    status="ERROR",
                    reason="Configured output echoed a supplied credential; no opinion accepted.",
                    backend_kind=backend_kind,
                    input_warnings=warnings,
                )
        return result.model_copy(update={"backend_kind": backend_kind, "input_warnings": warnings})
    except Exception as exc:
        # Persist only exception classes, never response bodies, request URLs, or credentials.
        return ModelReview(
            status="ERROR",
            reason=f"Configured review failed ({type(exc).__name__}); no hypothesis accepted.",
            backend_kind=backend_kind,
            input_warnings=warnings,
        )
