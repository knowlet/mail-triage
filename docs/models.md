# Optional model workflow

Normal `triage` performs deterministic offline checks and leaves model stages
`NOT_RUN`. Pydantic AI review can now run through an explicitly configured
self-hosted chat-completions adapter in `graph-ingest`; `connect-demo` exercises
that adapter with mocked HTTP. No real inference endpoint was connected or tested.
DSPy remains a separate offline evaluation path, not a live email stage.

## Typed content hypothesis

`run_typed_review()` / `run_typed_review_async()` create a Pydantic AI `Agent`
with a bounded output type and no executable function/native tools. An accepted
`ModelOpinion` is an untrusted content hypothesis citing existing unique
`Finding.code` values. Invented/duplicate citations, extra authentication/action
fields, unsupported labels and oversized input/output fail closed with `ERROR`.
No deterministic findings means `NOT_RUN`. Citation membership does not verify
that the model's interpretation is correct.

Model output cannot change authentication, deterministic content findings,
reputation or `REVIEW_REQUIRED`. Email text cannot select a provider, credential,
endpoint or action. No attachment content, message URL fetch, retrieval, MCP,
model-selected tool or optimization is available.

## Configured self-hosted adapter

[`model_adapter.py`](../src/mail_triage/model_adapter.py) requires enabled
`ModelConfig`, an explicit endpoint/IP policy, explicit `model_name` and a
caller-supplied `SecretStr` credential. It has no public endpoint, model registry,
provider SDK, environment credential or automatic provider selection. The CLI
receives `model_key` only in explicit JSON standard input; see
[connector configuration](integrations.md#configuration-and-credentials).

One request goes to the exact configured `POST /v1/chat/completions` route through
[`ControlledTransport`](../src/mail_triage/transport.py). TLS verification,
origin/path/method and IP pinning, credential destination, byte caps and
connection/read/total deadlines are enforced outside the prompt. There are no
redirects, retries, ambient proxies or follow-up requests. No existing model
service is started, modified or discovered.

The supported protocol is intentionally narrow: one nonstreaming completion,
one assistant output-schema function call, the expected function name, JSON
object arguments, and no parallel calls, text fallback or refusal content. The
function-call encoding carries structured output; it grants no executable
function capability. The endpoint must support that response shape. A structurally
valid reply still passes the typed output and finding-citation checks.

Final configured-model input is at most 998 subject characters, 8,000 body
characters and 32 findings, each with a 160-character description and one
160-character excerpt. This reduction leaves original report evidence unchanged
and produces a warning when inputs are reduced. Output arguments are bounded
at 4,096 characters. At most 512 output tokens are requested with no output
retries; a server token cap remains a protocol request, while transport byte/time
caps are enforced locally. The total configured-review deadline is the explicit
endpoint policy (15 seconds by default).

Missing credentials/findings leave review `NOT_RUN`; invalid credentials,
transport/protocol errors or rejected output leave `ERROR`. Sanitized failure
classes/codes are persisted without credentials or raw server replies. The
adapter rejects an otherwise accepted opinion if its decoded fields or serialized
JSON contain the exact supplied model credential. This is an echo guard, not a
general detector for transformed/encoded secret disclosures.

The report records `backend_kind: MOCK` for injected HTTP mocks and `CONFIGURED` for
the configured path; these labels do not claim that a live deployment has been
validated. Review endpoint-side retention, logging, model safety and downstream
egress before sending real message excerpts.

## DSPy held-out evaluation

`evaluate_held_out()` uses a DSPy `Signature` and `Predict` on bounded authored
`LabeledExample` fixtures marked `held_out`. Expected labels and example IDs are
withheld from prediction input. It accepts no training split, optimizer, saved
program, pickle or ambient LM. It never learns from a live message. Fixture label
agreement is not a phishing-performance estimate.

Before explicitly importing DSPy for an injected backend, keep its cache local
with project-owned `DSPY_CACHEDIR`, and use
`LITELLM_LOCAL_MODEL_COST_MAP=True` for the bundled cost map. Tests set both
before import. Normal `triage` and the configured model adapter do not import DSPy.

## Verification labels

`tests/test_model_workflow.py` uses scripted Pydantic AI `FunctionModel` and DSPy
`DummyLM` replies labeled `STUB`. `tests/test_model_adapter.py` and the connector
demo use `httpx.MockTransport`, labeled `MOCK`; they validate actual request and
response adapter wiring without real inference. Tests deny real socket/DNS
connections. Scripted agreement or accepted hypotheses are mechanics evidence,
not live-service success, model quality or detection accuracy.

```sh
.venv/bin/pytest tests/test_model_workflow.py tests/test_model_adapter.py
```

## Official dependency/API references

Pinned dependencies were checked on 2026-10-14:
[Pydantic AI Slim 2.56.0](https://pypi.org/project/pydantic-ai-slim/2.56.0/) and
[DSPy 3.4.1](https://pypi.org/project/dspy/3.4.1/). Slim supplies the framework
without every provider integration. Framework references are
[typed output](https://pydantic.dev/docs/ai/core-concepts/output/),
[FunctionModel testing](https://pydantic.dev/docs/ai/guides/testing/),
[DSPy structured programs](https://dspy.ai/current/getting-started/program-dont-prompt/)
and [DummyLM](https://github.com/stanfordnlp/dspy/blob/3.4.1/dspy/utils/dummies.py).
