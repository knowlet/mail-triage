# Optional model workflow

The normal `.eml` pipeline performs deterministic offline checks. Pydantic AI
review and DSPy evaluation remain `NOT_RUN` unless application code explicitly
supplies a backend object. The CLI accepts no provider, credentials, endpoint or
model selection. No real inference service was connected or tested for this
version.

`run_typed_review()` creates a Pydantic AI `Agent` with a bounded output type and
no function tools or native tools. It accepts a subject, bounded text and existing
deterministic `Finding` records. An accepted `ModelOpinion` is an untrusted content
hypothesis that cites existing unique `Finding.code` values. Invented or duplicate
citations, extra action/authentication fields, unsupported labels and oversized
input/output fail closed with `ERROR`. Missing evidence yields `NOT_RUN`. A
syntactically valid citation does not establish that the model's interpretation
is correct. This is a citation integrity check, not semantic verification.

The review makes at most one model request, uses no output retries and requests
at most 512 output tokens with a 15-second provider timeout. These provider limits
are advisory to the injected backend; this module is not a process sandbox or a
network firewall. A future real backend needs a separately enforced inference
egress policy, deadlines, secret handling, data minimization and retention policy.
Message data must never choose a provider or endpoint. Model output cannot mutate
deterministic authentication, reputation, findings or message disposition.

`evaluate_held_out()` uses a DSPy `Signature` and `Predict` only on bounded,
authored `LabeledExample` fixtures marked `held_out`. Expected labels and example
IDs are withheld from the predictor. It reports fixture label agreement and
accepts no training split, optimizer, saved program, pickle or ambient LM. It is
separate from message triage and never learns from a live message. The evaluation
corpus here is too small to measure real phishing performance.

Before importing DSPy for an explicitly injected backend, keep its cache local
by setting `DSPY_CACHEDIR` to a project-owned directory, and set
`LITELLM_LOCAL_MODEL_COST_MAP=True` to use the bundled model-cost map. The tests
set both before import. The normal CLI never imports DSPy or uses its caches.

## Scripted tests

`tests/test_model_workflow.py` injects Pydantic AI `FunctionModel` and DSPy
`DummyLM` scripted replies. Results are labeled `backend_kind: STUB`. Tests deny
socket connections and disable Pydantic AI's real model requests. They exercise
typed output, citation checks, rejected action/tool attempts, input limits and
held-out evaluation wiring. A scripted 100% label agreement is not LLM or phishing
accuracy. No tests contact an LLM, Outlook, Assemblyline or Sublime.

Run with the optional model dependencies and development dependencies installed:

```sh
.venv/bin/pytest tests/test_model_workflow.py
```

## Official dependency/API references

Checked on 2026-10-14. Exact dependency pins are
[`pydantic-ai-slim==2.56.0`](https://pypi.org/project/pydantic-ai-slim/2.56.0/)
and [`dspy==3.4.1`](https://pypi.org/project/dspy/3.4.1/). The slim package provides
the Pydantic AI API without bundling every provider integration. The code uses
[`Agent` typed output](https://pydantic.dev/docs/ai/core-concepts/output/),
[`FunctionModel` testing](https://pydantic.dev/docs/ai/guides/testing/),
[`DSPy` structured programs](https://dspy.ai/current/getting-started/program-dont-prompt/)
and the official
[`DummyLM` test utility](https://github.com/stanfordnlp/dspy/blob/3.4.1/dspy/utils/dummies.py).
