# Delivery evidence

Project directory: `mail-triage/`. Work is isolated to this project. No existing
model service, mailbox, tenant or unrelated checkout was modified. No deployment,
release, merge, persistent service or real connector access is included.

## Runnable flows

The existing `mail-triage triage <local.eml> --out <new-directory>` flow remains
offline: bounded regular-file/MIME ingestion, independent evidence, exact original
bytes, typed JSON and inert HTML. It needs no service listener. All cases require
human review; authentication stays `UNKNOWN` absent independent trusted evidence.

The additional `mail-triage connect-demo --out <new-directory>` exercises actual
adapter code through `httpx.MockTransport`. It uses six scripted exchanges:
Graph wrapper MIME GET, itemAttachment metadata GET, original MIME GET,
Assemblyline submission POST, Sublime analysis POST and model POST. Results are
explicitly `MOCK`, not live integration success. Credentials/messages are synthetic.

The configured path is:

```sh
.venv/bin/mail-triage graph-ingest --config operator-connectors.json \
  --message-id SELECTED_WRAPPER_ID --attachment-id SELECTED_ITEM_ATTACHMENT_ID \
  --out reports/new-configured-case --allow-egress --secrets-stdin
```

This path is executable but has not been tested against live services. Nonsecret
`ConnectorSettings` JSON selects explicit origins, exact pins, mailbox/model/rule
settings and bounds. Credentials arrive as JSON standard input, never environment,
keychain or secret-file discovery. The [all-disabled configuration example](configured-connectors.example.json)
contains no endpoint or secret. No token acquisition, consent, tenant setup,
mailbox listing or email action is implemented.

## Source responsibilities

| Module | Responsibility |
| --- | --- |
| `schemas.py` | Versioned independent evidence/provenance and limits |
| `ingest.py` | Bounded MIME construction/decoding and safe regular-file reads |
| `evidence.py` | Independent authentication/content/reputation states |
| `reporting.py` | Private case artifacts, exact-byte provenance and inert HTML |
| `transport.py` | Exact origin/route/IP/TLS policy, bounds and sanitized failures |
| `graph_ingest.py` | Three selected read-only GETs; exact separate wrapper/original MIME |
| `service_adapters.py` | Explicit AL/Sublime POSTs, selected response validation and durable intent claims |
| `model_adapter.py` | Explicit bounded self-hosted chat-completions protocol through controlled HTTP |
| `model_workflow.py` | Pydantic AI typed citation validation and separate DSPy held-out evaluation |
| `connections.py` | Explicit credential/config orchestration and per-stage case evidence |
| `cli.py`, `__main__.py` | Offline and opt-in connector commands |
| `connector_cli.py` | Bounded nonsecret config / explicit stdin credentials and connector exit states |
| `contract_demo.py` | Authored fixture, synthetic credentials and six mocked HTTP exchanges |

Assemblyline provides a validated submission receipt only, without polling or
analysis-result claims. Sublime response structure is validated but no score/match
is promoted to a verdict. Model output remains a separate untrusted hypothesis.
No sender OSINT, trusted gateway reputation or spam-rate telemetry exists.

## Verification scope

Run `make check` for Ruff lint/format, strict mypy and pytest. Test totals are
reported by the actual command output for the checked revision. The original
[offline verification transcript](../demo/verification.txt) records the initial
slice and is not a claim about the expanded suite's current count.
The expanded local run passed Ruff lint/format, strict mypy over 15 source files,
and **277 tests**. CI confirmation for the final head is a separate result and
is not claimed by this local run.
The actual captured output is [connectors-verification.txt](../demo/connectors-verification.txt).
Credential echo, incomplete Sublime rule results and non-mock transport injection
are rejected with regression coverage. The original 64-test offline suite remains
passing.

Tests deny real sockets/DNS. They exercise malformed/oversized MIME, parser-time
part/depth limits, cumulative header/decoded/text budgets, charsets/encodings,
spoofed authentication, safe HTML/attachment handling, nested identity isolation,
exact provenance, private permissions and output collision refusal.

Connector tests use mocked HTTP to cover exact three-GET Graph retrieval,
wrapper/original separation, quoted opaque IDs, selected metadata types/IDs,
byte limits, no implicit config/credentials, fixed origins/routes/pins, TLS/SNI
intent, mapped/private-address rules, redirects/compression/timeouts, service
reply validation, durable claim duplication and uncertain POST outcomes.
Mock transport does not establish real TLS handshakes, tenant permissions,
service-version compatibility or production retention behavior.

Pydantic AI `FunctionModel` and DSPy `DummyLM` tests use replies labeled `STUB`.
They validate schema, evidence-ID citations, rejected action/authentication fields,
held-out-only evaluation and withheld expected labels. Model-adapter mock tests
also validate strict protocol wiring and one-request behavior. No result is a
real-inference or phishing-accuracy measurement.

## Preserved offline demonstration

The authored [fixture](../fixtures/synthetic-phish.eml) is 1,966 bytes, SHA-256
`4e31d9fb762cc859cf266a509e293fadbbd1e4a77feb41c1080f494e4fa10fca`.
It contains fake authentication passes, prompt injection, active HTML source,
reserved `.invalid` URLs and a non-executable synthetic attachment named
`../../invoice.docm`. The immutable `demo/offline-case/` artifacts preserve this
first demonstration:

- Six deterministic content observations and `REVIEW_REQUIRED`.
- SPF, DKIM, DMARC, alignment and gateway spam rate: `UNKNOWN`.
- Models, OSINT, gateway reputation, Assemblyline, Sublime and Outlook: `NOT_RUN`.
- Exact original bytes; no attachment-named file is written.

Inspect [CLI output](../demo/cli-output.json), [JSON report](../demo/offline-case/report.json),
[HTML report](../demo/offline-case/report.html) and [original bytes](../demo/offline-case/original.eml).
The separate [visually reviewed rendition](../demo/reviewed-report.html) contains
unchanged evidence with improved MIME headings; the original case is preserved.
[Rejection smoke output](../demo/rejection-smoke.json) records actual malformed/
5 MiB + 1 byte CLI rejections with exit 2 and no case directory.

## Connector demonstration artifacts

The captured command is:

```sh
.venv/bin/mail-triage connect-demo --out demo/connectors-case
```

Use a fresh output directory when reproducing it; an existing case is refused.
[Connector CLI output](../demo/connectors-cli-output.json) and
[connector outcomes](../demo/connectors-case/connectors.json) identify mocked
execution. The case adds exact `wrapper.eml`, exact Graph-returned `original.eml`,
`graph-provenance.json` and `submissions/` records, alongside the JSON/HTML report.
Authentication and spam-rate evidence stay `UNKNOWN` after all mocked adapters.
Source kind `graph_original` refers to the selected original, never wrapper identity.

The new report's native Safari smoke check was attempted but blocked because the
Mac was locked and automatic unlock was unavailable. No browser security or
permission setting was changed. Automated HTML/provenance/permissions checks
passed; no new native visual-inspection success is claimed. Earlier native review
of the separate offline rendition does not verify this connector report.

No configured/live connection was performed. API receipts/hypotheses demonstrate
request/response mechanics only. The source endpoint and hashes preserve provenance
without asserting that Graph returned original SMTP wire bytes or authenticated
the sender. External API links and message URLs are never followed.

## Remaining limitations and next step

This is a CLI prototype without production API/RBAC, queue, case database,
encryption, retention system or tenant setup. HTTPX/certifi-trusted TLS and operator
maintenance of exact pins are required. No insecure TLS/custom CA switch or
server-side idempotency is supplied. Submission deduplication is per case; a new
case can submit again, and a failed POST may have an unknown server outcome.

Strict parsing rejects malformed/unknown charsets and undeclared non-ASCII text.
Local nested-container inventory hashes describe reserialization with an explicit
warning; the Graph original artifact separately uses exact returned MIME bytes.
Private stdlib MIME hooks are tested on Python 3.12, not an OS sandbox.

The next smallest authentication step remains a local versioned trusted-ingress
assertion contract bound to exact original SHA-256, authenticated issuer, receive
and policy version, event ID/expiry and replay protection. A user-writable trust
flag, allowlisted authserv-id or mailbox retrieval alone is insufficient.
Live connector acceptance additionally needs separately authorized synthetic
in-scope/out-of-scope permission tests and service-specific retention/egress review.

The project license remains undecided. No LICENSE has been added or inferred
from upstream dependencies or engine licenses. Work continues in the existing
feature/PR scope; no extra PR, merge, deployment or release is part of this change.
