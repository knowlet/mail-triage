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

Adding `--assemblyline-poll` runs a separate nine-exchange mock flow: the same six
base exchanges plus two completion GETs separated by a real one-second interval,
then a full-result GET. The saved submission receipt precedes polling. The bounded
result projection and request provenance remain separate from deterministic
content and authentication evidence; `COMPLETED` is not a safety verdict.

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

With Assemblyline and its polling policy enabled, configured ingestion continues
from one submission to bounded completion polling and result retrieval. A separate
GET-only command can resume readback from the saved case without another POST:

```sh
.venv/bin/mail-triage assemblyline-readback --config operator-connectors.json \
  --case reports/existing-configured-case --allow-egress --secrets-stdin
```

Only `assemblyline_key` is needed in its stdin JSON. Receipt/original hash,
endpoint/pin and execution mode are checked before requests. Ctrl-C during
configured polling records cancellation and exits 130; ordinary task cancellation
propagates while preserving the receipt. Completion exits 0, recorded partial/
failure/timeout outcomes exit 3, and rejected configuration/input exits 2.

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
| `assemblyline_results.py` | Bounded GET-only polling, result identity checks and untrusted projection/provenance |
| `model_adapter.py` | Explicit bounded self-hosted chat-completions protocol through controlled HTTP |
| `model_workflow.py` | Pydantic AI typed citation validation and separate DSPy held-out evaluation |
| `connections.py` | Explicit credential/config orchestration and per-stage case evidence |
| `cli.py`, `__main__.py` | Offline and opt-in connector commands |
| `connector_cli.py` | Bounded nonsecret config / explicit stdin credentials and connector exit states |
| `contract_demo.py` | Authored fixture, synthetic credentials and six or nine mocked HTTP exchanges |

Assemblyline keeps its validated submission receipt separate from optional
analysis readback. The projected raw score/counters do not establish phishing
probability, sender trust or safety. Sublime response structure is validated but no score/match
is promoted to a verdict. Model output remains a separate untrusted hypothesis.
No sender OSINT, trusted gateway reputation or spam-rate telemetry exists.

## Verification scope

Run `make check` for Ruff lint/format, strict mypy and pytest. Test totals are
reported by the actual command output for the checked revision. The original
[offline verification transcript](../demo/verification.txt) records the initial
slice and is not a claim about the expanded suite's current count.
The earlier connector-phase output is preserved in
[connectors-verification.txt](../demo/connectors-verification.txt); it does not
describe the later Assemblyline readback suite. Current lint/format/type/test
totals must come from the actual command output for the checked revision.
The current local run passed Ruff lint/format checks over 34 files, strict mypy
over 16 source files, and **347 tests**. Its captured output is
[assemblyline-verification.txt](../demo/assemblyline-verification.txt).
CI confirmation for the final head remains a separate, pending result.
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
Readback coverage includes strict completion booleans, pending-only repeat GETs,
SID/original-hash binding, partial/error/missing-key projections, deadlines/poll
limits, cancellation and saved-case recovery without resubmission.
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

## Assemblyline readback demonstration

The additional authored mock command is:

```sh
.venv/bin/mail-triage connect-demo --assemblyline-poll --out demo/assemblyline-case
```

Its [CLI output](../demo/assemblyline-cli-output.json),
[analysis/provenance](../demo/assemblyline-case/assemblyline-analysis.json),
[saved receipt](../demo/assemblyline-case/assemblyline-submission.json) and
[request metadata](../demo/assemblyline-case/mock-requests.json) are separate from
the preserved offline and earlier connector demonstrations. All nine exchanges
are `MOCK`; the one-second interval is an actual asynchronous wait, not a live
service operation.
The captured completion requests are 1.033361 seconds apart. There is exactly one
Assemblyline POST, followed by two completion GETs and one full-result GET. The
projection is `COMPLETED` with raw external score `350` and zero recorded partial/
error/missing-key counters; authentication and gateway spam rate remain `UNKNOWN`
and disposition remains `REVIEW_REQUIRED`. The score is not a probability.

The receipt records the SID, original hash and endpoint/pin/mode binding before
the first completion check. A readback retains bounded status/score/counters,
service names, request timestamps and response hashes. It preserves one
`assemblyline-readback-<id>.json` history record per explicit run, while
`assemblyline-analysis.json` and JSON/HTML reports are updated snapshots. Raw
service bodies, error strings, attachments, credentials and arbitrary API links
are not copied into those projections. Partial, timed-out, cancelled and rejected
results cannot become successful analysis or sender authentication.

No new native UI inspection is claimed: the Mac-lock blocker remains. Mock
protocol and artifact checks are the available evidence; no real Assemblyline
credential or service connection was used.

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

## Trusted-ingress evidence receiver (2026-10-15)

Implemented from PR #1 head `ca7915b591817954759c42a36bd5ede8be677cdd`.
The unchanged baseline was independently rerun with all 347 tests passing.
The new [v1 contract](trusted-ingress.md) adds three strict wire schemas, a
MAC-authenticated envelope, issuer/key/scoped original identity and exact MIME
binding, time/boundary gates, a durable single-host replay barrier and locally
recomputed strict/relaxed authenticated alignment. It does not add an SMTP
verifier, HTTP ingestion API, Graph custody mapping or live enterprise integration.

Report schema 1.1 separates source acceptance from per-mechanism outcomes and
retains legacy 1.0 read compatibility. The new explicit offline `trusted-ingress`
CLI leaves ordinary triage/Graph authentication UNKNOWN. The message's raw claims
remain untrusted even when separate evidence is accepted. Every case remains
REVIEW_REQUIRED. See `ingress_contract.py`, `trusted_ingress.py`, `ingress_cli.py`,
the schema export script and `tests/test_trusted_ingress.py`.

Final development-tree validation: Ruff lint and formatting, strict mypy over
19 source files, and **509 passing tests** (347 existing + 162 new synthetic
cases/schema checks). Output is preserved in
[trusted-ingress-verification.txt](../demo/trusted-ingress-verification.txt).
The new cases include malformed/unsigned/MAC-tampered evidence, unknown and
relabeled issuers, cross-tenant/mailbox/object and raw-byte substitutions,
key/time/boundary/profile failures, concurrent replay, rotated-key and JSON-format
replay, unsafe ledgers and fsync failures, forged headers, missing SMTP context,
multiple/incomplete DKIM signatures, HELO/null reverse paths, IDNA/PSL PRIVATE/
wildcard/exception rules, strict/relaxed and inconsistent DMARC claims, preserved
legacy reports, and end-to-end CLI output/redaction. Tests globally deny sockets
and DNS. HMAC keys and messages are explicitly synthetic/public test fixtures.

This is development-tree evidence, not a claim that a later GitHub head passed
CI. Exact-head GitHub Actions status is reported separately in PR #1 after push.
No real enterprise Outlook tenant, gateway, policy retrieval, producer key custody,
SMTP-time authentication, deployment, release or merge has been validated or done.

## Sender OSINT phase 1 (2026-10-18)

Added an explicitly enabled, self-hosted MISP adapter and `sender-osint` CLI.
Queries use only bounded operator-selected IP/domain indicators, the existing
pinned HTTPS transport, explicit stdin keys and egress permission. Response
projections preserve per-source status, query/update times, response hashes,
attribute UUIDs, update recency and conflicting current detection-use flags.
No MISP score or flag changes message disposition/authentication. DNS, automatic
sender-IP extraction and gateway telemetry remain outside this phase.

Local own-cloud validation (`PYTHONPATH=src make check`, reusing the pinned
dependency environment while forcing this worktree source): Ruff lint passed,
44 files format-clean, strict mypy passed on 21 source files, and **574 tests
passed** (509 existing + 65 added). See
[sender-osint-verification.txt](../demo/sender-osint-verification.txt). New tests
cover success, exact filtering, stale/future updates, two-source flag conflict,
mixed service errors, absent results, malformed/deleted/oversized attributes,
redirect/timeout rejection, cancellation, real per-run pacing, CLI secret
redaction and legacy report loading. Socket/DNS denial remains enabled for all
tests. No live customer data, service credentials or external MISP query was
used. Existing demo reports are unchanged. This local transcript does not claim
that the later published head passed GitHub CI; exact-head CI is separate.

See [research, CLI and limitations](sender-osint.md). Production service/version
acceptance, distributed quota enforcement, feed governance and detection-quality
measurement remain unverified. No merge, deployment or release was performed.
