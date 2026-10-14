# Mail Triage

A runnable defensive email triage prototype with an offline default and explicit,
self-hosted connector adapters. Each case preserves original bytes, independent
typed evidence and an inert HTML report. Every case remains `REVIEW_REQUIRED`.
The implementation covers the user's readable three-part design; it makes no
claim about an omitted design response or production detection accuracy.

## Run locally

Requires Python 3.12 and [uv](https://docs.astral.sh/uv/). Dependencies and caches
stay inside this project. Setup installs the optional Pydantic AI/DSPy libraries;
it does not configure a provider or connect to a service.

```sh
cd mail-triage
make setup
make check
mkdir -p reports
.venv/bin/mail-triage triage fixtures/synthetic-phish.eml --out reports/my-case
```

The offline command writes `original.eml`, `report.json` and `report.html`.
Open the HTML file locally; no listener or background service is required.
Directories use `0700`, files use `0600`, and existing output paths are refused.
Use a new directory on each run. Keep real cases outside source control.

A smaller installation can omit model dependencies:

```sh
UV_CACHE_DIR=.uv-cache uv sync --locked --index-url https://pypi.org/simple
```

`triage` performs no network request, model inference, DNS lookup, URL retrieval,
mailbox read or email action. It does not import the configured connector flow.

## Implemented stages

| Stage | Offline `triage` | Explicit connector flow |
| --- | --- | --- |
| MIME/provenance | Bounded parsing, original bytes/SHA-256, attachment inventory | Same bounds on Graph wrapper and original, stored separately |
| SPF, DKIM, DMARC, alignment | `UNKNOWN` | Still `UNKNOWN`; Graph retrieval and API replies do not authenticate the sender |
| Content | Independent deterministic wording/domain/attachment/HTML observations | Same observations; optional model hypothesis kept separate |
| Sender OSINT/gateway reputation | `NOT_RUN` | Not implemented |
| Gateway spam rate | `UNKNOWN` | `UNKNOWN`; no named telemetry/denominator/window |
| Outlook reports | `NOT_RUN` | Three selected Graph GETs; no mailbox listing or token acquisition |
| Assemblyline | `NOT_RUN` | One selected EML submission; optional bounded polling and separate untrusted result readback |
| Sublime | `NOT_RUN` | One raw-message analysis request with explicit operator-authored rules |
| Pydantic AI | `NOT_RUN` | Optional single bounded self-hosted chat-completions request; validated finding citations |
| DSPy | `NOT_RUN` | Separate offline authored held-out evaluation; no live optimization |

External replies and model output are untrusted observations, never safety,
identity or impersonation proof. The application never executes/unpacks
attachments, follows message/API links, quarantines/deletes/replies to email,
or sends messages. Service-side analysis may have its own execution, retention
and onward-egress behavior and needs separate review.

## Connector demonstration: mocked HTTP only

```sh
.venv/bin/mail-triage connect-demo --out reports/mock-connectors
```

This runs the executable adapters through `httpx.MockTransport`: three Graph GETs,
one Assemblyline POST, one Sublime POST and one model POST. It uses authored
messages, scripted replies and synthetic credentials. No live tenant, service or
model is contacted. `MOCK` labels identify contract execution, not integration
accuracy or live-service success.

A connector case adds `wrapper.eml`, `graph-provenance.json`, `connectors.json`
and a `submissions/` intent directory to the ordinary original/report artifacts.
The demo also writes `mock-requests.json` with inert method/host/path/size records.
Wrapper and original hashes/identities are separate; `original.eml` contains the
exact Graph itemAttachment `/$value` response, not MIME reserialization.
External POST intents persist even after uncertain outcomes, preventing automatic
resubmission of the same artifact/service/configuration within that case. A new
case can submit again; there is no global deduplication system.

The captured [connector CLI output](demo/connectors-cli-output.json) and
[connector case](demo/connectors-case/connectors.json) show the mocked flow.
They preserve the earlier six-exchange demonstration. To exercise result readback
as well, use another new directory:

```sh
.venv/bin/mail-triage connect-demo --assemblyline-poll --out reports/mock-assemblyline
```

This adds two mocked completion GETs, separated by a real one-second interval,
and one full-result GET: nine local mock exchanges in total. Inspect the captured
[polling CLI output](demo/assemblyline-cli-output.json),
[analysis/provenance](demo/assemblyline-case/assemblyline-analysis.json) and
[request log](demo/assemblyline-case/mock-requests.json). A saved receipt precedes
polling; the result records the external raw score and error/missing-result
counters separately from authentication and content evidence. `COMPLETED` means
the bounded readback checks passed, not that the email is safe or that its sender
is trusted. The mock score is not a phishing probability or an accuracy estimate.

The original [offline JSON](demo/offline-case/report.json),
[offline HTML](demo/offline-case/report.html),
[preserved fixture bytes](demo/offline-case/original.eml) and
[offline CLI output](demo/cli-output.json) remain unchanged. The authored
1,966-byte fixture produces six content observations while all authentication
checks remain `UNKNOWN`. These examples demonstrate mechanics, not accuracy.

## Explicit configured connections

Live connections have **not** been tested. The CLI path is available for a
separately authorized operator with existing service access:

```sh
.venv/bin/mail-triage graph-ingest --config operator-connectors.json \
  --message-id SELECTED_WRAPPER_ID --attachment-id SELECTED_ITEM_ATTACHMENT_ID \
  --out reports/new-configured-case --allow-egress --secrets-stdin
```

The configuration is typed, nonsecret JSON. Start with the
[all-disabled example](docs/configured-connectors.example.json). For each enabled
stage supply an explicit HTTPS origin and exact IP pin, plus the chosen mailbox,
model name, Assemblyline username or Sublime rule sources. IDs are explicit CLI
arguments; there is no discovery, pagination, tenant consent or account setup.
See [configuration and contracts](docs/integrations.md#configuration-and-credentials).

Supply credentials as one JSON object on standard input, using the keys
`graph_token`, `assemblyline_key`, `sublime_key` and `model_key` for enabled
stages. Values become `SecretStr` objects. There is no environment, keychain or
credential-file lookup. Do not put credentials in the config, command arguments,
reports or repository. `--allow-egress` is required for the configured CLI path;
ordinary `triage` never gains egress from configuration.

Assemblyline polling is separately opt-in through `assemblyline.polling.enabled`;
it defaults to `false`. Enabled polling uses a 2-second interval, a 60-second
overall deadline and at most 30 completion checks by default. Limits and outcomes
are described in [the Assemblyline contract](docs/integrations.md#assemblyline-submission-and-readback).

After a successful submission, `assemblyline-submission.json` preserves the SID,
original hash, endpoint/pin binding and execution mode before polling begins.
An existing case with that receipt can be read again without another POST:

```sh
.venv/bin/mail-triage assemblyline-readback --config operator-connectors.json \
  --case reports/existing-configured-case --allow-egress --secrets-stdin
```

Supply only `assemblyline_key` in the stdin JSON for this command. The config
must enable Assemblyline and its polling policy. Readback checks the saved receipt,
original/report hash, endpoint and pin, and mode before any request; a mock case
cannot be used for configured live readback. It performs GETs only, never Graph
retrieval, submission, Sublime analysis or model inference. Each explicit run adds
an `assemblyline-readback-<id>.json` history file, atomically replaces the latest
`assemblyline-analysis.json`, and separately refreshes the report snapshots.

Connector commands exit 0 for completion, 3 for recorded partial/failure/timeout
outcomes, 2 for rejected input/configuration, and 130 for cancellation. During
configured polling, Ctrl-C records `CANCELLED` and preserves the receipt; it stops
local readback and later stages, without cancelling the server's job or resubmitting.

Transport enforces exact origin/method/path, an exact IP pin, TLS verification,
Host/SNI preservation, byte/time bounds, and no redirects, retries or ambient
proxies. Private pins require explicit opt-in; loopback/link-local/multicast/
unspecified destinations remain forbidden. See [security boundaries](docs/security-boundaries.md).

## Verification and limitations

`make check` runs Ruff lint/format, strict mypy and pytest. Tests deny real socket/
DNS access and exercise bounded MIME handling, spoofed headers, inert HTML,
provenance, controlled transport, invalid service replies, uncertain POSTs and
credential separation. Pydantic AI `FunctionModel`/DSPy `DummyLM` tests are labeled
`STUB`; connector tests and the connector demo use `MOCK`. No real LLM, Outlook,
Assemblyline or Sublime connection is claimed. Optional model tests require the
model dependency extra.
Polling tests additionally cover strict completion booleans, SID/original-hash
binding, partial/error/missing-result counters, bounded waits, cancellation and
GET-only recovery without a second submission. Current test totals belong to the
actual verification output for the checked revision.

This CLI prototype has no production API, queue, case database, RBAC, encryption,
retention system or tenant setup. Application parser limits are not an OS sandbox.
Malformed input and undeclared non-ASCII text fail closed. For local EML nested
message/container inventory, hashes describe parser reserialization with a warning;
the Graph adapter separately preserves the exact MIME bytes returned by Graph.
TLS uses HTTPX's default certifi CA bundle; no custom CA or insecure-TLS switch
is provided.
Fixed pins require operator maintenance. The model endpoint must implement the
strict supported chat-completions response shape.

See [models](docs/models.md), [dependency provenance](docs/dependencies.md) and
[delivery evidence](docs/implementation-report.md). The next step toward actual
SPF/DKIM/DMARC results is a tested, authenticated trusted-ingress assertion
contract bound to exact original hashes; mailbox retrieval alone is insufficient.

The [CI workflow](.github/workflows/ci.yml) installs locked dependencies and runs
the same checks with read-only repository permissions. No external integration or
real inference is enabled in CI. No merge, deployment or release is included.

## License status

No project license has been selected or added. Public source availability does
not mean this project is offered under an open-source license. Selecting a license
for the original code remains an owner decision; upstream dependency or engine
licenses are separate and have not been adopted for this project.
