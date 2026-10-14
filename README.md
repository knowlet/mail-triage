# Mail Triage

A runnable, self-hosted defensive email triage prototype. Supply a local `.eml`;
receive independent typed evidence, an inert HTML review report, and an exact
copy of the original message. Every case remains `REVIEW_REQUIRED`.

This first slice implements the user's authentication, reputation/integration,
and Pydantic AI + DSPy design boundaries. It does not implement any unseen design
response or claim production detection accuracy.

## Run locally

Requires Python 3.12 and [uv](https://docs.astral.sh/uv/). All packages and caches
stay inside this project. The setup command installs the optional model libraries
for framework tests; no provider or credentials are configured.

```sh
cd mail-triage
make setup
make check
make demo
```

Or run one case explicitly, using a new output directory with an existing parent:

```sh
mkdir -p reports
.venv/bin/mail-triage triage fixtures/synthetic-phish.eml --out reports/my-case
```

The CLI prints a JSON summary. A successful case contains:

- `original.eml`: exact original bytes, bound to the report by SHA-256.
- `report.json`: versioned Pydantic report with provenance, limits and independent stages.
- `report.html`: local review UI; all email markup, URLs and metadata are escaped text.

Open `reports/my-case/report.html` in a browser. No server or background service
is required. Directories are private (`0700`), files are private (`0600`), and
existing outputs—including symlinks—are refused. Failure exits with status 2 and
a sanitized JSON diagnostic. Keep real cases outside source control.

For a smaller installation without optional model libraries, use
`UV_CACHE_DIR=.uv-cache uv sync --locked --index-url https://pypi.org/simple`.
The normal CLI uses Pydantic and the Python standard library only.

## What runs

| Stage | First-version behavior |
| --- | --- |
| MIME/provenance | Bounded parsing; original-byte copy and SHA-256; attachment inventory |
| SPF, DKIM, DMARC, alignment | `UNKNOWN`; uploaded headers cannot authenticate themselves |
| Content | Offline wording, literal domain difference, attachment-extension and HTML/URL observations |
| OSINT, gateway reputation | `NOT_RUN`; no provider or trusted gateway configured |
| Gateway spam rate | `UNKNOWN`; no source, numerator, denominator or time window |
| Assemblyline, Sublime, Outlook | `NOT_RUN`; documented adapter contracts only |
| Pydantic AI | `NOT_RUN` in CLI; optional code-injected typed review validates finding-ID citations |
| DSPy | `NOT_RUN` in CLI; separate offline held-out fixture evaluation path |

No DNS lookups, URL fetching, attachment execution, live LLM requests, mailbox
reads or email actions occur during normal triage. Attachment filenames never
become output paths. Nested attached messages cannot supply the wrapper's
identity or authentication. Prompt instructions in email and model output have
no action capabilities. Heuristics and model hypotheses do not prove maliciousness,
safety, impersonation or domain ownership.

## Actual demonstration

The authored 1,966-byte [fixture](fixtures/synthetic-phish.eml) contains fake
authentication-pass headers, plain text, active HTML source and a synthetic
attachment named `../../invoice.docm`. Its reserved `.invalid` URLs are never
visited. The actual outputs are checked in for inspection:

- [CLI output](demo/cli-output.json) (output directory normalized to a relative path)
- [Typed JSON report](demo/offline-case/report.json)
- [Inert HTML report](demo/offline-case/report.html)
- [HTML after visual review](demo/reviewed-report.html) (same evidence; table headings improved)
- [Preserved original](demo/offline-case/original.eml)

Six content observations are produced. All authentication checks remain
`UNKNOWN` despite the spoofed pass claims; all model/live integration stages
remain `NOT_RUN`. This demonstrates mechanics, not phishing accuracy.

## Verification and limitations

`make check` runs Ruff lint/format checks, strict mypy for application code and
pytest. Network connections/DNS are denied in tests. Tests cover malformed and
oversized input, MIME depth/part/header/decoded-text budgets, authentication-header
spoofing, attachments/HTML, nested identity isolation, output collisions and
provenance. Model tests use explicitly labeled Pydantic AI `FunctionModel` and
DSPy `DummyLM` stubs; no real LLM was connected. Optional model tests skip if the
model dependencies are not installed.

This is a CLI prototype, with no production API, queue, case database, RBAC,
encryption, retention policy or tenant connection. Parser limits are application
bounds, not an OS sandbox. Malformed messages and undeclared non-ASCII text fail
closed. Attached-message/container hashes describe parser reserialization with
an explicit warning; exact embedded-message extraction remains future work.
HTML safety is covered by structural tests. The synthetic report was also inspected
in the existing Safari browser using native app controls; markup stays literal text.

See [security boundaries](docs/security-boundaries.md),
[integration contracts](docs/integrations.md), [model workflow](docs/models.md)
and [dependency provenance](docs/dependencies.md). The next smallest step is a
tested local trusted-ingress sidecar contract bound to original-byte hashes;
live authentication or mailbox integrations follow only with an authenticated
collector and separately authorized, controlled egress.

## Repository state

Local `main` holds the clean initialization commit. Development is on
`feat/offline-triage`, prepared for a Draft PR against the public
[`knowlet/mail-triage`](https://github.com/knowlet/mail-triage) repository, as
explicitly requested by the user. Review, merge and deployment are separate steps.

The [CI workflow](.github/workflows/ci.yml) runs on pull requests and pushes to
`main`, with read-only repository permissions and a 15-minute job deadline. It
installs the locked dependencies and runs the same `make check` used locally.
Tests deny network/DNS access and use scripted model backends; no external email
integration or real inference is enabled in CI. Action revisions and uv are pinned.
