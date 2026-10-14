# First-version delivery evidence

Project directory: `mail-triage/`.
The selected workspace was empty before creation; no other checkout, model
service, mailbox, tenant, or persistent service was changed.

## Delivered flow

`mail-triage triage <local.eml> --out <new-case-directory>` reads one bounded
regular file, parses MIME, collects independent typed evidence, and writes exact
original bytes plus JSON and inert HTML. No network stage or model runs in this
flow. All cases require human review.

Source modules:

- [`schemas.py`](../src/mail_triage/schemas.py): versioned evidence contracts and limits.
- [`ingest.py`](../src/mail_triage/ingest.py): bounded MIME/resource handling and regular-file reads.
- [`evidence.py`](../src/mail_triage/evidence.py): independent authentication/content/external stage evidence.
- [`model_workflow.py`](../src/mail_triage/model_workflow.py): opt-in typed hypotheses and separate held-out evaluation.
- [`reporting.py`](../src/mail_triage/reporting.py): provenance-bound private case artifacts and escaped HTML.
- [`cli.py`](../src/mail_triage/cli.py), [`__main__.py`](../src/mail_triage/__main__.py): runnable CLI/module entrypoints.

Setup, pinned dependency provenance, startup and limits are documented in
[`README.md`](../README.md), [`dependencies.md`](dependencies.md),
[`models.md`](models.md), [`integrations.md`](integrations.md) and
[`security-boundaries.md`](security-boundaries.md).

## Actual verification

`make check` passes:

- Ruff lint: passed.
- Ruff format check: passed.
- Strict mypy: no issues in 8 application source files.
- pytest: **64 passed**. Network/DNS calls are denied in tests.
- One upstream `pydantic_graph` Python 3.12 event-loop deprecation warning remains;
  no application warning was suppressed.

The captured command output is [`demo/verification.txt`](../demo/verification.txt);
its machine-specific absolute project prefix is normalized to `<project>`.
Tests exercise malformed/oversized input, parser construction limits, header/line/
decoded/text limits, encoding failures, spoofed authentication headers, inert HTML,
attachment names/content, nested-message identity isolation, byte/hash provenance,
private permissions, and output collision/symlink refusal.

Pydantic AI `FunctionModel` and DSPy `DummyLM` tests use scripted replies labeled
`STUB`. They check typed output, evidence-ID citations, rejected action/tool
attempts, bounds, missing inputs, held-out-only evaluation and withheld expected
labels. They are framework mechanics tests, not real inference or accuracy tests.

## Actual end-to-end demonstration

Command:

```sh
.venv/bin/mail-triage triage fixtures/synthetic-phish.eml --out demo/offline-case
```

The authored synthetic message is **1,966 bytes**, with SHA-256
`4e31d9fb762cc859cf266a509e293fadbbd1e4a77feb41c1080f494e4fa10fca`.
It includes fake SPF/DKIM/DMARC passes, a prompt-injection sentence, active HTML
source, reserved `.invalid` URLs and a non-executable synthetic attachment whose
untrusted filename is `../../invoice.docm`.

Actual results:

- `REVIEW_REQUIRED`; six deterministic content observations.
- SPF, DKIM, DMARC and alignment: `UNKNOWN`, despite reported pass claims.
- Gateway spam rate: `UNKNOWN`.
- Models, OSINT, gateway reputation, Assemblyline, Sublime and Outlook: `NOT_RUN`.
- Original bytes compare exactly with the input; only the three fixed artifacts
  are written, never the attachment's filename.

Inspect the [actual CLI output](../demo/cli-output.json),
[full JSON report](../demo/offline-case/report.json),
[HTML report](../demo/offline-case/report.html), and
[preserved original](../demo/offline-case/original.eml).
The CLI transcript's output directory is normalized to a relative path; message
and report evidence remain unchanged. A [visually reviewed HTML rendition](../demo/reviewed-report.html)
uses the same JSON evidence with nonbreaking MIME table headings. The original
HTML/JSON/EML artifacts remain byte-for-byte preserved.
Separate actual subprocess CLI runs rejected malformed and 5 MiB + 1 byte inputs
with exit 2 and no case directory: [rejection smoke output](../demo/rejection-smoke.json).

## Repository and environment

Local `main` initialization: `16c2e13b28a30894b0361580232f40405a6b0393`,
`chore: initialize isolated mail triage project`.
Implementation branch: `feat/offline-triage`; feature commit uses
`feat: add bounded offline email triage and typed evidence reports`.
Local commits are unsigned: the configured GPG agent was inaccessible in the
filesystem sandbox. GPG reported `Operation not permitted` creating a temporary
file under `.gnupg`, then `can't connect to the agent`, `No agent running`,
`FAILURE sign 33554509`, and `gpg failed to sign the data`. This was an operational
tool failure, not an automatic permission-review rejection. The original local
commit commands used `git -c commit.gpgsign=false`. Before public publication,
the authenticated GitHub identity was verified as `knowlet`, ID `4388697`, and
only this task's unpublished author/committer metadata was rewritten to that
account's standard GitHub noreply address. Reviewed tree content was preserved.
This rewrite used unsigned `git commit-tree` without invoking GPG or changing
signing settings. Signing was not retried and no global Git/GPG setting,
credential, keyring access or permission was changed.

The read-only network-authorized `gh auth status` succeeded for the existing
active `knowlet` account. `gh repo list knowlet --limit 1000` found no
`mail-triage` name collision. Proposed remote: **public `knowlet/mail-triage`**,
following the user's explicit public-project request. The parent accepted the
first-slice review before authorizing publication and one Draft PR. At the
completion of the initial review, no remote or PR had been created. No merge,
deployment or release is included. No project listener or background process runs.

## Remaining limits and next step

No live LLM, Outlook, Assemblyline, Sublime or intelligence connection was made.
Only Pydantic AI/DSPy scripted wiring tests ran. This prototype has no production
API, authentication/RBAC, queue, database, encryption, retention or tenant setup.
HTML structure/escaping/CSP were tested. The browser-tab connector inventory was
empty, but native app inventory exposed existing Safari. Native controls opened
only the local synthetic report in a new tab. Visible layout, escaped markup,
untrusted filenames and explicit stage states were verified without clicking
message URLs or changing browser permissions. A table-heading wrap issue was fixed.

Strict parsing rejects malformed/unknown charsets and undeclared non-ASCII text.
Encapsulated-message/container hashes describe parser reserialization with an
explicit warning; exact embedded-message extraction is not implemented. Parser
limits are application bounds and use tested private stdlib hooks on Python 3.12.

The next smallest integration step is a local versioned trusted-ingress sidecar
contract bound to the original SHA-256, authenticated collector identity, event
ID/time and policy version, with mismatch/replay/unknown-issuer tests. Do not
accept user-writable trust flags or trust an authserv-id alone. Only then add a
separately authorized collector or network adapter with explicit egress controls.

## Independent pre-publication review

Independent reviewers inspected all tracked files and the MIME parsing, resource
limits, attachment handling, HTML escaping, model citation validation and default
offline boundary. No blocking code defect was found. The focused independent run
of ingestion/CLI/acceptance tests passed 42 tests. Finding IDs are checked for
membership and uniqueness after model output validation; this does not validate
the meaning of a model hypothesis. DSPy expected labels/IDs are withheld from
prediction input.

Review cleanup removed four machine-specific absolute paths from documentation
and transcripts. The CLI now preserves an operator-supplied relative output path
in its summary, with a regression assertion. Native Safari visual review found
and verified the fix for midword MIME table-heading wrapping. The original EML,
JSON and HTML artifacts were preserved; the improved HTML is a separate rendition.

The tracked inventory contains only source/tests, package metadata and lockfile,
documentation, and authored synthetic fixture/demo artifacts. No cache, virtual
environment, dependency binary, credential/private-key indicator, or unrelated
file was found. The review itself is acceptance evidence; publication follows
the user's separately given public-project instruction. The bounded GitHub CI
workflow installs pinned dependencies and repeats the existing local checks.
CI success is reported only after the exact final head has completed.
