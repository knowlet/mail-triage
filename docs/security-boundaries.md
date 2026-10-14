# Security boundaries

This is an analyst-assistance CLI prototype. Every report requires review; a
lack of findings, external receipt or model opinion does not establish safety.
There is no automatic quarantine, deletion, reply, forwarding or message sending.

## Offline ingestion

`triage` reads only the selected regular local `.eml`; symlinks, devices and FIFOs
are refused. Exact bytes are preserved in `original.eml`, with SHA-256, size,
source name and ingestion time. Duplicate headers, all body text, URLs, filenames,
authentication claims and model replies remain untrusted data.

| MIME budget | Default |
| --- | ---: |
| Raw message | 5 MiB |
| MIME parts, including containers | 100 |
| Nesting, root counts as 1 | 12 |
| Cumulative MIME headers | 128 KiB |
| Individual line | 32 KiB |
| Cumulative decoded payloads | 5 MiB |
| Message text | 100,000 characters |

Depth and part limits apply during parser construction. Malformed/over-budget
inputs fail rather than yielding a partial safety assessment. Missing charset
means strict US-ASCII; invalid text/unsupported charsets fail closed. These are
application bounds, not an OS sandbox. Private stdlib-hook behavior is tested on
Python 3.12 and must be reviewed for interpreter upgrades.

Attachments are metadata/hash inventory only: no execution, helper applications,
unpacking, or attacker-selected filesystem paths. For local nested messages and
containers, inventory hashes/sizes describe parser reserialization, with an
explicit warning; child identity/body does not merge into the wrapper. Graph
retrieval separately stores exact returned original MIME bytes, without using
that serialization. Graph's returned bytes are not an attestation of original
SMTP wire bytes or sender authentication.

HTML, metadata and JSON are escaped as inert report text. Control/bidi characters
are displayed visibly and a restrictive CSP applies. Message URLs are not
clickable report links and are never fetched. Parsing performs no DNS, network
or model request. No listener/background service is started.

## Case storage and secrets

New case directories use `0700`, files use `0600`, and existing output paths are
refused. Fixed artifact names are independent of email filenames. This is access
control, not encryption or retention. Connector artifact writes fsync file and
directory; report updates use fsynced private temporary files and atomic rename.
There is no transaction covering every artifact in a case. Real cases can contain
personal data; operators control access, backup, sharing and deletion and keep them out of
source control. Checked-in fixtures are authored non-sensitive mechanics examples.

Connector configuration is nonsecret typed JSON from one explicit path.
Credentials are supplied only by explicit JSON standard input and held as
`SecretStr`; there is no environment, keychain, credential-file, account discovery
or token-acquisition path. Keys must not appear in config, arguments, logs or
reports. API errors are reduced to static failure codes/classes. Reports retain
selected source/hash/time/receipt fields rather than arbitrary API responses or
credential-bearing URLs. Submitting a real message still discloses it to each
explicitly enabled service; model input is minimized as described in [models](models.md).

## Controlled egress

Only the separate `graph-ingest` path can use configured adapters; its CLI
requires `--allow-egress` and explicit secrets input. `connect-demo` injects
`httpx.MockTransport` in code and cannot turn a response/email into a live
connection. Ordinary `triage` remains offline regardless of connector settings.
No live connection is part of the verification evidence.

[`ControlledTransport`](../src/mail_triage/transport.py) enforces:

- One explicit bare HTTPS origin and exact method/raw-path routes per adapter.
  No message-derived provider, URL, query, redirect, proxy or credential destination.
- An exact operator-configured IP pin, avoiding DNS/rebinding; original Host and
  TLS SNI are retained with TLS verification enabled. No DNS fallback occurs.
- Non-global pins only with explicit `allow_private_ip`; loopback, link-local,
  multicast, unspecified and equivalent mapped-address destinations are refused
  even with that opt-in. This is not a blanket private-network allowance.
- No redirects, retries, ambient proxies or compressed responses; request/response
  bytes, declared lengths and connect/read/write/total durations are bounded.
  Graph and configured model operations also impose an overall deadline.
- No following message or API links, pagination, rule feeds, model registry
  lookup, tool requests or response-directed requests.

The allowed operations are Graph's selected wrapper/attachment GETs,
Assemblyline `POST /api/v4/submit/`, Sublime `POST /v0/messages/analyze`, and model
`POST /v1/chat/completions`. A fixed pin can become stale; the operator maintains
it and must have a certificate trusted by HTTPX's default certifi CA bundle.
No insecure TLS or custom CA-file option exists. Controls here do not restrict the
selected service's own execution, retention, logging or downstream network access;
review those separately.

Before a service POST, an exclusive durable per-case claim records hashes of
service/endpoint/input/rules and intent time. Claims persist after failure or
uncertain timeout and block automatic repeat submission within that case. No
retry/reset/poll operation is implemented. New cases can resubmit: this is not
global or server-side idempotency. A transport error may mean the service accepted
the original; it remains an uncertain outcome. Artifacts are preserved before
POSTs and partial cases retain individual failure evidence.

## Evidence and model separation

`Authentication-Results`, `Received`, `Return-Path` and DKIM metadata cannot
self-authenticate. An allowlisted `authserv-id`, Graph access, Assemblyline receipt,
Sublime response or model hypothesis does not change that. SPF, DKIM, DMARC and
alignment stay `UNKNOWN` without independently trusted evidence; no offline
cryptographic DKIM pass or invented gateway spam rate is claimed. See the
[trusted-ingress requirements](integrations.md#authentication-still-needs-trusted-ingress).

`OBSERVED` means an observation/response was produced, not an authentication pass,
malicious verdict or safe result. `NOT_RUN` means a stage did not execute;
`UNKNOWN` means evidence cannot establish the answer; `ERROR` cannot become
success. Independent deterministic evidence and `REVIEW_REQUIRED` remain intact.

Pydantic AI accepts one typed content hypothesis with existing unique finding
citations. The schema-only output function has no executable action capability.
Citation integrity does not establish semantic truth. Email/model text cannot
select endpoints, run tools or mutate other evidence. DSPy uses separately
authored held-out fixtures, never live-email training or optimization. Framework
scripted tests are `STUB`; HTTP connector tests/demo are `MOCK`. Neither is a live
integration or phishing-accuracy test.
