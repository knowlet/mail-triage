# Security boundaries

This is a local analyst-assistance prototype. Every report requires review;
neither a lack of findings nor a model opinion establishes safety. There is no
automatic quarantine, deletion, reply, forwarding or message sending.

## Current offline boundary

Only an operator-selected local `.eml` is ingested. The final input path must be
a regular file and cannot be a symlink or FIFO. Original bytes are preserved in
`original.eml`; provenance records SHA-256, size, source name and ingestion time.
Duplicate headers are retained as observations. All message headers and body
data, filenames, URLs, authentication claims and model replies are untrusted.

Defaults in [`Limits`](../src/mail_triage/schemas.py) apply before/during MIME
parsing and payload inspection:

| Budget | Default |
| --- | ---: |
| Raw message | 5 MiB |
| MIME parts, including containers | 100 |
| MIME nesting, root counts as 1 | 12 |
| Cumulative MIME headers | 128 KiB |
| Individual line | 32 KiB |
| Cumulative decoded payloads | 5 MiB |
| Message text | 100,000 characters |

Malformed or over-budget inputs fail rather than producing a partial safety
assessment. Text without a charset uses strict US-ASCII; unsupported charsets
or invalid encoded text fail rather than being silently repaired. These
application limits do not provide an OS process sandbox;
stdlib parser-hook compatibility is covered by regression tests. Validate new
Python versions before upgrading.

Attachments are inventoried by metadata/hash, never executed, opened by helper
applications, unpacked or written under attacker-chosen filenames. Nested
message/container hashes currently describe parser reserialization, not exact
embedded bytes; the report warns about this limitation. Nested content is not
merged into the outer message's analysis.

The report escapes all message-derived HTML, metadata and JSON as inert text,
shows control/bidi characters visibly, and uses a restrictive CSP. Message URLs
are not clickable report links and are never fetched. Parsing performs no DNS,
URL retrieval, reputation query or model request. No service listener is started.

Case directories use mode `0700` and files `0600`; existing output paths are
refused. This is access control, not encryption or a retention system. Case
artifacts contain the original message and may contain personal data: operators
must control local access, backups, sharing and deletion. Keep real cases and
credentials outside source control. This repository's fixtures are authored,
non-sensitive mechanics examples, not a detection benchmark.

## Evidence and model boundary

Uploaded `Authentication-Results`, `Received`, `Return-Path` and DKIM metadata
do not establish authentication. An allowlisted service name inside the message
does not change that. SPF, DKIM, DMARC and alignment remain `UNKNOWN` without
independently trusted evidence; no offline cryptographic DKIM pass is claimed.
The [trusted-ingress contract](integrations.md#trusted-ingress-the-next-smallest-step)
describes the required future boundary.

Keep deterministic content observations, authentication, reputation and model
hypotheses independent. `OBSERVED` means an observation was produced, not a pass
or malicious verdict. `NOT_RUN` means a stage was not executed; `UNKNOWN` means
the evidence cannot establish the result; `ERROR` must never become success.

Pydantic AI has no function tools or action capabilities; it requires an
explicitly injected model object and validates bounded output and existing
finding-ID citations. Citation validity does not prove the interpretation.
Email instructions and model replies cannot select endpoints, execute actions,
mutate evidence or authenticate a sender. DSPy is limited to separately authored,
held-out evaluation examples; no live-email optimization or training runs.
Scripted model tests are labeled `STUB`. See [model limits](models.md).

## Future egress

No network adapter is implemented. Before enabling one, require operator-owned
configuration and enforce these controls outside prompt instructions:

- Allowlist specific HTTPS service origins and paths; message data must never
  choose a URL, credential destination, provider, proxy or redirect target.
- Resolve and validate destinations, then bind the connection to approved
  addresses while validating TLS hostnames. Defend against DNS rebinding; deny
  loopback, link-local, private, multicast and metadata-service destinations.
  An approved self-hosted service needs an explicit pinned address/port exception,
  never a blanket private-network allowance.
- Disable redirects and ambient proxy inheritance. Bound request/response bytes,
  connection/read/total deadlines, concurrency and retries. Do not follow links
  supplied by an API response or message.
- Keep credentials out of reports/logs. Record request intent, artifact hash,
  source, time, outcome and sanitized failure class. Validate external responses
  as untrusted input; preserve provenance without accepting embedded actions.
- Review what each service itself can fetch, execute, retain or send onward.
  Approving one API endpoint does not approve that service's downstream egress.

Use synthetic fixtures and a local mock endpoint to test blocked destinations,
redirects, oversized responses, timeouts and provenance failures before any
authorized connection to a real service.
