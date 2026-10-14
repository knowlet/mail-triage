# Implemented connector contracts

Normal `triage` remains offline. Executable optional adapters now exist for
selected Microsoft Graph MIME retrieval, Assemblyline submission, Sublime
analysis and a self-hosted model. All default to disabled, without implicit
endpoints or credentials. Tests and `connect-demo` use `httpx.MockTransport` only.
No live tenant, service, model, consent or credential setup was performed.
Sender OSINT, gateway reputation and gateway spam-rate telemetry are not implemented.

## Configuration and credentials

`ConnectorSettings` in [`connections.py`](../src/mail_triage/connections.py)
accepts only `graph`, `assemblyline`, `sublime` and `model`. Unknown settings are
rejected. The [example JSON](configured-connectors.example.json) is valid with
all stages disabled and no destinations. Enabling Graph requires a mailbox and
endpoint; enabling each other stage requires its endpoint and specific settings.
The CLI caps config input at 64 KiB and secret JSON at 16 KiB; duplicate JSON
keys are rejected. Both inputs must be well-formed objects with known fields.

| Nonsecret setting | Meaning |
| --- | --- |
| `graph.mailbox` | One explicit mailbox identifier/UPN; maximum 512 characters |
| CLI `--message-id`, `--attachment-id` | One selected wrapper and item attachment; bounded, separately URL-quoted IDs |
| `graph.limits` | MIME/resource budgets applied independently to wrapper and original |
| `assemblyline.username` | Explicit `X-USER` identity, separate from the secret API key |
| `sublime.selected_rules` | Up to 16 unique operator-authored `{name, source, severity?}` records; source up to 8,000 characters |
| `model.model_name` | Explicit bounded model name; no provider/model lookup |

Every non-null `endpoint` uses this exact nonsecret policy schema:

| Endpoint field | Default / constraint |
| --- | --- |
| `origin` | Required bare HTTPS origin, optional explicit port; no path, credentials, query or fragment |
| `pinned_ip` | Required exact IPv4/IPv6 address; no DNS lookup |
| `allow_private_ip` | `false`; explicit opt-in for a selected non-global pin |
| `connect_timeout` | 5 seconds; accepted range 0.1–30 |
| `read_timeout` | 5 seconds; accepted range 0.1–30; also bounds writes |
| `total_timeout` | 15 seconds; accepted range 0.1–60 |
| `max_request_bytes` | 8 MiB; accepted range 1 byte–16 MiB |
| `max_response_bytes` | 5 MiB; accepted range 1 byte–8 MiB |

Graph additionally bounds the entire three-request fetch by `total_timeout`.
Services accept at most 5 MiB of input and interpret at most 1 MiB of JSON reply.
Graph metadata is capped at 64 KiB. There is no private-network blanket allowlist:
only the configured exact pin is contacted; loopback, link-local, multicast and
unspecified addresses are always refused. TLS verification remains enabled.

The configured CLI requires both `--allow-egress` and `--secrets-stdin`.
Credentials arrive as JSON on standard input and are validated as
`ExplicitCredentials`: `graph_token`, `assemblyline_key`, `sublime_key`,
`model_key`. Enabled stages require their explicitly supplied secret; values use
Pydantic `SecretStr`. There is no environment, keychain, secret-file, token
acquisition or account-discovery path. Nonsecret config is read only from the
selected config path. The exact configured origins/pins, mailbox and IDs need
operator review before use. Do not place secrets in arguments or config files.

## Outlook user reports and exact original MIME

Outlook Report targets an internal Exchange Online reporting mailbox, then this
read-only adapter retrieves explicit resources. It is not a native self-hosted
webhook. Microsoft supports **My reporting mailbox only**, rather than direct
routing to an external self-hosted address. See [user-reported message settings](https://learn.microsoft.com/en-us/defender-office-365/submissions-user-reported-messages-custom-mailbox).

[`GraphAdapter`](../src/mail_triage/graph_ingest.py) makes exactly:

1. `GET /v1.0/users/{mailbox}/messages/{wrapper-id}/$value` for wrapper MIME.
2. `GET /v1.0/users/{mailbox}/messages/{wrapper-id}/attachments/{attachment-id}`
   to require `#microsoft.graph.itemAttachment` and the selected attachment ID.
3. `GET` on that attachment's `/$value` for original MIME.

All path segments are individually quoted. Both messages pass bounded parsing;
wrapper headers/body never become original-message evidence. Exact response bytes
are saved as `wrapper.eml` and `original.eml` with separate hashes/IDs in
`graph-provenance.json`. “Exact” refers to bytes returned by Graph, not an
assertion that Graph retained original SMTP wire bytes. No parser serialization
is used to obtain the original artifact. See [Graph message MIME](https://learn.microsoft.com/en-us/graph/api/message-get?view=graph-rest-1.0)
and [itemAttachment MIME `/$value`](https://learn.microsoft.com/en-us/graph/api/attachment-get?view=graph-rest-1.0).

The adapter uses caller-supplied bearer credentials for read-only `Mail.Read`
operations. It performs no mailbox listing, pagination, token acquisition, tenant
consent, configuration writes or email actions. Before production authorization,
test in-scope and out-of-scope mailboxes: Entra consent and Exchange Application
RBAC grants are additive. A narrow RBAC grant cannot cancel an existing broad
permission. See [Exchange application RBAC](https://learn.microsoft.com/en-us/exchange/permissions-exo/application-rbac).

## Assemblyline submission

[`AssemblylineAdapter`](../src/mail_triage/service_adapters.py) sends the selected
original EML to the configured instance with `POST /api/v4/submit/`, `X-USER`,
`X-APIKEY`, multipart `bin`, and `json` metadata containing SHA-256/correlation ID.
A validated receipt supplies a submission ID. The adapter does **not** poll or
retrieve analysis results, interpret a score, or establish sender reputation.
See the [official submission contract](https://cybercentrecanada.github.io/assemblyline4_docs/integration/rest/).

Assemblyline is MIT-licensed file triage. Its services may execute content or
make external requests; this application does not deploy/configure them. Review
the selected instance's egress, retention and service policies separately.

## Sublime analysis

[`SublimeAdapter`](../src/mail_triage/service_adapters.py) sends one
`POST /v0/messages/analyze` containing base64 `raw_message`, explicit rule
sources and empty `queries`. There is no automatic rule feed or URL retrieval.
The adapter requires a configured instance and rejects the public
`analyzer.sublime.security` / `platform.sublime.security` host families. It validates
bounded rule/query response structure, then records a response hash and
`OBSERVED`; it does not promote matches to a malicious/safe/identity verdict.
It requires exactly one result for every selected rule, with the selected name
and source echoed exactly, `success: true`, and a boolean `matched`. Missing,
duplicate, unexpected or failed rule results are rejected rather than treated
as a clean analysis. Requests contain no queries; nonempty query results are rejected.
See [Sublime message analysis](https://docs.sublime.security/reference/analyzemessage).

No Sublime images are bundled or deployed. Its deployment repository license does
not license the platform images for embedding: the Docker platform is limited
to 100 active mailboxes with best-effort support, and embedding its images is
unsupported. Review telemetry and downstream data handling separately. See
[Sublime Platform caveats](https://github.com/sublime-security/sublime-platform).

## Submission intent and uncertain outcomes

Before either service POST, a durable private `submissions/` claim binds service,
endpoint/pin hash, original SHA-256 and selected-rules hash. Exclusive creation
blocks duplicate submissions within that case, including after timeouts or
network failures. Claims are not automatically removed, retried or reset.
A timeout may mean the server accepted a submission; it remains an uncertain
outcome, never success or a reason to silently retry. A new case can submit the
same message again. This is local per-case intent protection, not a distributed
idempotency guarantee.
Intent files and their containing directories are fsynced. Connector case-file
writes are also fsynced with their directories; report replacements use a private
temporary file and atomic rename. These are durable individual writes, not a
transaction spanning every case artifact.

`connectors.json` retains selected source/time/hash/receipt fields and sanitized
failure reasons, not raw service responses, credentials or arbitrary API links.
The original case is preserved before service POSTs. A service/model failure can
leave a partial case; inspect individual outcomes rather than inferring success
from the presence of a directory. See [model behavior](models.md).

The connector CLI returns exit 0 for a completed run, exit 3 for recorded partial
stage failure, and exit 2 for rejected input/configuration or an ingestion failure.

## Authentication still needs trusted ingress

Graph retrieval does not authenticate the original sender. Uploaded
`Authentication-Results`, an allowlisted `authserv-id`, `Received`, envelope-like
headers and model claims remain unverified. SPF needs the actual SMTP peer and
envelope identity; DKIM needs controlled cryptographic/key verification; DMARC
needs verified aligned SPF **or** DKIM. Relaxed alignment needs organizational-domain
and public-suffix handling, not the last two labels. Missing evidence remains
`UNKNOWN`. See [RFC 8601](https://www.rfc-editor.org/info/rfc8601/),
[RFC 7208](https://www.rfc-editor.org/rfc/rfc7208.html#section-4.1) and
[RFC 7489](https://www.rfc-editor.org/rfc/rfc7489.html#section-3.1).

The next smallest authentication step is a versioned trusted-ingress assertion
contract bound to exact original SHA-256, authenticated collector identity,
receive time, policy version and replay-resistant event ID. Reject hash mismatch,
unknown issuers, expiry/replay and missing provenance. Require attestation that
forged internal assertions were stripped at the documented ingress boundary;
a user-writable `trusted: true` flag is insufficient.

Spam rates remain unavailable without a named telemetry source, numerator,
denominator, time window, population and classification definition. A model or
single message cannot supply gateway reputation or prove impersonation.
The [example analyzer repository](https://github.com/aliex23k65/Phishing_Email_Analyzer/tree/main)
was research material only; no prompts/skills/code or unseen requirements were copied.
