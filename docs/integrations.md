# Integration contracts

This version ingests a local `.eml` only. Outlook, sender OSINT, gateway
reputation, Assemblyline and Sublime adapters are **not implemented or connected**;
their report stages remain `NOT_RUN` or `UNKNOWN`. The contracts below describe
future work, not working configuration switches. No credentials, tenant consent,
mailbox access or external submissions were used to build this version.

## Trusted ingress: the next smallest step

Implement and test a versioned sidecar contract with authored fixtures before
adding a live service. Bind the sidecar to the exact original message SHA-256,
authenticated collector identity, receive time, ingress/policy version and
replay-resistant event ID. Reject mismatched bytes, unknown issuers, expired or
replayed assertions, and missing provenance. Do not accept a user-supplied
`trusted: true` flag or treat Graph retrieval alone as authentication evidence.

For authentication assertions, the collector must be inside a documented trust
boundary and attest that forged internal assertions were stripped at ingress.
An allowlisted `authserv-id` in uploaded MIME is insufficient: anyone can write
that header. Preserve the uploaded bytes without alteration; record sanitation
and verified assertions separately. See [RFC 8601 trust boundaries and removal
of existing fields](https://www.rfc-editor.org/info/rfc8601/).

SPF evaluation needs the actual SMTP peer IP and envelope identity, not a guessed
`Received` hop or visible `From`. See [RFC 7208 section 4.1](https://www.rfc-editor.org/rfc/rfc7208.html#section-4.1).
DKIM needs cryptographic verification with a controlled key-resolution policy.
DMARC needs a verified aligned SPF pass **or** a verified aligned DKIM pass,
with policy evaluation. Strict and relaxed alignment must remain distinct;
relaxed alignment needs organizational-domain/public-suffix handling, never
"last two labels." Missing evidence stays `UNKNOWN`. See [RFC 7489 section
3.1](https://www.rfc-editor.org/rfc/rfc7489.html#section-3.1).

## Outlook user reports

The supported design is Outlook Report → an internal Exchange Online reporting
mailbox → a separately authorized ingestion adapter. Microsoft's report settings
support **My reporting mailbox only**; they cannot route directly to an external
self-hosted address. No native self-hosted webhook is assumed. See [Microsoft's
user reported settings](https://learn.microsoft.com/en-us/defender-office-365/submissions-user-reported-messages-custom-mailbox).

The future adapter retrieves MIME with
`GET /users/{mailbox}/messages/{id}/$value` using read-only `Mail.Read` access.
Preserve the report wrapper and its provenance. Extract an attached original
message as a separate bounded artifact with a parent/child relationship and its
own exact-byte hash; do not combine wrapper headers with original-message
authentication. Extraction of exact original attached-message bytes is **not
implemented** here. See [Graph message MIME retrieval](https://learn.microsoft.com/en-us/graph/api/message-get?view=graph-rest-1.0).

Before production authorization, test both in-scope and out-of-scope mailboxes.
Entra permission consents and Exchange Application RBAC grants are additive;
a scoped RBAC assignment does not neutralize an existing broad grant. Review
the effective union of permissions. See [Exchange application RBAC](https://learn.microsoft.com/en-us/exchange/permissions-exo/application-rbac).
Do not add write, send, quarantine or deletion permissions to this adapter.

## Assemblyline file triage

[Assemblyline](https://github.com/CybercentreCanada/assemblyline) is an MIT-licensed
self-hosted file-triage and malware-analysis framework. It supplies file evidence,
not sender reputation or gateway spam rates. Its stage appears alongside other
external evidence in this report for display convenience.

A future adapter submits only an explicitly selected artifact to the configured
instance: `POST /api/v4/submit/`, `X-USER` and `X-APIKEY` authentication, multipart
`bin` bytes and optional `json` submission parameters/metadata. Include the local
artifact hash and case correlation ID; retain submission ID, instance identity,
service versions, timestamps and response hash separately. Validate the instance's
API contract before use. See [Assemblyline REST submission](https://cybercentrecanada.github.io/assemblyline4_docs/integration/rest/).

Keep this adapter disabled until service-level egress and data retention are
reviewed: analysis services may contact external systems. A remote score must not
overwrite independent authentication/content evidence or trigger disposition.

## Sublime analysis

Keep an optional API adapter boundary. The proposed call is
`POST /v0/messages/analyze` with base64 `raw_message` and explicitly selected
rules, following the configured instance's schema. Require an explicit endpoint;
never silently fall back to a public analyzer. Record endpoint identity, rule
identifiers/versions, evaluation time and raw-response hash. See [Sublime raw
message analysis](https://docs.sublime.security/reference/analyzemessage).

Do not bundle Sublime Docker images as this project's engine. The deployment
repository's license does not establish a license for the platform images. Its
Docker setup is limited to 100 active mailboxes with best-effort support, and
using those images inside another implementation is unsupported. See [Sublime
Platform caveats](https://github.com/sublime-security/sublime-platform).
Review telemetry defaults and downstream data sharing before any future
deployment. No Sublime deployment or telemetry configuration was performed.

## Sender and gateway intelligence

A future result needs a named source, exact queried indicator, collection and
observation timestamps, source/version, raw-response hash and limitations. Keep
sender/domain/IP observations separate; a claimed `Received` IP is untrusted.
Do not infer a sending gateway or prove impersonation from model output alone.

Report a spam rate only when authorized telemetry supplies a numerator,
denominator, time window, population and classification definition. Missing
telemetry stays `UNKNOWN`; no percentage is estimated from an individual email.

All future network adapters must satisfy the [egress boundary](security-boundaries.md#future-egress).
Pydantic AI and DSPy integration details are in [models.md](models.md); those
frameworks do not supply authentication, gateway reputation or mailbox ingestion.

The user's [example analyzer reference](https://github.com/aliex23k65/Phishing_Email_Analyzer/tree/main)
is a research source only. No code, repository prompts, skills or instructions
from it were copied into this implementation, and no unseen design response is
claimed as implemented.
