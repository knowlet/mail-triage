# Sender-indicator OSINT: research and design

Research reviewed on 2026-10-18. This document separates the recommended first
adapter from deferred integrations. The recommendations below are local design
decisions, not claims that a feed can authenticate a sender or determine whether
an email is safe.

## Decision

Use an operator-selected, self-hosted MISP instance for bounded lookups of
explicitly selected domain and IP indicators. Keep the adapter opt-in and keep
ordinary local triage offline. Report exact observed matches with provenance;
do not calculate a sender reputation, probability, allow/block decision or mail
disposition.

MISP is AGPL-3.0 open-source software with on-premises deployment and structured
indicator exchange. This makes it a practical first backend without coupling
mail-triage to a proprietary reputation vendor. It is a platform, however, not
a guarantee that its configured intelligence is public, accurate or current.
The operator must supply and govern the data. See the official
[MISP repository](https://github.com/MISP/MISP).

## Alternatives considered

| Option | Useful capability | Recommendation |
| --- | --- | --- |
| Self-hosted MISP | Atomic attributes, event provenance, existing feed imports and REST search | First integration: one tightly scoped lookup endpoint |
| Self-hosted OpenCTI Community Edition | STIX-oriented intelligence graph and relationships | Defer until the operator already runs it or needs relationship queries |
| Self-hosted DNS resolver / DoH | Current A, AAAA, MX, TXT, PTR and DNS response observations | Separate future evidence adapter; DNS resolution is not threat intelligence |
| Direct public feeds/APIs | Additional, source-specific indicator coverage | Import selected sources into operator MISP first; avoid per-message calls to multiple providers |

OpenCTI Community Edition is Apache-2.0; its Enterprise Edition has a separate
license. The documented architecture includes a GraphQL platform, workers,
connectors, Elasticsearch/OpenSearch, Redis, object storage and RabbitMQ. The
extra deployment and query surface is unnecessary for the initial exact-value
use case. This is a scope judgment, not a comparison of detection quality. See
[OpenCTI editions](https://github.com/OpenCTI-Platform/opencti) and
[deployment architecture](https://docs.opencti.io/latest/deployment/overview/).

Unbound is a self-hostable validating recursive resolver. It supports downstream
DoH, with TLS and HTTP/2. Standard DoH uses DNS wire messages with
`application/dns-message`; a provider-specific JSON DNS API is not equivalent
to the interoperable wire format. A future adapter should distinguish DNS
RCODEs from HTTP status: an HTTP 200 response can still contain NXDOMAIN or
SERVFAIL. See [Unbound DoH](https://unbound.docs.nlnetlabs.nl/en/latest/topics/privacy/dns-over-https.html)
and [RFC 8484](https://www.rfc-editor.org/info/rfc8484/).

MISP supports MISP-format, CSV and free-text feeds, with distinct caching and
import operations. An attribute search over locally stored data should not be
described as a search of all configured feed caches. Fetch/import the selected
sources before using this adapter; feed provisioning is outside mail-triage.
See [MISP feeds](https://www.misp-project.org/feeds/).

Public availability does not remove access, usage or freshness constraints. For
example, ThreatFox requires an Auth-Key, applies fair-use/commercial terms, and
has expired indicators older than six months from API/export results since
2025-05-01 to reduce stale-infrastructure false positives. It is useful input
for a curated collection, not universal sender reputation. See
[ThreatFox API](https://threatfox.abuse.ch/api).

## Phase-one trust boundary

1. Accept only a small operator-supplied list of domain and IP values. Record
   them as operator-selected indicators. Selection alone does not establish
   their relationship to the message or its SMTP sender.
2. Never infer an originating IP from uploaded `Received`, `X-Originating-IP`,
   `Authentication-Results` or other MIME headers. A parsed From-domain is also
   an unverified claim, not permission for automatic external disclosure.
3. Normalize and validate before dispatch: canonical IP literals and bounded
   DNS domain names. Reject URLs, ports, CIDRs, wildcards, search operators,
   control characters and unsupported types. Do not reduce domains to their
   last two labels or automatically search parents/subdomains.
4. Do not perform forward/reverse DNS, SPF/DKIM/DMARC evaluation, URL retrieval,
   recursive enrichment, feed updates, event creation or sightings submission.
5. Use the existing controlled transport: explicit HTTPS origin and IP pin,
   TLS verification, fixed method/path, explicit credentials, bounded bytes and
   deadlines, no redirects, proxies, retries or response-directed requests.
6. Send only the selected indicator and fixed search filters. Do not transmit
   the email body, headers, recipient list or attachments to MISP.

RFC 8601 makes authentication-results consumption dependent on a trust boundary;
SPF requires SMTP transaction inputs including the client IP and envelope
identity. OSINT lookup is a separate evidence channel and cannot fill missing
authentication evidence. See [RFC 8601](https://www.rfc-editor.org/rfc/rfc8601.html#section-1.2),
[RFC 7208](https://www.rfc-editor.org/rfc/rfc7208.html#section-4.1) and the local
[trusted-ingress contract](trusted-ingress.md).

## MISP request and projection contract

Use `POST /attributes/restSearch` with `returnFormat: "json"`, one validated
indicator value, selected simple attribute types, `deleted: false`, `page: 1`
and a bounded `limit`. Omit `to_ids` to preserve both contextual and actionable
attributes. No attachment/proposal/correlation/decay expansion is requested. Do not use `searchall` or `quickfilter`.

The documented JSON envelope is `response.Attribute`. The API offers
`X-Result-Count`, and `deleted: 1` selects only deleted attributes; selecting both
states uses `[0,1]`. `includeContext` and `requested_attributes` are CSV options,
not a way to minimize JSON fields. See the official [OpenAPI specification](https://www.misp-project.org/openapi/)
and [OpenAPI source](https://raw.githubusercontent.com/MISP/MISP/develop/app/webroot/doc/openapi.yaml).

Use `domain`/`hostname` for domain observations and `ip-src`/`ip-dst` for IP
observations. Exclude compound values such as `domain|ip` and `ip-dst|port` from
phase one. Independently verify the returned type and normalized value against
the selected indicator; a server-side search filter is not the local acceptance
boundary. Ignore unrelated types and non-exact values; never present them as sender evidence.
Malformed matching attributes fail the lookup closed. Do not invent an `exactMatch` REST parameter.

Preserve only bounded fields needed for review: local lookup time, endpoint
identity, queried indicator, response hash, attribute UUID, type,
value, `to_ids` and last-update timestamp. Event/organization context and
first/last-seen times are deferred. Keep all
external text inert. A source means the configured MISP response; an event UUID
or organization claim does not independently authenticate its original author.
The adapter retains its configured source ID/origin and attribute UUID;
original-author attribution is not independently verified. API-supplied
URLs never become follow-up destinations.

Prefer a read-only MISP auth key with limited account visibility, expiry and an
operator-maintained source-IP restriction. The automation guide documents these
controls and recommends checking the exact installed version's `/api/openapi`.
Provisioning credentials is a separate operator action; the adapter must not
create or save them. See [MISP automation](https://www.circl.lu/doc/misp/automation/).

## Important wire and interpretation details

- `timestamp` is the attribute's last-change time, represented as a decimal
  Unix-seconds JSON string. It is not the observation time or proof a feed is
  fresh. Keep a distinct local retrieval timestamp.
- `first_seen` and `last_seen` are optional ISO-8601 datetimes, and examples use
  null for missing values. Do not parse them as the seconds-based `timestamp`.
- `to_ids` is the source's actionability flag, not a maliciousness verdict or
  calibrated confidence. False does not mean benign.
- `deleted` denotes revocation. Request nondeleted results and locally refuse
  a revoked attribute as current evidence.
- Event/attribute distribution controls constrain dissemination. Do not assume
  intelligence returned by an authorized API key can be freely reshared.

These meanings are described in the project's [MISP core-format draft](https://www.misp-standard.org/rfc/misp-standard-core.html#section-2.3.2),
which is a work-in-progress format document, not an IETF Internet Standard.

Current implementation details matter: JSON export declares itself
nonrestrictive; numeric `to_ids: 0` can become a filter for false rather than
meaning "all". Omitting the filter avoids that ambiguity. The attribute model
converts stored microsecond observation timestamps to ISO text on read. The
value filter works on `value1`/`value2`, reinforcing the need to restrict types
and perform local exact-value checks. See official [JSON export](https://raw.githubusercontent.com/MISP/MISP/2.5/app/Lib/Export/JsonExport.php),
[event filters](https://raw.githubusercontent.com/MISP/MISP/2.5/app/Model/Event.php)
and [attribute model](https://raw.githubusercontent.com/MISP/MISP/2.5/app/Model/MispAttribute.php).

## Coverage and result language

- A valid match says that this instance returned that exact indicator at that
  time. It does not establish the indicator's ownership, current compromise,
  message authorship or maliciousness.
- An empty valid result says no matches were returned within this query's
  visibility and limits. Never label it "clean", "trusted" or "safe".
- Authentication failure, timeout, malformed data and unavailable service are
  errors, never empty successful searches.
- A full first page retains a `possibly_truncated` warning. The adapter does
  not interpret `X-Result-Count`; reported and undisclosed server-side caps
  cannot establish exhaustive coverage. Do not follow pagination automatically or claim exhaustive
  coverage. If the server applies an undisclosed smaller cap, completeness
  cannot be independently established.
- Preserve per-indicator outcomes when some queries fail. An overall summary
  must not erase errors, skipped indicators or bounded/truncated coverage.
- No lookup outcome changes the deterministic authentication evidence or the
  existing requirement for analyst review.

## Deferred work and validation

Keep DNS in a separately enabled adapter with explicit query types, resolver
identity, question/answer validation, record/byte/query budgets, bounded CNAME
handling, TTL/RCODE provenance and no automatic querying of returned names.
DoH encrypts the path to the resolver; the resolver can still observe queries,
and recursive resolution may disclose names to upstream servers. A/AAAA/MX
answers and PTR agreement are contextual observations, not sender identity.

Before live deployment, verify the installed MISP release and an operator-owned
test instance. Exercise true/false `to_ids`, deleted results, missing/invalid
timestamps, duplicate attributes, unrelated values, near matches, full pages,
malformed totals, oversized replies, authorization failures and cancellation.
Mock tests demonstrate local mechanics only; they do not establish live MISP
compatibility, feed quality, sender-reputation accuracy or phishing accuracy.

## Implemented CLI and limits

The `sender-osint` command reads a local regular `.eml`, creates a new private
case, and embeds typed evidence in `report.json` and the inert HTML report.
It never changes an existing case. The email's exact SHA-256 binds the lookup
record to that case, but does not prove the selected indicators belong to it.
The source is the configured MISP origin/ID; attribute UUIDs are claims from it.

Example nonsecret configuration (documentation-only TEST-NET endpoint):

```json
{
  "enabled": true,
  "sources": [{
    "source_id": "local",
    "endpoint": {
      "origin": "https://misp.example",
      "pinned_ip": "192.0.2.1",
      "allow_private_ip": true
    }
  }],
  "indicators": [{"kind": "domain", "value": "sender.example"}],
  "max_age_seconds": 604800,
  "min_interval_seconds": 1.0,
  "max_attributes": 100
}
```

```sh
mail-triage sender-osint synthetic.eml --config osint.json --out reports/osint-case \
  --allow-egress --secrets-stdin
```

Supply a JSON object on stdin with `keys` mapping each configured source ID to
its MISP API key. Do not put keys in command-line arguments, config, environment,
reports or shell history. Provisioning keys and real-endpoint acceptance are
operator actions outside this implementation. The example endpoint is not a
working service. Only explicitly selected indicators are disclosed to each
configured MISP instance; approve that disclosure before running on real data.

Defaults are disabled; both CLI switches and `enabled: true` are necessary for
requests. The library also requires `allow_egress=True`. The CLI rejects an
existing output before any query. Credentials are read only from bounded stdin,
never discovered or saved. A disabled configuration produces `NOT_RUN` evidence.

Limits: at most four distinct endpoints, eight unique indicators, one page per
pair (32 queries total), 1–1,000 attributes per response, a 4 KiB request and
1 MiB response cap, plus existing endpoint connect/read/total deadlines (default
5/5/15 seconds). Query starts are serialized and at least one second apart,
including after service errors, within each adapter invocation. This is a
per-run limiter, not a distributed rate limiter across processes; operators
must enforce aggregate quotas at their MISP/reverse proxy. There are no retries,
backoff loops, pagination, model calls or response-directed lookups. Task/SIGINT
cancellation stops further dispatch. A remotely received query cannot be undone.

`update_recency` is `CURRENT`, `STALE` or `FUTURE` relative to retrieval and the
configured age window. It describes last-update age only, not intelligence
validity. `conflicting_to_ids` lists indicators with both current true and false
flags, even across separate configured sources; it is a flag disagreement, not
proof that one source considers the indicator benign. Every source result is
retained. An overall `OBSERVED` can coexist with per-source errors; the CLI
returns 3 when any query failed, 2 for input/configuration/I/O errors, and 130
for cancellation. Missing evidence is `UNKNOWN`, never a favorable reputation.

OSINT cases use report schema 1.2. Reports without OSINT retain 1.1 and now emit
a nullable `sender_osint_evidence` field; this reader accepts legacy 1.0/1.1
reports without it. Older strict readers may need updating for the added field.
No historical demo reports are rewritten. The report's disposition stays
`REVIEW_REQUIRED`; OSINT cannot replace trusted ingress authentication or
invent gateway telemetry. Exact schema/behavior compatibility with a deployed
MISP release, TLS handshake, credentials, real feeds and production cancellation
remain unverified. All added tests use synthetic attributes and mock transport;
existing tests prohibit network and DNS access globally.
