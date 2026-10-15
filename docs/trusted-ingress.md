# Trusted-ingress authentication evidence, version 1

This implements an **offline evidence receiver**, not an SMTP gateway, a local
SPF/DKIM verifier, a DMARC DNS resolver, or a production Outlook integration.
An explicitly provisioned ingress producer authenticates an attestation with a
per-issuer HMAC-SHA256 key. The receiver verifies that evidence independently of
all MIME headers and projects typed results into report schema **1.1**. Legacy
1.0 reports remain readable; loading any report is not a new verification event.

No authorized enterprise tenant, real gateway, live SMTP/DNS authentication or
production key custody has been tested. Synthetic tests establish contract
behavior, not real-world authentication correctness or phishing accuracy.

## Trust boundary and original identity

The producer must obtain results from its actual SMTP session, controlled SPF/
DKIM/DMARC verifier and policy evaluator. It must sanitize forged *internal*
authentication assertions at its configured boundary before exporting the
bound artifact. `internal_auth_headers_sanitized: true` is accepted only inside
a valid MAC from an explicitly authorized issuer/key/boundary/verifier version.
It is an attestation of producer behavior, not proof that its implementation is
correct. A compromised/misconfigured authorized producer can still lie.

`Authentication-Results`, an allowlisted `authserv-id`, `Received`, `Received-SPF`,
`Return-Path`, `DKIM-Signature`, ARC and model-generated assertions are never
promoted to trusted results. They remain inert, untrusted observations in the
report, including when a separate envelope is accepted. The receiver does not
strip or reserialize `original.eml`: that would change the authenticated bytes.
External Authentication-Results can remain present without affecting decisions.
See [RFC 8601, especially sections 5 and 7](https://www.rfc-editor.org/rfc/rfc8601.html).

The attestation binds SHA-256 **and byte length of the exact complete original
MIME**, plus an independent `{tenant_id, mailbox_id, message_id}` object identity.
The expected identity must come from an authorized adapter/orchestrator or
operator, never be copied from the attestation or from MIME `Message-ID`.
Mailbox/object IDs are case-sensitive, opaque identifiers in the selected
original-artifact namespace; they are not SMTP sender/recipient identities.
There are no wildcard grants. Identity and hash are both required: neither is
a substitute for the other. Body changes, newline conversion, reserialization,
wrapper substitution and reuse against another object/mailbox/tenant are rejected.
The exact bytes are reparsed to require exactly one From header and one author
mailbox; the author domain must match the attested domain after IDNA normalization.

**Graph is not an authentication authority here.** The existing Graph adapter
still yields UNKNOWN for all four checks. Graph's original itemAttachment MIME
is the exact API response, not a promise of original SMTP wire bytes. Version 1
requires byte equality; it has no transformation/canonicalization attestation.
A gateway-to-Graph original-identity/custody mapping is not implemented. Do not
rehash a Graph response and attach an old SMTP result merely because the sender,
subject or Message-ID matches. Use the retained, correctly bound ingress original,
or leave authentication UNKNOWN until an authorized adapter proves the binding.
See [Graph MIME retrieval](https://learn.microsoft.com/en-us/graph/outlook-get-mime-message).

## Versioned wire records

Authoritative types are in [ingress_contract.py](../src/mail_triage/ingress_contract.py).
Published JSON Schemas:

- [Signed envelope](schemas/ingress-envelope-v1.json): `mail-triage.ingress-envelope/1`.
- [Decoded assertion](schemas/ingress-assertion-v1.json): `mail-triage.ingress-assertion/1`.
- [Operator trust policy](schemas/ingress-trust-v1.json): `mail-triage.ingress-trust/1`.

All records reject unknown fields, duplicate JSON keys, wrong types (including
boolean-as-integer and truthy strings), unsupported versions/algorithms/profiles
and oversized values. JSON Schema alone cannot enforce signatures, identity,
time, policy applicability, alignment consistency or replay rules. Use the actual
verifier, not `model_validate()` or a supplied `trusted: true` flag.
Regenerate schemas with `.venv/bin/python scripts/export_ingress_schemas.py`.

The envelope contains `schema_version`, `algorithm`, `issuer_id`, `key_id`,
`payload`, and `mac`. `payload` is **canonical unpadded base64url** of the original
UTF-8 assertion JSON bytes. No decode/reserialize cycle is used for MAC checking;
JSON formatting need not be canonical. Duplicate keys inside the signed payload
are still forbidden. The lowercase hexadecimal MAC is:

```text
HMAC-SHA256(key,
  ASCII("mail-triage.ingress.mac.v1") || NUL ||
  ASCII(schema_version) || NUL || ASCII(algorithm) || NUL ||
  ASCII(issuer_id) || NUL || ASCII(key_id) || NUL || ASCII(payload))
```

The algorithm is exactly `HMAC-SHA256`. There is no `none`, key URL, JWKS lookup,
algorithm negotiation or certificate/header trust shortcut. The protected issuer
and key ID select an **out-of-band grant and secret**, not a key supplied by email.
The assertion contains audience, event ID, issuance/expiry/receive timestamps,
boundary/verifier version, original binding, author domain, individual mechanism
results, evaluated DMARC policy provenance, and claimed alignment/profile.
The signed envelope and parsed assertion are retained only after acceptance;
rejections retain a bounded reason code and, when within the input cap, input hash.
Secret keys are never retained in reports.

## Provisioned source identity, time and keys

The trust policy maps each unique `(issuer_id, key_id)` to a tenant, explicit
mailbox list, audience, boundary ID, approved producer version, and key validity
window. Keep this policy and all parent paths in operator-controlled storage,
not an upload directory. It must not be selectable by an untrusted API client.
Future HTTP adapters must apply their own authenticated authorization before
selecting the expected object and trust policy. No HTTP listener is added here.

Keys arrive separately as stdin JSON:

```json
{"keys":[{"issuer_id":"YOUR_ISSUER","key_id":"YOUR_KEY_ID","key_hex":"64_LOWERCASE_HEX_CHARACTERS_FROM_32_RANDOM_BYTES"}]}
```

The placeholder above is intentionally not valid key material. Provision 32
cryptographically random bytes per independent issuer/key; never reuse the
public fixture key from tests. There are no environment, keychain, credential-file
or implicit secret lookups. Rotate by adding an explicitly granted key/window,
then removing the old grant and secret; revocation is local policy removal.
The same issuer/event ID cannot be replayed under a rotated key.

**HMAC is a symmetric message authentication code, not a public-key digital
signature or non-repudiation mechanism.** Both producer and verifier holding the
key can forge attestations. Protect their processes, key delivery and filesystem;
compromise of either side breaks this trust model. Do not place keys in shell
arguments, policy files, email, logs or the repository. An asymmetric envelope
would require a separately reviewed contract version, not a silent algorithm swap.

Timestamps are integer Unix seconds. Defaults/maximum configurable values are:

| Gate | Default | Maximum |
| --- | --- | --- |
| Age since issuance | 900 seconds | 86,400 seconds |
| Issued-to-expiry lifetime | 900 seconds | 86,400 seconds |
| Age since original receipt | 30 days | 90 days |
| Future clock skew | 60 seconds | 300 seconds |

Expiry is strict (`now < expires_at`), even within the clock-skew allowance.
Both issuance and current verification time must be inside the key's validity
window. Receipt may predate issuance for delayed user reports, but must remain
inside the receive-age window and cannot be implausibly after issuance/current
time. The service clock is part of the trusted computing base. The CLI has no
clock override; tests inject a fixed clock through the Python interface.

## Mechanisms and alignment

An evaluated SPF result requires the actual SMTP peer IP, tested identity scope
and domain. Missing SMTP context can be represented only as SPF `UNKNOWN` with
null peer/domain, allowing independently verified DKIM evidence to remain useful.
A HELO pass is DMARC-eligible only for a null MAIL FROM reverse path. Return-Path
and Received headers are never used to reconstruct this context.

DKIM retains bounded per-signature results, d= domain and selector, plus a
`complete` flag. Any *passing and aligned* signature can satisfy DKIM alignment;
an unaligned first signature does not hide a later aligned pass. An incomplete
set without an aligned pass is UNKNOWN, not a definitive alignment failure.
The receiver does not perform DKIM cryptography or certify that all signatures
were actually evaluated. The authorized producer is responsible for those facts.

The fixed profile is `rfc7489-psl-private-v1`, based on
[RFC 7489 identifier alignment](https://www.rfc-editor.org/rfc/rfc7489.html#section-3.1):

- Strict (`s`) compares normalized IDNA2008 A-label domains exactly.
- Relaxed (`r`) compares organizational domains from the **pinned bundled PSL**,
  with ICANN **and PRIVATE** rules, wildcard/exception handling, no network fetch
  and no ambient cache. Unknown suffixes or suffix-only names yield UNKNOWN,
  never a last-two-label guess. PRIVATE is an explicit conservative profile
  choice; producers using a different organizational-domain policy must not
  claim this profile. Cross-tenant `github.io` names therefore do not align.
- Alignment is *authenticated* alignment: matching domains on a failed signature,
  softfail/neutral SPF or unverified headers do not count as a pass. Temporary,
  permanent and unknown verification errors remain indeterminate for alignment.

`tldextract==5.3.0` is deliberately locked. Its bundled snapshot SHA-256 is
`b69315c085d53972724b8f2df111ffc329b0c84fe0a47d62c8c91655cc774a38`.
Both the attested snapshot and installed snapshot must match. IDNA normalization
uses pinned `idna==3.20`, not permissive URL parsing or Unicode casefolding.
The PSL is not automatically kept current. Review its suitability and freshness
before production; a snapshot/profile update needs coordinated producer/receiver
review and regression tests. See [the PSL source](https://publicsuffix.org/list/).

The receiver recomputes SPF/DKIM alignment and rejects inconsistent signed
alignment claims. DMARC PASS requires applicable evaluated policy provenance
and an authenticated aligned SPF **or** DKIM pass. DMARC FAIL cannot contradict
an aligned pass or incomplete/indeterminate evidence. Policy domain must be the
author domain or its organizational domain. This is a consistency/applicability
check, **not** a live DNS policy discovery/precedence check. `p=none` is a policy,
not a failed authentication result. A no-policy (`NONE`), error or unknown DMARC
result is never upgraded merely because some domain comparison passes.

## Replay and resource bounds

Use one persistent, pre-created `0700` ledger directory owned by the service UID,
with trusted parent directories. Each accepted event claims a `0600` file using
exclusive create, keyed by SHA-256 of issuer + NUL + event ID. The directory is
opened without following its final symlink; the receipt and directory are fsynced.
The event ID must be unique across that issuer's tenants/mailboxes and key rotations.
All MAC/hash/identity/time/boundary/alignment checks finish **before** consuming
an event. Concurrent duplicate attempts have at most one winner. Invalid inputs
cannot consume a fresh event. Missing, unsafe or unavailable ledgers fail closed.

This is a **single-host filesystem replay barrier**, not a distributed database
or end-to-end transactional case store. A storage failure or crash can consume
an event before the case report is written. It must not be silently replayed;
obtain a freshly issued event after investigating the failure. Do not delete or
reset ledger entries automatically. Protect ledger continuity across restarts;
its removal/replacement by an attacker defeats replay protection. Existing case
reports are historical output, not tokens for bypassing current verification.

Envelope/policy inputs are capped at 64 KiB, decoded assertion JSON at 32 KiB,
secret JSON at 16 KiB, DKIM signatures at 32, and grants at 32 with up to 32
mailboxes each. MIME keeps the existing 5 MiB default and parser resource limits.
CLI files must be regular files, not final-path symlinks/FIFOs. No DNS/HTTP, model,
OSINT, Assemblyline, Sublime or mailbox request is dispatched by this command.

## Run and consume the report

After separately provisioning a real producer, policy, keys and expected object:

```sh
mkdir -m 700 /YOUR_PRIVATE_STATE/ingress-replay
.venv/bin/mail-triage trusted-ingress /YOUR_PRIVATE_CASE/original.eml \
  --evidence /YOUR_PRIVATE_CASE/ingress-envelope.json \
  --trust-policy /YOUR_OPERATOR_CONFIG/ingress-trust.json \
  --tenant-id EXPECTED_TENANT --mailbox-id EXPECTED_MAILBOX \
  --original-id EXPECTED_ORIGINAL_OBJECT_ID \
  --replay-dir /YOUR_PRIVATE_STATE/ingress-replay \
  --out /YOUR_PRIVATE_CASE/new-report --secrets-stdin
```

Supply the key JSON through a protected stdin channel, not an argument. No
production configuration or valid default key is included. For runnable synthetic
examples use `.venv/bin/pytest tests/test_trusted_ingress.py`; its independent
producer helper demonstrates the MAC framing with explicitly public fixture keys.

`authentication.trusted_ingress.status` is `MISSING`, `REJECTED`, or `ACCEPTED`.
The structured `results` separately records `spf`, `dkim`, `dmarc`,
`spf_alignment`, `dkim_alignment`, and combined `alignment`.
Missing/rejected evidence leaves **all four authentication checks UNKNOWN** and
all six typed results UNKNOWN. Accepted evidence can contain PASS, FAIL, NONE,
errors or UNKNOWN; acceptance is source verification, not a blanket auth pass.
Legacy `Check.status=OBSERVED` is still an observation state, not a PASS enum.
Consumers of schema 1.1 must read the typed results, not infer them from status.
The HTML report explicitly distinguishes source acceptance and authentication.

Exit 0 means the envelope was accepted, even when it reports DMARC FAIL. Exit 3
means rejected/missing usable evidence with an UNKNOWN report. Exit 2 means
invalid input/operator configuration or a case-write failure. Every successful
case write preserves exact `original.eml`, JSON and inert HTML; disposition stays
**REVIEW_REQUIRED**, regardless of authentication results. Authentication PASS
never establishes that content is benign or that a sender account is uncompromised.
