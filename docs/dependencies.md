# Dependency provenance

The project uses exact direct pins in `pyproject.toml`; `uv.lock` records
transitive versions, official registry URLs and distribution hashes. Official
PyPI metadata was checked on 2026-10-14. Installation does not connect a provider,
read a mailbox or run inference. The optional DSPy dependency brings provider SDKs
transitively; the configured model adapter does not instantiate those SDKs.

| Dependency | Version | Role | Official metadata |
| --- | --- | --- | --- |
| Pydantic | 2.14.1 | Typed evidence, reports and connector configuration | https://pypi.org/pypi/pydantic/2.14.1/json |
| HTTPX | 0.28.1 | Optional controlled asynchronous HTTP adapters and MockTransport | https://pypi.org/pypi/httpx/0.28.1/json |
| Pydantic AI Slim | 2.56.0 | Optional typed content hypothesis | https://pypi.org/pypi/pydantic-ai-slim/2.56.0/json |
| DSPy | 3.4.1 | Optional authored held-out fixture evaluation | https://pypi.org/pypi/dspy/3.4.1/json |
| pytest | 9.1.1 | Verification | https://pypi.org/pypi/pytest/9.1.1/json |
| Ruff | 0.17.0 | Lint and format | https://pypi.org/pypi/ruff/0.17.0/json |
| mypy | 2.4.0 | Strict application typing | https://pypi.org/pypi/mypy/2.4.0/json |
| Hatchling | 1.32.4 | Package build | https://pypi.org/pypi/hatchling/1.32.4/json |

HTTPX is a base installed dependency so the connector commands work without a
separate HTTP extra. The offline `triage` path does not import connector modules
or use HTTPX. `--extra models` installs the optional frameworks for configured
review and scripted framework tests; DSPy is used only for separate evaluation.
No Assemblyline/Sublime engine images, Microsoft SDK, model runtime, database,
credential store or hosted service is bundled.

The tested interpreter is the Mac's already installed CPython 3.12.11, selected
inside this project's `.venv`. `.python-version` and `requires-python` keep the
prototype on Python 3.12. Private stdlib MIME hooks have construction-limit
regression tests and need review before supporting another Python minor version.

Transport uses HTTPX's default certifi CA bundle with verification on and
`trust_env=False`; it does not load `SSL_CERT_FILE` / `SSL_CERT_DIR` overrides.
There is no `verify=False`, custom CA-file setting or proxy inheritance. A
self-hosted certificate must chain to that bundle's trusted roots. Exact IP
pins are explicit operational configuration and must be maintained as addresses
change. Test mocks establish policy mechanics, not real DNS/TLS/service compatibility.

References: [HTTPX transports](https://www.python-httpx.org/advanced/transports/),
[Pydantic AI agents](https://pydantic.dev/docs/ai/core-concepts/agent/),
[Pydantic AI testing](https://pydantic.dev/docs/ai/testing/),
[DSPy signatures](https://dspy.ai/learn/programming/signatures/).

## Trusted-ingress additions

The core now explicitly pins `idna==3.20` (IDNA2008 A-label normalization) and
`tldextract==5.3.0` (offline organizational-domain resolution). The lock also
adds `requests-file==3.0.1`; other HTTP dependencies were already present.
No new cryptography dependency is added: HMAC-SHA256 uses Python's standard library.
The receiver disables tldextract URL updates and disk caches, enables PRIVATE
suffix rules, and checks its bundled snapshot SHA-256 against the contract pin.
This is reproducible offline behavior, not a claim that the bundled PSL is current.
See the [snapshot/version boundary](trusted-ingress.md#mechanisms-and-alignment).
No upstream source or PSL asset is copied into this repository; locked packages
retain their own licensing and provenance.

## Filelock security follow-up (2026-11-10)

The lock now selects filelock 4.2.1, the first patched release for the October
advisories affecting 3.32.7. In particular,
[GHSA-69hj-f68j-2879](https://github.com/tox-dev/filelock/security/advisories/GHSA-69hj-f68j-2879)
describes Unix lock acquisition truncating an existing regular file at the lock
path and changing its mode when an explicit mode is requested. Exploitation
requires local filesystem access with the described rename/hard-link permissions;
this is not evidence of exploitation through a reported email.

The original LiteLLM 1.105.1 requires `filelock<4.0`, so a filelock-only update
would not satisfy the optional model dependency graph. The resolver-compatible
update uses LiteLLM 1.108.4 (`filelock<5`), plus its minimum boto3 1.43.117 and the
matching botocore 1.43.117. All direct project pins and the other 86 package
records are unchanged. CI-pinned uv 0.12.23 regenerated the lock (revision 5);
no dependency override or ignored advisory is used. Distribution URLs, sizes and
SHA-256 hashes for all four changed packages were checked against official PyPI
metadata, which returned no known advisories for those exact versions. This is
not a guarantee that those packages are free of defects.

Seven bounded offline regression/control cases cover the installed FileLock and
Hugging Face WeakFileLock consumer, existing-file and hard-link byte/mode
preservation, ordinary contention/release, and the production resolver's disabled
disk-lock path. The old filelock fails all four preservation cases; the fixed
version passes all seven. These use synthetic files owned by the test process,
not another user's files or a cross-account attack. Platform-specific Unix tests
do not establish Windows or macOS acceptance. Full offline application checks also
exercise the existing scripted model stubs; no provider or model is called.

### Remaining DiskCache advisory

The optional DSPy dependency still installs diskcache 5.6.3.
[GHSA-w8v5-vhqr-4h9v](https://github.com/advisories/GHSA-w8v5-vhqr-4h9v)
has no published patched version in the metadata checked for this update. It
concerns default pickle deserialization when an attacker can write the cache
directory. This update neither removes DiskCache nor claims it is safe. Core
PSL processing uses tldextract's separate JSON cache implementation with disk
caching disabled; that is not a remediation for DSPy's optional cache. Existing
tests redirect DSPy cache state into the isolated test directory and deny network
connections. No user's cache permissions or system settings were changed.
