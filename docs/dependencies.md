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
