# Dependency provenance

Official PyPI JSON metadata was retrieved on 2026-10-14 before installation.
The project uses exact direct pins; `uv.lock` records transitive versions, official
registry URLs and distribution hashes. No model provider package or service was
configured. DSPy brings provider SDKs transitively; installing those is not a
connection or an inference run.

| Dependency | Version | Role | Official metadata |
| --- | --- | --- | --- |
| Pydantic | 2.14.1 | Typed evidence and report validation | https://pypi.org/pypi/pydantic/json |
| Pydantic AI Slim | 2.56.0 | Optional typed content hypothesis | https://pypi.org/pypi/pydantic-ai-slim/json |
| DSPy | 3.4.1 | Optional held-out fixture evaluation | https://pypi.org/pypi/dspy/json |
| pytest | 9.1.1 | Verification | https://pypi.org/pypi/pytest/json |
| Ruff | 0.17.0 | Lint and format | https://pypi.org/pypi/ruff/json |
| mypy | 2.4.0 | Strict application typing | https://pypi.org/pypi/mypy/json |
| Hatchling | 1.32.4 | Package build | https://pypi.org/pypi/hatchling/json |

The tested interpreter is the Mac's already installed CPython 3.12.11, selected
only inside this project's `.venv`. `.python-version` and `requires-python` keep
this initial version on Python 3.12; private stdlib MIME hooks have regression
tests and must be reviewed before supporting another Python minor version.

Framework references: [Pydantic AI agents](https://pydantic.dev/docs/ai/core-concepts/agent/),
[Pydantic AI testing](https://pydantic.dev/docs/ai/testing/),
[DSPy signatures](https://dspy.ai/learn/programming/signatures/).
