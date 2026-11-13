"""Reproduce wire schemas from the pinned Pydantic models; no network access."""

import json
from pathlib import Path

from mail_triage.ingress_contract import (
    IngressAssertionV1,
    IngressTrustPolicy,
    SignedEnvelopeV1,
)

root = Path(__file__).resolve().parents[1] / "docs" / "schemas"
root.mkdir(exist_ok=True)
for name, model in (
    ("ingress-envelope-v1", SignedEnvelopeV1),
    ("ingress-assertion-v1", IngressAssertionV1),
    ("ingress-trust-v1", IngressTrustPolicy),
):
    schema = model.model_json_schema()
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    schema["$id"] = f"urn:mail-triage:{name}"
    (root / f"{name}.json").write_text(json.dumps(schema, indent=2) + "\n", encoding="utf-8")
