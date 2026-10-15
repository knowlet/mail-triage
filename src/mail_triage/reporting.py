"""Write private local case artifacts without interpreting message markup."""

import hashlib
import html
import json
import os
import shutil
import tempfile
from pathlib import Path

from mail_triage.schemas import Check, Report


def _escape(value: object) -> str:
    # Make invisible controls visible, including terminal escapes and bidi overrides.
    visible = "".join(
        f"\\u{ord(char):04x}"
        if (ord(char) < 32 and char not in "\n\t")
        or 0x202A <= ord(char) <= 0x202E
        or 0x2066 <= ord(char) <= 0x2069
        else char
        for char in str(value)
    )
    return html.escape(visible, quote=True)


def _check(label: str, check: Check) -> str:
    observations = "".join(f"<li>{_escape(item)}</li>" for item in check.observations)
    return (
        f"<article><h3>{_escape(label)} <span>{_escape(check.status)}</span></h3>"
        f"<p>{_escape(check.reason)}</p><ul>{observations}</ul></article>"
    )


def render_html(report: Report) -> str:
    """Return inert HTML; email HTML, URLs and all metadata are escaped text."""
    auth = "".join(
        _check(name.upper(), getattr(report.authentication, name))
        for name in ("spf", "dkim", "dmarc", "alignment")
    )
    ingress = report.authentication.trusted_ingress
    if ingress is not None:
        auth += (
            f"<h3>Ingress evidence source: {_escape(ingress.status)}</h3>"
            f"<p>{_escape(ingress.reason_code)}</p>"
            "<p>Source acceptance is separate from authentication results and message safety.</p>"
            f"<pre>{_escape(json.dumps(ingress.results.model_dump(), indent=2))}</pre>"
        )
    finding_rows = "".join(
        f"<article><h3>{_escape(item.code)}</h3><p>{_escape(item.description)}</p>"
        + "".join(f"<pre>{_escape(value)}</pre>" for value in item.evidence)
        + "</article>"
        for item in report.content.findings
    )
    if not finding_rows:
        finding_rows = (
            "<p>No configured heuristic matched. "
            "This does not establish that the message is safe.</p>"
        )
    previews = "".join(
        f"<h3>Part {_escape(segment.part_id)} · {_escape(segment.kind)}</h3>"
        f"<pre>{_escape(segment.text)}</pre>"
        for segment in report.message.text_segments
    )
    rows = "".join(
        "<tr>"
        + "".join(
            f"<td>{_escape(value)}</td>"
            for value in (
                part.part_id,
                part.media_type,
                part.filename or "—",
                part.decoded_bytes,
                "yes" if part.is_attachment else "no",
                part.sha256,
            )
        )
        + "</tr>"
        for part in report.message.parts
    )
    integrations = "".join(
        _check(name.replace("_", " "), getattr(report.reputation, name))
        for name in type(report.reputation).model_fields
    )
    models = "".join(_check(name, stage) for name, stage in report.model_stages.items())
    warnings = "".join(f"<li>{_escape(value)}</li>" for value in report.warnings)
    raw_json = _escape(json.dumps(report.model_dump(mode="json"), indent=2, ensure_ascii=True))
    report_kind = (
        "GRAPH ORIGINAL · EXPLICIT CONNECTOR REPORT"
        if report.provenance.source_kind == "graph_original"
        else "OFFLINE CASE REPORT"
    )
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none';
 style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<meta name="referrer" content="no-referrer">
<title>Mail Triage · Local review</title>
<style>
:root {{color-scheme:light; font-family:system-ui,sans-serif; color:#193047; background:#eef2f6}}
body {{max-width:1120px; margin:32px auto; padding:0 24px 40px}}
header,section {{background:white; padding:24px; margin:20px 0; border-radius:12px}}
h1 {{margin-bottom:8px}} h2 {{margin-top:0}} h3 {{font-size:1rem}}
.badge,span {{background:#fff1cd; color:#674800; padding:4px 8px; border-radius:5px}}
span {{font-size:.75rem}} .muted {{color:#53677b}} article {{border-top:1px solid #dde5ec}}
pre {{white-space:pre-wrap; overflow-wrap:anywhere; background:#f4f7fa; padding:14px;
 border-radius:6px; font-size:.85rem; unicode-bidi:plaintext}}
table {{border-collapse:collapse; width:100%; font-size:.8rem}}
td,th {{padding:9px; text-align:left; border-bottom:1px solid #dde5ec; overflow-wrap:anywhere}}
th {{white-space:nowrap; overflow-wrap:normal}}
.table {{overflow:auto}} code {{overflow-wrap:anywhere}} li {{margin:7px 0}}
</style></head><body>
<header><p class="muted">MAIL TRIAGE · {report_kind}</p>
<h1>{_escape(report.message.subject or "(no subject)")}</h1>
<p><strong class="badge">REVIEW REQUIRED</strong></p>
<p>Heuristic observations support human review. They do not prove phishing, safety, or identity.</p>
<p>Source: {_escape(report.provenance.source_name)} · {report.provenance.raw_bytes} bytes</p>
<p>SHA-256: <code>{_escape(report.provenance.sha256)}</code></p>
<p>Ingested: {_escape(report.provenance.ingested_at.isoformat())}</p></header>
<section><h2>Authentication and alignment</h2>
<p>{_escape(report.authentication.trust_boundary)}</p>{auth}</section>
<section><h2>Content observations</h2>{finding_rows}</section>
<section><h2>Message source as inert text</h2>
<p>HTML below is source text. Links and attachments are not opened or fetched.</p>
{previews}</section>
<section><h2>MIME inventory</h2><div class="table"><table>
<thead><tr><th>Part</th><th>Type</th><th>Filename (untrusted)</th><th>Decoded bytes</th>
<th>Attachment</th><th>SHA-256</th></tr></thead><tbody>{rows}</tbody></table></div></section>
<section><h2>External evidence</h2>{integrations}</section>
<section><h2>Model stages</h2>{models}</section>
<section><h2>Limitations and warnings</h2><ul>{warnings}</ul></section>
<section><details><summary>Full typed report JSON</summary><pre>{raw_json}</pre></details></section>
</body></html>
"""


def write_case(output: Path, raw: bytes, report: Report) -> None:
    """Write a new private case directory; refuse existing paths, including symlinks."""
    if report.provenance.sha256 != hashlib.sha256(
        raw
    ).hexdigest() or report.provenance.raw_bytes != len(raw):
        raise ValueError("Report provenance does not match the original bytes.")
    # Parent must already exist. Do not create a hierarchy derived from message data.
    output = output.absolute()
    temporary = Path(tempfile.mkdtemp(prefix=".mail-triage-", dir=output.parent))
    try:
        for filename, contents in (
            ("original.eml", raw),
            ("report.json", (report.model_dump_json(indent=2) + "\n").encode("utf-8")),
            ("report.html", render_html(report).encode("utf-8")),
        ):
            path = temporary / filename
            with path.open("xb") as stream:
                os.chmod(path, 0o600)
                stream.write(contents)
                stream.flush()
                os.fsync(stream.fileno())
        # mkdir provides an atomic no-clobber reservation even for an existing empty directory.
        output.mkdir(mode=0o700)
        try:
            for path in temporary.iterdir():
                path.rename(output / path.name)
            for directory in (output, output.parent):
                descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try:
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
        except BaseException:
            shutil.rmtree(output)
            raise
    finally:
        shutil.rmtree(temporary)
