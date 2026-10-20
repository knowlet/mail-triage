"""Bounded, offline MIME ingestion. Message content is always untrusted data."""

from __future__ import annotations

import hashlib
import os
import re
import stat
from email import errors, policy
from email.feedparser import BytesFeedParser
from email.message import EmailMessage, MIMEPart
from email.utils import getaddresses
from pathlib import Path

from mail_triage.schemas import Header, Limits, MimePart, ParsedEmail, TextSegment


class IngestError(ValueError):
    """The input cannot be safely interpreted as an email message."""


class ResourceLimitError(IngestError):
    """The input exceeds an ingestion resource budget."""


class _BoundedParser(BytesFeedParser):
    """Stop nesting/part bombs before stdlib constructs the next message.

    These two private hooks are intentionally covered by regression tests. The
    stdlib calls _new_message before descending, and _parse_headers for every
    MIME part, including encapsulated messages.
    """

    _msgstack: list[EmailMessage]

    def __init__(self, limits: Limits) -> None:
        super().__init__(policy=policy.default.clone(raise_on_defect=True))
        self.limits = limits
        self.part_count = 0
        self.header_bytes = 0

    def _new_message(self) -> None:
        if self.part_count >= self.limits.max_parts:
            raise ResourceLimitError("MIME part count exceeds max_parts.")
        if len(self._msgstack) >= self.limits.max_depth:
            raise ResourceLimitError("MIME nesting exceeds max_depth (root counts as 1).")
        self.part_count += 1
        super()._new_message()  # type: ignore[misc]

    def _parse_headers(self, lines: list[str]) -> None:
        self.header_bytes += sum(len(line.encode("ascii", "surrogateescape")) for line in lines)
        if self.header_bytes > self.limits.max_header_bytes:
            raise ResourceLimitError("Cumulative MIME headers exceed max_header_bytes.")
        super()._parse_headers(lines)  # type: ignore[misc]


def read_eml(path: Path, limits: Limits) -> bytes:
    """Read only a regular, non-symlink final path, without blocking on a FIFO."""
    fd: int | None = None
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise IngestError("EML input must be a regular file.")
        if info.st_size > limits.max_raw_bytes:
            raise ResourceLimitError("EML input exceeds max_raw_bytes.")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, min(64 * 1024, limits.max_raw_bytes + 1 - total))
            if not chunk:
                return b"".join(chunks)
            chunks.append(chunk)
            total += len(chunk)
            if total > limits.max_raw_bytes:
                raise ResourceLimitError("EML input exceeds max_raw_bytes.")
    except OSError as exc:
        raise IngestError(
            f"Cannot read EML as a regular non-symlink file ({exc.strerror})."
        ) from exc
    finally:
        if fd is not None:
            os.close(fd)


def _validate_headers(message: EmailMessage) -> None:
    for part in message.walk():
        if part.defects:
            raise IngestError("MIME parser reported a malformed message.")
        # Headerregistry parses lazily. Access every value, including headers
        # on attachments, then reject any defects it would otherwise repair.
        for _name, value in part.items():
            if getattr(value, "defects", ()):
                raise IngestError("MIME parser reported a malformed header.")


def _decoded_payload(part: MIMEPart) -> bytes:
    encoding = str(part.get("Content-Transfer-Encoding", "7bit")).strip().lower()
    if encoding not in {"7bit", "8bit", "binary", "base64", "quoted-printable"}:
        raise IngestError("Unsupported Content-Transfer-Encoding.")
    if encoding == "quoted-printable":
        encoded = part.get_payload()
        if isinstance(encoded, str) and re.search(r"=(?![0-9A-Fa-f]{2}|\r\n|\n|\r)", encoded):
            raise IngestError("Malformed quoted-printable payload.")
    payload = part.get_payload(decode=True)
    if not isinstance(payload, bytes):
        raise IngestError("Expected a single MIME payload.")
    if part.defects:
        raise IngestError("MIME parser reported a malformed encoded payload.")
    return payload


def parse_eml(raw: bytes, limits: Limits | None = None) -> ParsedEmail:
    """Parse an EML without network access, HTML rendering, or attachment writes."""
    limits = limits or Limits()
    if len(raw) > limits.max_raw_bytes:
        raise ResourceLimitError("EML input exceeds max_raw_bytes.")
    if not raw or not re.search(rb"\r\n\r\n|\n\n|\r\r", raw):
        raise IngestError("EML input needs a header/body separator.")
    if any(len(line) > limits.max_line_bytes for line in re.split(rb"\r\n|\n|\r", raw)):
        raise ResourceLimitError("EML line exceeds max_line_bytes.")

    try:
        parser = _BoundedParser(limits)
        for offset in range(0, len(raw), 16 * 1024):
            parser.feed(raw[offset : offset + 16 * 1024])
        message = parser.close()
        if not isinstance(message, EmailMessage) or not message.keys():
            raise IngestError("EML input needs at least one header.")
        _validate_headers(message)
        return _inventory(message, limits)
    except IngestError:
        raise
    except (errors.MessageError, ValueError, TypeError, LookupError, RecursionError) as exc:
        # Do not echo attacker-controlled message content in errors/logs.
        raise IngestError(f"Malformed MIME message ({type(exc).__name__}).") from exc


def _inventory(message: EmailMessage, limits: Limits) -> ParsedEmail:
    parts: list[MimePart] = []
    segments: list[TextSegment] = []
    warnings: list[str] = []
    decoded_total = 0
    text_total = 0

    def visit(part: MIMEPart, part_id: str) -> None:
        nonlocal decoded_total, text_total
        media_type = part.get_content_type()
        disposition = part.get_content_disposition()
        filename = part.get_filename()
        is_attachment = (
            disposition == "attachment" or filename is not None or media_type.startswith("message/")
        )
        if part.is_multipart() and not is_attachment:
            for index, child in enumerate(part.iter_parts(), 1):
                visit(child, f"{part_id}.{index}")
            return
        if part.is_multipart():
            # stdlib represents message/rfc822 and multipart attachments as a
            # tree rather than raw payload bytes. Never mingle it with wrapper
            # headers/body. Its exact original bytes remain in original.eml.
            payload = part.as_bytes(policy=policy.default.clone(linesep="\r\n"))
            warnings.append(
                f"Part {part_id}: attached message/container is metadata only; its hash and size "
                "describe parser reserialization, not exact embedded bytes. No child content "
                "was included in wrapper analysis."
            )
        else:
            payload = _decoded_payload(part)
        decoded_total += len(payload)
        if decoded_total > limits.max_decoded_bytes:
            raise ResourceLimitError("MIME payloads exceed max_decoded_bytes.")
        parts.append(
            MimePart(
                part_id=part_id,
                media_type=media_type,
                disposition=disposition,
                filename=filename,
                decoded_bytes=len(payload),
                sha256=hashlib.sha256(payload).hexdigest(),
                is_attachment=is_attachment,
            )
        )
        if media_type in {"text/plain", "text/html"} and not is_attachment:
            text = payload.decode(part.get_content_charset() or "us-ascii", errors="strict")
            text_total += len(text)
            if text_total > limits.max_text_chars:
                raise ResourceLimitError("Message text exceeds max_text_chars.")
            segments.append(
                TextSegment(
                    part_id=part_id,
                    kind="plain" if media_type == "text/plain" else "html_source",
                    text=text,
                )
            )

    visit(message, "1")
    return ParsedEmail(
        headers=[Header(name=name, value=str(value)) for name, value in message.items()],
        subject=str(message.get("Subject", "")),
        from_addresses=[address for _, address in getaddresses(message.get_all("From", []))],
        reply_to_addresses=[
            address for _, address in getaddresses(message.get_all("Reply-To", []))
        ],
        parts=parts,
        text_segments=segments,
        warnings=warnings,
    )
