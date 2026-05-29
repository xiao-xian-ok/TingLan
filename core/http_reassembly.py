"""HTTP payload reassembly helpers for PyShark/tshark decoded fields."""

from __future__ import annotations

import re
from typing import Any, Iterable, List, Optional


_HEX_CHARS = set("0123456789abcdefABCDEF")


def _flatten_values(value: Any) -> Iterable[Any]:
    if value is None:
        return
    if isinstance(value, (list, tuple)):
        for item in value:
            yield from _flatten_values(item)
        return
    yield value


def _field_aliases(name: str) -> List[str]:
    return [
        name,
        name.replace("_", "."),
        name.replace("_", "-"),
        f"http_{name}",
        f"http_http_{name}",
        f"http.{name.replace('_', '.')}",
        f"http-{name.replace('_', '-')}",
    ]


def _normalized_field(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", name.lower())


def get_http_field_values(http_layer: Any, *names: str) -> List[Any]:
    """Return all matching HTTP field values from PyShark or EK LayerWrapper objects."""
    values: List[Any] = []
    seen_ids = set()

    for name in names:
        for alias in _field_aliases(name):
            try:
                value = getattr(http_layer, alias, None)
            except Exception:
                value = None
            if value is not None:
                for item in _flatten_values(value):
                    item_id = id(item)
                    if item_id not in seen_ids:
                        seen_ids.add(item_id)
                        values.append(item)

    raw_data = getattr(http_layer, "_data", None)
    if isinstance(raw_data, dict):
        wanted = {_normalized_field(alias) for name in names for alias in _field_aliases(name)}
        wanted.update(_normalized_field(name) for name in names)
        for key, value in raw_data.items():
            normalized = _normalized_field(str(key))
            if normalized in wanted or any(normalized.endswith(w) for w in wanted):
                for item in _flatten_values(value):
                    item_id = id(item)
                    if item_id not in seen_ids:
                        seen_ids.add(item_id)
                        values.append(item)

    return values


def decode_hex_field(value: Any) -> Optional[bytes]:
    """Decode tshark hex field values like ``0a:3c:21`` into bytes."""
    if value is None:
        return None
    if isinstance(value, bytes):
        return value

    if isinstance(value, (list, tuple)):
        chunks = []
        for item in value:
            decoded = decode_hex_field(item)
            if decoded:
                chunks.append(decoded)
        return b"".join(chunks) if chunks else None

    text = str(value).strip()
    if not text:
        return None

    # tshark may emit colon separated hex, whitespace separated hex, or 0xNN tokens.
    compact = re.sub(r"(?i)0x", "", text)
    compact = re.sub(r"[\s:,\-]+", "", compact)
    if len(compact) < 2 or len(compact) % 2:
        return None
    if any(ch not in _HEX_CHARS for ch in compact):
        return None

    try:
        return bytes.fromhex(compact)
    except ValueError:
        return None


def decode_http_body_bytes(http_layer: Any) -> bytes:
    """Decode HTTP entity body from file_data first, then chunk_data fallback."""
    for field_names in (("file_data", "request_body"), ("chunk_data", "chunk")):
        chunks = []
        for value in get_http_field_values(http_layer, *field_names):
            decoded = decode_hex_field(value)
            if decoded:
                chunks.append(decoded)
            elif isinstance(value, str):
                chunks.append(value.encode("utf-8", errors="replace"))
        if chunks:
            return b"".join(chunks)
    return b""


def _charset_from_content_type(content_type: str) -> str:
    if not content_type:
        return "utf-8"
    match = re.search(r"charset\s*=\s*([A-Za-z0-9._-]+)", content_type, re.IGNORECASE)
    return match.group(1) if match else "utf-8"


def _first_text(http_layer: Any, *names: str) -> str:
    for value in get_http_field_values(http_layer, *names):
        if value is not None:
            text = str(value)
            if text:
                return text
    return ""


def decode_http_body_text(http_layer: Any) -> str:
    body = decode_http_body_bytes(http_layer)
    if not body:
        return ""
    content_type = _first_text(http_layer, "content_type")
    return body.decode(_charset_from_content_type(content_type), errors="replace")


def restore_visible_escapes(text: str) -> str:
    """Convert visible ``\\n``/``\\t`` sequences to real control characters for display."""
    if not text:
        return text

    escaped_count = sum(text.count(seq) for seq in ("\\r\\n", "\\n", "\\r", "\\t"))
    if escaped_count == 0:
        return text

    actual_breaks = text.count("\n") + text.count("\r") + text.count("\t")
    looks_like_dumped_text = actual_breaks == 0 or text.lstrip().startswith(("\\n", "\\r\\n"))
    looks_like_html = bool(re.search(r"\\n\s*<|<!DOCTYPE|<html\b", text, re.IGNORECASE))
    if not (looks_like_dumped_text or looks_like_html):
        return text

    return (
        text.replace("\\r\\n", "\n")
        .replace("\\n", "\n")
        .replace("\\r", "\n")
        .replace("\\t", "    ")
    )


_VOID_HTML_TAGS = {
    "area", "base", "br", "col", "embed", "hr", "img", "input",
    "link", "meta", "param", "source", "track", "wbr",
}


def _html_tag_name(tag: str) -> str:
    match = re.match(r"</?\s*([a-zA-Z0-9:-]+)", tag)
    return match.group(1).lower() if match else ""


def _looks_like_html(text: str, content_type: str = "") -> bool:
    if "html" in (content_type or "").lower():
        return True
    return bool(re.search(r"<!DOCTYPE\s+html|<html\b|<body\b", text, re.IGNORECASE))


def _pretty_print_html(text: str) -> str:
    text = text.strip()
    if not text:
        return text

    # Split adjacent tags even when the server sent minified HTML.
    text = re.sub(r">\s*<", ">\n<", text)
    tokens = [token for token in re.split(r"(<[^>]+>)", text) if token and token.strip()]

    lines: List[str] = []
    indent = 0
    for token in tokens:
        stripped = token.strip()
        if not stripped:
            continue

        if stripped.startswith("<"):
            tag_name = _html_tag_name(stripped)
            is_close = stripped.startswith("</")
            is_comment_or_decl = stripped.startswith(("<!--", "<!", "<?"))
            is_self_closing = (
                stripped.endswith("/>")
                or tag_name in _VOID_HTML_TAGS
                or is_comment_or_decl
            )

            if is_close:
                indent = max(indent - 1, 0)

            lines.append(f"{'  ' * indent}{stripped}")

            if not is_close and not is_self_closing:
                indent += 1
        else:
            for part in stripped.splitlines():
                part = part.strip()
                if part:
                    lines.append(f"{'  ' * indent}{part}")

    return "\n".join(lines)


def format_http_body_for_display(text: str, content_type: str = "") -> str:
    """Make decoded HTTP bodies readable without changing detection semantics."""
    if not text:
        return text

    text = restore_visible_escapes(text)
    text = text.replace("\r\n", "\n").replace("\r", "\n")

    if _looks_like_html(text, content_type):
        return _pretty_print_html(text)

    return text


def reconstruct_http_response(http_layer: Any, include_body: bool = True) -> str:
    """Build a Burp-style HTTP response text from available decoded fields."""
    version = _first_text(http_layer, "response_version") or "HTTP/1.1"
    code = _first_text(http_layer, "response_code", "response_status")
    phrase = _first_text(http_layer, "response_phrase", "response_code_desc")

    status_line = f"{version} {code} {phrase}".strip()
    lines = [status_line]

    headers = {
        "Content-Type": _first_text(http_layer, "content_type"),
        "Content-Length": _first_text(http_layer, "content_length"),
        "Transfer-Encoding": _first_text(http_layer, "transfer_encoding"),
        "Server": _first_text(http_layer, "server"),
        "Set-Cookie": _first_text(http_layer, "set_cookie"),
    }
    for name, value in headers.items():
        if value:
            lines.append(f"{name}: {value}")

    lines.append("")
    if include_body:
        body = decode_http_body_text(http_layer)
        if body:
            lines.append(format_http_body_for_display(body, headers.get("Content-Type", "")))

    return "\r\n".join(lines)


def reconstruct_http_response_from_fields(fields: dict, include_body: bool = True) -> str:
    """Build a response from raw dict keys such as ``response-version`` and ``chunk-data``."""
    class _MappingLayer:
        def __init__(self, data: dict):
            self._data = data

    return reconstruct_http_response(_MappingLayer(fields or {}), include_body=include_body)
