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
    content_type = ""
    try:
        content_type = getattr(http_layer, "content_type", "") or ""
    except Exception:
        content_type = ""
    return body.decode(_charset_from_content_type(content_type), errors="replace")


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
            lines.append(body)

    return "\r\n".join(lines)


def reconstruct_http_response_from_fields(fields: dict, include_body: bool = True) -> str:
    """Build a response from raw dict keys such as ``response-version`` and ``chunk-data``."""
    class _MappingLayer:
        def __init__(self, data: dict):
            self._data = data

    return reconstruct_http_response(_MappingLayer(fields or {}), include_body=include_body)
