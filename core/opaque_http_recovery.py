"""Bounded recovery of HTTP responses from opaque TCP follow output."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, Iterable, Optional
from urllib.parse import unquote, urlsplit

from core.http_reassembly import decode_http_content_bytes


FILE_LIKE_EXTENSIONS = frozenset({
    "7z", "apk", "asp", "aspx", "bat", "bz2", "cab", "cfg", "class",
    "conf", "crt", "csv", "db", "dll", "doc", "docx", "elf", "exe",
    "gz", "htm", "html", "ico", "ini", "jar", "jpeg", "jpg", "js",
    "json", "log", "php", "pdf", "ppt", "pptx", "py", "rar", "sh",
    "so", "sql", "svg", "tar", "txt", "vbs", "wasm", "xls", "xlsx",
    "xml", "zip",
})
HIGH_VALUE_EXTENSIONS = frozenset({
    "7z", "apk", "cab", "class", "dll", "doc", "docx", "elf", "exe",
    "gz", "jar", "pdf", "ppt", "pptx", "rar", "so", "tar", "xls", "xlsx", "zip",
})


@dataclass(frozen=True)
class OpaqueHttpRequest:
    stream_id: int
    uri: str
    frame_number: int = 0
    host: str = ""


@dataclass(frozen=True)
class OpaqueHttpResponse:
    body: bytes
    headers: Dict[str, str]
    status_code: int


def is_file_like_uri(uri: str, extensions: Iterable[str] = FILE_LIKE_EXTENSIONS) -> bool:
    """Return true when the URI path ends in a known downloadable extension."""
    value = (uri or "").strip()
    if not value:
        return False
    try:
        path = urlsplit(value).path or value.split("?", 1)[0].split("#", 1)[0]
    except ValueError:
        path = value.split("?", 1)[0].split("#", 1)[0]
    basename = unquote(path.rsplit("/", 1)[-1]).lower()
    if "." not in basename:
        return False
    extension = basename.rsplit(".", 1)[-1]
    return extension in {str(item).lstrip(".").lower() for item in extensions}


def file_like_uri_score(uri: str) -> int:
    """Rank likely downloads ahead of scanner wordlists while retaining generic extensions."""
    if not is_file_like_uri(uri):
        return -1
    try:
        basename = unquote(urlsplit(uri).path.rsplit("/", 1)[-1]).lower()
    except ValueError:
        basename = (uri or "").split("?", 1)[0].rsplit("/", 1)[-1].lower()
    extension = basename.rsplit(".", 1)[-1]
    score = 100 if extension in HIGH_VALUE_EXTENSIONS else 10
    if basename.startswith("."):
        score -= 50
    if basename.rsplit(".", 1)[0].isdigit():
        score -= 20
    return score


def _decode_hex_line(line: str) -> Optional[bytes]:
    compact = re.sub(r"[\s:]", "", line or "")
    if not compact or len(compact) % 2 or not re.fullmatch(r"[0-9a-fA-F]+", compact):
        return None
    try:
        return bytes.fromhex(compact)
    except ValueError:
        return None


def _decode_chunked(body: bytes, max_size: int) -> Optional[bytes]:
    output = bytearray()
    position = 0
    while True:
        line_end = body.find(b"\r\n", position)
        separator = 2
        if line_end < 0:
            line_end = body.find(b"\n", position)
            separator = 1
        if line_end < 0:
            return None
        size_text = body[position:line_end].split(b";", 1)[0].strip()
        try:
            chunk_size = int(size_text, 16)
        except ValueError:
            return None
        position = line_end + separator
        if chunk_size == 0:
            return bytes(output)
        if chunk_size > max_size or len(output) + chunk_size > max_size:
            return None
        if len(body) < position + chunk_size + separator:
            return None
        output.extend(body[position:position + chunk_size])
        position += chunk_size
        if body[position:position + separator] != (b"\r\n" if separator == 2 else b"\n"):
            return None
        position += separator


def parse_http_response_bytes(data: bytes, max_body_size: int = 1024 * 1024) -> Optional[OpaqueHttpResponse]:
    """Parse the first complete successful HTTP response in raw TCP bytes."""
    if not data:
        return None
    response_pattern = re.compile(br"HTTP/1\.[01]\s+(\d{3})[^\r\n]*\r?\n", re.IGNORECASE)
    match = response_pattern.search(data)
    while match:
        header_end = data.find(b"\r\n\r\n", match.end())
        delimiter_size = 4
        if header_end < 0:
            header_end = data.find(b"\n\n", match.end())
            delimiter_size = 2
        if header_end < 0:
            return None
        headers: Dict[str, str] = {}
        header_block = data[match.end():header_end]
        for line in re.split(br"\r?\n", header_block):
            if b":" not in line:
                continue
            key, value = line.split(b":", 1)
            headers[key.decode("latin1", errors="replace").strip().lower()] = value.decode(
                "latin1", errors="replace"
            ).strip()

        status_code = int(match.group(1))
        body_start = header_end + delimiter_size
        if not 200 <= status_code < 300:
            match = response_pattern.search(data, body_start)
            continue

        transfer_encoding = headers.get("transfer-encoding", "").lower()
        if "chunked" in transfer_encoding:
            body = _decode_chunked(data[body_start:], max_body_size)
            if body is None:
                return None
        elif "content-length" in headers:
            try:
                length = int(headers["content-length"].strip())
            except ValueError:
                return None
            if length < 0 or length > max_body_size or len(data) - body_start < length:
                return None
            body = data[body_start:body_start + length]
        else:
            body = data[body_start:]
            if len(body) > max_body_size:
                return None

        body = decode_http_content_bytes(body, headers.get("content-encoding", ""))
        if len(body) > max_body_size:
            return None
        return OpaqueHttpResponse(body=body, headers=headers, status_code=status_code)
    return None


def parse_follow_tcp_raw(output: str, max_body_size: int = 1024 * 1024) -> Optional[OpaqueHttpResponse]:
    """Decode TShark follow,tcp,raw output and parse the server direction."""
    directions = [bytearray(), bytearray()]
    direction = 0
    for line in (output or "").splitlines():
        stripped = line.strip()
        if stripped.lower().startswith("node 1:"):
            direction = 1
            continue
        if stripped.lower().startswith("node 0:"):
            direction = 0
            continue
        decoded = _decode_hex_line(stripped)
        if decoded is None:
            continue
        directions[direction].extend(decoded)

    for payload in (directions[1], directions[0]):
        response = parse_http_response_bytes(bytes(payload), max_body_size=max_body_size)
        if response is not None:
            return response
    return None


def response_filename(response: OpaqueHttpResponse, uri: str) -> str:
    disposition = response.headers.get("content-disposition", "")
    match = re.search(r"filename\*\s*=\s*[^']*'[^']*'([^;]+)|filename\s*=\s*([^;]+)", disposition, re.IGNORECASE)
    if match:
        return unquote((match.group(1) or match.group(2)).strip().strip('"\''))
    try:
        path = urlsplit(uri or "").path or uri.split("?", 1)[0]
    except ValueError:
        path = uri.split("?", 1)[0]
    return unquote(path.rsplit("/", 1)[-1])
