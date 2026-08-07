"""In-memory classification for HTTP response bodies."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import math
import os
import re
from typing import Iterable, Optional, Tuple
from urllib.parse import unquote_to_bytes, urlsplit


def content_disposition_from_response_lines(response_lines: Iterable[str]) -> str:
    """Extract a Content-Disposition value from TShark's aggregated header rows.

    ``-T fields`` joins repeated ``http.response.line`` values with commas.
    Commas inside quoted filename values are valid, so the next header boundary
    is recognized only while outside a quoted string.
    """
    if isinstance(response_lines, str):
        response_lines = (response_lines,)

    for raw_line in response_lines:
        line = str(raw_line or "").replace("\\r\\n", "\n").replace("\\n", "\n")
        match = re.search(
            r"(?:^|[\r\n,])\s*content-disposition\s*:\s*",
            line,
            re.IGNORECASE,
        )
        if not match:
            continue

        start = match.end()
        quote = ""
        index = start
        while index < len(line):
            character = line[index]
            if quote:
                if character == "\\":
                    index += 2
                    continue
                if character == quote:
                    quote = ""
            elif character in ("'", '"'):
                quote = character
            elif character in "\r\n":
                break
            elif character == ",":
                following_header = re.match(
                    r"\s*[A-Za-z][A-Za-z0-9-]*\s*:", line[index + 1:]
                )
                if following_header:
                    break
            index += 1

        value = line[start:index].strip()
        if value:
            return value
    return ""


@dataclass(frozen=True)
class HttpResponseMatch:
    filename: str
    content_type: str
    file_type: str
    is_disguised: bool = False


class HttpResponseInspector:
    """Classify useful HTTP response bodies without creating artifacts."""

    _MAGIC_SIGNATURES = (
        (b"PK\x03\x04", ("zip", "application/zip", "archive")),
        (b"PK\x05\x06", ("zip", "application/zip", "archive")),
        (b"PK\x07\x08", ("zip", "application/zip", "archive")),
        (b"Rar!\x1a\x07", ("rar", "application/x-rar-compressed", "archive")),
        (b"7z\xbc\xaf'\x1c", ("7z", "application/x-7z-compressed", "archive")),
        (b"\x1f\x8b\x08", ("gz", "application/gzip", "archive")),
        (b"BZh", ("bz2", "application/x-bzip2", "archive")),
        (b"MSCF", ("cab", "application/vnd.ms-cab-compressed", "archive")),
        (b"MZ", ("exe", "application/x-msdownload", "executable")),
        (b"\x7fELF", ("elf", "application/x-executable", "executable")),
        (b"\xca\xfe\xba\xbe", ("class", "application/java-vm", "executable")),
        (b"%PDF", ("pdf", "application/pdf", "document")),
        (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", ("doc", "application/msword", "document")),
        (b"\x89PNG\r\n\x1a\n", ("png", "image/png", "image")),
        (b"\xff\xd8\xff", ("jpg", "image/jpeg", "image")),
        (b"GIF8", ("gif", "image/gif", "image")),
        (b"BM", ("bmp", "image/bmp", "image")),
        (b"SQLite format 3", ("sqlite", "application/x-sqlite3", "database")),
    )

    _DECLARED_TYPES = {
        "application/zip": ("zip", "application/zip", "archive"),
        "application/x-rar": ("rar", "application/x-rar-compressed", "archive"),
        "application/x-rar-compressed": ("rar", "application/x-rar-compressed", "archive"),
        "application/x-7z-compressed": ("7z", "application/x-7z-compressed", "archive"),
        "application/gzip": ("gz", "application/gzip", "archive"),
        "application/x-gzip": ("gz", "application/gzip", "archive"),
        "application/x-bzip2": ("bz2", "application/x-bzip2", "archive"),
        "application/vnd.ms-cab-compressed": ("cab", "application/vnd.ms-cab-compressed", "archive"),
        "application/pdf": ("pdf", "application/pdf", "document"),
        "application/msword": ("doc", "application/msword", "document"),
        ("application/vnd.openxmlformats-officedocument.wordprocessingml.document"):
            ("docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", "document"),
        "application/vnd.ms-excel": ("xls", "application/vnd.ms-excel", "document"),
        ("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"):
            ("xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "document"),
        "application/vnd.ms-powerpoint": ("ppt", "application/vnd.ms-powerpoint", "document"),
        ("application/vnd.openxmlformats-officedocument.presentationml.presentation"):
            ("pptx", "application/vnd.openxmlformats-officedocument.presentationml.presentation", "document"),
        "application/x-msdownload": ("exe", "application/x-msdownload", "executable"),
        "application/x-executable": ("bin", "application/x-executable", "executable"),
        "application/x-php": ("php", "application/x-php", "script"),
        "application/x-httpd-php": ("php", "application/x-php", "script"),
        "application/x-sqlite3": ("sqlite", "application/x-sqlite3", "database"),
        "application/octet-stream": ("bin", "application/octet-stream", "binary"),
        "image/png": ("png", "image/png", "image"),
        "image/jpeg": ("jpg", "image/jpeg", "image"),
        "image/gif": ("gif", "image/gif", "image"),
        "image/bmp": ("bmp", "image/bmp", "image"),
    }

    _IMAGE_EXTENSIONS = {"jpg", "jpeg", "png", "gif", "bmp", "ico", "svg", "webp"}
    _DOCUMENT_EXTENSIONS = {"doc", "docx", "pdf", "xls", "xlsx", "ppt", "pptx", "txt"}
    _EXECUTABLE_EXTENSIONS = {"exe", "dll", "elf", "so", "class", "jar"}
    _SCRIPT_EXTENSIONS = {"php", "jsp", "asp", "aspx", "py", "sh", "bat", "ps1", "vbs", "js"}
    _ARCHIVE_EXTENSIONS = {"zip", "rar", "7z", "tar", "gz", "bz2", "cab"}
    _STATIC_ASSET_EXTENSIONS = {"css", "gif", "ico", "jpeg", "jpg", "js", "map", "png", "svg", "webp"}

    def inspect(
        self,
        frame_number: int,
        body: bytes,
        content_type: str,
        content_disposition: str,
        request_uri: str,
    ) -> Optional[HttpResponseMatch]:
        if not body:
            return None

        declared_content_type = self._normalise_content_type(content_type)
        attachment_name = self._attachment_filename(content_disposition)
        has_attachment = bool(attachment_name)
        uri_filename = self._uri_filename(request_uri)
        magic = self._magic_info(body, declared_content_type)
        suspicious = self._suspicious_content_info(body)

        if not magic and not suspicious and self._looks_like_html_or_error(body, declared_content_type):
            return None

        # A PHP/shebang prefix identifies a script, but content rules can make
        # that classification more specific (for example, a PHP eval webshell).
        # Binary magic must remain authoritative over generic entropy findings.
        if magic and suspicious and magic[0] in {"php", "sh"}:
            info = suspicious
        else:
            info = magic or suspicious or self._declared_info(declared_content_type)
        if not info and self._looks_binary(body):
            info = ("bin", "application/octet-stream", "binary")
        if not info and attachment_name and not declared_content_type.startswith("text/html"):
            info = self._filename_info(attachment_name)
        if not info and uri_filename:
            attachment_name = uri_filename
            info = self._filename_info(uri_filename)
        if not info:
            return None

        extension, match_content_type, file_type = info
        if not has_attachment and (
            file_type == "image"
            or (extension in self._STATIC_ASSET_EXTENSIONS and suspicious is None)
        ):
            return None

        filename = attachment_name or f"frame_{int(frame_number)}.{extension}"
        return HttpResponseMatch(
            filename=filename,
            content_type=match_content_type,
            file_type=file_type,
            is_disguised=self._is_extension_disguised(filename, extension),
        )

    @staticmethod
    def _normalise_content_type(content_type: str) -> str:
        return (content_type or "").split(";", 1)[0].strip().lower()

    @staticmethod
    def _attachment_filename(content_disposition: str) -> str:
        value = (content_disposition or "").replace("\\r\\n", "\n").replace("\\n", "\n")
        extended = re.search(r"(?:^|;)\s*filename\*\s*=\s*(?:\"([^\"]*)\"|([^;\r\n]*))", value, re.IGNORECASE)
        if extended:
            raw_value = (extended.group(1) or extended.group(2) or "").strip()
            parts = raw_value.split("'", 2)
            if len(parts) == 3:
                charset, _language, encoded_name = parts
                try:
                    return unquote_to_bytes(encoded_name).decode(charset or "utf-8", errors="replace").strip()
                except (LookupError, UnicodeError):
                    return unquote_to_bytes(encoded_name).decode("utf-8", errors="replace").strip()
            return raw_value.strip().strip("\"'")

        plain = re.search(r"(?:^|;)\s*filename\s*=\s*(?:\"([^\"]+)\"|([^;,\r\n\s]+))", value, re.IGNORECASE)
        if not plain:
            return ""
        return (plain.group(1) or plain.group(2) or "").strip()

    @staticmethod
    def _uri_filename(request_uri: str) -> str:
        path = urlsplit(request_uri or "").path
        filename = os.path.basename(path)
        return filename if os.path.splitext(filename)[1] else ""

    def _magic_info(self, body: bytes, declared_content_type: str) -> Optional[Tuple[str, str, str]]:
        prefix = body[:64]
        for signature, info in self._MAGIC_SIGNATURES:
            if prefix.startswith(signature):
                if info[0] == "zip":
                    return self._office_zip_info(body, declared_content_type) or info
                if info[0] == "doc" and declared_content_type in self._DECLARED_TYPES:
                    return self._DECLARED_TYPES[declared_content_type]
                return info

        stripped = body[:512].lstrip(b"\xef\xbb\xbf\t\r\n ").lower()
        if stripped.startswith(b"<?php"):
            return "php", "application/x-php", "script"
        if stripped.startswith(b"#!"):
            return "sh", "text/x-shellscript", "script"
        return None

    def _office_zip_info(
        self,
        body: bytes,
        declared_content_type: str,
    ) -> Optional[Tuple[str, str, str]]:
        if declared_content_type in self._DECLARED_TYPES:
            declared = self._DECLARED_TYPES[declared_content_type]
            if declared[2] == "document":
                return declared
        sample = body[-65536:].lower()
        if b"word/" in sample:
            return self._DECLARED_TYPES[
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
            ]
        if b"xl/" in sample:
            return self._DECLARED_TYPES[
                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
            ]
        if b"ppt/" in sample:
            return self._DECLARED_TYPES[
                "application/vnd.openxmlformats-officedocument.presentationml.presentation"
            ]
        return None

    def _declared_info(self, content_type: str) -> Optional[Tuple[str, str, str]]:
        if content_type in self._DECLARED_TYPES:
            return self._DECLARED_TYPES[content_type]
        if content_type.startswith("application/") and content_type not in {
            "application/json",
            "application/xml",
            "application/javascript",
            "application/x-www-form-urlencoded",
        }:
            return "bin", content_type, "binary"
        return None

    def _suspicious_content_info(self, body: bytes) -> Optional[Tuple[str, str, str]]:
        content = body[:50 * 1024]
        lowered = content.lower()

        php_patterns = (
            b"eval(", b"assert(", b"system(", b"exec(", b"shell_exec(", b"passthru(",
            b"popen(", b"proc_open(", b"base64_decode(", b"gzinflate(", b"str_rot13(",
            b"$_post[", b"$_get[", b"$_request[", b"@ini_set", b"@eval($_",
        )
        if (b"<?php" in lowered or b"<?" in lowered) and any(marker in lowered for marker in php_patterns):
            return "php", "application/x-php", "webshell"

        powershell_patterns = (
            (b"powershell", b"-encodedcommand"),
            (b"powershell", b"-nop"),
            (b"powershell", b"downloadstring"),
            (b"powershell", b"invoke-expression"),
            (b"[system.convert]::frombase64", None),
            (b"new-object system.net.webclient", None),
        )
        if self._matches_any(lowered, powershell_patterns):
            return "ps1", "text/plain", "script"

        vbs_patterns = (
            (b"wscript.shell", b"run"),
            (b"wscript.shell", b"exec"),
            (b"scripting.filesystemobject", None),
            (b"adodb.stream", None),
        )
        if self._matches_any(lowered, vbs_patterns):
            return "vbs", "text/plain", "script"

        shell_dangers = (b"curl ", b"wget ", b"/dev/tcp/", b"nc ", b"netcat ", b"bash -i", b"/bin/sh", b"python -c", b"perl -e", b"rm -rf", b"chmod 777", b"base64 -d")
        if content.lstrip().startswith(b"#!") and any(marker in lowered for marker in shell_dangers):
            return "sh", "text/x-shellscript", "script"

        batch_patterns = (
            (b"@echo off", b"powershell"),
            (b"@echo off", b"certutil"),
            (b"@echo off", b"bitsadmin"),
            (b"cmd /c", b"powershell"),
        )
        if self._matches_any(lowered, batch_patterns):
            return "bat", "text/plain", "script"

        if self._entropy(content[:4096]) > 7.5:
            return "bin", "application/x-suspicious", "encrypted"
        return None

    @staticmethod
    def _matches_any(content: bytes, patterns: tuple[tuple[bytes, Optional[bytes]], ...]) -> bool:
        return any(first in content and (second is None or second in content) for first, second in patterns)

    @staticmethod
    def _entropy(data: bytes) -> float:
        if not data:
            return 0.0
        size = len(data)
        return -sum((count / size) * math.log2(count / size) for count in Counter(data).values())

    @staticmethod
    def _looks_binary(body: bytes) -> bool:
        sample = body[:1024]
        if not sample:
            return False
        non_printable = sum(byte < 32 and byte not in (9, 10, 13) or byte > 126 for byte in sample)
        return non_printable > len(sample) * 0.3

    @staticmethod
    def _looks_like_html_or_error(body: bytes, content_type: str) -> bool:
        sample = body[:2048].lstrip().lower()
        if content_type == "text/html" or any(marker in sample[:256] for marker in (b"<!doctype", b"<html", b"<head", b"<body", b"<title")):
            return True
        return any(marker in sample for marker in (b"404 not found", b"403 forbidden", b"500 internal server error", b"access denied", b"error occurred"))

    @staticmethod
    def _filename_info(filename: str) -> Tuple[str, str, str]:
        extension = os.path.splitext(filename)[1].lstrip(".").lower() or "bin"
        if extension in HttpResponseInspector._ARCHIVE_EXTENSIONS:
            return extension, "application/octet-stream", "archive"
        if extension in HttpResponseInspector._EXECUTABLE_EXTENSIONS:
            return extension, "application/octet-stream", "executable"
        if extension in HttpResponseInspector._SCRIPT_EXTENSIONS:
            return extension, "text/plain", "script"
        if extension in HttpResponseInspector._DOCUMENT_EXTENSIONS:
            return extension, "application/octet-stream", "document"
        return extension, "application/octet-stream", "binary"

    @classmethod
    def _is_extension_disguised(cls, filename: str, real_extension: str) -> bool:
        named_extension = os.path.splitext(filename)[1].lstrip(".").lower()
        if not named_extension or named_extension == real_extension.lower():
            return False
        if real_extension in cls._EXECUTABLE_EXTENSIONS and named_extension in (cls._IMAGE_EXTENSIONS | cls._DOCUMENT_EXTENSIONS):
            return True
        if real_extension in cls._SCRIPT_EXTENSIONS and named_extension in (cls._IMAGE_EXTENSIONS | cls._DOCUMENT_EXTENSIONS):
            return True
        return real_extension in cls._ARCHIVE_EXTENSIONS and named_extension in cls._IMAGE_EXTENSIONS
