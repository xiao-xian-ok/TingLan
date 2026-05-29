"""Helpers for safe rendering of decoded packet payloads."""

from __future__ import annotations

from typing import Any


LOSSY_DECODE_MARKER = "\ufffd"
LOSSY_TEXT_NOTICE = (
    "[二进制/压缩数据未成功解码，当前文本已包含替换字符(�)，"
    "原始字节无法从该字符串可靠还原。请优先使用 chunk-data/file-data 重新解码。]"
)


def _to_text(data: Any) -> str:
    if data is None:
        return ""
    if isinstance(data, bytes):
        return data.decode("latin-1", errors="replace")
    return str(data)


def is_lossy_decoded_text(data: Any, *, min_markers: int = 2, ratio_threshold: float = 0.01) -> bool:
    """Return True when text already contains many Unicode replacement chars."""
    text = _to_text(data)
    if not text:
        return False

    sample = text[:4096]
    marker_count = sample.count(LOSSY_DECODE_MARKER)
    if marker_count == 0:
        return False

    return marker_count >= min_markers or (marker_count / len(sample)) >= ratio_threshold


def is_binary_or_corrupt_text(data: Any, threshold: float = 0.30) -> bool:
    """Detect binary payloads and lossy-decoded text before putting them in text widgets."""
    if data is None:
        return False

    if isinstance(data, bytes):
        sample_bytes = data[:4096]
        if not sample_bytes:
            return False
        control_count = sum(1 for b in sample_bytes if b < 32 and b not in (9, 10, 13))
        high_count = sum(1 for b in sample_bytes if b >= 128)
        return (control_count / len(sample_bytes)) > threshold or (
            control_count > 0 and (high_count / len(sample_bytes)) > 0.50
        )

    text = str(data)
    if not text:
        return False

    if is_lossy_decoded_text(text):
        return True

    sample = text[:4096]
    control_count = sum(1 for ch in sample if ord(ch) < 32 and ch not in "\n\r\t")
    c1_control_count = sum(1 for ch in sample if 0x80 <= ord(ch) <= 0x9F)
    length = len(sample)
    if length == 0:
        return False

    return (control_count / length) > threshold or (c1_control_count / length) > 0.05


def format_binary_as_hex(data: Any, max_bytes: int = 4096) -> str:
    """Render preserved bytes as a Wireshark-style hex dump; avoid fake hex for lossy text."""
    if is_lossy_decoded_text(data):
        return LOSSY_TEXT_NOTICE

    try:
        if isinstance(data, bytes):
            raw_bytes = data[:max_bytes]
        elif isinstance(data, str):
            try:
                raw_bytes = data.encode("latin-1", errors="strict")[:max_bytes]
            except UnicodeEncodeError:
                raw_bytes = data.encode("utf-8", errors="replace")[:max_bytes]
        else:
            raw_bytes = bytes(data)[:max_bytes]

        lines = []
        for i in range(0, len(raw_bytes), 16):
            chunk = raw_bytes[i:i + 16]
            offset = f"{i:04x}"
            hex_left = " ".join(f"{b:02x}" for b in chunk[:8])
            hex_right = " ".join(f"{b:02x}" for b in chunk[8:])
            hex_part = f"{hex_left:<23}  {hex_right:<23}"
            ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            lines.append(f"{offset}   {hex_part}  |{ascii_part}|")

        if len(raw_bytes) == max_bytes:
            lines.append(f"\n... (仅显示前 {max_bytes} 字节)")

        return "\n".join(lines)
    except Exception as exc:
        return f"[无法格式化二进制数据: {exc}]"


def safe_display_text(data: Any, max_length: int = 50000) -> str:
    """Return text suitable for display without flooding the UI with corrupt characters."""
    if data is None:
        return ""

    if is_binary_or_corrupt_text(data):
        return format_binary_as_hex(data, max_bytes=min(max_length, 4096))

    text = _to_text(data)
    if len(text) > max_length:
        return text[:max_length] + "\n... (截断)"
    return text
