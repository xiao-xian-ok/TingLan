"""Formatting helpers for protocol finding details."""

from __future__ import annotations

import json
from typing import Any, Iterable, List


def _truncate_text(text: str, limit: int = 1000) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + "... (截断)"


def _format_hex_preview(value: dict, key: str, byte_key: str, total_key: str, truncated_key: str) -> str:
    preview = str(value.get(key) or "")
    shown_bytes = value.get(byte_key, 0)
    total_bytes = value.get(total_key, shown_bytes)
    suffix = ""
    if value.get(truncated_key):
        suffix = f" ... (截断, 原始 {total_bytes} bytes, 显示前 {shown_bytes} bytes)"
    return f"{preview}{suffix}"


def _format_structured_value(value: Any) -> str:
    if isinstance(value, dict):
        kind = value.get("kind", "")
        if kind == "encrypted_http_body":
            summary = (
                f"Encrypted HTTP Body: frame={value.get('frame_number', '?')} "
                f"stream={value.get('tcp_stream', '?')} {value.get('method', '')} "
                f"{value.get('uri', '')} declared={value.get('declared_length', '?')} "
                f"frame_len={value.get('frame_length', '?')} "
                f"encrypted={value.get('encrypted_length', '?')} "
                f"hmac={value.get('hmac_length', '?')} "
                f"entropy={float(value.get('entropy', 0.0)):.2f} "
                f"content_type={value.get('content_type', '')}"
            )
            details = [
                summary,
                (
                    f"    length_prefix_hex={value.get('length_prefix_hex', '')} "
                    f"cipher_offset={value.get('cipher_offset', '?')} "
                    f"hmac_offset={value.get('hmac_offset', '?')} "
                    f"trailing={value.get('trailing_length', 0)}"
                ),
            ]
            frame_hex = value.get("frame_hex_preview")
            if frame_hex:
                details.append(
                    "    frame_hex_preview="
                    + _format_hex_preview(
                        value,
                        "frame_hex_preview",
                        "frame_hex_preview_bytes",
                        "frame_length",
                        "frame_hex_truncated",
                    )
                )
            encrypted_hex = value.get("encrypted_hex_preview")
            if encrypted_hex:
                details.append(
                    "    encrypted_hex_preview="
                    + _format_hex_preview(
                        value,
                        "encrypted_hex_preview",
                        "encrypted_hex_preview_bytes",
                        "encrypted_length",
                        "encrypted_hex_truncated",
                    )
                )
            if value.get("hmac_hex"):
                details.append(f"    hmac_hex={value.get('hmac_hex')}")
            if value.get("artifact_json_path"):
                details.append(f"    full_export_json={value.get('artifact_json_path')}")
            if value.get("artifact_bin_path"):
                details.append(f"    full_export_bin={value.get('artifact_bin_path')}")
            if value.get("decode_note"):
                details.append(f"    note={value.get('decode_note')}")
            return "\n".join(details)
        if "cookie" in value:
            cookie = str(value.get("cookie", ""))
            return (
                f"Metadata Cookie: source={value.get('source', '?')} "
                f"decoded_len={value.get('decoded_length', '?')} "
                f"confidence={float(value.get('confidence', 0.0)):.0%} "
                f"cookie={_truncate_text(cookie, 160)}"
            )

    try:
        return _truncate_text(
            json.dumps(value, ensure_ascii=False, sort_keys=True, default=str),
            1000,
        )
    except TypeError:
        return _truncate_text(str(value), 1000)


def _append_truncation_notice(lines: List[str], shown: int, total: int) -> None:
    if shown < total:
        lines.append(f"... (仅显示前 {shown} 项，剩余 {total - shown} 项已省略)")


def format_protocol_raw_values(
    raw_values: Iterable[Any],
    *,
    max_items: int = 512,
    max_chars: int = 30000,
) -> List[str]:
    """Format protocol raw values without assuming they are numeric."""
    values = list(raw_values or [])
    if not values:
        return []

    shown_values = values[:max_items]
    total = len(values)
    lines: List[str] = []

    all_ints = all(isinstance(v, int) and not isinstance(v, bool) for v in shown_values)
    is_bit_sequence = all_ints and all(v in (0, 1) for v in shown_values)

    if is_bit_sequence:
        lines.append(f"=== 二进制位序列 ({total} bits) ===")
        for i in range(0, len(shown_values), 32):
            chunk = shown_values[i:i + 32]
            groups = []
            for j in range(0, len(chunk), 8):
                group = chunk[j:j + 8]
                groups.append("".join(str(b) for b in group))
            lines.append(f"  [{i:04d}]  {' '.join(groups)}")

        _append_truncation_notice(lines, len(shown_values), total)
        lines.append("")
        lines.append("=== 二进制转文本 ===")
        usable_bits = (len(shown_values) // 8) * 8
        text_result = []
        for i in range(0, usable_bits, 8):
            byte_bits = shown_values[i:i + 8]
            byte_val = 0
            for bit in byte_bits:
                byte_val = (byte_val << 1) | bit
            if 32 <= byte_val <= 126:
                text_result.append(chr(byte_val))
            elif byte_val == 0:
                text_result.append("\\0")
            else:
                text_result.append(".")
        lines.append("  " + "".join(text_result))
    elif all_ints:
        lines.append(f"=== 原始值序列 ({total} 值) ===")
        for i in range(0, len(shown_values), 16):
            chunk = shown_values[i:i + 16]
            num_str = " ".join(f"{v:>3}" for v in chunk)
            lines.append(f"  [{i:04d}]  {num_str}")

        _append_truncation_notice(lines, len(shown_values), total)
        lines.append("")
        lines.append("=== ASCII转换 ===")
        ascii_result = []
        for v in shown_values:
            if 32 <= v <= 126:
                ascii_result.append(chr(v))
            else:
                ascii_result.append(".")
        lines.append("  " + "".join(ascii_result))
    else:
        lines.append(f"=== 结构化原始值 ({total} 项) ===")
        for idx, value in enumerate(shown_values):
            lines.append(f"  [{idx:04d}] {_format_structured_value(value)}")
        _append_truncation_notice(lines, len(shown_values), total)

    output: List[str] = []
    current_chars = 0
    for line in lines:
        next_len = len(line) + 1
        if current_chars + next_len > max_chars:
            output.append(f"... (显示内容超过 {max_chars} 字符，已截断)")
            break
        output.append(line)
        current_chars += next_len
    return output
