"""Export helpers for Cobalt Strike encrypted HTTP payload evidence."""

from __future__ import annotations

import html
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List

from core.safe_paths import ensure_child_path, safe_unique_path, sanitize_filename


PROJECT_ROOT = Path(__file__).resolve().parent.parent
CS_EXPORT_ROOT = PROJECT_ROOT / "output" / "cs_payloads"


def default_cs_payload_output_dir(pcap_path: str) -> str:
    pcap_name = Path(pcap_path or "unknown").stem or "unknown"
    safe_name = sanitize_filename(pcap_name, fallback="unknown", max_length=80)
    return str(CS_EXPORT_ROOT / safe_name)


def _chunk_hex(hex_text: str, bytes_per_line: int = 32) -> List[str]:
    step = bytes_per_line * 2
    lines = []
    for i in range(0, len(hex_text), step):
        line = hex_text[i:i + step]
        lines.append(" ".join(line[j:j + 2] for j in range(0, len(line), 2)))
    return lines


def write_cs_payload_artifact(
    record: Dict[str, Any],
    body: bytes,
    output_dir: str,
    *,
    index: int = 0,
) -> None:
    """Persist the complete encrypted CS HTTP frame outside the UI payload."""
    if not isinstance(record, dict) or not isinstance(body, (bytes, bytearray)):
        return

    declared_length = int(record.get("declared_length") or 0)
    if declared_length <= 0 or len(body) < 4:
        return

    frame_length = min(4 + declared_length, len(body))
    frame = bytes(body[:frame_length])
    encrypted = frame[4:-16] if len(frame) >= 20 else b""
    signature = frame[-16:] if len(frame) >= 20 else b""

    os.makedirs(output_dir, exist_ok=True)
    base_name = sanitize_filename(
        f"cs_body_{index:04d}_frame_{record.get('frame_number', 'unknown')}_"
        f"stream_{record.get('tcp_stream', 'unknown')}",
        fallback=f"cs_body_{index:04d}",
        max_length=120,
    )

    bin_path, bin_name = safe_unique_path(output_dir, f"{base_name}.bin", fallback=f"cs_body_{index:04d}.bin")
    json_path, json_name = safe_unique_path(output_dir, f"{base_name}.json", fallback=f"cs_body_{index:04d}.json")

    with open(bin_path, "wb") as fp:
        fp.write(frame)

    metadata = {
        "artifact_type": "tinglan_cobaltstrike_encrypted_http_body",
        "export_time": datetime.now().isoformat(timespec="seconds"),
        "frame_file": bin_name,
        "metadata": {k: v for k, v in record.items() if not str(k).endswith("_hex")},
        "frame_hex": frame.hex(),
        "encrypted_hex": encrypted.hex(),
        "hmac_hex": signature.hex(),
    }
    with open(json_path, "w", encoding="utf-8") as fp:
        json.dump(metadata, fp, ensure_ascii=False, indent=2)

    record.update({
        "artifact_dir": os.path.abspath(output_dir),
        "artifact_bin_path": os.path.abspath(bin_path),
        "artifact_json_path": os.path.abspath(json_path),
        "artifact_frame_bytes": len(frame),
    })


def _safe_artifact_json_path(path_value: Any) -> str:
    if not path_value:
        return ""
    try:
        path = os.path.abspath(str(path_value))
        root = os.path.abspath(str(CS_EXPORT_ROOT))
        if os.path.commonpath([root, path]) != root:
            return ""
        return ensure_child_path(os.path.dirname(path), path)
    except Exception:
        return ""


def _load_artifact_payload(record: Dict[str, Any]) -> Dict[str, str]:
    path = _safe_artifact_json_path(record.get("artifact_json_path"))
    if path and os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as fp:
                payload = json.load(fp)
            if payload.get("artifact_type") == "tinglan_cobaltstrike_encrypted_http_body":
                return {
                    "frame_hex": str(payload.get("frame_hex") or ""),
                    "encrypted_hex": str(payload.get("encrypted_hex") or ""),
                    "hmac_hex": str(payload.get("hmac_hex") or record.get("hmac_hex") or ""),
                }
        except Exception:
            return {}
    return {
        "frame_hex": str(record.get("frame_hex") or record.get("frame_hex_preview") or ""),
        "encrypted_hex": str(record.get("encrypted_hex") or record.get("encrypted_hex_preview") or ""),
        "hmac_hex": str(record.get("hmac_hex") or ""),
    }


def collect_cs_payload_records(raw_values: Iterable[Any]) -> List[Dict[str, Any]]:
    records: List[Dict[str, Any]] = []
    for value in raw_values or []:
        if not isinstance(value, dict) or value.get("kind") != "encrypted_http_body":
            continue
        payload = _load_artifact_payload(value)
        record = {k: v for k, v in value.items() if not str(k).endswith("_preview")}
        record.update(payload)
        record["is_full_export"] = bool(value.get("artifact_json_path") and payload.get("frame_hex"))
        records.append(record)
    return records


def _write_json_report(records: List[Dict[str, Any]], output_path: str) -> None:
    report = {
        "export_type": "cobaltstrike_encrypted_payload_evidence",
        "export_time": datetime.now().isoformat(timespec="seconds"),
        "record_count": len(records),
        "records": records,
    }
    with open(output_path, "w", encoding="utf-8") as fp:
        json.dump(report, fp, ensure_ascii=False, indent=2)


def _write_html_report(records: List[Dict[str, Any]], output_path: str) -> None:
    parts = [
        "<!DOCTYPE html>",
        "<html><head><meta charset=\"utf-8\">",
        "<title>Cobalt Strike Payload Evidence</title>",
        "<style>",
        "body{font-family:Arial,'Microsoft YaHei',sans-serif;margin:24px;color:#1f2933;}",
        "h1{font-size:20px;margin-bottom:8px;} h2{font-size:16px;margin-top:24px;}",
        "table{border-collapse:collapse;margin:8px 0 12px;width:100%;}",
        "td{border:1px solid #d8dee4;padding:6px 8px;font-size:12px;vertical-align:top;}",
        "td:first-child{width:180px;background:#f6f8fa;font-weight:600;}",
        "pre{white-space:pre-wrap;word-break:break-all;background:#0f172a;color:#d1e7ff;padding:12px;border-radius:4px;font-size:12px;}",
        ".note{color:#9a3412;background:#fff7ed;border:1px solid #fed7aa;padding:8px;margin:10px 0;}",
        "</style></head><body>",
        "<h1>Cobalt Strike 加密 HTTP Payload 取证导出</h1>",
        f"<p>导出时间: {html.escape(datetime.now().isoformat(timespec='seconds'))}</p>",
        f"<p>记录数: {len(records)}</p>",
        "<div class=\"note\">未提供 Beacon AES/HMAC 会话密钥时无法还原明文命令；本报告导出完整加密帧、密文和 HMAC 证据。</div>",
    ]

    metadata_keys = [
        "frame_number", "tcp_stream", "src_ip", "dst_ip", "method", "uri",
        "declared_length", "frame_length", "encrypted_length", "hmac_length",
        "entropy", "content_type", "length_prefix_hex", "hmac_hex",
        "artifact_bin_path", "artifact_json_path",
    ]
    for idx, record in enumerate(records):
        parts.append(f"<h2>Encrypted HTTP Body [{idx:04d}]</h2>")
        parts.append("<table>")
        for key in metadata_keys:
            if key in record and record.get(key) not in (None, ""):
                parts.append(
                    "<tr><td>"
                    + html.escape(str(key))
                    + "</td><td>"
                    + html.escape(str(record.get(key)))
                    + "</td></tr>"
                )
        parts.append("</table>")
        for label, key in (("Frame Hex", "frame_hex"), ("Encrypted Hex", "encrypted_hex")):
            hex_value = str(record.get(key) or "")
            if not hex_value:
                continue
            parts.append(f"<h3>{html.escape(label)} ({len(hex_value) // 2} bytes)</h3>")
            parts.append("<pre>")
            parts.append(html.escape("\n".join(_chunk_hex(hex_value))))
            parts.append("</pre>")

    parts.append("</body></html>")
    with open(output_path, "w", encoding="utf-8") as fp:
        fp.write("\n".join(parts))


def export_cs_payload_report(raw_values: Iterable[Any], output_path: str) -> int:
    records = collect_cs_payload_records(raw_values)
    if not records:
        raise ValueError("没有可导出的 Cobalt Strike 加密 Payload")

    ext = Path(output_path).suffix.lower()
    if ext == ".html" or ext == ".htm":
        _write_html_report(records, output_path)
    else:
        _write_json_report(records, output_path)
    return len(records)
