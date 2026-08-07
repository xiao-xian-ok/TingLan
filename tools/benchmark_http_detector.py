"""Benchmark TingLan's HTTP request detector with a minimal TShark fields stream."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.attack_detector import AttackDetector  # noqa: E402
from core.tshark_fields import separator_arg, split_fields  # noqa: E402
from core.tshark_locator import find_tshark  # noqa: E402


FIELDS = (
    "frame.number",
    "ip.src",
    "ip.dst",
    "tcp.stream",
    "http.request.method",
    "http.request.uri",
    "http.host",
    "http.content_type",
    "http.user_agent",
    "http.file_data",
)


def decode_hex_field(value: str) -> bytes:
    cleaned = value.replace(":", "").replace(" ", "")
    if not cleaned:
        return b""
    try:
        return bytes.fromhex(cleaned)
    except ValueError:
        return value.encode("utf-8", errors="replace")


def benchmark(
    pcap_path: Path,
    max_detections: int,
    benchmark_auto_decode: bool = False,
) -> dict:
    tshark = find_tshark()
    if not tshark:
        raise RuntimeError("TShark not found")

    command = [
        tshark,
        "-r",
        str(pcap_path),
        "-n",
        "-Y",
        "http.request",
        "-T",
        "fields",
    ]
    for field in FIELDS:
        command.extend(("-e", field))
    command.extend(("-E", separator_arg(), "-E", "quote=n"))

    popen_kwargs = {
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "text": True,
        "encoding": "utf-8",
        "errors": "replace",
        "bufsize": 1,
    }
    if sys.platform == "win32":
        popen_kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)

    detector = AttackDetector()
    seen = set()
    detection_streams = set()
    requests = 0
    unique_requests = 0
    duplicates = 0
    detections = 0
    detected_payloads: list[tuple[str, str]] = []
    detector_seconds = 0.0
    started = time.perf_counter()
    process = subprocess.Popen(command, **popen_kwargs)

    assert process.stdout is not None
    assert process.stderr is not None
    try:
        for line in process.stdout:
            values = split_fields(line.rstrip("\r\n"), expected=len(FIELDS))
            requests += 1

            stream_id = values[3]
            method = values[4]
            uri = values[5]
            content_type = values[7]
            body = decode_hex_field(values[9])
            if not body and "?" in uri:
                body = uri.split("?", 1)[1].encode("utf-8", errors="replace")
            if not body:
                body = uri.encode("utf-8", errors="replace")

            dedup_key = f"{method}:{uri[:100]}:{len(body)}"
            if dedup_key in seen:
                duplicates += 1
                continue
            seen.add(dedup_key)
            unique_requests += 1

            if detections >= max_detections or not body:
                continue

            detect_started = time.perf_counter()
            result = detector.detect(
                data=body,
                method=method,
                uri=uri,
                content_type=content_type,
            )
            detector_seconds += time.perf_counter() - detect_started
            if result.get("detected", False) and result.get("total_weight", 0) >= 20:
                detections += 1
                if stream_id.isdigit():
                    detection_streams.add(int(stream_id))
                if benchmark_auto_decode:
                    detected_payloads.append(
                        (body.decode("utf-8", errors="replace")[:5000], uri)
                    )
    finally:
        process.stdout.close()

    stderr = process.stderr.read()
    returncode = process.wait()
    elapsed = time.perf_counter() - started
    auto_decode_result = None
    if benchmark_auto_decode:
        from core.auto_decoder import MagicDecoder

        decoder = MagicDecoder()
        decode_calls = 0
        meaningful_results = 0
        decode_started = time.perf_counter()
        for raw_body, uri in detected_payloads:
            candidates = []
            if len(raw_body) > 10:
                candidates.append(raw_body)
            if "?" in uri:
                query = uri.split("?", 1)[1]
                if len(query) > 4:
                    candidates.append(query)
            for candidate in candidates:
                decoded = decoder.decode_http_payload(candidate)
                decode_calls += 1
                if (
                    (decoded.total_layers > 0 or decoded.flags_found)
                    and decoded.is_meaningful
                ):
                    meaningful_results += 1
        auto_decode_result = {
            "elapsed_sec": round(time.perf_counter() - decode_started, 3),
            "calls": decode_calls,
            "meaningful_results": meaningful_results,
        }

    result = {
        "pcap": str(pcap_path.resolve()),
        "command": command,
        "returncode": returncode,
        "elapsed_sec": round(elapsed, 3),
        "detector_sec": round(detector_seconds, 3),
        "tshark_and_parse_sec": round(max(0.0, elapsed - detector_seconds), 3),
        "http_requests": requests,
        "unique_requests": unique_requests,
        "duplicates": duplicates,
        "detections": detections,
        "detection_stream_count": len(detection_streams),
        "detection_streams": sorted(detection_streams),
        "stderr_preview": stderr[:2000],
        "secondary_auto_decode": auto_decode_result,
    }
    return result


def run_fields_command(command: list[str]) -> tuple[float, int, int, str, int]:
    started = time.perf_counter()
    completed = subprocess.run(
        command,
        capture_output=True,
        text=False,
        creationflags=(
            getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
            if sys.platform == "win32"
            else 0
        ),
    )
    elapsed = time.perf_counter() - started
    stdout = completed.stdout or b""
    stderr = (completed.stderr or b"").decode("utf-8", errors="replace")
    return elapsed, len(stdout), stdout.count(b"\n"), stderr, completed.returncode


def benchmark_responses(pcap_path: Path, detection_streams: list[int]) -> dict:
    tshark = find_tshark()
    if not tshark:
        raise RuntimeError("TShark not found")

    metadata_fields = (
        "frame.number",
        "tcp.stream",
        "http.response.code",
        "http.content_type",
        "http.content_length",
    )
    metadata_command = [
        tshark,
        "-r",
        str(pcap_path),
        "-n",
        "-Y",
        "http.response",
        "-T",
        "fields",
    ]
    for field in metadata_fields:
        metadata_command.extend(("-e", field))
    metadata_command.extend(("-E", separator_arg(), "-E", "quote=n"))

    started = time.perf_counter()
    completed = subprocess.run(
        metadata_command,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        creationflags=(
            getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
            if sys.platform == "win32"
            else 0
        ),
    )
    metadata_elapsed = time.perf_counter() - started
    target_streams = set(detection_streams)
    response_frames: dict[int, int] = {}
    response_rows = 0
    for line in completed.stdout.splitlines():
        values = split_fields(line, expected=len(metadata_fields))
        response_rows += 1
        if not values[0].isdigit() or not values[1].isdigit():
            continue
        stream_id = int(values[1])
        if stream_id in target_streams and stream_id not in response_frames:
            response_frames[stream_id] = int(values[0])

    body_result = {
        "elapsed_sec": 0.0,
        "stdout_bytes": 0,
        "records": 0,
        "returncode": 0,
        "stderr_preview": "",
        "command_chars": 0,
    }
    if response_frames:
        frame_filter = "frame.number in { " + ", ".join(
            str(frame) for frame in response_frames.values()
        ) + " }"
        body_command = [
            tshark,
            "-r",
            str(pcap_path),
            "-n",
            "-Y",
            frame_filter,
            "-T",
            "fields",
            "-e",
            "frame.number",
            "-e",
            "tcp.stream",
            "-e",
            "http.response.code",
            "-e",
            "http.content_type",
            "-e",
            "http.content_length",
            "-e",
            "http.response.line",
            "-e",
            "http.file_data",
            "-E",
            separator_arg(),
            "-E",
            "quote=n",
        ]
        elapsed, stdout_bytes, records, stderr, returncode = run_fields_command(body_command)
        body_result = {
            "elapsed_sec": round(elapsed, 3),
            "stdout_bytes": stdout_bytes,
            "records": records,
            "returncode": returncode,
            "stderr_preview": stderr[:2000],
            "command_chars": sum(len(arg) + 1 for arg in body_command),
        }

    return {
        "metadata": {
            "elapsed_sec": round(metadata_elapsed, 3),
            "stdout_bytes": len(completed.stdout.encode("utf-8")),
            "records": response_rows,
            "returncode": completed.returncode,
            "stderr_preview": completed.stderr[:2000],
        },
        "requested_streams": len(target_streams),
        "matched_streams": len(response_frames),
        "targeted_body": body_result,
        "total_elapsed_sec": round(metadata_elapsed + body_result["elapsed_sec"], 3),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("pcap", type=Path)
    parser.add_argument("--max-detections", type=int, default=5000)
    parser.add_argument("--include-response", action="store_true")
    parser.add_argument("--benchmark-auto-decode", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    result = benchmark(
        args.pcap,
        args.max_detections,
        benchmark_auto_decode=args.benchmark_auto_decode,
    )
    if args.include_response:
        result["response_benchmark"] = benchmark_responses(
            args.pcap, result["detection_streams"]
        )
    rendered = json.dumps(result, ensure_ascii=False, indent=2)
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered)
    return 0 if result["returncode"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
