from typing import Iterable
import tempfile

import pytest

from core.stream_worker import AnalysisOptions, StreamAnalysisWorker
from core.tshark_stream import PacketData, OutputFormat
from models.detection_result import DetectionResult


class RecordingHandler:
    def __init__(self, packets: Iterable[PacketData]) -> None:
        self.packets = list(packets)
        self.configs = []

    def stream_packets(self, config):
        self.configs.append(config)
        yield from self.packets


def _detection(stream_id: int) -> DetectionResult:
    return DetectionResult(
        raw_result={"tcp_stream": stream_id},
        tcp_stream=stream_id,
    )


def _response(stream_id: int, status: str, body: bytes) -> PacketData:
    return PacketData(
        tcp_stream=stream_id,
        http_response_code=status,
        http_response_body=body,
    )


def test_response_scan_scans_once_and_keeps_first_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first_stream_10 = _response(10, "200", b"first-stream-10")
    later_stream_10 = _response(10, "201", b"later-stream-10")
    unrelated_stream = _response(999, "418", b"unrelated-stream")
    first_stream_20 = _response(20, "404", b"first-stream-20")
    handler = RecordingHandler(
        [first_stream_10, later_stream_10, unrelated_stream, first_stream_20]
    )

    worker = StreamAnalysisWorker("capture.pcap", tshark_path="test-tshark")
    worker._handler = handler
    worker._is_cancelled = False

    inspected_streams: list[int] = []

    def record_headers(packet: PacketData) -> str:
        inspected_streams.append(packet.tcp_stream)
        return ""

    monkeypatch.setattr(worker, "_extract_response_headers", record_headers)

    results = [_detection(10), _detection(10), _detection(20)]
    extracted_files = worker._scan_http_responses(results)

    assert extracted_files == []
    assert len(handler.configs) == 1

    config = handler.configs[0]
    assert config.display_filter == "http.response"
    assert "tcp.stream" not in config.display_filter
    assert config.output_format is OutputFormat.FIELDS

    # The unrelated packet must never be treated as a response candidate.
    assert inspected_streams == [10, 20]

    for result in results[:2]:
        assert result.raw_result["response_status"] == "200"
        assert result.raw_result["response_sample"] == "first-stream-10"
        assert result.response_sample == "first-stream-10"
        assert result.response_data == "HTTP/1.1 200\r\n\r\nfirst-stream-10"

    result = results[2]
    assert result.raw_result["response_status"] == "404"
    assert result.raw_result["response_sample"] == "first-stream-20"
    assert result.response_sample == "first-stream-20"
    assert result.response_data == "HTTP/1.1 404\r\n\r\nfirst-stream-20"


def test_response_scan_uses_content_disposition_from_response_line(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    packet = _response(10, "200", b"PK\x03\x04archive")
    packet.frame_number = 42
    packet.http_content_type = "application/zip"
    packet.http_response_lines = [
        'Content-Disposition: attachment; filename="from-header.zip"'
    ]
    handler = RecordingHandler([packet])
    worker = StreamAnalysisWorker(
        "capture.pcap",
        options=AnalysisOptions(extract_files=True),
        tshark_path="test-tshark",
    )
    worker._handler = handler
    worker._is_cancelled = False
    monkeypatch.setattr(tempfile, "mkdtemp", lambda _prefix: str(tmp_path))

    extracted_files = worker._scan_http_responses([])

    assert "http.content_disposition" not in handler.configs[0].fields
    assert extracted_files[0].file_name == "from-header.zip"
    assert (tmp_path / "from-header.zip").read_bytes() == packet.http_response_body


def test_response_content_disposition_preserves_quoted_comma_and_colon() -> None:
    packet = _response(10, "200", b"")
    packet.http_response_lines = [
        'Content-Disposition: attachment; filename="report,final:1.zip",Content-Type: application/zip'
    ]

    worker = StreamAnalysisWorker("capture.pcap", tshark_path="test-tshark")

    assert worker._response_content_disposition(packet) == (
        'attachment; filename="report,final:1.zip"'
    )
