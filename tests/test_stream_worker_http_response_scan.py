from unittest.mock import Mock

import pytest

import core.stream_worker as stream_worker
from core.stream_worker import AnalysisOptions, StreamAnalysisWorker
from core.tshark_stream import OutputFormat, PacketData
from models.detection_result import DetectionResult
from services.analysis_service import AnalysisService


class RecordingHandler:
    def __init__(self, packets: list[PacketData]) -> None:
        self.packets = packets
        self.configs = []

    def stream_packets(self, config):
        self.configs.append(config)
        yield from self.packets


def _worker() -> StreamAnalysisWorker:
    return StreamAnalysisWorker(
        "capture.pcap",
        options=AnalysisOptions(
            auto_decode=False,
            file_recovery=False,
        ),
        tshark_path="test-tshark",
    )


def _detection(request_frame: int) -> DetectionResult:
    return DetectionResult(
        raw_result={"tcp_stream": 9, "frame_number": request_frame},
        tcp_stream=9,
        packet_number=request_frame,
    )


def _response(
    frame_number: int,
    body: bytes,
    *,
    request_frame: int | None = None,
    content_type: str = "text/plain",
    content_disposition: str = "",
) -> PacketData:
    packet = PacketData(
        frame_number=frame_number,
        tcp_stream=9,
        http_response_code="201",
        http_content_type=content_type,
        http_response_body=body,
    )
    packet.http_request_in = str(request_frame) if request_frame is not None else ""
    packet.http_content_disposition = content_disposition
    return packet


def test_response_scan_uses_one_fields_stream_for_links_and_unlinked_files(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    linked_detection = _detection(request_frame=17)
    handler = RecordingHandler(
        [
            _response(23, b'{"ok":true}', request_frame=17, content_type="application/json"),
            _response(
                41,
                b"PK\x03\x04archive-data",
                content_disposition='attachment; filename="archive.zip"',
            ),
        ]
    )
    worker = _worker()
    worker._handler = handler
    legacy_export = Mock(return_value=[])
    monkeypatch.setattr(AnalysisService, "extract_http_objects", legacy_export)

    extracted_files = worker._scan_http_responses([linked_detection])

    assert len(handler.configs) == 1
    config = handler.configs[0]
    assert config.display_filter == "http.response"
    assert config.output_format is OutputFormat.FIELDS
    assert "http.file_data" in config.fields
    assert "http.content_disposition" not in config.fields
    legacy_export.assert_not_called()

    assert linked_detection.raw_result["response_status"] == "201"
    assert linked_detection.response_sample == '{"ok":true}'
    assert len(extracted_files) == 1
    assert extracted_files[0].file_name == "archive.zip"
    assert extracted_files[0].source_packet == 41


class ClosableIterator:
    def __init__(self, worker: StreamAnalysisWorker) -> None:
        self.worker = worker
        self.close_calls = 0
        self._yielded = False

    def __iter__(self):
        return self

    def __next__(self) -> PacketData:
        if self._yielded:
            raise StopIteration
        self._yielded = True
        self.worker._is_cancelled = True
        return _response(99, b"<html>cancelled</html>")

    def close(self) -> None:
        self.close_calls += 1


class IteratorHandler:
    def __init__(self, packet_iter: ClosableIterator) -> None:
        self.packet_iter = packet_iter
        self.configs = []

    def stream_packets(self, config):
        self.configs.append(config)
        return self.packet_iter


def test_response_scan_cancellation_closes_tshark_iterator() -> None:
    worker = _worker()
    packet_iter = ClosableIterator(worker)
    worker._handler = IteratorHandler(packet_iter)

    assert worker._scan_http_responses([]) == []
    assert packet_iter.close_calls == 1


def test_response_scan_does_not_allocate_paths_for_static_images(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    worker = _worker()
    worker._handler = RecordingHandler(
        [_response(72, b"\x89PNG\r\n\x1a\n" + b"x" * 300, content_type="image/png")]
    )
    safe_path = Mock(side_effect=AssertionError("static images must not be materialized"))
    monkeypatch.setattr(stream_worker, "safe_unique_path", safe_path)

    assert worker._scan_http_responses([]) == []
    safe_path.assert_not_called()
