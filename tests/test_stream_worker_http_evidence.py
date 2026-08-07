from types import SimpleNamespace
from unittest.mock import Mock

import pytest

import core.attack_detector as attack_detector
import core.protocol_analyzer as protocol_analyzer
from core.stream_worker import AnalysisOptions, StreamAnalysisWorker
from core.tshark_stream import OutputFormat, PacketData
from models.detection_result import DetectionResult


class RecordingHandler:
    def __init__(self, packets: list[PacketData]) -> None:
        self.packets = packets
        self.configs = []

    def stream_packets(self, config):
        self.configs.append(config)
        yield from self.packets


class NoDetectionAttackDetector:
    def detect(self, **_kwargs):
        return {"detected": False}


def _detection(stream_id: int, request_frame: int) -> DetectionResult:
    return DetectionResult(
        raw_result={"tcp_stream": stream_id, "frame_number": request_frame},
        tcp_stream=stream_id,
        packet_number=request_frame,
    )


def _response(
    stream_id: int,
    request_frame: int,
    status: str,
    body: bytes,
) -> PacketData:
    packet = PacketData(
        tcp_stream=stream_id,
        http_response_code=status,
        http_response_body=body,
    )
    packet.http_request_in = str(request_frame)
    return packet


def test_http_request_analysis_uses_fields_with_cookie_body_and_response_link(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    handler = RecordingHandler([])
    worker = StreamAnalysisWorker("capture.pcap", tshark_path="test-tshark")
    worker._handler = handler

    monkeypatch.setattr(attack_detector, "AttackDetector", NoDetectionAttackDetector)

    assert worker._run_http_stream_analysis(total_packets=1) == []

    assert len(handler.configs) == 1
    config = handler.configs[0]
    assert config.output_format is OutputFormat.FIELDS
    assert {"http.cookie", "http.file_data", "http.response_in"}.issubset(
        config.fields
    )


def test_cobalt_strike_uses_request_cookie_evidence_without_pcap_rescan(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cookie_header = "session=first-pass-metadata"
    request = PacketData(
        http_method="POST",
        http_uri="/submit",
        http_request_body=b"safe=request",
    )
    request.http_cookie = cookie_header

    class RecordingCobaltStrikeAnalyzer:
        instances = []

        def __init__(self) -> None:
            self.analyze_pcap_calls = 0
            self.cookie_headers = []
            type(self).instances.append(self)

        def analyze(self, packets):
            self.cookie_headers = [packet.http.cookie for packet in packets]
            return SimpleNamespace(findings=[])

        def analyze_pcap(self, _pcap_path):
            self.analyze_pcap_calls += 1
            return SimpleNamespace(findings=[])

    worker = StreamAnalysisWorker("capture.pcap", tshark_path="test-tshark")
    worker._handler = RecordingHandler([request])

    monkeypatch.setattr(attack_detector, "AttackDetector", NoDetectionAttackDetector)
    monkeypatch.setattr(
        protocol_analyzer,
        "CobaltStrikeAnalyzer",
        RecordingCobaltStrikeAnalyzer,
    )

    worker._run_http_stream_analysis(total_packets=1)
    assert worker._run_cs_detection() == []

    analyzer = RecordingCobaltStrikeAnalyzer.instances[0]
    assert analyzer.analyze_pcap_calls == 0
    assert analyzer.cookie_headers == [cookie_header]


def _stub_analysis_boundaries(
    worker: StreamAnalysisWorker,
    monkeypatch: pytest.MonkeyPatch,
    protocol_counts: dict[str, int],
) -> tuple[Mock, Mock, Mock, Mock]:
    dns_analysis = Mock(return_value=[])
    rtp_analysis = Mock(return_value=[])
    deep_analysis = Mock(wraps=lambda: ([], []))
    http_export = Mock(return_value=[])

    monkeypatch.setattr(
        worker,
        "_run_protocol_stats",
        lambda: (protocol_counts, 1, []),
    )
    monkeypatch.setattr(worker, "_run_http_stream_analysis", lambda _total: [])
    monkeypatch.setattr(worker, "_run_icmp_analysis", lambda: [])
    monkeypatch.setattr(worker, "_run_dns_analysis", dns_analysis)
    monkeypatch.setattr(worker, "_run_cs_detection", lambda: [])
    monkeypatch.setattr(worker, "_run_rtp_analysis", rtp_analysis)
    monkeypatch.setattr(worker, "_run_deep_protocol_analysis", deep_analysis)
    monkeypatch.setattr(
        worker,
        "_scan_http_responses",
        lambda _results: [],
        raising=False,
    )
    monkeypatch.setattr(worker, "_export_http_objects", http_export, raising=False)

    return dns_analysis, rtp_analysis, deep_analysis, http_export


def test_protocol_counts_do_not_skip_dns_rtp_or_deep_analysis(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    worker = StreamAnalysisWorker(
        "capture.pcap",
        options=AnalysisOptions(
            auto_decode=False,
            extract_files=False,
            file_recovery=False,
        ),
        tshark_path="test-tshark",
    )
    dns_analysis, rtp_analysis, deep_analysis, _http_export = _stub_analysis_boundaries(
        worker,
        monkeypatch,
        {"UDP": 1},
    )

    worker._run_analysis()

    dns_analysis.assert_called_once_with()
    rtp_analysis.assert_called_once_with()
    deep_analysis.assert_called_once_with()


def test_deep_manager_does_not_repeat_already_run_protocols(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    worker = StreamAnalysisWorker("capture.pcap", tshark_path="test-tshark")
    captured = {}

    class RecordingManager:
        def analyze_all_pcap(self, pcap_path, **kwargs):
            captured["pcap_path"] = pcap_path
            captured.update(kwargs)
            return {}

    monkeypatch.setattr(protocol_analyzer, "ProtocolAnalyzerManager", RecordingManager)

    assert worker._run_deep_protocol_analysis() == ([], [])
    assert captured["pcap_path"] == "capture.pcap"
    assert protocol_analyzer.ProtocolType.ICMP not in captured["enabled_protocols"]
    assert protocol_analyzer.ProtocolType.DNS not in captured["enabled_protocols"]
    assert protocol_analyzer.ProtocolType.COBALT_STRIKE not in captured["enabled_protocols"]
    assert captured["parallel"] is True
    assert captured["max_workers"] == 4


def test_extract_files_disabled_skips_http_object_export(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    worker = StreamAnalysisWorker(
        "capture.pcap",
        options=AnalysisOptions(
            auto_decode=False,
            extract_files=False,
            file_recovery=False,
        ),
        tshark_path="test-tshark",
    )
    _dns_analysis, _rtp_analysis, _deep_analysis, http_export = _stub_analysis_boundaries(
        worker,
        monkeypatch,
        {"HTTP": 1},
    )

    worker._run_analysis()

    http_export.assert_not_called()
