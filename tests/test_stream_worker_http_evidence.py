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
    deep_analysis = Mock(wraps=lambda *_args, **_kwargs: ([], []))
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
    # 协议分级统计要原样传给深度分析，它靠这个决定哪些分析器跑了也没用
    deep_analysis.assert_called_once_with({"UDP": 1})


def test_deep_manager_does_not_repeat_already_run_protocols(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    worker = StreamAnalysisWorker("capture.pcap", tshark_path="test-tshark")
    captured = {}
    real_manager = protocol_analyzer.ProtocolAnalyzerManager

    class RecordingManager:
        # 门控逻辑用真的那一份，这样这个测试同时锁住"统计怎么影响选型"
        select_runnable_protocols = real_manager.select_runnable_protocols

        def analyze_all_pcap(self, pcap_path, **kwargs):
            captured["pcap_path"] = pcap_path
            captured.update(kwargs)
            return {}

    monkeypatch.setattr(protocol_analyzer, "ProtocolAnalyzerManager", RecordingManager)

    # 统计里只有 HTTP：ICMP/DNS/CS 由前面的独立阶段跑过，不该重复；
    # FTP/SMTP/USB 这些协议层压根不存在，跑了也必然匹配 0 个包。
    assert worker._run_deep_protocol_analysis({"HTTP": 12}) == ([], [])
    assert captured["pcap_path"] == "capture.pcap"
    enabled = captured["enabled_protocols"]
    assert protocol_analyzer.ProtocolType.ICMP not in enabled
    assert protocol_analyzer.ProtocolType.DNS not in enabled
    assert protocol_analyzer.ProtocolType.COBALT_STRIKE not in enabled
    assert protocol_analyzer.ProtocolType.FTP not in enabled
    assert protocol_analyzer.ProtocolType.USB not in enabled
    # 带裸端口/裸 SYN 路径的分析器不受协议层门控
    assert protocol_analyzer.ProtocolType.SSH in enabled
    assert protocol_analyzer.ProtocolType.TLS in enabled
    assert captured["parallel"] is True
    assert captured["max_workers"] == 4


def test_deep_analysis_runs_everything_when_stats_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """协议统计失败时不许门控——"统计没出来"和"没有这个协议"是两回事"""
    worker = StreamAnalysisWorker("capture.pcap", tshark_path="test-tshark")
    captured = {}
    real_manager = protocol_analyzer.ProtocolAnalyzerManager

    class RecordingManager:
        select_runnable_protocols = real_manager.select_runnable_protocols

        def analyze_all_pcap(self, pcap_path, **kwargs):
            captured.update(kwargs)
            return {}

    monkeypatch.setattr(protocol_analyzer, "ProtocolAnalyzerManager", RecordingManager)

    worker._run_deep_protocol_analysis({})

    enabled = captured["enabled_protocols"]
    assert protocol_analyzer.ProtocolType.FTP in enabled
    assert protocol_analyzer.ProtocolType.USB in enabled
    assert protocol_analyzer.ProtocolType.SMB in enabled


def test_extract_files_disabled_produces_no_artifacts(tmp_path) -> None:
    """extract_files=False 时不产出任何落盘文件

    这条原来断言的是 `http_export.assert_not_called()`，而 `_export_http_objects`
    已经作为死代码删除了 —— `monkeypatch.setattr(..., raising=False)` 只是凭空
    建了个属性，谁也不会调它，于是断言**恒真、永不失败**。绿的、没人看、零保护，
    比没有更糟。

    改成断言**产出**：给一个带可落盘响应体的响应包，走真实的
    `_scan_http_responses`，看开关有没有真的挡住文件生成。
    """
    body = b"PK\x03\x04" + b"A" * 512          # zip 魔数，inspector 会认

    def _make_worker(extract_files: bool):
        packet = PacketData(
            frame_number=42,
            tcp_stream=1,
            http_response_code="200",
            http_response_body=body,
            http_content_type="application/zip",
        )
        packet.http_response_lines = [
            'Content-Disposition: attachment; filename="loot.zip"'
        ]
        worker = StreamAnalysisWorker(
            "capture.pcap",
            options=AnalysisOptions(extract_files=extract_files),
            tshark_path="test-tshark",
        )
        worker._handler = RecordingHandler([packet])
        worker._is_cancelled = False
        return worker

    # 先证明这个包在开关打开时确实会产出文件，否则下面的"没产出"是假通过
    import tempfile as _tempfile
    original_mkdtemp = _tempfile.mkdtemp
    try:
        _tempfile.mkdtemp = lambda _prefix: str(tmp_path)
        enabled = _make_worker(True)._scan_http_responses([])
        assert len(enabled) == 1
        assert enabled[0].file_name == "loot.zip"

        disabled = _make_worker(False)._scan_http_responses([])
        assert disabled == []
    finally:
        _tempfile.mkdtemp = original_mkdtemp
