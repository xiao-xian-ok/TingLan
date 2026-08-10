from threading import Barrier
from unittest.mock import Mock

from core.protocol_analyzer import (
    ProtocolAnalysisResult,
    ProtocolAnalyzerManager,
    ProtocolType,
)


def test_analyze_all_pcap_runs_only_enabled_protocols() -> None:
    selected_protocol = ProtocolType.DNS
    disabled_protocol = ProtocolType.FTP

    selected_result = ProtocolAnalysisResult(
        protocol=selected_protocol,
        packet_count=1,
    )
    disabled_result = ProtocolAnalysisResult(
        protocol=disabled_protocol,
        packet_count=1,
    )

    selected_analyzer = Mock()
    selected_analyzer.analyze_pcap.return_value = selected_result
    disabled_analyzer = Mock()
    disabled_analyzer.analyze_pcap.return_value = disabled_result

    manager = ProtocolAnalyzerManager.__new__(ProtocolAnalyzerManager)
    manager._analyzers = {
        selected_protocol: selected_analyzer,
        disabled_protocol: disabled_analyzer,
    }

    results = manager.analyze_all_pcap(
        "capture.pcap",
        enabled_protocols={selected_protocol},
    )

    selected_analyzer.analyze_pcap.assert_called_once()
    disabled_analyzer.analyze_pcap.assert_not_called()
    assert results == {selected_protocol: selected_result}


def test_analyze_all_pcap_runs_every_registered_analyzer_when_not_gated() -> None:
    manager = ProtocolAnalyzerManager.__new__(ProtocolAnalyzerManager)
    expected_results = {
        protocol: ProtocolAnalysisResult(protocol=protocol, packet_count=1)
        for protocol in ProtocolType
    }
    manager._analyzers = {}

    for protocol, result in expected_results.items():
        analyzer = Mock()
        analyzer.analyze_pcap.return_value = result
        manager._analyzers[protocol] = analyzer

    results = manager.analyze_all_pcap("capture.pcap")

    assert results == expected_results
    for protocol, analyzer in manager._analyzers.items():
        expected_filter = manager._BASE_ANALYZER_FILTERS.get(protocol)
        if expected_filter:
            analyzer.analyze_pcap.assert_called_once_with(
                "capture.pcap",
                display_filter=expected_filter,
            )
        else:
            analyzer.analyze_pcap.assert_called_once_with("capture.pcap")


def test_analyze_all_pcap_reports_analyzer_progress() -> None:
    manager = ProtocolAnalyzerManager.__new__(ProtocolAnalyzerManager)
    protocols = [ProtocolType.FTP, ProtocolType.SMTP]
    manager._analyzers = {}
    for protocol in protocols:
        analyzer = Mock()
        analyzer.analyze_pcap.return_value = ProtocolAnalysisResult(
            protocol=protocol,
            packet_count=1,
        )
        manager._analyzers[protocol] = analyzer

    updates = []
    manager.analyze_all_pcap(
        "capture.pcap",
        progress_callback=lambda index, total, protocol: updates.append(
            (index, total, protocol)
        ),
    )

    assert updates == [(0, 2, protocols[0]), (1, 2, protocols[1])]


def test_base_packet_analyzers_receive_protocol_filters() -> None:
    manager = ProtocolAnalyzerManager.__new__(ProtocolAnalyzerManager)
    ftp = Mock()
    smtp = Mock()
    ftp.analyze_pcap.return_value = ProtocolAnalysisResult(
        protocol=ProtocolType.FTP,
        packet_count=0,
    )
    smtp.analyze_pcap.return_value = ProtocolAnalysisResult(
        protocol=ProtocolType.SMTP,
        packet_count=0,
    )
    manager._analyzers = {
        ProtocolType.FTP: ftp,
        ProtocolType.SMTP: smtp,
    }

    manager.analyze_all_pcap("capture.pcap")

    ftp.analyze_pcap.assert_called_once_with(
        "capture.pcap",
        display_filter="ftp || ftp-data",
    )
    smtp.analyze_pcap.assert_called_once_with(
        "capture.pcap",
        display_filter="smtp",
    )


def test_bluetooth_filter_uses_supported_dissector_names() -> None:
    bluetooth_filter = ProtocolAnalyzerManager._BASE_ANALYZER_FILTERS[
        ProtocolType.BLUETOOTH
    ]

    assert "l2cap" not in bluetooth_filter.split()


def test_analyze_all_pcap_can_run_analyzers_in_parallel() -> None:
    manager = ProtocolAnalyzerManager.__new__(ProtocolAnalyzerManager)
    protocols = [ProtocolType.FTP, ProtocolType.SMTP]
    barrier = Barrier(len(protocols))
    manager._analyzers = {}

    for protocol in protocols:
        analyzer = Mock()

        def analyze(_pcap_path, _protocol=protocol, **_kwargs):
            barrier.wait(timeout=2)
            return ProtocolAnalysisResult(protocol=_protocol, packet_count=1)

        analyzer.analyze_pcap.side_effect = analyze
        manager._analyzers[protocol] = analyzer

    results = manager.analyze_all_pcap(
        "capture.pcap",
        parallel=True,
        max_workers=2,
    )

    assert set(results) == set(protocols)


# ------------------------------------------------ 按 io,phs 统计门控分析器
#
# 这是听澜里少数几个允许的"跳过"，边界必须锁死：只能跳过那些每一次 tshark
# 调用都带协议层过滤的分析器，且统计拿不到时一律照跑。


SELECT = ProtocolAnalyzerManager.select_runnable_protocols
ALL_DEEP = [
    ProtocolType.FTP, ProtocolType.MMS, ProtocolType.BLUETOOTH,
    ProtocolType.SMTP, ProtocolType.USB, ProtocolType.SMB,
    ProtocolType.TLS, ProtocolType.RDP, ProtocolType.REDIS, ProtocolType.SSH,
]


def test_missing_protocol_layer_is_skipped() -> None:
    """纯 HTTP 抓包不该再为 FTP/SMTP/USB 各扫一趟全文件"""
    runnable, skipped = SELECT(ALL_DEEP, {"HTTP": 500, "TCP": 900, "ETH": 900})

    assert ProtocolType.FTP in skipped
    assert ProtocolType.SMTP in skipped
    assert ProtocolType.USB in skipped
    assert ProtocolType.MMS in skipped


def test_present_protocol_layer_still_runs() -> None:
    runnable, skipped = SELECT(ALL_DEEP, {"HTTP": 10, "FTP": 3, "SMB2": 7})

    assert ProtocolType.FTP in runnable
    assert ProtocolType.SMB in runnable
    assert ProtocolType.FTP not in skipped


def test_port_based_analyzers_are_never_gated() -> None:
    """TLS/RDP/Redis/SSH 有裸端口或裸 SYN 路径，不带协议层也能出东西"""
    runnable, skipped = SELECT(ALL_DEEP, {"HTTP": 500, "ETH": 500})

    for protocol in (ProtocolType.TLS, ProtocolType.RDP,
                     ProtocolType.REDIS, ProtocolType.SSH):
        assert protocol in runnable, f"{protocol.value} 不允许被协议层门控"
        assert protocol not in skipped


def test_ntlm_over_http_keeps_smb_analyzer_alive() -> None:
    """只有 HTTP NTLM 认证、没有 SMB 时，SMB 分析器仍要跑（它抓的是哈希）"""
    runnable, _skipped = SELECT(ALL_DEEP, {"HTTP": 20, "NTLMSSP": 4})

    assert ProtocolType.SMB in runnable


def test_missing_stats_runs_everything() -> None:
    """统计失败 != 没有这些协议，必须全部照跑"""
    for empty in ({}, None):
        runnable, skipped = SELECT(ALL_DEEP, empty)
        assert skipped == set()
        assert runnable == set(ALL_DEEP)


def test_zero_count_layer_is_treated_as_absent() -> None:
    runnable, skipped = SELECT([ProtocolType.FTP], {"FTP": 0, "HTTP": 9})

    assert ProtocolType.FTP in skipped
    assert runnable == set()


def test_unknown_protocol_without_alias_always_runs() -> None:
    """别名表里没登记的协议要默认跑，查表落空不能变成跳过"""
    runnable, skipped = SELECT([ProtocolType.HTTP], {"FTP": 3})

    assert ProtocolType.HTTP in runnable
    assert skipped == set()

