# mock服务，开发调试用的

import os
from typing import List, Optional, Callable, Tuple

from services.interfaces import IAnalysisService
from models.detection_result import (
    DetectionResult,
    DetectionType,
    ThreatLevel,
    ProtocolStats,
    AnalysisSummary,
    ExtractedFile
)


class MockAnalysisService(IAnalysisService):

    def find_tshark(self) -> Optional[str]:
        return "/mock/tshark"

    def analyze_pcap(
        self,
        pcap_path: str,
        options: dict,
        on_progress: Optional[Callable[[int, str], None]] = None,
        on_detection: Optional[Callable[[DetectionResult], None]] = None
    ) -> AnalysisSummary:
        def emit_progress(pct: int, msg: str):
            if on_progress:
                on_progress(pct, msg)

        emit_progress(0, "[Mock] 开始模拟分析...")
        emit_progress(30, "[Mock] 模拟协议统计...")
        emit_progress(50, "[Mock] 模拟Webshell检测...")

        detections = []
        if options.get("detect_webshell", True):
            det1 = DetectionResult(
                detection_type=DetectionType.ANTSWORD,
                threat_level=ThreatLevel.HIGH,
                method="POST",
                uri="/shell.php",
                indicator="@ini_set 特征",
                source_ip="192.168.1.100",
                dest_ip="192.168.1.200",
                payload={"cmd": "whoami", "encoded": "base64..."},
                raw_result={"type": "antsword", "confidence": 0.95}
            )
            detections.append(det1)
            if on_detection:
                on_detection(det1)

            det2 = DetectionResult(
                detection_type=DetectionType.CAIDAO,
                threat_level=ThreatLevel.HIGH,
                method="POST",
                uri="/admin/backdoor.php",
                indicator="z0 参数特征",
                source_ip="192.168.1.100",
                dest_ip="192.168.1.200",
                payload={"z0": "QGluaV9zZXQ..."},
                raw_result={"type": "caidao", "confidence": 0.88}
            )
            detections.append(det2)
            if on_detection:
                on_detection(det2)

        emit_progress(70, "[Mock] 模拟文件提取...")

        extracted_files = self.extract_http_objects(pcap_path)

        emit_progress(90, "[Mock] 生成报告...")

        protocol_stats = [
            ProtocolStats("HTTP", 1250, 45.5),
            ProtocolStats("TCP", 2800, 100.0),
            ProtocolStats("TLS", 500, 17.9),
            ProtocolStats("DNS", 120, 4.3),
            ProtocolStats("UDP", 80, 2.9),
        ]

        summary = AnalysisSummary(
            file_path=pcap_path,
            total_packets=2800,
            protocol_stats=protocol_stats,
            detections=detections,
            extracted_files=extracted_files,
            analysis_time=1.5
        )

        emit_progress(100, "[Mock] 模拟分析完成")
        return summary

    def extract_http_objects(self, pcap_path: str) -> List[ExtractedFile]:
        return [
            ExtractedFile(
                file_path="/mock/shell.zip",
                file_name="shell.zip",
                file_type="archive",
                file_size=4403,
                source_packet=30540,
                content_type="application/zip",
                pcap_path=pcap_path
            ),
            ExtractedFile(
                file_path="/mock/logo.png",
                file_name="logo.png",
                file_type="image",
                file_size=15234,
                source_packet=1024,
                content_type="image/png",
                pcap_path=pcap_path
            ),
            ExtractedFile(
                file_path="/mock/config.json",
                file_name="config.json",
                file_type="code",
                file_size=892,
                source_packet=2048,
                content_type="application/json",
                pcap_path=pcap_path
            ),
            ExtractedFile(
                file_path="/mock/document.pdf",
                file_name="document.pdf",
                file_type="document",
                file_size=125678,
                source_packet=5000,
                content_type="application/pdf",
                pcap_path=pcap_path
            ),
        ]

    def get_file_hex_content(self, file_path: str, max_bytes: int = 4096) -> str:
        # 模拟 ZIP 文件头
        if "zip" in file_path.lower():
            return """0000   50 4b 03 04 14 00 00 00  08 00 54 d5 47 69 5a d5   PK........T.GiZ.
0010   00 00 00 00 04 00 00 00  00 00 00 00 09 00 1c 00   ................
0020   73 68 65 6c 6c 2e 70 68  70 55 54 09 00 03 54 d5   shell.phpUT...T.
0030   47 69 5a d5 47 69 75 78  0b 00 01 04 e8 03 00 00   GiZ.Giux........
0040   04 e8 03 00 00 3c 3f 70  68 70 20 40 69 6e 69 5f   .....<?php @ini_
0050   73 65 74 28 22 64 69 73  70 6c 61 79 5f 65 72 72   set("display_err

... (仅显示前 4096 字节)"""

        # 模拟 PNG 文件头
        if "png" in file_path.lower():
            return """0000   89 50 4e 47 0d 0a 1a 0a  00 00 00 0d 49 48 44 52   .PNG........IHDR
0010   00 00 00 64 00 00 00 64  08 06 00 00 00 70 e2 95   ...d...d.....p..
0020   54 00 00 00 09 70 48 59  73 00 00 0b 13 00 00 0b   T....pHYs.......
0030   13 01 00 9a 9c 18 00 00  00 04 67 41 4d 41 00 00   ..........gAMA..

... (仅显示前 4096 字节)"""

        # 默认
        return """0000   00 01 02 03 04 05 06 07  08 09 0a 0b 0c 0d 0e 0f   ................
0010   10 11 12 13 14 15 16 17  18 19 1a 1b 1c 1d 1e 1f   ................

... (Mock 数据)"""

    def get_packet_detail(self, pcap_path: str, packet_num: int) -> Tuple[str, List[str]]:
        protocol_layers = [
            f"Frame {packet_num}: 4469 bytes on wire (35752 bits), 4469 bytes captured (35752 bits)",
            "Ethernet II, Src: VMware_70:1b:62 (00:0c:29:70:1b:62), Dst: VMware_15:62:83 (00:0c:29:15:62:83)",
            "Internet Protocol Version 4, Src: 192.168.1.201, Dst: 192.168.1.200",
            "Transmission Control Protocol, Src Port: 8080, Dst Port: 46584, Seq: 257, Ack: 91, Len: 4403",
            "[2 Reassembled TCP Segments (4659 bytes): #30537(256), #30540(4403)]",
            "Hypertext Transfer Protocol",
            "Media Type"
        ]

        hex_dump = """0000   00 0c 29 15 62 83 00 0c  29 70 1b 62 08 00 45 00   ..)·b··)p·b··E·
0010   11 67 15 8a 40 00 40 06  8f 25 c0 a8 01 c9 c0 a8   ·g··@·@··%······
0020   01 c8 1f 90 b5 f8 07 17  11 c9 81 0b 11 cc 80 18   ················
0030   01 fd 96 3b 00 00 01 01  08 0a b5 f5 db 87 8b 7c   ···;···········|
0040   d5 e2 50 4b 03 04 14 00  09 00 08 00 24 31 95 5b   ··PK········$1·["""

        return hex_dump, protocol_layers
