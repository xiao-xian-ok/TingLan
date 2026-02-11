# protocol_analyzer.py - 协议统计分析

import logging
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from collections import Counter
from enum import Enum

logger = logging.getLogger(__name__)


class ProtocolType(Enum):
    ICMP = "icmp"
    DNS = "dns"
    FTP = "ftp"
    HTTP = "http"
    TCP = "tcp"
    UDP = "udp"
    UNKNOWN = "unknown"


class FindingType(Enum):
    HIDDEN_DATA = "hidden_data"
    ANOMALY = "anomaly"
    COVERT_CHANNEL = "covert_channel"
    EXFILTRATION = "exfiltration"
    INFO = "info"


@dataclass
class AnalysisFinding:
    finding_type: FindingType
    protocol: ProtocolType
    title: str
    description: str
    data: Optional[str] = None
    raw_values: List[Any] = field(default_factory=list)
    confidence: float = 0.0
    is_flag: bool = False

    def to_dict(self) -> Dict:
        return {
            'finding_type': self.finding_type.value,
            'protocol': self.protocol.value,
            'title': self.title,
            'description': self.description,
            'data': self.data,
            'confidence': self.confidence,
            'is_flag': self.is_flag
        }


@dataclass
class ProtocolAnalysisResult:
    protocol: ProtocolType
    packet_count: int
    findings: List[AnalysisFinding] = field(default_factory=list)
    summary: str = ""

    def has_findings(self) -> bool:
        return len(self.findings) > 0

    def get_flags(self) -> List[str]:
        return [f.data for f in self.findings if f.is_flag and f.data]


class ProtocolAnalyzer(ABC):
    """协议分析器基类"""

    @property
    @abstractmethod
    def protocol_type(self) -> ProtocolType:
        pass

    @abstractmethod
    def analyze(self, packets: List) -> ProtocolAnalysisResult:
        pass

    @staticmethod
    def bytes_to_ascii(values: List[int], replace_char: str = ".") -> str:
        result = []
        for v in values:
            if 32 <= v <= 126:
                result.append(chr(v))
            else:
                result.append(replace_char)
        return "".join(result)

    @staticmethod
    def is_binary_sequence(values: List[int]) -> bool:
        if not values or len(values) < 8:
            return False
        return all(v in (0, 1) for v in values)

    @staticmethod
    def is_two_value_binary(values: List[int]) -> bool:
        """两值二进制编码，常见于TTL隐写: 32/64, 64/128"""
        if not values or len(values) < 8:
            return False
        unique = set(values)
        return len(unique) == 2 and not unique.issubset({0, 1})

    @staticmethod
    def two_value_to_bits(values: List[int]) -> List[int]:
        """较小值->0，较大值->1"""
        unique = sorted(set(values))
        mapping = {unique[0]: 0, unique[1]: 1}
        return [mapping[v] for v in values]

    @staticmethod
    def binary_bits_to_text(bits: List[int]) -> str:
        """二进制位序列转文本"""
        usable_bits = (len(bits) // 8) * 8
        if usable_bits == 0:
            return ""

        bits = bits[:usable_bits]
        result = []
        for i in range(0, len(bits), 8):
            byte_bits = bits[i:i+8]
            byte_val = 0
            for bit in byte_bits:
                byte_val = (byte_val << 1) | bit
            if 32 <= byte_val <= 126:
                result.append(chr(byte_val))
            elif byte_val == 0:
                pass
            else:
                result.append('.')
        return "".join(result)

    @staticmethod
    def binary_bits_to_string(bits: List[int]) -> str:
        return "".join(str(b) for b in bits)

    @classmethod
    def smart_decode_values(cls, values: List[int], replace_char: str = ".") -> str:
        """自动检测编码方式: 0/1位序列、两值二进制(TTL)、或直接ASCII"""
        if cls.is_binary_sequence(values):
            text = cls.binary_bits_to_text(values)
            if text and cls._is_meaningful_text(text):
                return text
            return cls.binary_bits_to_string(values)

        elif cls.is_two_value_binary(values):
            bits = cls.two_value_to_bits(values)
            text = cls.binary_bits_to_text(bits)
            if text and cls._is_meaningful_text(text):
                return text
            return cls.binary_bits_to_string(bits)

        else:
            return cls.bytes_to_ascii(values, replace_char)

    @staticmethod
    def _is_meaningful_text(text: str) -> bool:
        if not text:
            return False
        printable = sum(1 for c in text if 32 <= ord(c) <= 126)
        return printable / len(text) >= 0.7

    @staticmethod
    def detect_flag_pattern(text: str) -> bool:
        if not text:
            return False
        text_lower = text.lower()
        patterns = ['flag{', 'ctf{', 'ctfhub{', 'key{', 'secret{', '{flag', 'flag:', 'key:']
        return any(p in text_lower for p in patterns)


class ICMPAnalyzer(ProtocolAnalyzer):
    """ICMP隐写分析: data长度、TTL、载荷偏移、序列号"""

    @property
    def protocol_type(self) -> ProtocolType:
        return ProtocolType.ICMP

    def analyze(self, packets: List) -> ProtocolAnalysisResult:
        findings = []

        data_lengths = []
        payloads = []
        ttls = []
        seq_numbers = []

        for pkt in packets:
            try:
                if hasattr(pkt, 'icmp') and pkt.icmp.type == '8':
                    d_len = 0
                    if hasattr(pkt.icmp, 'data_len'):
                        d_len = int(pkt.icmp.data_len)
                    elif hasattr(pkt.icmp, 'data_data'):
                        d_len = len(pkt.icmp.data_data.replace(':', '')) // 2
                    data_lengths.append(d_len)

                    if hasattr(pkt.icmp, 'data_data'):
                        payloads.append(pkt.icmp.data_data.replace(':', ''))

                    if hasattr(pkt, 'ip'):
                        ttls.append(int(pkt.ip.ttl))

                    if hasattr(pkt.icmp, 'seq'):
                        seq_numbers.append(int(pkt.icmp.seq))

            except Exception as e:
                logger.debug(f"ICMP包解析异常: {e}")
                continue

        packet_count = len(data_lengths)

        # Data长度序列隐写
        if data_lengths and len(set(data_lengths)) > 1:
            char_sequence = self.smart_decode_values(data_lengths, "?")
            is_flag = self.detect_flag_pattern(char_sequence)
            finding = AnalysisFinding(
                finding_type=FindingType.HIDDEN_DATA,
                protocol=ProtocolType.ICMP,
                title="Data长度序列隐写",
                description="ICMP包的Data长度序列可能编码了隐藏信息",
                data=char_sequence,
                raw_values=data_lengths,
                confidence=0.7 if is_flag else 0.5,
                is_flag=is_flag
            )
            findings.append(finding)

        # 载荷内容偏移扫描
        if payloads:
            most_common_len = Counter([len(p) for p in payloads]).most_common(1)[0][0]
            filtered_payloads = [p for p in payloads if len(p) == most_common_len]

            byte_len = most_common_len // 2
            dynamic_offsets = []

            for i in range(byte_len):
                column_data = []
                for p in filtered_payloads:
                    byte_val = int(p[i*2:i*2+2], 16)
                    column_data.append(byte_val)

                if len(set(column_data)) > 1:
                    col_str = self.smart_decode_values(column_data, ".")
                    dynamic_offsets.append((i, col_str, column_data))

            if dynamic_offsets:
                for offset, col_str, col_data in dynamic_offsets:
                    is_flag = self.detect_flag_pattern(col_str)
                    if is_flag or len(set(col_data)) > len(col_data) * 0.3:
                        finding = AnalysisFinding(
                            finding_type=FindingType.HIDDEN_DATA,
                            protocol=ProtocolType.ICMP,
                            title=f"载荷偏移{offset}隐写",
                            description=f"在Data载荷偏移{offset}处发现变化数据",
                            data=col_str,
                            raw_values=col_data,
                            confidence=0.8 if is_flag else 0.6,
                            is_flag=is_flag
                        )
                        findings.append(finding)

        # TTL序列隐写
        if ttls and len(set(ttls)) > 1:
            ttl_char_seq = self.smart_decode_values(ttls, "?")
            is_flag = self.detect_flag_pattern(ttl_char_seq)

            finding = AnalysisFinding(
                finding_type=FindingType.HIDDEN_DATA,
                protocol=ProtocolType.ICMP,
                title="TTL序列隐写",
                description="IP层TTL值序列可能编码了隐藏信息",
                data=ttl_char_seq,
                raw_values=ttls,
                confidence=0.8 if is_flag else 0.6,
                is_flag=is_flag
            )
            findings.append(finding)

        # 序列号分析
        if seq_numbers and len(set(seq_numbers)) > 1:
            low_bytes = [s & 0xFF for s in seq_numbers]
            low_char_seq = self.smart_decode_values(low_bytes, "?")
            is_flag = self.detect_flag_pattern(low_char_seq)

            if is_flag or len(set(low_bytes)) > len(low_bytes) * 0.3:
                finding = AnalysisFinding(
                    finding_type=FindingType.HIDDEN_DATA,
                    protocol=ProtocolType.ICMP,
                    title="序列号隐写",
                    description="ICMP序列号可能编码了隐藏信息",
                    data=low_char_seq,
                    raw_values=seq_numbers,
                    confidence=0.7 if is_flag else 0.4,
                    is_flag=is_flag
                )
                findings.append(finding)

        summary_parts = []
        if findings:
            summary_parts.append(f"发现 {len(findings)} 处可疑隐写")
            flags = [f.data for f in findings if f.is_flag]
            if flags:
                summary_parts.append(f"可能的FLAG: {', '.join(flags)}")
        else:
            summary_parts.append("未发现明显的隐写痕迹")

        return ProtocolAnalysisResult(
            protocol=ProtocolType.ICMP,
            packet_count=packet_count,
            findings=findings,
            summary="; ".join(summary_parts)
        )


class DNSAnalyzer(ProtocolAnalyzer):
    """DNS隐写分析 (待实现): 子域名隐写、TXT记录、CNAME链"""

    @property
    def protocol_type(self) -> ProtocolType:
        return ProtocolType.DNS

    def analyze(self, packets: List) -> ProtocolAnalysisResult:
        # TODO: 实现DNS分析
        return ProtocolAnalysisResult(
            protocol=ProtocolType.DNS,
            packet_count=0,
            summary="DNS分析功能待实现"
        )


class ProtocolAnalyzerManager:

    def __init__(self):
        self._analyzers: Dict[ProtocolType, ProtocolAnalyzer] = {}
        self._register_default_analyzers()

    def _register_default_analyzers(self):
        self.register(ICMPAnalyzer())
        self.register(DNSAnalyzer())

    def register(self, analyzer: ProtocolAnalyzer):
        self._analyzers[analyzer.protocol_type] = analyzer

    def get_analyzer(self, protocol: ProtocolType) -> Optional[ProtocolAnalyzer]:
        return self._analyzers.get(protocol)

    def analyze_protocol(self, protocol: ProtocolType, packets: List) -> Optional[ProtocolAnalysisResult]:
        analyzer = self.get_analyzer(protocol)
        if analyzer:
            return analyzer.analyze(packets)
        return None

    def analyze_all(self, packets: List) -> Dict[ProtocolType, ProtocolAnalysisResult]:
        results = {}
        for protocol, analyzer in self._analyzers.items():
            try:
                result = analyzer.analyze(packets)
                if result and result.packet_count > 0:
                    results[protocol] = result
            except Exception as e:
                logger.error(f"{protocol.value}协议分析异常: {e}")
        return results


def analyze_icmp(packets: List) -> ProtocolAnalysisResult:
    analyzer = ICMPAnalyzer()
    return analyzer.analyze(packets)


if __name__ == '__main__':
    from utils import read_pcap

    file_path = input("请输入pcap文件路径: ").strip('"')
    print(f"[*] 正在分析: {file_path}，请稍候...")

    try:
        cap = read_pcap(file_path)
        pkts = list(cap)
        cap.close()

        print("\n" + "=" * 20 + " ICMP 自动化综合分析 " + "=" * 20)
        result = analyze_icmp(pkts)

        print(f"\n分析完成，共处理 {result.packet_count} 个ICMP包")
        print(f"摘要: {result.summary}")

        if result.findings:
            print("\n" + "=" * 20 + " 发现摘要 " + "=" * 20)
            for f in result.findings:
                flag_mark = " [FLAG]" if f.is_flag else ""
                print(f"[{f.finding_type.value}] {f.title}{flag_mark}: {f.data}")

    except Exception as e:
        print(f"[!] 运行出错: {e}")
