# protocol_analyzer.py - 协议统计分析（统一框架）

import logging
import os
import re
import base64
import struct
import binascii
import hashlib
import hmac as hmac_mod
import subprocess
import tempfile
import pathlib
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from collections import Counter, defaultdict
from enum import Enum

logger = logging.getLogger(__name__)


# ============================================================
# 枚举定义
# ============================================================

class ProtocolType(Enum):
    ICMP = "icmp"
    DNS = "dns"
    FTP = "ftp"
    HTTP = "http"
    TCP = "tcp"
    UDP = "udp"
    MMS = "mms"
    USB = "usb"
    BLUETOOTH = "bluetooth"
    SMTP = "smtp"
    COBALT_STRIKE = "cobalt_strike"
    TLS = "tls"
    RDP = "rdp"
    REDIS = "redis"
    SMB = "smb"
    SSH = "ssh"
    UNKNOWN = "unknown"


class FindingType(Enum):
    HIDDEN_DATA = "hidden_data"
    ANOMALY = "anomaly"
    COVERT_CHANNEL = "covert_channel"
    EXFILTRATION = "exfiltration"
    INFO = "info"
    CREDENTIAL = "credential"
    FILE_EXTRACTION = "file_extraction"
    C2_COMMUNICATION = "c2_communication"
    DEVICE_INPUT = "device_input"


# ============================================================
# 数据结构
# ============================================================

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
    extracted_files: List[str] = field(default_factory=list)
    output_dir: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def has_findings(self) -> bool:
        return len(self.findings) > 0

    def get_flags(self) -> List[str]:
        return [f.data for f in self.findings if f.is_flag and f.data]


# ============================================================
# 基类
# ============================================================

class ProtocolAnalyzer(ABC):
    """协议分析器基类"""

    @property
    @abstractmethod
    def protocol_type(self) -> ProtocolType:
        pass

    @abstractmethod
    def analyze(self, packets: List, **kwargs) -> ProtocolAnalysisResult:
        pass

    def analyze_pcap(self, pcap_path: str, **kwargs) -> ProtocolAnalysisResult:
        """从pcap文件路径分析。默认实现：读取数据包后调用analyze()。
        USB/CS等需要文件路径的分析器可重写此方法。"""
        from utils import read_pcap
        cap = read_pcap(pcap_path)
        packets = list(cap)
        cap.close()
        return self.analyze(packets, **kwargs)

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


# ============================================================
# ICMPAnalyzer
# ============================================================

class ICMPAnalyzer(ProtocolAnalyzer):
    """ICMP隐写分析: data长度、TTL、载荷偏移、序列号"""

    @property
    def protocol_type(self) -> ProtocolType:
        return ProtocolType.ICMP

    def analyze(self, packets: List, **kwargs) -> ProtocolAnalysisResult:
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


# ============================================================
# DNSCovertChannelAnalyzer
# ============================================================

class DNSCovertChannelAnalyzer(ProtocolAnalyzer):
    """DNS隐蔽通道分析: 子域名编码数据提取、TXT指令捕获、域名统计"""

    def __init__(self, decode_mode: str = "hex", trigger_domain: str = "bnh0.com",
                 output_dir: Optional[str] = None):
        self.decode_mode = decode_mode  # "hex" 或 "base64"
        self.trigger_domain = trigger_domain.lower()
        self.output_dir = output_dir

    @property
    def protocol_type(self) -> ProtocolType:
        return ProtocolType.DNS

    @staticmethod
    def _decode_hex_mode(hex_str: str) -> Optional[str]:
        """Hex -> Base64 -> GB2312"""
        try:
            if len(hex_str) % 2 != 0:
                hex_str = hex_str[:-1]
            raw_b64 = bytes.fromhex(hex_str)
            return base64.b64decode(raw_b64).decode("gb2312", errors='ignore')
        except Exception:
            return None

    @staticmethod
    def _decode_base64_mode(b64_str: str) -> Optional[str]:
        """Base64 -> GB2312"""
        try:
            safe_b64 = b64_str.replace('-', '+').replace('_', '/')
            padding = len(safe_b64) % 4
            if padding:
                safe_b64 += '=' * (4 - padding)
            return base64.b64decode(safe_b64).decode("gb2312", errors='ignore')
        except Exception:
            return None

    @staticmethod
    def _is_readable(text: str) -> bool:
        """判断解码结果是否为可读文本"""
        if not text or len(text.strip()) < 2:
            return False
        printable = sum(1 for c in text if c.isprintable() or c in '\r\n\t')
        return printable / max(len(text), 1) > 0.5

    @classmethod
    def try_decode_buffer(cls, buffer: str) -> Tuple[Optional[str], Optional[str]]:
        """自动尝试 Hex / Base64 两种模式解码，返回 (decoded_text, mode_name) 或 (None, None)"""
        hex_result = cls._decode_hex_mode(buffer)
        if hex_result and cls._is_readable(hex_result):
            return hex_result, "Hex→Base64→GB2312"

        b64_result = cls._decode_base64_mode(buffer)
        if b64_result and cls._is_readable(b64_result):
            return b64_result, "Base64→GB2312"

        return None, None

    def analyze(self, packets: List, **kwargs) -> ProtocolAnalysisResult:
        findings = []
        buffer = ""
        seen_packets = set()
        all_domains = []
        decoded_segments = []
        txt_commands = []
        packet_count = 0

        decode_mode = kwargs.get('decode_mode', self.decode_mode)
        trigger_domain = kwargs.get('trigger_domain', self.trigger_domain)

        for pkt in packets:
            if not hasattr(pkt, 'dns'):
                continue

            try:
                packet_count += 1
                stream_index = None
                if hasattr(pkt, 'layers') and len(pkt.layers) > 2:
                    stream_index = pkt.layers[2].get_field_value("stream")

                qry_name = pkt.dns.get_field_value("qry_name") if hasattr(pkt.dns, 'get_field_value') else getattr(pkt.dns, 'qry_name', None)
                if not qry_name:
                    continue

                all_domains.append(qry_name.lower())

                # TXT 指令解析
                txt_field = pkt.dns.get_field_value("txt") if hasattr(pkt.dns, 'get_field_value') else getattr(pkt.dns, 'txt', None)
                if txt_field:
                    try:
                        cmd = base64.b64decode(base64.b64decode(txt_field)).decode("utf-8")
                        print(f"[!] 捕获指令 | Index: {stream_index} | CMD: {cmd}")
                        txt_commands.append(cmd)
                    except Exception:
                        pass

                # 载荷处理
                packet_id = f"{stream_index}_{qry_name}"
                if packet_id in seen_packets:
                    continue
                seen_packets.add(packet_id)

                if qry_name.lower() == trigger_domain:
                    if buffer:
                        print(f"\n[!] 触发结算 (流 {stream_index}):")
                        result = self._decode_hex_mode(buffer) if decode_mode == "hex" else self._decode_base64_mode(buffer)
                        if result:
                            decoded_segments.append(result.strip())
                            print(f">>> 回显内容:\n{result.strip()}")
                        else:
                            print(f">>> [错误] 该模式下解码失败，请确认编码格式。")
                        print("-" * 30)
                        buffer = ""
                else:
                    prefix = qry_name.split('.')[0]
                    if len(prefix) <= 4:
                        continue

                    if decode_mode == "hex":
                        if all(c in '0123456789abcdefABCDEF' for c in prefix):
                            buffer += prefix
                            preview = self._decode_hex_mode(prefix)
                            if preview:
                                print(f"[*] 捕获 Hex 片段: [{prefix}] -> {preview}")
                    else:
                        if all(c.isalnum() or c in '-_' for c in prefix):
                            buffer += prefix
                            preview = self._decode_base64_mode(prefix)
                            if preview:
                                print(f"[*] 捕获 B64 片段: [{prefix}] -> {preview}")

            except Exception:
                continue

        # 收尾结算
        if buffer:
            result = self._decode_hex_mode(buffer) if decode_mode == "hex" else self._decode_base64_mode(buffer)
            if result:
                decoded_segments.append(result.strip())
                print(f"\n>>> 最终未结算内容:\n{result.strip()}")

        # 生成 findings
        if decoded_segments:
            full_decoded = "\n".join(decoded_segments)
            is_flag = self.detect_flag_pattern(full_decoded)
            findings.append(AnalysisFinding(
                finding_type=FindingType.COVERT_CHANNEL,
                protocol=ProtocolType.DNS,
                title="DNS子域名隐蔽通道数据",
                description=f"从DNS查询子域名中提取并解码了 {len(decoded_segments)} 段隐藏数据 (模式: {decode_mode})",
                data=full_decoded,
                confidence=0.9 if is_flag else 0.7,
                is_flag=is_flag
            ))

        if txt_commands:
            findings.append(AnalysisFinding(
                finding_type=FindingType.COVERT_CHANNEL,
                protocol=ProtocolType.DNS,
                title="DNS TXT 指令",
                description=f"捕获 {len(txt_commands)} 条双层Base64编码的TXT指令",
                data="\n".join(txt_commands),
                confidence=0.8,
                is_flag=False
            ))

        if all_domains:
            top_10 = Counter(all_domains).most_common(10)
            domain_report = "\n".join(f"#{i:<5}{count:<14}{domain}" for i, (domain, count) in enumerate(top_10, 1))
            findings.append(AnalysisFinding(
                finding_type=FindingType.INFO,
                protocol=ProtocolType.DNS,
                title="域名频率统计 (Top 10)",
                description=f"共 {len(all_domains)} 条DNS查询, {len(set(all_domains))} 个唯一域名",
                data=domain_report,
                confidence=0.3,
                is_flag=False
            ))

        # 写域名列表到文件
        output_file = kwargs.get('output_file')
        output_dir = kwargs.get('output_dir', self.output_dir)
        extracted_files = []
        if output_file and all_domains:
            os.makedirs(os.path.dirname(output_file), exist_ok=True)
            with open(output_file, "w", encoding="utf-8") as f:
                for d in all_domains:
                    f.write(d + "\n")
            extracted_files.append(output_file)
            print(f"\n[+] 全量清单已导出: {output_file}")
        elif output_dir and all_domains:
            os.makedirs(output_dir, exist_ok=True)
            domain_file = os.path.join(output_dir, "dns_domains.txt")
            with open(domain_file, "w", encoding="utf-8") as f:
                for d in all_domains:
                    f.write(d + "\n")
            extracted_files.append(domain_file)
            print(f"\n[+] 全量清单已导出: {domain_file}")

        # 域名频率报表
        if all_domains:
            print("\n" + " " * 10 + ">>> 域名频率报表 <<<")
            for i, (domain, count) in enumerate(top_10, 1):
                print(f"#{i:<5}{count:<14}{domain}")
            print("=" * 30)

        summary_parts = []
        if decoded_segments:
            summary_parts.append(f"解码 {len(decoded_segments)} 段隐蔽通道数据")
        if txt_commands:
            summary_parts.append(f"捕获 {len(txt_commands)} 条TXT指令")
        summary_parts.append(f"共 {packet_count} 个DNS包")
        flags = [f.data for f in findings if f.is_flag]
        if flags:
            summary_parts.append(f"可能的FLAG: {flags[0][:80]}")

        return ProtocolAnalysisResult(
            protocol=ProtocolType.DNS,
            packet_count=packet_count,
            findings=findings,
            summary="; ".join(summary_parts),
            extracted_files=extracted_files,
            output_dir=output_dir
        )


# ============================================================
# FTPAnalyzer
# ============================================================

class FTPAnalyzer(ProtocolAnalyzer):
    """FTP流量分析: 凭证提取、文件还原"""

    def __init__(self, output_dir: Optional[str] = None):
        self.output_dir = output_dir

    @property
    def protocol_type(self) -> ProtocolType:
        return ProtocolType.FTP

    def analyze(self, packets: List, **kwargs) -> ProtocolAnalysisResult:
        findings = []
        extracted_files = []
        packet_count = 0

        output_dir = kwargs.get('output_dir', self.output_dir)

        credentials = []
        filename_map = {}
        file_data_map = {}
        current_filename = "other_file"
        current_user = None

        for pkt in packets:
            # 控制流分析
            if hasattr(pkt, 'ftp'):
                packet_count += 1
                try:
                    ftp = pkt.ftp
                    if hasattr(ftp, 'request_command'):
                        cmd = ftp.request_command.upper()
                        arg = getattr(ftp, 'request_arg', '').strip()

                        if cmd == 'USER':
                            current_user = arg
                        elif cmd == 'PASS':
                            cred = f"{current_user or 'unknown'}:{arg}"
                            credentials.append(cred)
                        elif cmd in ['RETR', 'STOR']:
                            current_filename = arg
                except Exception:
                    pass

            # 数据流分析
            if hasattr(pkt, 'tcp'):
                try:
                    stream_id = pkt.tcp.stream
                    has_ftp_data = hasattr(pkt, 'layers') and any(l.layer_name == 'ftp-data' for l in pkt.layers)

                    if has_ftp_data:
                        packet_count += 1
                        if stream_id not in filename_map:
                            filename_map[stream_id] = current_filename

                        if stream_id not in file_data_map:
                            file_data_map[stream_id] = bytearray()

                        # 尝试提取 FTP-DATA 层数据
                        ftp_data_layer = None
                        if hasattr(pkt, 'layers'):
                            for l in pkt.layers:
                                if l.layer_name == 'ftp-data':
                                    ftp_data_layer = l
                                    break

                        if ftp_data_layer:
                            raw_hex = getattr(ftp_data_layer, 'data_text', None)
                            if raw_hex:
                                raw_bytes = bytes.fromhex(raw_hex.replace(':', ''))
                                file_data_map[stream_id].extend(raw_bytes)
                            elif hasattr(pkt.tcp, 'payload'):
                                try:
                                    file_data_map[stream_id].extend(pkt.tcp.payload.binary_value)
                                except Exception:
                                    pass
                except Exception:
                    pass

        # 生成凭证 findings
        if credentials:
            findings.append(AnalysisFinding(
                finding_type=FindingType.CREDENTIAL,
                protocol=ProtocolType.FTP,
                title="FTP登录凭证",
                description=f"捕获 {len(credentials)} 组FTP登录凭证",
                data="\n".join(credentials),
                confidence=0.95,
                is_flag=False
            ))

        # 写入文件并生成 findings
        if output_dir and file_data_map:
            os.makedirs(output_dir, exist_ok=True)

        for s_id, data in file_data_map.items():
            if len(data) == 0:
                continue

            raw_fname = filename_map.get(s_id, "other_file")
            base_fname = "".join([c for c in raw_fname if c.isalnum() or c in "._-"])
            if not base_fname:
                base_fname = f"stream_{s_id}"

            save_path = None
            if output_dir:
                name_part, ext_part = os.path.splitext(base_fname)
                final_fname = base_fname
                save_path = os.path.join(output_dir, final_fname)
                counter = 1
                while os.path.exists(save_path):
                    final_fname = f"{name_part}{counter}{ext_part}"
                    save_path = os.path.join(output_dir, final_fname)
                    counter += 1

                with open(save_path, "wb") as f:
                    f.write(data)
                extracted_files.append(save_path)

            is_flag = self.detect_flag_pattern(data.decode(errors='ignore'))
            findings.append(AnalysisFinding(
                finding_type=FindingType.FILE_EXTRACTION,
                protocol=ProtocolType.FTP,
                title=f"FTP文件提取: {raw_fname}",
                description=f"从TCP流 {s_id} 提取文件 {raw_fname} ({len(data)} bytes)",
                data=save_path or f"[{len(data)} bytes, 未指定output_dir]",
                confidence=0.9,
                is_flag=is_flag
            ))

        summary_parts = []
        if credentials:
            summary_parts.append(f"发现 {len(credentials)} 组凭证")
        if file_data_map:
            summary_parts.append(f"提取 {len([d for d in file_data_map.values() if len(d) > 0])} 个文件")
        summary_parts.append(f"共 {packet_count} 个FTP相关包")

        return ProtocolAnalysisResult(
            protocol=ProtocolType.FTP,
            packet_count=packet_count,
            findings=findings,
            summary="; ".join(summary_parts),
            extracted_files=extracted_files,
            output_dir=output_dir
        )


# ============================================================
# MMSAnalyzer
# ============================================================

class MMSAnalyzer(ProtocolAnalyzer):
    """MMS协议分析: InvokeID追踪、文件传输提取"""

    def __init__(self, output_dir: Optional[str] = None):
        self.output_dir = output_dir

    @property
    def protocol_type(self) -> ProtocolType:
        return ProtocolType.MMS

    def analyze(self, packets: List, **kwargs) -> ProtocolAnalysisResult:
        findings = []
        extracted_files = []
        packet_count = 0

        output_dir = kwargs.get('output_dir', self.output_dir)
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)

        # 核心状态追踪池
        open_inv_to_name = {}   # InvokeID -> 文件名 (72 Request)
        frsm_to_name = {}       # FRSMID -> 文件名 (72 Response)
        read_inv_to_name = {}   # InvokeID -> 文件名 (73 Request)

        for pkt in packets:
            try:
                if 'mms' not in [l.layer_name for l in pkt.layers]:
                    continue

                packet_count += 1
                mms = pkt.mms
                pkt_num = pkt.number
                inv_id = getattr(mms, 'invokeid', None)

                # --- 阶段 1: 文件打开请求 (Confirmed-RequestPDU, 72) ---
                if hasattr(mms, 'confirmedservicerequest') and int(mms.confirmedservicerequest) == 72:
                    if hasattr(mms, 'filename_item'):
                        try:
                            raw_fname = mms.filename_item.fields[0].get_default_value()
                            fname = os.path.basename(str(raw_fname))
                            if inv_id:
                                open_inv_to_name[inv_id] = fname
                            print(f'[#Pkt:{pkt_num} | ID:{inv_id}] \u53d1\u73b0 Open \u8bf7\u6c42: {fname}')
                        except Exception:
                            pass

                # --- 阶段 2: 绑定 FRSMID (Confirmed-ResponsePDU, 72) ---
                elif hasattr(mms, 'confirmedserviceresponse') and int(mms.confirmedserviceresponse) == 72:
                    if inv_id in open_inv_to_name:
                        fname = open_inv_to_name.pop(inv_id)
                        if hasattr(mms, 'frsmid'):
                            f_id = str(mms.frsmid)
                            frsm_to_name[f_id] = fname
                            print(f'[#Pkt:{pkt_num} | ID:{inv_id}] Open \u6210\u529f: {fname} (\u83b7\u5f97 FRSMID: {f_id})')

                # --- 阶段 3: 文件读取请求 (Confirmed-RequestPDU, 73) ---
                elif hasattr(mms, 'confirmedservicerequest') and int(mms.confirmedservicerequest) == 73:
                    if hasattr(mms, 'fileread'):
                        f_id = str(mms.fileread)
                        if f_id in frsm_to_name:
                            fname = frsm_to_name[f_id]
                            if inv_id:
                                read_inv_to_name[inv_id] = fname
                            if 'flag' in fname.lower():
                                print(f'\n{"="*60}')
                                print(f'[!] [#Pkt:{pkt_num} | ID:{inv_id}] \u5173\u952e\u8bfb\u53d6: \u6b63\u5728\u8bf7\u6c42 {fname}')
                                print(f'{"="*60}\n')

                # --- 阶段 4: 提取文件数据 (Confirmed-ResponsePDU, 73) ---
                elif hasattr(mms, 'confirmedserviceresponse') and int(mms.confirmedserviceresponse) == 73:
                    if inv_id in read_inv_to_name:
                        fname = read_inv_to_name.pop(inv_id)

                        if hasattr(mms, 'filedata'):
                            raw_val = str(mms.filedata).replace(':', '').replace(' ', '')
                            try:
                                data_to_save = binascii.unhexlify(raw_val)
                            except Exception:
                                data_to_save = raw_val.encode('utf-8')

                            if output_dir:
                                file_path = os.path.join(output_dir, fname)
                                with open(file_path, 'ab') as f:
                                    f.write(data_to_save)
                                extracted_files.append(file_path)

                            is_flag = 'flag' in fname.lower()
                            if is_flag:
                                decoded_content = data_to_save.decode(errors='ignore')
                                print(f'\n{"="*20} FLAG FOUND {"="*20}')
                                print(f'\u6570\u636e\u5305\u53f7: {pkt_num}')
                                print(f'InvokeID: {inv_id} (Wireshark \u8fc7\u6ee4\u5668: mms.invokeID == {inv_id})')
                                print(f'\u6587\u4ef6\u5185\u5bb9: {decoded_content}')
                                print(f'{"="*52}\n')
                                findings.append(AnalysisFinding(
                                    finding_type=FindingType.HIDDEN_DATA,
                                    protocol=ProtocolType.MMS,
                                    title=f'MMS FLAG\u6587\u4ef6: {fname}',
                                    description=f'Pkt:{pkt_num} InvokeID:{inv_id} \u6587\u4ef6: {fname} ({len(data_to_save)} bytes)',
                                    data=decoded_content,
                                    confidence=0.95,
                                    is_flag=True
                                ))
                            else:
                                print(f'[+] [#Pkt:{pkt_num} | ID:{inv_id}] \u5df2\u8fd8\u539f\u6570\u636e\u5230: {fname}')
                                findings.append(AnalysisFinding(
                                    finding_type=FindingType.FILE_EXTRACTION,
                                    protocol=ProtocolType.MMS,
                                    title=f'MMS\u6587\u4ef6\u63d0\u53d6: {fname}',
                                    description=f'Pkt:{pkt_num} InvokeID:{inv_id} \u6587\u4ef6: {fname} ({len(data_to_save)} bytes)',
                                    data=f'[{len(data_to_save)} bytes]',
                                    confidence=0.8,
                                    is_flag=False
                                ))

                    # 容错：处理那些"孤立"但带数据的响应包
                    elif hasattr(mms, 'filedata'):
                        print(f'[?] [#Pkt:{pkt_num} | ID:{inv_id}] \u53d1\u73b0\u672a\u5339\u914d\u6570\u636e\u7684\u54cd\u5e94\uff0c\u8bf7\u68c0\u67e5\u8be5 ID')

            except Exception:
                continue

        print(f'\n>>> wireshark\u641c\u7d22 mms.invokeID == ID\u53f7 \u53ef\u8fdb\u4e00\u6b65\u67e5\u770b\u5185\u5bb9')

        summary_parts = []
        if extracted_files:
            summary_parts.append(f'\u63d0\u53d6 {len(extracted_files)} \u4e2a\u6587\u4ef6')
        flags = [f for f in findings if f.is_flag]
        if flags:
            summary_parts.append(f'\u53d1\u73b0FLAG\u6587\u4ef6: {flags[0].data[:80] if flags[0].data else ""}')
        summary_parts.append(f'\u5171 {packet_count} \u4e2aMMS\u5305')

        return ProtocolAnalysisResult(
            protocol=ProtocolType.MMS,
            packet_count=packet_count,
            findings=findings,
            summary='; '.join(summary_parts),
            extracted_files=extracted_files,
            output_dir=output_dir
        )


# ============================================================
# BluetoothAnalyzer
# ============================================================

class BluetoothAnalyzer(ProtocolAnalyzer):
    """蓝牙流量分析: OBEX文件传输、L2CAP/GATT数据"""

    def __init__(self, output_dir: Optional[str] = None):
        self.output_dir = output_dir

    @property
    def protocol_type(self) -> ProtocolType:
        return ProtocolType.BLUETOOTH

    @staticmethod
    def _clean_hex_string(raw_hex: str) -> str:
        if not raw_hex:
            return ""
        cleaned = re.sub(r'[^0-9a-fA-F]', '', str(raw_hex))
        if len(cleaned) % 2 != 0:
            cleaned = cleaned[:-1]
        return cleaned

    def analyze(self, packets: List, **kwargs) -> ProtocolAnalysisResult:
        findings = []
        extracted_files = []
        packet_count = 0

        output_dir = kwargs.get('output_dir', self.output_dir)
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)

        obex_sessions = {}
        l2cap_records = []
        gatt_records = []

        for packet in packets:
            try:
                session_id = f"{packet.bluetooth.src}_{packet.bluetooth.dst}" if hasattr(packet, 'bluetooth') else "unknown"
            except Exception:
                session_id = "unknown"

            # OBEX文件传输
            layer_names = [l.layer_name.lower() for l in packet.layers] if hasattr(packet, 'layers') else []

            if 'obex' in layer_names or hasattr(packet, 'obex'):
                packet_count += 1
                try:
                    obex = packet.obex
                    if session_id not in obex_sessions:
                        obex_sessions[session_id] = {'filename': None, 'data': ''}

                    if hasattr(obex, 'name'):
                        obex_sessions[session_id]['filename'] = os.path.basename(str(obex.name))

                    if hasattr(obex, 'header_value_byte_sequence'):
                        obex_sessions[session_id]['data'] += str(obex.header_value_byte_sequence)

                    is_final = False
                    if hasattr(obex, 'final_flag') and str(obex.final_flag) == '1':
                        is_final = True
                    elif hasattr(obex, 'opcode'):
                        try:
                            if int(getattr(obex, 'opcode', '0x00'), 16) & 0x80:
                                is_final = True
                        except Exception:
                            pass

                    if is_final:
                        session = obex_sessions[session_id]
                        if session['filename'] and session['data']:
                            hex_str = self._clean_hex_string(session['data'])
                            if hex_str:
                                file_data = binascii.unhexlify(hex_str)

                                save_path = None
                                if output_dir:
                                    obex_dir = os.path.join(output_dir, 'obex_files')
                                    os.makedirs(obex_dir, exist_ok=True)
                                    save_path = os.path.join(obex_dir, session['filename'])
                                    with open(save_path, 'wb') as f:
                                        f.write(file_data)
                                    extracted_files.append(save_path)

                                is_flag = self.detect_flag_pattern(file_data.decode(errors='ignore'))
                                findings.append(AnalysisFinding(
                                    finding_type=FindingType.FILE_EXTRACTION,
                                    protocol=ProtocolType.BLUETOOTH,
                                    title=f"OBEX文件: {session['filename']}",
                                    description=f"从OBEX会话提取文件 {session['filename']} ({len(file_data)} bytes)",
                                    data=save_path or f"[{len(file_data)} bytes]",
                                    confidence=0.9,
                                    is_flag=is_flag
                                ))

                        obex_sessions[session_id] = {'filename': None, 'data': ''}
                except Exception:
                    pass

            # L2CAP
            elif 'btl2cap' in layer_names or hasattr(packet, 'btl2cap'):
                packet_count += 1
                try:
                    if hasattr(packet.btl2cap, 'payload'):
                        payload = self._clean_hex_string(packet.btl2cap.payload)
                        if payload:
                            l2cap_records.append(f"[{packet.number}] {payload}")
                except Exception:
                    pass

            # GATT
            elif 'btatt' in layer_names or hasattr(packet, 'btatt'):
                packet_count += 1
                try:
                    if hasattr(packet.btatt, 'value'):
                        val = self._clean_hex_string(packet.btatt.value)
                        handle = getattr(packet.btatt, 'handle', 'N/A')
                        gatt_records.append(f"[{packet.number}] Handle {handle}: {val}")
                except Exception:
                    pass

        # L2CAP / GATT info findings
        if l2cap_records:
            findings.append(AnalysisFinding(
                finding_type=FindingType.INFO,
                protocol=ProtocolType.BLUETOOTH,
                title="L2CAP Payload记录",
                description=f"收集 {len(l2cap_records)} 条L2CAP数据记录",
                data="\n".join(l2cap_records[:50]),
                confidence=0.3,
                is_flag=False
            ))

        if gatt_records:
            findings.append(AnalysisFinding(
                finding_type=FindingType.INFO,
                protocol=ProtocolType.BLUETOOTH,
                title="GATT Attribute记录",
                description=f"收集 {len(gatt_records)} 条GATT属性值",
                data="\n".join(gatt_records[:50]),
                confidence=0.3,
                is_flag=False
            ))

        summary_parts = []
        if extracted_files:
            summary_parts.append(f"提取 {len(extracted_files)} 个OBEX文件")
        if l2cap_records:
            summary_parts.append(f"{len(l2cap_records)} 条L2CAP记录")
        if gatt_records:
            summary_parts.append(f"{len(gatt_records)} 条GATT记录")
        summary_parts.append(f"共 {packet_count} 个蓝牙包")

        return ProtocolAnalysisResult(
            protocol=ProtocolType.BLUETOOTH,
            packet_count=packet_count,
            findings=findings,
            summary="; ".join(summary_parts),
            extracted_files=extracted_files,
            output_dir=output_dir
        )


# ============================================================
# SMTPAnalyzer
# ============================================================

class SMTPAnalyzer(ProtocolAnalyzer):
    """SMTP邮件流量分析: 认证凭证、发件人/收件人、邮件内容/附件提取"""

    def __init__(self, output_dir: Optional[str] = None):
        self.output_dir = output_dir

    @property
    def protocol_type(self) -> ProtocolType:
        return ProtocolType.SMTP

    @staticmethod
    def _safe_decode(b64_str: str) -> Optional[str]:
        try:
            clean_str = re.sub(r'^[CS]:\s*', '', b64_str).strip()
            missing_padding = len(clean_str) % 4
            if missing_padding:
                clean_str += '=' * (4 - missing_padding)
            return base64.b64decode(clean_str).decode('utf-8', errors='ignore')
        except Exception:
            return None

    @staticmethod
    def _clean_line(line: str) -> str:
        if not line:
            return ""
        return line.replace('\\xd\\xa', '').replace('\r', '').replace('\n', '').strip()

    @staticmethod
    def _extract_images_from_raw(mail_buffer: List[str], folder_path: str) -> List[str]:
        """根据文件头还原Base64图片附件"""
        full_text = "".join(mail_buffer)
        b64_blocks = re.findall(r'[A-Za-z0-9+/=\s]{100,}', full_text)

        extracted = []
        img_count = 0
        for block in b64_blocks:
            clean_block = block.replace('\n', '').replace('\r', '').replace(' ', '')
            try:
                data = base64.b64decode(clean_block)
                ext = ""
                if data.startswith(b'\xff\xd8\xff'):
                    ext = "jpg"
                elif data.startswith(b'\x89PNG\r\n\x1a\n'):
                    ext = "png"
                elif data.startswith(b'GIF8'):
                    ext = "gif"

                if ext:
                    img_count += 1
                    img_name = f"attachment_{img_count:02d}.{ext}"
                    save_path = os.path.join(folder_path, img_name)
                    with open(save_path, 'wb') as f:
                        f.write(data)
                    extracted.append(save_path)
            except Exception:
                continue
        return extracted

    def analyze(self, packets: List, **kwargs) -> ProtocolAnalysisResult:
        findings = []
        extracted_files = []
        packet_count = 0

        output_dir = kwargs.get('output_dir', self.output_dir)
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)

        mail_count = 0
        is_collecting_data = False
        current_mail_buffer = []

        tracking_sender = "Unknown"
        tracking_receiver = "Unknown"
        auth_stage = 0
        credentials = []

        for packet in packets:
            msg = ""
            if hasattr(packet, 'smtp'):
                packet_count += 1
                msg = getattr(packet.smtp, 'command_line', "") or getattr(packet.smtp, 'response_line', "")

            if not msg and hasattr(packet, 'tcp') and hasattr(packet.tcp, 'payload'):
                try:
                    msg = bytes.fromhex(packet.tcp.payload.replace(':', '')).decode('utf-8', errors='ignore')
                except Exception:
                    continue

            if not msg:
                continue

            raw_line = self._clean_line(msg)
            if not raw_line:
                continue

            # 认证追踪
            if "AUTH LOGIN" in raw_line.upper():
                auth_stage = 1
                continue
            if auth_stage == 1 and (raw_line.startswith('C:') or len(raw_line) > 10):
                u = self._safe_decode(raw_line)
                if u:
                    auth_stage = 2
                    credentials.append({'username': u, 'password': None})
                    continue
            if auth_stage == 2 and (raw_line.startswith('C:') or len(raw_line) > 10):
                p = self._safe_decode(raw_line)
                if p and credentials:
                    credentials[-1]['password'] = p
                    auth_stage = 0
                    continue

            # 发件人/收件人
            if "MAIL FROM:" in raw_line.upper():
                tracking_sender = raw_line[10:].split(' ')[0].strip('<>')
            elif "RCPT TO:" in raw_line.upper():
                tracking_receiver = raw_line[8:].strip('<>')

            # 邮件内容抓取
            if "DATA" in raw_line.upper() and raw_line.upper().strip() == "DATA":
                is_collecting_data = True
                current_mail_buffer = []
                continue

            if is_collecting_data:
                if raw_line == ".":
                    is_collecting_data = False
                    mail_count += 1

                    mail_subject = "NoSubject"
                    for line in current_mail_buffer:
                        if line.upper().startswith("SUBJECT:"):
                            mail_subject = line[8:].strip()
                            break

                    if output_dir:
                        safe_subject = re.sub(r'[\\/:*?"<>|]', '_', mail_subject)[:40]
                        folder_name = os.path.join(output_dir, f"Mail_{mail_count:02d}_{safe_subject}")
                        os.makedirs(folder_name, exist_ok=True)

                        content_path = os.path.join(folder_name, "content.html")
                        with open(content_path, "w", encoding="utf-8") as f:
                            f.write("\n".join(current_mail_buffer))
                        extracted_files.append(content_path)

                        img_files = self._extract_images_from_raw(current_mail_buffer, folder_name)
                        extracted_files.extend(img_files)

                    # 检测flag
                    mail_text = "\n".join(current_mail_buffer)
                    is_flag = self.detect_flag_pattern(mail_text)

                    findings.append(AnalysisFinding(
                        finding_type=FindingType.FILE_EXTRACTION,
                        protocol=ProtocolType.SMTP,
                        title=f"邮件 #{mail_count}: {mail_subject}",
                        description=f"发件人: {tracking_sender}, 收件人: {tracking_receiver}",
                        data=mail_text[:500] if is_flag else f"[{len(current_mail_buffer)} 行]",
                        confidence=0.9 if is_flag else 0.7,
                        is_flag=is_flag
                    ))
                    continue
                else:
                    current_mail_buffer.append(raw_line)
                    continue

        # 凭证 findings
        if credentials:
            cred_strs = [f"{c['username']}:{c['password'] or '???'}" for c in credentials]
            findings.append(AnalysisFinding(
                finding_type=FindingType.CREDENTIAL,
                protocol=ProtocolType.SMTP,
                title="SMTP认证凭证",
                description=f"捕获 {len(credentials)} 组SMTP登录凭证 (AUTH LOGIN)",
                data="\n".join(cred_strs),
                confidence=0.95,
                is_flag=False
            ))

        # 发件人/收件人 info
        if tracking_sender != "Unknown" or tracking_receiver != "Unknown":
            findings.append(AnalysisFinding(
                finding_type=FindingType.INFO,
                protocol=ProtocolType.SMTP,
                title="SMTP通信方",
                description=f"发件人: {tracking_sender}, 收件人: {tracking_receiver}",
                data=f"From: {tracking_sender}\nTo: {tracking_receiver}",
                confidence=0.5,
                is_flag=False
            ))

        summary_parts = []
        if credentials:
            summary_parts.append(f"发现 {len(credentials)} 组凭证")
        if mail_count > 0:
            summary_parts.append(f"导出 {mail_count} 封邮件")
        summary_parts.append(f"共 {packet_count} 个SMTP包")

        return ProtocolAnalysisResult(
            protocol=ProtocolType.SMTP,
            packet_count=packet_count,
            findings=findings,
            summary="; ".join(summary_parts),
            extracted_files=extracted_files,
            output_dir=output_dir
        )


# ============================================================
# CobaltStrikeAnalyzer
# ============================================================

class CobaltStrikeAnalyzer(ProtocolAnalyzer):
    """Cobalt Strike流量分析: Cookie提取、RSA密钥提取、Metadata解密、流量解密"""

    def __init__(self, key_file_path: Optional[str] = None, output_dir: Optional[str] = None):
        self.key_file_path = key_file_path
        self.output_dir = output_dir
        self._sessions = []  # 存储已解密的session信息

    @property
    def protocol_type(self) -> ProtocolType:
        return ProtocolType.COBALT_STRIKE

    @property
    def sessions(self) -> List[Dict]:
        return self._sessions

    @staticmethod
    def _parse_metadata(data: bytes) -> Optional[Dict]:
        """解析解密后的Metadata二进制数据"""
        try:
            if data[0:4] != b'\x00\x00\xbe\xef':
                print("[-] 非标准 CS Metadata 格式")
                return None

            raw_master_key = data[8:24]
            derived_hash = hashlib.sha256(raw_master_key).digest()
            aes_key = derived_hash[:16]
            hmac_key = derived_hash[16:32]

            bid = struct.unpack('>I', data[28:32])[0]
            pid = struct.unpack('>I', data[32:36])[0]
            port = struct.unpack('>H', data[36:38])[0]

            flag = data[38]
            is64 = 1 if (flag & 2) or (flag & 4) else 0
            barch = "x64" if (flag & 1) else "x86"

            win_major = data[39]
            win_minor = data[40]
            win_build = struct.unpack('>H', data[41:43])[0]

            ip_bytes = data[55:59]
            internal_ip = ".".join(map(str, ip_bytes[::-1]))

            strings = data[59:].decode('utf-8', errors='ignore').split('\t')
            pc_name = strings[0] if len(strings) > 0 else "Unknown"
            user_name = strings[1] if len(strings) > 1 else "Unknown"
            process_name = strings[2] if len(strings) > 2 else "Unknown"

            print(f"Beacon id:{bid}")
            print(f"pid:{pid}")
            print(f"port:{port}")
            print(f"barch:{barch}")
            print(f"is64:{is64}")
            print(f"bypass:False")
            print(f"windows var:{win_major/10}.{win_minor}")
            print(f"windows build:{win_build}")
            print(f"host:{internal_ip}")
            print(f"PC name:{pc_name}")
            print(f"username:{user_name}")
            print(f"process name:{process_name}")
            print(f"AES key:{aes_key.hex()}")
            print(f"HMAC key:{hmac_key.hex()}")

            return {
                'bid': bid,
                'pid': pid,
                'port': port,
                'barch': barch,
                'is64': is64,
                'win_ver': f"{win_major / 10}.{win_minor}",
                'win_build': win_build,
                'host': internal_ip,
                'pc_name': pc_name,
                'username': user_name,
                'process_name': process_name,
                'aes_key': aes_key,
                'hmac_key': hmac_key,
                'aes_key_hex': aes_key.hex(),
                'hmac_key_hex': hmac_key.hex(),
                'info': f"{user_name}@{internal_ip} ({bid})"
            }
        except Exception as e:
            print(f"[!] Metadata 解析失败: {e}")
            return None

    @staticmethod
    def _extract_keys_from_java_keystore(key_path: str) -> Optional[bytes]:
        """从Java KeyPair文件提取RSA私钥PEM"""
        try:
            import javaobj.v2 as javaobj
        except ImportError:
            return None

        try:
            with open(key_path, "rb") as fd:
                pobj = javaobj.load(fd)

            private_key_bytes = pobj.array.value.privateKey.encoded.data
            private_key_data = bytes(b & 0xFF for b in private_key_bytes)

            private_pem = (
                b"-----BEGIN PRIVATE KEY-----\n" +
                base64.encodebytes(private_key_data) +
                b"-----END PRIVATE KEY-----"
            )
            return private_pem
        except Exception as e:
            logger.error(f"密钥提取失败: {e}")
            return None

    def analyze(self, packets: List, **kwargs) -> ProtocolAnalysisResult:
        """Stage 1: 从HTTP数据包提取潜在的CS Metadata Cookie"""
        findings = []
        packet_count = 0

        seen_cookies = set()
        cookies_list = []

        for pkt in packets:
            if hasattr(pkt, 'http'):
                packet_count += 1
                try:
                    cookie = getattr(pkt.http, 'cookie', '')
                    if cookie and len(cookie) > 30 and cookie not in seen_cookies:
                        print(f"[+] 捕获新 Cookie: {cookie}")
                        seen_cookies.add(cookie)
                        cookies_list.append(cookie)
                except AttributeError:
                    continue

        if cookies_list:
            findings.append(AnalysisFinding(
                finding_type=FindingType.C2_COMMUNICATION,
                protocol=ProtocolType.COBALT_STRIKE,
                title="CS Metadata Cookie",
                description=f"捕获 {len(cookies_list)} 个潜在的Cobalt Strike Metadata Cookie",
                data="\n".join(cookies_list),
                confidence=0.7,
                is_flag=False
            ))

        summary = f"提取 {len(cookies_list)} 个CS Cookie; 共 {packet_count} 个HTTP包"
        print(f"[OK] 共找到 {len(cookies_list)} 个潜在的 Metadata Cookie。\n")

        return ProtocolAnalysisResult(
            protocol=ProtocolType.COBALT_STRIKE,
            packet_count=packet_count,
            findings=findings,
            summary=summary,
            metadata={'cookies': cookies_list}
        )

    def analyze_pcap(self, pcap_path: str, **kwargs) -> ProtocolAnalysisResult:
        """完整4阶段分析: Cookie提取 -> 密钥提取 -> Metadata解密 -> Session存储"""
        from utils import read_pcap

        key_file_path = kwargs.get('key_file_path', self.key_file_path)
        output_dir = kwargs.get('output_dir', self.output_dir)

        findings = []
        extracted_files = []
        self._sessions = []

        # ---- Stage 1: 提取 Cookie ----
        print(f"\n[*] [步骤1] 正在分析 PCAP: {os.path.basename(pcap_path)}")
        cap = read_pcap(pcap_path)
        packets = list(cap)
        cap.close()

        stage1_result = self.analyze(packets)
        findings.extend(stage1_result.findings)
        cookies_list = stage1_result.metadata.get('cookies', [])
        packet_count = stage1_result.packet_count

        if not cookies_list:
            return ProtocolAnalysisResult(
                protocol=ProtocolType.COBALT_STRIKE,
                packet_count=packet_count,
                findings=findings,
                summary="未发现CS Cookie",
                metadata={'cookies': [], 'sessions': []}
            )

        # ---- Stage 2: 提取 RSA 密钥 ----
        if not key_file_path:
            findings.append(AnalysisFinding(
                finding_type=FindingType.INFO,
                protocol=ProtocolType.COBALT_STRIKE,
                title="需要密钥文件",
                description="需要提供 .cobaltstrike.beacon_keys 文件路径才能解密Cookie。"
                            "请通过 key_file_path 参数传入。",
                confidence=0.5,
                is_flag=False
            ))
            return ProtocolAnalysisResult(
                protocol=ProtocolType.COBALT_STRIKE,
                packet_count=packet_count,
                findings=findings,
                summary=f"提取 {len(cookies_list)} 个Cookie, 但缺少密钥文件",
                metadata={'cookies': cookies_list, 'sessions': []}
            )

        # 检查依赖
        missing_deps = []
        try:
            import javaobj.v2  # noqa: F401
        except ImportError:
            missing_deps.append("javaobj-py3")
        try:
            from cryptography.hazmat.primitives import serialization  # noqa: F401
        except ImportError:
            missing_deps.append("cryptography")

        if missing_deps:
            findings.append(AnalysisFinding(
                finding_type=FindingType.INFO,
                protocol=ProtocolType.COBALT_STRIKE,
                title="缺少依赖包",
                description=f"CS完整解密需要以下Python包: {', '.join(missing_deps)}。"
                            f"请运行: pip install {' '.join(missing_deps)}",
                confidence=1.0,
                is_flag=False
            ))
            return ProtocolAnalysisResult(
                protocol=ProtocolType.COBALT_STRIKE,
                packet_count=packet_count,
                findings=findings,
                summary=f"提取 {len(cookies_list)} 个Cookie, 但缺少依赖: {', '.join(missing_deps)}",
                metadata={'cookies': cookies_list, 'sessions': []}
            )

        print(f"[*] [步骤2] 正在提取密钥文件: {key_file_path}")
        private_pem = self._extract_keys_from_java_keystore(key_file_path)
        if not private_pem:
            print(f"[-] 密钥提取失败")
            findings.append(AnalysisFinding(
                finding_type=FindingType.INFO,
                protocol=ProtocolType.COBALT_STRIKE,
                title="密钥提取失败",
                description=f"无法从 {key_file_path} 提取RSA私钥",
                confidence=0.9,
                is_flag=False
            ))
            return ProtocolAnalysisResult(
                protocol=ProtocolType.COBALT_STRIKE,
                packet_count=packet_count,
                findings=findings,
                summary=f"提取 {len(cookies_list)} 个Cookie, 密钥提取失败",
                metadata={'cookies': cookies_list, 'sessions': []}
            )

        # 保存PEM文件
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
            priv_path = os.path.join(output_dir, "cs_private.pem")
            with open(priv_path, "wb") as f:
                f.write(private_pem)
            extracted_files.append(priv_path)
            print(f"[+] 私钥已保存: {priv_path}")

        # ---- Stage 3: RSA解密Cookie -> 解析Metadata ----
        print(f"[*] [步骤3] 正在加载私钥并解密 Cookie...")
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import padding

        try:
            private_key = serialization.load_pem_private_key(private_pem, password=None)
        except Exception as e:
            print(f"[-] 加载私钥失败: {e}")
            findings.append(AnalysisFinding(
                finding_type=FindingType.INFO,
                protocol=ProtocolType.COBALT_STRIKE,
                title="PEM加载失败",
                description=str(e),
                confidence=0.9,
                is_flag=False
            ))
            return ProtocolAnalysisResult(
                protocol=ProtocolType.COBALT_STRIKE,
                packet_count=packet_count,
                findings=findings,
                summary="PEM私钥加载失败",
                metadata={'cookies': cookies_list, 'sessions': []}
            )

        for idx, cookie_b64 in enumerate(cookies_list):
            print(f"\n--- 分析第 {idx+1} 个 Cookie ---")
            try:
                ciphertext = base64.b64decode(cookie_b64)
                plaintext = private_key.decrypt(ciphertext, padding.PKCS1v15())
                session_info = self._parse_metadata(plaintext)

                if session_info:
                    self._sessions.append(session_info)

                    meta_str = (
                        f"Beacon ID: {session_info['bid']}, "
                        f"PID: {session_info['pid']}, "
                        f"Host: {session_info['host']}, "
                        f"User: {session_info['username']}@{session_info['pc_name']}, "
                        f"Arch: {session_info['barch']}, "
                        f"AES Key: {session_info['aes_key_hex']}"
                    )
                    findings.append(AnalysisFinding(
                        finding_type=FindingType.C2_COMMUNICATION,
                        protocol=ProtocolType.COBALT_STRIKE,
                        title=f"CS Session #{idx+1} Metadata",
                        description=meta_str,
                        data=meta_str,
                        confidence=0.95,
                        is_flag=False
                    ))

            except Exception as e:
                print(f"[-] 该 Cookie 解密或解析失败 (可能不是 Metadata): {e}")
                continue

        # ---- Stage 4: 存储session信息 ----
        summary_parts = [
            f"提取 {len(cookies_list)} 个Cookie",
            f"解密 {len(self._sessions)} 个Session"
        ]
        if self._sessions:
            summary_parts.append(f"Beacon IDs: {', '.join(str(s['bid']) for s in self._sessions)}")

        return ProtocolAnalysisResult(
            protocol=ProtocolType.COBALT_STRIKE,
            packet_count=packet_count,
            findings=findings,
            summary="; ".join(summary_parts),
            extracted_files=extracted_files,
            output_dir=output_dir,
            metadata={'cookies': cookies_list, 'sessions': [
                {k: v for k, v in s.items() if k not in ('aes_key', 'hmac_key')}
                for s in self._sessions
            ]}
        )

    def decrypt_traffic(self, hex_data: str, session_index: int = 0) -> Optional[Dict]:
        """使用已解密的session密钥解密CS传输数据"""
        if not self._sessions or session_index >= len(self._sessions):
            return None

        try:
            from Crypto.Cipher import AES
        except ImportError:
            return {'error': '缺少 pycryptodome 包, 请运行: pip install pycryptodome'}

        session = self._sessions[session_index]
        aes_key_bytes = session['aes_key']
        hmac_key_bytes = session['hmac_key']
        iv_bytes = b"abcdefghijklmnop"

        try:
            encrypt_data = binascii.unhexlify(hex_data.strip())

            encrypt_data_length = int.from_bytes(encrypt_data[0:4], byteorder='big')
            encrypt_data_l = encrypt_data[4:]

            if len(encrypt_data_l) < encrypt_data_length:
                print("[-] 数据长度不足，可能截断")
                return {'error': '数据长度不足，可能截断'}

            data1 = encrypt_data_l[0:encrypt_data_length - 16]
            signature = encrypt_data_l[encrypt_data_length - 16:encrypt_data_length]

            calculated_mac = hmac_mod.new(hmac_key_bytes, data1, hashlib.sha256).digest()[:16]

            print(f"收到签名: {signature.hex()}")
            print(f"计算签名: {calculated_mac.hex()}")

            hmac_valid = hmac_mod.compare_digest(calculated_mac, signature)

            if not hmac_valid:
                print("[-] HMAC 校验失败！Key 不匹配。")
                return {'error': 'HMAC校验失败, Key不匹配', 'session_bid': session['bid']}

            print("[+] HMAC 校验成功！Key 匹配。")
            cypher = AES.new(aes_key_bytes, AES.MODE_CBC, iv_bytes)
            dec = cypher.decrypt(data1)

            counter = int.from_bytes(dec[0:4], byteorder='big')
            dec_length = int.from_bytes(dec[4:8], byteorder='big')

            print(f"Counter: {counter}")
            print(f"任务返回长度: {dec_length}")

            de_data = dec[8:]
            task_type = int.from_bytes(de_data[0:4], byteorder='big') if len(de_data) >= 4 else None
            raw_content = de_data[4:dec_length + 4] if len(de_data) >= 4 else de_data

            if task_type is not None:
                print(f"任务输出类型: {task_type}")
            print(f"结果内容(Raw): {raw_content}")
            try:
                print(f"结果内容(Text): \n{raw_content.decode('utf-8', errors='ignore')}")
            except:
                pass

            return {
                'session_bid': session['bid'],
                'hmac_valid': True,
                'counter': counter,
                'task_length': dec_length,
                'task_type': task_type,
                'raw_content': raw_content,
                'text_content': raw_content.decode('utf-8', errors='ignore')
            }
        except Exception as e:
            print(f"[-] 任务解密过程出错: {e}")
            return {'error': str(e)}


# ============================================================
# USBAnalyzer
# ============================================================

class USBAnalyzer(ProtocolAnalyzer):
    """USB流量分析: 键盘还原、鼠标轨迹恢复"""

    KEY_MAP = {
        0x04: "a", 0x05: "b", 0x06: "c", 0x07: "d", 0x08: "e",
        0x09: "f", 0x0a: "g", 0x0b: "h", 0x0c: "i", 0x0d: "j",
        0x0e: "k", 0x0f: "l", 0x10: "m", 0x11: "n", 0x12: "o",
        0x13: "p", 0x14: "q", 0x15: "r", 0x16: "s", 0x17: "t",
        0x18: "u", 0x19: "v", 0x1a: "w", 0x1b: "x", 0x1c: "y",
        0x1d: "z", 0x1e: "1", 0x1f: "2", 0x20: "3", 0x21: "4",
        0x22: "5", 0x23: "6", 0x24: "7", 0x25: "8", 0x26: "9",
        0x27: "0", 0x28: "\n", 0x2c: " ", 0x2d: "-", 0x2e: "=",
        0x2f: "[", 0x30: "]", 0x31: "\\", 0x33: ";", 0x34: "'",
        0x36: ",", 0x37: ".", 0x38: "/"
    }

    SHIFT_MAP = {
        "a": "A", "b": "B", "c": "C", "d": "D", "e": "E", "f": "F",
        "g": "G", "h": "H", "i": "I", "j": "J", "k": "K", "l": "L",
        "m": "M", "n": "N", "o": "O", "p": "P", "q": "Q", "r": "R",
        "s": "S", "t": "T", "u": "U", "v": "V", "w": "W", "x": "X",
        "y": "Y", "z": "Z", "1": "!", "2": "@", "3": "#", "4": "$",
        "5": "%", "6": "^", "7": "&", "8": "*", "9": "(", "0": ")",
        "-": "_", "=": "+", "[": "{", "]": "}", "\\": "|", ";": ":",
        "'": "\"", ",": "<", ".": ">", "/": "?"
    }

    def __init__(self, generate_plot: bool = False):
        self.generate_plot = generate_plot

    @property
    def protocol_type(self) -> ProtocolType:
        return ProtocolType.USB

    def analyze(self, packets: List, **kwargs) -> ProtocolAnalysisResult:
        """USB分析需要通过tshark从pcap提取，直接包分析不可用"""
        raise NotImplementedError(
            "USBAnalyzer需要pcap文件路径, 请使用 analyze_pcap() 方法"
        )

    def analyze_pcap(self, pcap_path: str, **kwargs) -> ProtocolAnalysisResult:
        findings = []
        generate_plot = kwargs.get('generate_plot', self.generate_plot)

        from services.analysis_service import AnalysisService
        tshark_path = AnalysisService().find_tshark()

        if not tshark_path:
            return ProtocolAnalysisResult(
                protocol=ProtocolType.USB,
                packet_count=0,
                findings=[AnalysisFinding(
                    finding_type=FindingType.INFO,
                    protocol=ProtocolType.USB,
                    title="tshark未找到",
                    description="未找到tshark，请安装Wireshark或将tshark加入PATH",
                    confidence=1.0,
                    is_flag=False
                )],
                summary="tshark不可用"
            )

        cmd = [
            tshark_path, "-r", pcap_path,
            "-T", "fields",
            "-e", "usbhid.data",
            "-e", "usb.capdata",
            "-e", "data.data"
        ]

        try:
            process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, encoding='utf-8'
            )
            stdout, stderr = process.communicate()
        except FileNotFoundError:
            return ProtocolAnalysisResult(
                protocol=ProtocolType.USB,
                packet_count=0,
                findings=[AnalysisFinding(
                    finding_type=FindingType.INFO,
                    protocol=ProtocolType.USB,
                    title="tshark未找到",
                    description=f"无法找到tshark: {tshark_path}",
                    confidence=1.0,
                    is_flag=False
                )],
                summary="tshark不可用"
            )

        kb_result = []
        mouse_trace = []
        cur_x, cur_y = 0, 0
        packet_count = 0

        for line in stdout.strip().split('\n'):
            data = "".join(line.split()).replace(':', '')
            if not data:
                continue

            packet_count += 1
            d_len = len(data)

            # 12字符: 12-bit坐标鼠标
            if d_len == 12:
                try:
                    btn = int(data[2:4], 16)
                    b1, b2, b3 = int(data[4:6], 16), int(data[6:8], 16), int(data[8:10], 16)
                    x = b1 | ((b2 & 0x0f) << 8)
                    y = (b2 >> 4) | (b3 << 4)
                    if x > 2047: x -= 4096
                    if y > 2047: y -= 4096
                    cur_x += x
                    cur_y += y
                    if btn != 0:
                        mouse_trace.append((cur_x, cur_y))
                except Exception:
                    continue

            # 8字符: 标准3字节鼠标
            elif d_len == 8:
                try:
                    btn = int(data[0:2], 16)
                    x, y = int(data[2:4], 16), int(data[4:6], 16)
                    if x > 127: x -= 256
                    if y > 127: y -= 256
                    cur_x += x
                    cur_y += y
                    if btn & 0x7:
                        mouse_trace.append((cur_x, cur_y))
                except Exception:
                    continue

            # 16字符: 标准键盘
            elif d_len == 16:
                try:
                    mod = int(data[0:2], 16)
                    key = int(data[4:6], 16)
                    if key == 0:
                        continue
                    char = self.KEY_MAP.get(key, "")
                    if char:
                        is_shift = (mod & 0x02) or (mod & 0x20)
                        kb_result.append(self.SHIFT_MAP.get(char, char.upper()) if is_shift else char)
                except Exception:
                    continue

        # 生成 findings
        if kb_result:
            kb_text = "".join(kb_result)
            is_flag = self.detect_flag_pattern(kb_text)
            findings.append(AnalysisFinding(
                finding_type=FindingType.DEVICE_INPUT,
                protocol=ProtocolType.USB,
                title="USB键盘输入还原",
                description=f"从USB HID数据还原 {len(kb_result)} 个按键",
                data=kb_text,
                confidence=0.9,
                is_flag=is_flag
            ))

            if is_flag:
                findings.append(AnalysisFinding(
                    finding_type=FindingType.HIDDEN_DATA,
                    protocol=ProtocolType.USB,
                    title="键盘输入中发现FLAG",
                    description="在还原的键盘输入中检测到flag模式",
                    data=kb_text,
                    confidence=0.95,
                    is_flag=True
                ))

        if mouse_trace:
            findings.append(AnalysisFinding(
                finding_type=FindingType.INFO,
                protocol=ProtocolType.USB,
                title="USB鼠标轨迹",
                description=f"恢复 {len(mouse_trace)} 个鼠标坐标点",
                data=f"[{len(mouse_trace)} 个坐标点]",
                confidence=0.7,
                is_flag=False
            ))

        # 绘图（可选）
        if generate_plot and mouse_trace:
            try:
                import matplotlib.pyplot as plt
                import numpy as np

                x_coords = np.array([p[0] for p in mouse_trace])
                y_coords = np.array([p[1] for p in mouse_trace])
                time_index = np.linspace(0, 1, len(mouse_trace))

                plt.figure(figsize=(10, 6))
                plt.plot(x_coords, y_coords, color='gray', linewidth=0.5, alpha=0.3)
                scatter = plt.scatter(x_coords, y_coords, c=time_index, cmap='jet', s=15, edgecolors='none', zorder=5)
                cbar = plt.colorbar(scatter)
                cbar.set_label('Time Progression (Start: Blue -> End: Red)')
                plt.gca().invert_yaxis()
                plt.axis('equal')
                plt.title("Mouse Movement Trace (Gradient Analysis)")
                plt.grid(True, linestyle=':', alpha=0.6)
                plt.show()
            except ImportError:
                logger.warning("matplotlib/numpy 未安装, 跳过鼠标轨迹绘图")

        summary_parts = []
        if kb_result:
            summary_parts.append(f"还原 {len(kb_result)} 个按键")
        if mouse_trace:
            summary_parts.append(f"恢复 {len(mouse_trace)} 个鼠标点")
        summary_parts.append(f"共 {packet_count} 个USB包")
        flags = [f.data for f in findings if f.is_flag]
        if flags:
            summary_parts.append(f"FLAG: {flags[0][:80]}")

        return ProtocolAnalysisResult(
            protocol=ProtocolType.USB,
            packet_count=packet_count,
            findings=findings,
            summary="; ".join(summary_parts),
            metadata={'mouse_trace': mouse_trace, 'keyboard_text': "".join(kb_result)}
        )



# ============================================================
# TLSAnalyzer
# ============================================================

class TLSAnalyzer(ProtocolAnalyzer):
    """SSL/TLS加密流量分析 (CTF向): 握手信息、证书、私钥解密、keylog解密、HTTP提取"""

    # TLS keylog 行的合法 label
    _KEYLOG_LABELS = [
        'CLIENT_RANDOM',
        'CLIENT_HANDSHAKE_TRAFFIC_SECRET',
        'SERVER_HANDSHAKE_TRAFFIC_SECRET',
        'CLIENT_TRAFFIC_SECRET_0',
        'SERVER_TRAFFIC_SECRET_0',
        'EXPORTER_SECRET',
        'EARLY_TRAFFIC_SECRET',
        'RSA',
    ]
    _KEYLOG_PATTERN = re.compile(
        r'(?:' + '|'.join(_KEYLOG_LABELS) + r')\s+[0-9a-fA-F]{64}\s+[0-9a-fA-F]{48,}'
    )

    def __init__(self, key_file: Optional[str] = None, keylog_file: Optional[str] = None,
                 server_ip: Optional[str] = None, port: str = '443',
                 output_dir: Optional[str] = None):
        self.key_file = key_file
        self.keylog_file = keylog_file
        self.server_ip = server_ip
        self.port = port
        self.output_dir = output_dir

    @property
    def protocol_type(self) -> ProtocolType:
        return ProtocolType.TLS

    def analyze(self, packets: List, **kwargs) -> ProtocolAnalysisResult:
        """TLS分析需要通过tshark从pcap提取，直接包分析不可用"""
        raise NotImplementedError(
            "TLSAnalyzer需要pcap文件路径, 请使用 analyze_pcap() 方法"
        )

    @staticmethod
    def _run_tshark(tshark_path, args):
        cmd = [tshark_path] + args
        try:
            process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, encoding='utf-8'
            )
            stdout, stderr = process.communicate()
            return stdout
        except FileNotFoundError:
            print(f'[!] 无法找到tshark: {tshark_path}')
            return ''

    def extract_tls_handshake(self, pcap_file, tshark_path):
        """提取 TLS 握手信息: 版本、密码套件、SNI、证书"""

        # --- Client Hello: SNI + 支持的版本 ---
        ch_stdout = self._run_tshark(tshark_path, [
            '-r', pcap_file,
            '-Y', 'tls.handshake.type == 1',
            '-T', 'fields',
            '-e', 'ip.src',
            '-e', 'ip.dst',
            '-e', 'tls.handshake.extensions.server_name',
            '-e', 'tls.handshake.version',
        ])

        client_hellos = []
        for line in ch_stdout.strip().splitlines():
            fields = line.split('\t')
            if len(fields) >= 3:
                client_hellos.append({
                    'src': fields[0],
                    'dst': fields[1],
                    'sni': fields[2] if len(fields) > 2 else '',
                    'version': fields[3] if len(fields) > 3 else '',
                })

        if client_hellos:
            print(f'[+] Client Hello ({len(client_hellos)} 条)')
            seen_sni = set()
            for ch in client_hellos:
                sni = ch['sni'] or '(无SNI)'
                key = f"{ch['src']}->{ch['dst']}:{sni}"
                if key not in seen_sni:
                    seen_sni.add(key)
                    print(f'    {ch["src"]} -> {ch["dst"]} | SNI: {sni}')
            print()

        # --- Server Hello: 选定的密码套件 + 版本 ---
        sh_stdout = self._run_tshark(tshark_path, [
            '-r', pcap_file,
            '-Y', 'tls.handshake.type == 2',
            '-T', 'fields',
            '-e', 'ip.src',
            '-e', 'tls.handshake.version',
            '-e', 'tls.handshake.ciphersuite',
            '-e', 'tls.handshake.extensions.supported_version',
        ])

        server_hellos = []
        for line in sh_stdout.strip().splitlines():
            fields = line.split('\t')
            if len(fields) >= 2:
                server_hellos.append({
                    'server': fields[0],
                    'version': fields[1] if len(fields) > 1 else '',
                    'cipher': fields[2] if len(fields) > 2 else '',
                    'supported_ver': fields[3] if len(fields) > 3 else '',
                })

        version_map = {
            '0x0300': 'SSL 3.0', '0x0301': 'TLS 1.0', '0x0302': 'TLS 1.1',
            '0x0303': 'TLS 1.2', '0x0304': 'TLS 1.3',
            '0x00000300': 'SSL 3.0', '0x00000301': 'TLS 1.0', '0x00000302': 'TLS 1.1',
            '0x00000303': 'TLS 1.2', '0x00000304': 'TLS 1.3',
        }

        # 已知弱密码套件关键词
        weak_ciphers = ['RC4', 'DES', 'NULL', 'EXPORT', 'anon', 'MD5']

        if server_hellos:
            print(f'[+] Server Hello ({len(server_hellos)} 条)')
            for sh in server_hellos:
                ver = sh['supported_ver'] or sh['version']
                ver_name = version_map.get(ver, ver)
                print(f'    服务器: {sh["server"]} | 版本: {ver_name} | 密码套件: {sh["cipher"]}')

                # 检测弱密码套件
                cipher_str = sh['cipher'].upper()
                found_weak = [w for w in weak_ciphers if w.upper() in cipher_str]
                if found_weak:
                    print(f'    [!] 检测到弱密码套件: {", ".join(found_weak)}')

                # 检测是否使用 RSA 密钥交换 (可用私钥解密)
                if 'RSA' in cipher_str and 'DHE' not in cipher_str and 'ECDHE' not in cipher_str:
                    print(f'    [*] 使用 RSA 密钥交换，可用私钥解密')
            print()

        # --- 证书信息 ---
        cert_stdout = self._run_tshark(tshark_path, [
            '-r', pcap_file,
            '-Y', 'tls.handshake.type == 11',
            '-T', 'fields',
            '-e', 'ip.src',
            '-e', 'x509sat.utf8String',
            '-e', 'x509sat.printableString',
            '-e', 'x509ce.dNSName',
            '-e', 'x509sat.CountryName',
        ])

        certs = []
        for line in cert_stdout.strip().splitlines():
            fields = line.split('\t')
            if len(fields) >= 2:
                cert = {
                    'server': fields[0],
                    'utf8': fields[1] if len(fields) > 1 else '',
                    'printable': fields[2] if len(fields) > 2 else '',
                    'dns_name': fields[3] if len(fields) > 3 else '',
                    'country': fields[4] if len(fields) > 4 else '',
                }
                certs.append(cert)

        if certs:
            print(f'[+] 服务器证书 ({len(certs)} 条)')
            for c in certs:
                names = ','.join(filter(None, [c['utf8'], c['printable'], c['dns_name']]))
                print(f'    来源: {c["server"]}')
                if names:
                    print(f'    证书名称: {names}')
                if c['country']:
                    print(f'    国家: {c["country"]}')
            print()

        return {'client_hellos': client_hellos, 'server_hellos': server_hellos, 'certs': certs}

    def extract_tls_sessions(self, pcap_file, tshark_path):
        """统计 TLS 会话"""

        stdout = self._run_tshark(tshark_path, [
            '-r', pcap_file,
            '-Y', 'tls',
            '-T', 'fields',
            '-e', 'ip.src',
            '-e', 'ip.dst',
            '-e', 'tcp.srcport',
            '-e', 'tcp.dstport',
            '-e', 'tcp.stream',
        ])

        streams = defaultdict(lambda: {'packets': 0, 'src': '', 'dst': '', 'sport': '', 'dport': ''})
        for line in stdout.strip().splitlines():
            fields = line.split('\t')
            if len(fields) >= 5:
                sid = fields[4]
                streams[sid]['packets'] += 1
                if not streams[sid]['src']:
                    streams[sid].update({
                        'src': fields[0], 'dst': fields[1],
                        'sport': fields[2], 'dport': fields[3],
                    })

        if streams:
            print(f'[+] TLS 会话统计 (共 {len(streams)} 个 TCP 流)')
            for sid, info in sorted(streams.items(), key=lambda x: -x[1]['packets'])[:20]:
                print(f'    Stream #{sid}: {info["src"]}:{info["sport"]} -> {info["dst"]}:{info["dport"]} | {info["packets"]} 包')
            if len(streams) > 20:
                print(f'    ... 共 {len(streams)} 个流')
            print()

        return streams

    def decrypt_with_key(self, pcap_file, tshark_path, key_file, server_ip=None, port='443'):
        """使用 RSA 私钥解密 TLS 流量并提取 HTTP 数据"""

        if not os.path.isfile(key_file):
            print(f'[!] 私钥文件不存在: {key_file}')
            return []

        with open(key_file, 'r', errors='ignore') as f:
            key_head = f.read(256)

        if 'PRIVATE KEY' in key_head:
            print(f'[*] 检测到私钥文件: {key_file}')
        else:
            print(f'[*] 使用密钥文件: {key_file}')

        ip = server_ip or '0.0.0.0'
        key_abs = os.path.abspath(key_file)

        # 尝试解密并提取 HTTP 数据
        http_stdout = self._run_tshark(tshark_path, [
            '-r', pcap_file,
            '-o', f'tls.keys_list:{ip},{port},http,{key_abs}',
            '-Y', 'http',
            '-T', 'fields',
            '-e', 'frame.number',
            '-e', 'ip.src',
            '-e', 'ip.dst',
            '-e', 'http.request.method',
            '-e', 'http.request.uri',
            '-e', 'http.host',
            '-e', 'http.response.code',
            '-e', 'http.content_type',
        ])

        http_records = []
        for line in http_stdout.strip().splitlines():
            fields = line.split('\t')
            if len(fields) >= 3:
                http_records.append({
                    'frame': fields[0],
                    'src': fields[1],
                    'dst': fields[2],
                    'method': fields[3] if len(fields) > 3 else '',
                    'uri': fields[4] if len(fields) > 4 else '',
                    'host': fields[5] if len(fields) > 5 else '',
                    'status': fields[6] if len(fields) > 6 else '',
                    'content_type': fields[7] if len(fields) > 7 else '',
                })

        if http_records:
            print(f'[+] 私钥解密成功！提取到 {len(http_records)} 条 HTTP 记录')
            for r in http_records:
                if r['method']:
                    print(f'    #{r["frame"]} {r["method"]} {r["host"]}{r["uri"]}')
                elif r['status']:
                    print(f'    #{r["frame"]} <- {r["status"]} ({r["content_type"]})')
            print()
        else:
            print('[*] 私钥解密未提取到 HTTP 数据')
            print('    可能原因:')
            print('    - 私钥与服务器证书不匹配')
            print('    - 使用了 DHE/ECDHE 密钥交换 (前向保密)，私钥无法解密')
            print('    - 试试使用 keylog 文件解密')
            print()

        return http_records

    def decrypt_with_keylog(self, pcap_file, tshark_path, keylog_file):
        """使用 TLS keylog 文件 (SSLKEYLOGFILE) 解密流量"""

        if not os.path.isfile(keylog_file):
            print(f'[!] keylog 文件不存在: {keylog_file}')
            return []

        print(f'[*] 使用 TLS keylog 文件: {keylog_file}')
        keylog_abs = os.path.abspath(keylog_file)

        # 解密后提取 HTTP
        http_stdout = self._run_tshark(tshark_path, [
            '-r', pcap_file,
            '-o', f'tls.keylog_file:{keylog_abs}',
            '-Y', 'http',
            '-T', 'fields',
            '-e', 'frame.number',
            '-e', 'ip.src',
            '-e', 'ip.dst',
            '-e', 'http.request.method',
            '-e', 'http.request.uri',
            '-e', 'http.host',
            '-e', 'http.response.code',
            '-e', 'http.content_type',
        ])

        http_records = []
        for line in http_stdout.strip().splitlines():
            fields = line.split('\t')
            if len(fields) >= 3:
                http_records.append({
                    'frame': fields[0],
                    'src': fields[1],
                    'dst': fields[2],
                    'method': fields[3] if len(fields) > 3 else '',
                    'uri': fields[4] if len(fields) > 4 else '',
                    'host': fields[5] if len(fields) > 5 else '',
                    'status': fields[6] if len(fields) > 6 else '',
                    'content_type': fields[7] if len(fields) > 7 else '',
                })

        if http_records:
            print(f'[+] Keylog 解密成功！提取到 {len(http_records)} 条 HTTP 记录')
            for r in http_records:
                if r['method']:
                    print(f'    #{r["frame"]} {r["method"]} {r["host"]}{r["uri"]}')
                elif r['status']:
                    print(f'    #{r["frame"]} <- {r["status"]} ({r["content_type"]})')
            print()
        else:
            print('[*] Keylog 解密未提取到 HTTP 数据')
            print()

        return http_records

    def export_decrypted_objects(self, pcap_file, tshark_path, output_dir, key_file=None, keylog_file=None):
        """解密后导出 HTTP 对象"""

        os.makedirs(output_dir, exist_ok=True)

        extra_args = []
        if keylog_file and os.path.isfile(keylog_file):
            extra_args = ['-o', f'tls.keylog_file:{os.path.abspath(keylog_file)}']
        elif key_file and os.path.isfile(key_file):
            extra_args = ['-o', f'tls.keys_list:0.0.0.0,443,http,{os.path.abspath(key_file)}']

        if not extra_args:
            return []

        cmd = [tshark_path, '-r', pcap_file] + extra_args + ['--export-objects', f'http,{output_dir}']
        try:
            process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, encoding='utf-8'
            )
            _, stderr = process.communicate()
        except FileNotFoundError:
            return []

        exported = [f for f in os.listdir(output_dir) if os.path.isfile(os.path.join(output_dir, f))]
        if exported:
            print(f'[+] 解密后导出 {len(exported)} 个 HTTP 文件 -> {output_dir}')
            for fname in exported:
                fpath = os.path.join(output_dir, fname)
                fsize = os.path.getsize(fpath)
                print(f'    - {fname} ({fsize} bytes)')
            print()
        else:
            print('[*] 解密后未导出 HTTP 文件')
            print()

        return exported

    def extract_keylog_from_pcap(self, pcap_file, tshark_path, output_dir):
        """从 pcap 的 TCP 流中搜索 TLS keylog 数据 (CLIENT_RANDOM 等)

        CTF 中常把 sslkeylog 藏在其他协议流量中 (HTTP/FTP/TCP 明文流等)
        """

        # 获取所有 TCP 流编号
        stream_stdout = self._run_tshark(tshark_path, [
            '-r', pcap_file,
            '-T', 'fields',
            '-e', 'tcp.stream',
        ])

        stream_ids = sorted(set(
            l.strip() for l in stream_stdout.strip().splitlines() if l.strip()
        ))

        if not stream_ids:
            return None

        all_keylog_lines = []

        for sid in stream_ids:
            follow_stdout = self._run_tshark(tshark_path, [
                '-r', pcap_file,
                '-qz', f'follow,tcp,ascii,{sid}',
            ])

            # 在 follow 输出中搜索 keylog 行
            for line in follow_stdout.splitlines():
                line = line.strip()
                if self._KEYLOG_PATTERN.search(line):
                    # 可能一行有多条，也可能混在其他文本中，逐个提取
                    for match in self._KEYLOG_PATTERN.finditer(line):
                        keylog_line = match.group(0)
                        if keylog_line not in all_keylog_lines:
                            all_keylog_lines.append(keylog_line)

        if not all_keylog_lines:
            # 兜底: 在所有 TCP payload 的原始 hex 中搜索
            payload_stdout = self._run_tshark(tshark_path, [
                '-r', pcap_file,
                '-Y', 'tcp.payload',
                '-T', 'fields',
                '-e', 'tcp.payload',
            ])
            for line in payload_stdout.strip().splitlines():
                hex_str = line.strip().replace(':', '')
                if not hex_str:
                    continue
                try:
                    text = bytes.fromhex(hex_str).decode('utf-8', errors='ignore')
                except ValueError:
                    continue
                for match in self._KEYLOG_PATTERN.finditer(text):
                    keylog_line = match.group(0)
                    if keylog_line not in all_keylog_lines:
                        all_keylog_lines.append(keylog_line)

        if not all_keylog_lines:
            return None

        # 保存到文件
        os.makedirs(output_dir, exist_ok=True)
        keylog_path = os.path.join(output_dir, 'sslkeylog.log')
        with open(keylog_path, 'w') as f:
            f.write('\n'.join(all_keylog_lines) + '\n')

        print(f'[+] 从流量包中提取到 {len(all_keylog_lines)} 条 TLS keylog 记录')
        for kl in all_keylog_lines[:10]:
            print(f'    {kl[:80]}...' if len(kl) > 80 else f'    {kl}')
        if len(all_keylog_lines) > 10:
            print(f'    ... 共 {len(all_keylog_lines)} 条')
        print(f'    已保存到: {keylog_path}')
        print()

        return keylog_path

    def search_and_highlight_flags(self, output_dir, exported_files):
        """在新导出的 HTTP 文件中搜索并高亮显示疑似的 Flag 内容"""
        if not exported_files:
            return

        print('[阶段6] 自动搜索解密内容中的 Flag')
        print('-' * 60)

        # 常见的 flag 正则表达式 (忽略大小写)
        # 支持匹配 flag{...}, ctf{...}, DASCTF{...}, flag_...{...} 等 CTF 常见格式
        flag_pattern = re.compile(r'((?:flag|ctf|[a-zA-Z0-9]+CTF)[_-]?\{.*?\})', re.IGNORECASE)
        found_flags = False

        for fname in exported_files:
            fpath = os.path.join(output_dir, fname)
            try:
                # 尝试以文本方式读取文件，忽略非文本（如图片）引发的解码错误
                with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()

                if flag_pattern.search(content):
                    found_flags = True
                    print(f'[!] 在解密文件 {fname} 中发现疑似 Flag:')

                    # 按行切分，只打印包含 Flag 的行，避免终端被大文件刷屏
                    lines = content.splitlines()
                    for i, line in enumerate(lines):
                        if flag_pattern.search(line):
                            # \033[91m = 亮红色, \033[1m = 粗体, \033[0m = 重置颜色
                            highlighted_line = flag_pattern.sub(r'\033[91m\033[1m\1\033[0m', line)
                            print(f'    [行 {i+1}] {highlighted_line.strip()}')
            except Exception:
                # 忽略因权限或格式问题无法读取的特殊文件
                continue

        if not found_flags:
            print('[*] 未在解密的 HTTP 文件中自动匹配到常见格式的 Flag。')
        print()

    def analyze_pcap(self, pcap_path: str, **kwargs) -> ProtocolAnalysisResult:
        """TLS 完整分析入口"""
        findings = []
        extracted_files_list = []

        key_file = kwargs.get('key_file', self.key_file)
        keylog_file = kwargs.get('keylog_file', self.keylog_file)
        server_ip = kwargs.get('server_ip', self.server_ip)
        port = kwargs.get('port', self.port)
        output_dir = kwargs.get('output_dir', self.output_dir)

        if not os.path.isfile(pcap_path):
            print(f'[!] 文件不存在: {pcap_path}')
            return ProtocolAnalysisResult(
                protocol=ProtocolType.TLS,
                packet_count=0,
                findings=[],
                summary="文件不存在"
            )

        from services.analysis_service import AnalysisService
        tshark_path = AnalysisService().find_tshark()
        if not tshark_path:
            return ProtocolAnalysisResult(
                protocol=ProtocolType.TLS,
                packet_count=0,
                findings=[AnalysisFinding(
                    finding_type=FindingType.INFO,
                    protocol=ProtocolType.TLS,
                    title="tshark未找到",
                    description="未找到tshark，请安装Wireshark或将tshark加入PATH",
                    confidence=1.0,
                    is_flag=False
                )],
                summary="tshark不可用"
            )

        if not output_dir:
            pcap_name = os.path.splitext(os.path.basename(pcap_path))[0]
            PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent
            output_dir = str(PROJECT_ROOT / 'output' / 'tls' / pcap_name)

        print(f'[*] 正在分析 SSL/TLS 流量: {pcap_path}')
        print('=' * 60)

        # 1. 握手信息 + 证书
        print('[阶段1] TLS 握手信息与证书')
        print('-' * 60)
        handshake = self.extract_tls_handshake(pcap_path, tshark_path)

        client_hellos = handshake.get('client_hellos', [])
        server_hellos = handshake.get('server_hellos', [])
        certs = handshake.get('certs', [])

        if client_hellos:
            sni_list = [ch['sni'] for ch in client_hellos if ch.get('sni')]
            findings.append(AnalysisFinding(
                finding_type=FindingType.INFO,
                protocol=ProtocolType.TLS,
                title="TLS Client Hello",
                description=f"捕获 {len(client_hellos)} 条 Client Hello",
                data=', '.join(set(sni_list)) if sni_list else None,
                confidence=0.9,
                is_flag=False
            ))

        if server_hellos:
            findings.append(AnalysisFinding(
                finding_type=FindingType.INFO,
                protocol=ProtocolType.TLS,
                title="TLS Server Hello",
                description=f"捕获 {len(server_hellos)} 条 Server Hello",
                data=', '.join(sh.get('cipher', '') for sh in server_hellos),
                confidence=0.9,
                is_flag=False
            ))

        if certs:
            cert_names = []
            for c in certs:
                names = ','.join(filter(None, [c.get('utf8', ''), c.get('printable', ''), c.get('dns_name', '')]))
                if names:
                    cert_names.append(names)
            findings.append(AnalysisFinding(
                finding_type=FindingType.INFO,
                protocol=ProtocolType.TLS,
                title="服务器证书",
                description=f"提取 {len(certs)} 个证书",
                data='; '.join(cert_names) if cert_names else None,
                confidence=0.9,
                is_flag=False
            ))

        # 2. 会话统计
        print('[阶段2] TLS 会话统计')
        print('-' * 60)
        sessions = self.extract_tls_sessions(pcap_path, tshark_path)

        # 2.5 自动从流量包中搜索 keylog 数据
        auto_keylog = None
        if not key_file and not keylog_file:
            print('[阶段3] 自动搜索 TLS Keylog 数据')
            print('-' * 60)
            auto_keylog = self.extract_keylog_from_pcap(pcap_path, tshark_path, output_dir)
            if auto_keylog:
                keylog_file = auto_keylog
                findings.append(AnalysisFinding(
                    finding_type=FindingType.HIDDEN_DATA,
                    protocol=ProtocolType.TLS,
                    title="自动提取 TLS Keylog",
                    description="从流量包中发现并提取了 TLS keylog 数据",
                    data=auto_keylog,
                    confidence=0.9,
                    is_flag=False
                ))
            else:
                print('[*] 未在流量包中发现 keylog 数据')
                print()

        # 3. 私钥解密
        http_from_key = []
        if key_file:
            print('[阶段3] RSA 私钥解密')
            print('-' * 60)
            http_from_key = self.decrypt_with_key(pcap_path, tshark_path, key_file, server_ip, port)
            if http_from_key:
                findings.append(AnalysisFinding(
                    finding_type=FindingType.HIDDEN_DATA,
                    protocol=ProtocolType.TLS,
                    title="RSA私钥解密HTTP",
                    description=f"使用私钥解密提取 {len(http_from_key)} 条HTTP记录",
                    data='\n'.join(
                        f"{r.get('method','')} {r.get('host','')}{r.get('uri','')}" if r.get('method')
                        else f"<- {r.get('status','')} ({r.get('content_type','')})"
                        for r in http_from_key
                    ),
                    confidence=0.95,
                    is_flag=False
                ))

        # 4. Keylog 解密
        http_from_keylog = []
        if keylog_file:
            print('[阶段4] TLS Keylog 解密')
            print('-' * 60)
            http_from_keylog = self.decrypt_with_keylog(pcap_path, tshark_path, keylog_file)
            if http_from_keylog:
                findings.append(AnalysisFinding(
                    finding_type=FindingType.HIDDEN_DATA,
                    protocol=ProtocolType.TLS,
                    title="Keylog解密HTTP",
                    description=f"使用keylog解密提取 {len(http_from_keylog)} 条HTTP记录",
                    data='\n'.join(
                        f"{r.get('method','')} {r.get('host','')}{r.get('uri','')}" if r.get('method')
                        else f"<- {r.get('status','')} ({r.get('content_type','')})"
                        for r in http_from_keylog
                    ),
                    confidence=0.95,
                    is_flag=False
                ))

        # 5. 导出文件
        exported = []
        if key_file or keylog_file:
            print('[阶段5] 解密后 HTTP 文件导出')
            print('-' * 60)
            exported = self.export_decrypted_objects(pcap_path, tshark_path, output_dir, key_file, keylog_file)
            extracted_files_list.extend(exported)

        if exported:
            self.search_and_highlight_flags(output_dir, exported)

        # 摘要
        print('=' * 60)
        hello_count = len(client_hellos)
        cert_count = len(certs)
        stream_count = len(sessions)
        http_count = len(http_from_key) + len(http_from_keylog)

        summary_parts = [f"TLS会话: {stream_count} 个", f"Client Hello: {hello_count} 条", f"证书: {cert_count} 个"]
        print(f'[摘要] {" | ".join(summary_parts)}')

        if http_count:
            summary_parts.append(f"解密HTTP记录: {http_count} 条")
            summary_parts.append(f"导出文件: {len(exported)} 个")
            print(f'       解密HTTP记录: {http_count} 条 | 导出文件: {len(exported)} 个')
            if exported:
                print(f'       文件保存至: {output_dir}')
        else:
            if not key_file and not keylog_file:
                can_rsa = False
                for sh in server_hellos:
                    c = sh.get('cipher', '').upper()
                    if 'RSA' in c and 'DHE' not in c and 'ECDHE' not in c:
                        can_rsa = True
                        break

                if can_rsa:
                    print('       [*] 检测到 RSA 密钥交换，如有服务器私钥可用 -k 参数解密')
                else:
                    print('       [*] 使用 DHE/ECDHE 前向保密，需要 keylog 文件才能解密 (-l 参数)')

        print('=' * 60)

        return ProtocolAnalysisResult(
            protocol=ProtocolType.TLS,
            packet_count=stream_count,
            findings=findings,
            summary="; ".join(summary_parts),
            extracted_files=extracted_files_list,
            output_dir=output_dir,
            metadata={
                'handshake': handshake,
                'sessions': dict(sessions),
                'http_from_key': http_from_key,
                'http_from_keylog': http_from_keylog,
            }
        )



# ============================================================
# RDPAnalyzer
# ============================================================

class RDPAnalyzer(ProtocolAnalyzer):
    """RDP协议流量分析 (CTF向): 会话元数据、Cookie用户名、NTLM认证、证书信息、私钥/keylog解密"""

    def __init__(self, key_file: Optional[str] = None, keylog_file: Optional[str] = None,
                 server_ip: Optional[str] = None, output_dir: Optional[str] = None):
        self.key_file = key_file
        self.keylog_file = keylog_file
        self.server_ip = server_ip
        self.output_dir = output_dir

    @property
    def protocol_type(self) -> ProtocolType:
        return ProtocolType.RDP

    def analyze(self, packets: List, **kwargs) -> ProtocolAnalysisResult:
        """RDP分析需要通过tshark从pcap提取，直接包分析不可用"""
        raise NotImplementedError(
            "RDPAnalyzer需要pcap文件路径, 请使用 analyze_pcap() 方法"
        )

    @staticmethod
    def _run_tshark(tshark_path, args):
        """执行 tshark 命令并返回 stdout"""
        cmd = [tshark_path] + args
        try:
            process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, encoding='utf-8'
            )
            stdout, stderr = process.communicate()
            return stdout
        except FileNotFoundError:
            print(f"[!] 无法找到tshark: {tshark_path}")
            return ""

    def extract_rdp_sessions(self, pcap_file, tshark_path):
        """提取 RDP 会话元数据: IP、端口、Cookie (含用户名)"""

        # 提取 RDP Cookie (mstshash=username)
        cookie_stdout = self._run_tshark(tshark_path, [
            "-r", pcap_file,
            "-Y", "rdp.rt_cookie",
            "-T", "fields",
            "-e", "ip.src",
            "-e", "ip.dst",
            "-e", "tcp.srcport",
            "-e", "tcp.dstport",
            "-e", "rdp.rt_cookie",
        ])

        cookies = []
        usernames = set()
        for line in cookie_stdout.strip().splitlines():
            fields = line.split('\t')
            if len(fields) >= 5:
                cookie = fields[4]
                cookies.append({
                    'src_ip': fields[0],
                    'dst_ip': fields[1],
                    'src_port': fields[2],
                    'dst_port': fields[3],
                    'cookie': cookie,
                })
                # mstshash=username 格式提取用户名
                if "mstshash=" in cookie:
                    username = cookie.split("mstshash=")[-1].strip()
                    if username:
                        usernames.add(username)

        if cookies:
            print(f"[+] RDP Cookie 信息 ({len(cookies)} 条)")
            for c in cookies:
                print(f"    {c['src_ip']}:{c['src_port']} -> {c['dst_ip']}:{c['dst_port']}")
                print(f"      Cookie: {c['cookie']}")
            if usernames:
                print(f"    [*] 提取到用户名: {', '.join(usernames)}")
            print()

        # RDP 协商信息
        neg_stdout = self._run_tshark(tshark_path, [
            "-r", pcap_file,
            "-Y", "rdp.neg",
            "-T", "fields",
            "-e", "ip.src",
            "-e", "ip.dst",
            "-e", "rdp.neg.type",
            "-e", "rdp.neg.selectedprotocol",
        ])

        negotiations = []
        for line in neg_stdout.strip().splitlines():
            fields = line.split('\t')
            if len(fields) >= 3:
                neg_type = fields[2]
                proto = fields[3] if len(fields) > 3 else ""
                negotiations.append({
                    'src_ip': fields[0],
                    'dst_ip': fields[1],
                    'type': neg_type,
                    'selected_protocol': proto,
                })

        if negotiations:
            print(f"[+] RDP 协商信息 ({len(negotiations)} 条)")
            proto_map = {"0": "标准RDP加密", "1": "TLS", "2": "CredSSP(NLA)", "3": "CredSSP+TLS"}
            for n in negotiations:
                proto_name = proto_map.get(n['selected_protocol'], n['selected_protocol'])
                type_name = "请求" if n['type'] == "1" else "响应" if n['type'] == "2" else n['type']
                print(f"    {n['src_ip']} -> {n['dst_ip']} | 类型: {type_name} | 安全协议: {proto_name}")
            print()

        # TCP 会话统计
        conv_stdout = self._run_tshark(tshark_path, [
            "-r", pcap_file,
            "-Y", "tcp.port == 3389",
            "-T", "fields",
            "-e", "ip.src",
            "-e", "ip.dst",
            "-e", "tcp.srcport",
            "-e", "tcp.dstport",
            "-e", "tcp.stream",
            "-e", "frame.time_relative",
        ])

        streams = defaultdict(list)
        for line in conv_stdout.strip().splitlines():
            fields = line.split('\t')
            if len(fields) >= 6:
                streams[fields[4]].append({
                    'src_ip': fields[0],
                    'dst_ip': fields[1],
                    'src_port': fields[2],
                    'dst_port': fields[3],
                    'time': fields[5],
                })

        if streams:
            print(f"[+] RDP 会话统计 (共 {len(streams)} 个 TCP 流)")
            for sid, pkts in streams.items():
                first, last = pkts[0], pkts[-1]
                if int(first['dst_port']) == 3389:
                    client = f"{first['src_ip']}:{first['src_port']}"
                    server = f"{first['dst_ip']}:{first['dst_port']}"
                else:
                    client = f"{first['dst_ip']}:{first['dst_port']}"
                    server = f"{first['src_ip']}:{first['src_port']}"
                try:
                    duration = float(last['time']) - float(first['time'])
                    print(f"    Stream #{sid}: {client} -> {server} | {len(pkts)} 包 | {duration:.2f}s")
                except ValueError:
                    print(f"    Stream #{sid}: {client} -> {server} | {len(pkts)} 包")
            print()

        return {'cookies': cookies, 'usernames': usernames, 'streams': streams}

    def extract_rdp_ntlm(self, pcap_file, tshark_path):
        """提取 RDP 中 CredSSP(NLA) 使用的 NTLMSSP 认证凭证"""

        # NTLMSSP CHALLENGE
        challenge_stdout = self._run_tshark(tshark_path, [
            "-r", pcap_file,
            "-Y", "ntlmssp.messagetype == 0x00000002",
            "-T", "fields",
            "-e", "ntlmssp.ntlmserverchallenge",
        ])

        challenges = []
        for line in challenge_stdout.strip().splitlines():
            ch = line.strip().replace(":", "").replace(" ", "")
            if ch:
                challenges.append(ch)

        # NTLMSSP AUTH
        auth_stdout = self._run_tshark(tshark_path, [
            "-r", pcap_file,
            "-Y", "ntlmssp.messagetype == 0x00000003",
            "-T", "fields",
            "-e", "ntlmssp.auth.username",
            "-e", "ntlmssp.auth.domain",
            "-e", "ntlmssp.auth.ntresponse",
            "-e", "ntlmssp.auth.lmresponse",
        ])

        credentials = []
        auth_lines = [l for l in auth_stdout.strip().splitlines() if l.strip()]

        for idx, line in enumerate(auth_lines):
            fields = line.split('\t')
            if len(fields) < 3:
                continue

            username = fields[0]
            domain = fields[1]
            ntresponse = fields[2]
            lmresponse = fields[3] if len(fields) > 3 else ""

            if not username or not ntresponse:
                continue

            nt_clean = ntresponse.replace(":", "").replace(" ", "")
            lm_clean = lmresponse.replace(":", "").replace(" ", "")
            challenge_clean = challenges[idx] if idx < len(challenges) else ""

            if len(nt_clean) == 48:
                cred = {'version': 'NTLMv1', 'username': username, 'domain': domain,
                         'challenge': challenge_clean, 'ntresponse': nt_clean, 'lmresponse': lm_clean}
                credentials.append(cred)
                hashcat_line = f"{username}::{domain}:{lm_clean}:{nt_clean}:{challenge_clean}"
                print(f"[+] NTLMv1 凭证")
                print(f"    用户名: {username} | 域: {domain}")
                print(f"    hashcat mode 5500: {hashcat_line}")
                print()

            elif len(nt_clean) > 48:
                ntproofstr = nt_clean[:32]
                ntresponse_rest = nt_clean[32:]
                cred = {'version': 'NTLMv2', 'username': username, 'domain': domain,
                         'challenge': challenge_clean, 'ntproofstr': ntproofstr, 'ntresponse_rest': ntresponse_rest}
                credentials.append(cred)
                hashcat_line = f"{username}::{domain}:{challenge_clean}:{ntproofstr}:{ntresponse_rest}"
                print(f"[+] NTLMv2 凭证")
                print(f"    用户名: {username} | 域: {domain}")
                print(f"    hashcat mode 5600: {hashcat_line}")
                print()

        if not credentials:
            print("[*] 未发现 NTLMSSP 认证凭证")

        return credentials

    def extract_rdp_certificates(self, pcap_file, tshark_path):
        """提取 RDP TLS 握手中的服务器证书信息"""

        cert_stdout = self._run_tshark(tshark_path, [
            "-r", pcap_file,
            "-Y", "tls.handshake.certificate && tcp.port == 3389",
            "-T", "fields",
            "-e", "ip.src",
            "-e", "x509sat.utf8String",
            "-e", "x509sat.printableString",
            "-e", "x509ce.dNSName",
        ])

        certs = []
        for line in cert_stdout.strip().splitlines():
            fields = line.split('\t')
            if len(fields) >= 2:
                cert = {
                    'server_ip': fields[0],
                    'utf8': fields[1] if len(fields) > 1 else "",
                    'printable': fields[2] if len(fields) > 2 else "",
                    'dns_name': fields[3] if len(fields) > 3 else "",
                }
                certs.append(cert)

                all_names = ','.join(filter(None, [cert['utf8'], cert['printable'], cert['dns_name']]))
                print(f"[+] TLS 证书 (来自 {cert['server_ip']})")
                print(f"    证书名称: {all_names}")

        if not certs:
            print("[*] 未发现 TLS 证书信息")

        print()
        return certs

    def decrypt_rdp_with_key(self, pcap_file, tshark_path, key_file, server_ip=None):
        """使用 RSA 私钥解密 RDP TLS 流量"""

        if not os.path.isfile(key_file):
            print(f"[!] 私钥文件不存在: {key_file}")
            return ""

        with open(key_file, 'r', errors='ignore') as f:
            key_head = f.read(256)

        if "PRIVATE KEY" in key_head:
            print(f"[*] 检测到私钥文件: {key_file}")
        else:
            print(f"[*] 使用密钥文件: {key_file}")

        # 构造 tshark TLS 解密参数
        # 方式1: ssl.keys_list (旧版)
        ip = server_ip or "0.0.0.0"
        tls_key_arg = f"{ip},3389,rdp,{os.path.abspath(key_file)}"

        # 先尝试解密并导出 RDP 层数据
        stdout = self._run_tshark(tshark_path, [
            "-r", pcap_file,
            "-o", f"tls.keys_list:{tls_key_arg}",
            "-Y", "rdp",
            "-T", "fields",
            "-e", "frame.number",
            "-e", "rdp.rt_cookie",
            "-e", "rdp.clientRequestedProtocols",
        ])

        rdp_frames = [l for l in stdout.strip().splitlines() if l.strip()]

        if rdp_frames:
            print(f"[+] 解密后发现 {len(rdp_frames)} 个 RDP 数据帧")
            for frame in rdp_frames[:20]:
                print(f"    {frame}")
            if len(rdp_frames) > 20:
                print(f"    ... 共 {len(rdp_frames)} 帧")

            # 提示用户可以导出 PDU 用 pyrdp 回放
            print()
            print("[*] 提示: 可在 Wireshark 中加载私钥解密后，通过以下步骤回放 RDP 会话:")
            print("    1. Wireshark -> Edit -> Preferences -> Protocols -> TLS -> RSA keys list")
            print(f"       添加: IP={ip}, Port=3389, Protocol=rdp, Key File={key_file}")
            print("    2. File -> Export PDUs to File -> OSI Layer 7 -> 保存为新 pcap")
            print("    3. 使用 pyrdp-player 打开导出的 pcap 回放 RDP 会话")
        else:
            print("[*] 未能通过私钥解密 RDP 流量")
            print("    可能原因:")
            print("    - 私钥与 RDP 服务器证书不匹配")
            print("    - 使用了 CredSSP/NLA 认证 (前向保密), 私钥无法解密")
            print("    - 尝试使用 TLS keylog 文件 (SSLKEYLOGFILE) 解密")

        print()
        return rdp_frames

    def decrypt_rdp_with_keylog(self, pcap_file, tshark_path, keylog_file):
        """使用 TLS keylog 文件 (SSLKEYLOGFILE) 解密 RDP 流量"""

        if not os.path.isfile(keylog_file):
            print(f"[!] keylog 文件不存在: {keylog_file}")
            return ""

        print(f"[*] 使用 TLS keylog 文件: {keylog_file}")

        stdout = self._run_tshark(tshark_path, [
            "-r", pcap_file,
            "-o", f"tls.keylog_file:{os.path.abspath(keylog_file)}",
            "-Y", "rdp",
            "-T", "fields",
            "-e", "frame.number",
            "-e", "ip.src",
            "-e", "ip.dst",
            "-e", "rdp.rt_cookie",
        ])

        frames = [l for l in stdout.strip().splitlines() if l.strip()]
        if frames:
            print(f"[+] 使用 keylog 解密后发现 {len(frames)} 个 RDP 数据帧")
            for f in frames[:20]:
                print(f"    {f}")
            if len(frames) > 20:
                print(f"    ... 共 {len(frames)} 帧")
            print()
            print("[*] 提示: 可用 pyrdp-player 回放解密后的 RDP 会话")
            print("    1. Wireshark 加载 keylog -> File -> Export PDUs to File -> OSI Layer 7")
            print("    2. pyrdp-player <exported.pcap>")
        else:
            print("[*] 使用 keylog 未能解密出 RDP 数据")

        print()
        return frames

    def analyze_pcap(self, pcap_path: str, **kwargs) -> ProtocolAnalysisResult:
        """RDP 完整分析入口"""
        findings = []

        key_file = kwargs.get('key_file', self.key_file)
        keylog_file = kwargs.get('keylog_file', self.keylog_file)
        server_ip = kwargs.get('server_ip', self.server_ip)

        if not os.path.isfile(pcap_path):
            print(f"[!] 文件不存在: {pcap_path}")
            return ProtocolAnalysisResult(
                protocol=ProtocolType.RDP,
                packet_count=0,
                findings=[],
                summary="文件不存在"
            )

        from services.analysis_service import AnalysisService
        tshark_path = AnalysisService().find_tshark()
        if not tshark_path:
            return ProtocolAnalysisResult(
                protocol=ProtocolType.RDP,
                packet_count=0,
                findings=[AnalysisFinding(
                    finding_type=FindingType.INFO,
                    protocol=ProtocolType.RDP,
                    title="tshark未找到",
                    description="未找到tshark，请安装Wireshark或将tshark加入PATH",
                    confidence=1.0,
                    is_flag=False
                )],
                summary="tshark不可用"
            )

        print(f"[*] 正在分析 RDP 流量: {pcap_path}")
        print("=" * 60)

        # 1. 会话元数据
        print("[阶段1] RDP 会话元数据")
        print("-" * 60)
        session_info = self.extract_rdp_sessions(pcap_path, tshark_path)

        cookies = session_info.get('cookies', [])
        usernames = session_info.get('usernames', set())
        streams = session_info.get('streams', {})

        if usernames:
            findings.append(AnalysisFinding(
                finding_type=FindingType.CREDENTIAL,
                protocol=ProtocolType.RDP,
                title="RDP Cookie 用户名",
                description=f"从 RDP Cookie (mstshash) 中提取 {len(usernames)} 个用户名",
                data=', '.join(usernames),
                confidence=0.9,
                is_flag=False
            ))

        if cookies:
            findings.append(AnalysisFinding(
                finding_type=FindingType.INFO,
                protocol=ProtocolType.RDP,
                title="RDP Cookie",
                description=f"捕获 {len(cookies)} 条 RDP Cookie",
                data='\n'.join(c['cookie'] for c in cookies),
                confidence=0.8,
                is_flag=False
            ))

        # 2. NTLM 凭证
        print("[阶段2] NTLMSSP 认证凭证")
        print("-" * 60)
        credentials = self.extract_rdp_ntlm(pcap_path, tshark_path)
        print()

        if credentials:
            for cred in credentials:
                version = cred.get('version', '')
                username = cred.get('username', '')
                domain = cred.get('domain', '')
                if version == 'NTLMv1':
                    hashcat_line = f"{username}::{domain}:{cred.get('lmresponse','')}:{cred.get('ntresponse','')}:{cred.get('challenge','')}"
                    findings.append(AnalysisFinding(
                        finding_type=FindingType.CREDENTIAL,
                        protocol=ProtocolType.RDP,
                        title=f"NTLMv1 凭证 ({username})",
                        description=f"用户: {username} | 域: {domain} | hashcat -m 5500",
                        data=hashcat_line,
                        confidence=0.95,
                        is_flag=False
                    ))
                elif version == 'NTLMv2':
                    hashcat_line = f"{username}::{domain}:{cred.get('challenge','')}:{cred.get('ntproofstr','')}:{cred.get('ntresponse_rest','')}"
                    findings.append(AnalysisFinding(
                        finding_type=FindingType.CREDENTIAL,
                        protocol=ProtocolType.RDP,
                        title=f"NTLMv2 凭证 ({username})",
                        description=f"用户: {username} | 域: {domain} | hashcat -m 5600",
                        data=hashcat_line,
                        confidence=0.95,
                        is_flag=False
                    ))

        # 3. TLS 证书
        print("[阶段3] TLS 证书信息")
        print("-" * 60)
        certs = self.extract_rdp_certificates(pcap_path, tshark_path)

        if certs:
            cert_names = []
            for c in certs:
                names = ','.join(filter(None, [c.get('utf8', ''), c.get('printable', ''), c.get('dns_name', '')]))
                if names:
                    cert_names.append(names)
            findings.append(AnalysisFinding(
                finding_type=FindingType.INFO,
                protocol=ProtocolType.RDP,
                title="RDP TLS 证书",
                description=f"提取 {len(certs)} 个证书",
                data='; '.join(cert_names) if cert_names else None,
                confidence=0.9,
                is_flag=False
            ))

        # 4. 私钥解密
        decrypted = []
        if key_file:
            print("[阶段4] RSA 私钥解密")
            print("-" * 60)
            decrypted = self.decrypt_rdp_with_key(pcap_path, tshark_path, key_file, server_ip)
            if decrypted:
                findings.append(AnalysisFinding(
                    finding_type=FindingType.HIDDEN_DATA,
                    protocol=ProtocolType.RDP,
                    title="RSA私钥解密RDP",
                    description=f"使用私钥解密发现 {len(decrypted)} 个 RDP 数据帧",
                    data=f"{len(decrypted)} 个解密帧",
                    confidence=0.95,
                    is_flag=False
                ))

        # 5. Keylog 解密
        keylog_decrypted = []
        if keylog_file:
            print("[阶段5] TLS Keylog 解密")
            print("-" * 60)
            keylog_decrypted = self.decrypt_rdp_with_keylog(pcap_path, tshark_path, keylog_file)
            if keylog_decrypted:
                findings.append(AnalysisFinding(
                    finding_type=FindingType.HIDDEN_DATA,
                    protocol=ProtocolType.RDP,
                    title="Keylog解密RDP",
                    description=f"使用keylog解密发现 {len(keylog_decrypted)} 个 RDP 数据帧",
                    data=f"{len(keylog_decrypted)} 个解密帧",
                    confidence=0.95,
                    is_flag=False
                ))

        # 摘要
        print("=" * 60)
        stream_count = len(streams)
        user_count = len(usernames)
        cred_count = len(credentials)

        summary_parts = [f"RDP会话: {stream_count} 个", f"Cookie用户名: {user_count} 个",
                         f"NTLM凭证: {cred_count} 条", f"证书: {len(certs)} 个"]
        print(f'[摘要] {" | ".join(summary_parts)}')

        if decrypted:
            summary_parts.append(f"私钥解密帧: {len(decrypted)} 个")
            print(f"       私钥解密帧: {len(decrypted)} 个")
        if keylog_decrypted:
            summary_parts.append(f"Keylog解密帧: {len(keylog_decrypted)} 个")
            print(f"       Keylog解密帧: {len(keylog_decrypted)} 个")

        if not key_file and not keylog_file:
            has_ntlmv2 = any(c['version'] == 'NTLMv2' for c in credentials) if credentials else False
            if has_ntlmv2:
                print("       [*] 检测到 NTLMv2 凭证，可用 hashcat -m 5600 离线破解")
            if not decrypted and not keylog_decrypted:
                print("       [*] 提示: 如有私钥文件可用 -k 参数解密; 如有 keylog 文件可用 -l 参数解密")

        print("=" * 60)

        return ProtocolAnalysisResult(
            protocol=ProtocolType.RDP,
            packet_count=stream_count,
            findings=findings,
            summary="; ".join(summary_parts),
            metadata={
                'session_info': {
                    'cookies': cookies,
                    'usernames': list(usernames),
                    'streams': dict(streams),
                },
                'credentials': credentials,
                'certs': certs,
                'decrypted_frames': decrypted,
                'keylog_decrypted_frames': keylog_decrypted,
            }
        )



# ============================================================
# RedisAnalyzer
# ============================================================

class RedisAnalyzer(ProtocolAnalyzer):
    """Redis协议流量分析 (CTF向): RESP命令解析、凭证提取、写入数据、CONFIG攻击检测"""

    def __init__(self, output_dir: Optional[str] = None):
        self.output_dir = output_dir

    @property
    def protocol_type(self) -> ProtocolType:
        return ProtocolType.REDIS

    def analyze(self, packets: List, **kwargs) -> ProtocolAnalysisResult:
        """Redis分析需要通过tshark从pcap提取，直接包分析不可用"""
        raise NotImplementedError(
            "RedisAnalyzer需要pcap文件路径, 请使用 analyze_pcap() 方法"
        )

    @staticmethod
    def _run_tshark(tshark_path, args):
        """执行 tshark 命令并返回 stdout"""
        cmd = [tshark_path] + args
        try:
            process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, encoding='utf-8'
            )
            stdout, stderr = process.communicate()
            return stdout
        except FileNotFoundError:
            print(f"[!] 无法找到tshark: {tshark_path}")
            return ""

    @staticmethod
    def _parse_resp(data):
        """解析 RESP 协议数据，还原为可读的 Redis 命令列表

        RESP 格式:
          *N\\r\\n          -> 数组(N个元素)
          $len\\r\\n        -> 批量字符串(len字节)
          +msg\\r\\n        -> 简单字符串
          -err\\r\\n        -> 错误
          :num\\r\\n        -> 整数
        """
        commands = []
        lines = data.replace('\r\n', '\n').replace('\r', '\n').split('\n')
        i = 0

        while i < len(lines):
            line = lines[i]

            # 数组: *N -> 后面跟 N 个 bulk string
            if line.startswith('*'):
                try:
                    count = int(line[1:])
                except ValueError:
                    i += 1
                    continue
                parts = []
                i += 1
                for _ in range(count):
                    if i >= len(lines):
                        break
                    if lines[i].startswith('$'):
                        # $len 后面跟实际内容
                        i += 1
                        if i < len(lines):
                            parts.append(lines[i])
                            i += 1
                    else:
                        parts.append(lines[i])
                        i += 1
                if parts:
                    commands.append(parts)

            # 简单字符串回复: +OK
            elif line.startswith('+'):
                commands.append([line])
                i += 1

            # 错误回复: -ERR ...
            elif line.startswith('-'):
                commands.append([line])
                i += 1

            # 整数回复: :N
            elif line.startswith(':'):
                commands.append([line])
                i += 1

            # 单个 bulk string (不在数组内)
            elif line.startswith('$'):
                i += 1
                if i < len(lines):
                    commands.append([lines[i]])
                    i += 1

            else:
                # 非RESP格式的行，可能是原始命令 (inline command)
                stripped = line.strip()
                if stripped:
                    commands.append(stripped.split())
                i += 1

        return commands

    @staticmethod
    def _format_command(parts):
        """将解析出的命令部分格式化为可读字符串"""
        if not parts:
            return ""
        # 回复类型
        if len(parts) == 1 and isinstance(parts[0], str) and parts[0].startswith(('+', '-', ':')):
            return parts[0]
        return ' '.join(parts)

    def extract_redis_commands(self, pcap_file, tshark_path):
        """从 TCP 流中提取并解析所有 Redis 命令"""

        # 获取所有 Redis 相关的 TCP 流编号
        stream_stdout = self._run_tshark(tshark_path, [
            "-r", pcap_file,
            "-Y", "tcp.port == 6379",
            "-T", "fields",
            "-e", "tcp.stream",
        ])

        stream_ids = sorted(set(
            l.strip() for l in stream_stdout.strip().splitlines() if l.strip()
        ))

        if not stream_ids:
            print("[*] 未发现 Redis 流量 (端口 6379)")
            return [], []

        print(f"[+] 发现 {len(stream_ids)} 个 Redis TCP 流")

        all_commands = []  # (方向, 命令parts)
        all_raw = []

        for sid in stream_ids:
            # follow tcp stream 获取原始内容
            follow_stdout = self._run_tshark(tshark_path, [
                "-r", pcap_file,
                "-qz", f"follow,tcp,ascii,{sid}",
            ])

            all_raw.append((sid, follow_stdout))

            # 从 follow 输出中提取客户端和服务端的数据
            client_data = ""
            server_data = ""
            current_direction = None  # 'client' or 'server'

            for line in follow_stdout.splitlines():
                # tshark follow 输出中 node0 = 客户端, node1 = 服务端
                if "node 0" in line or "Node 0" in line:
                    current_direction = 'client'
                    continue
                elif "node 1" in line or "Node 1" in line:
                    current_direction = 'server'
                    continue
                elif line.startswith("===") or line.startswith("Follow"):
                    continue

                if current_direction == 'client':
                    client_data += line + "\n"
                elif current_direction == 'server':
                    server_data += line + "\n"

            # 如果 follow 解析不出方向，就整体解析
            if not client_data and not server_data:
                combined = follow_stdout
                parsed = self._parse_resp(combined)
                for parts in parsed:
                    all_commands.append(('???', parts))
            else:
                if client_data:
                    for parts in self._parse_resp(client_data):
                        all_commands.append(('C->S', parts))
                if server_data:
                    for parts in self._parse_resp(server_data):
                        all_commands.append(('S->C', parts))

        return all_commands, all_raw

    def analyze_redis_traffic(self, pcap_file, tshark_path):
        """分析 Redis 流量，提取凭证、命令、写入数据等"""

        # 更可靠的方式: 直接提取 tcp payload
        payload_stdout = self._run_tshark(tshark_path, [
            "-r", pcap_file,
            "-Y", "tcp.port == 6379 && tcp.payload",
            "-T", "fields",
            "-e", "ip.src",
            "-e", "ip.dst",
            "-e", "tcp.srcport",
            "-e", "tcp.dstport",
            "-e", "tcp.payload",
        ])

        credentials = []
        key_values = []     # SET/HSET 写入的数据
        get_keys = []       # GET 请求的 key
        config_cmds = []    # CONFIG 命令 (可能是攻击行为)
        eval_cmds = []      # EVAL Lua 脚本
        other_cmds = []     # 其他命令
        all_decoded = []    # 所有解码后的命令

        for line in payload_stdout.strip().splitlines():
            fields = line.split('\t')
            if len(fields) < 5:
                continue

            src_ip, dst_ip, src_port, dst_port, payload_hex = fields[:5]

            # 判断方向: 发往6379的是客户端请求
            is_client = (dst_port == "6379")
            direction = "C->S" if is_client else "S->C"

            # 解码 payload
            try:
                raw = bytes.fromhex(payload_hex.replace(":", "")).decode('utf-8', errors='replace')
            except ValueError:
                continue

            # 解析 RESP
            parsed = self._parse_resp(raw)

            for parts in parsed:
                if not parts:
                    continue

                cmd_str = self._format_command(parts)
                all_decoded.append((direction, cmd_str, src_ip, dst_ip))

                if not is_client:
                    continue

                # 只分析客户端发出的命令
                cmd_upper = parts[0].upper() if parts else ""

                # AUTH 命令 -> 凭证
                if cmd_upper == "AUTH":
                    if len(parts) == 2:
                        credentials.append({'password': parts[1]})
                    elif len(parts) >= 3:
                        credentials.append({'username': parts[1], 'password': parts[2]})

                # SET / SETNX / SETEX / MSET -> 键值对
                elif cmd_upper in ("SET", "SETNX", "SETEX", "MSET", "HSET", "HSETNX", "APPEND"):
                    if cmd_upper == "MSET":
                        # MSET k1 v1 k2 v2 ...
                        for j in range(1, len(parts) - 1, 2):
                            key_values.append({'cmd': cmd_upper, 'key': parts[j], 'value': parts[j+1]})
                    elif cmd_upper == "SETEX" and len(parts) >= 4:
                        # SETEX key ttl value
                        key_values.append({'cmd': cmd_upper, 'key': parts[1], 'value': parts[3]})
                    elif cmd_upper == "HSET" and len(parts) >= 4:
                        # HSET hash field value
                        key_values.append({'cmd': cmd_upper, 'key': f"{parts[1]}->{parts[2]}", 'value': parts[3]})
                    elif len(parts) >= 3:
                        key_values.append({'cmd': cmd_upper, 'key': parts[1], 'value': parts[2]})

                # GET / HGET / MGET
                elif cmd_upper in ("GET", "HGET", "MGET", "HGETALL", "KEYS"):
                    get_keys.append({'cmd': cmd_upper, 'args': parts[1:]})

                # CONFIG SET -> 可能是攻击 (写webshell, 写ssh key等)
                elif cmd_upper == "CONFIG":
                    config_cmds.append(parts)

                # EVAL -> Lua 脚本执行
                elif cmd_upper == "EVAL":
                    eval_cmds.append(parts)

                # 其他写入类命令
                elif cmd_upper in ("LPUSH", "RPUSH", "SADD", "ZADD", "PUBLISH"):
                    if len(parts) >= 3:
                        key_values.append({'cmd': cmd_upper, 'key': parts[1], 'value': ' '.join(parts[2:])})

        return {
            'credentials': credentials,
            'key_values': key_values,
            'get_keys': get_keys,
            'config_cmds': config_cmds,
            'eval_cmds': eval_cmds,
            'other_cmds': other_cmds,
            'all_decoded': all_decoded,
        }

    def analyze_pcap(self, pcap_path: str, **kwargs) -> ProtocolAnalysisResult:
        """Redis 完整分析入口"""
        findings = []

        if not os.path.isfile(pcap_path):
            print(f"[!] 文件不存在: {pcap_path}")
            return ProtocolAnalysisResult(
                protocol=ProtocolType.REDIS,
                packet_count=0,
                findings=[],
                summary="文件不存在"
            )

        from services.analysis_service import AnalysisService
        tshark_path = AnalysisService().find_tshark()
        if not tshark_path:
            return ProtocolAnalysisResult(
                protocol=ProtocolType.REDIS,
                packet_count=0,
                findings=[AnalysisFinding(
                    finding_type=FindingType.INFO,
                    protocol=ProtocolType.REDIS,
                    title="tshark未找到",
                    description="未找到tshark，请安装Wireshark或将tshark加入PATH",
                    confidence=1.0,
                    is_flag=False
                )],
                summary="tshark不可用"
            )

        print(f"[*] 正在分析 Redis 流量: {pcap_path}")
        print("=" * 60)

        # 1. 提取并解析命令
        print("[阶段1] Redis 命令提取")
        print("-" * 60)
        result = self.analyze_redis_traffic(pcap_path, tshark_path)

        all_decoded = result['all_decoded']
        credentials = result['credentials']
        key_values = result['key_values']
        get_keys = result['get_keys']
        config_cmds = result['config_cmds']
        eval_cmds = result['eval_cmds']

        if not all_decoded:
            print("[*] 未发现 Redis 流量 (端口 6379)")
            # 尝试用 follow tcp stream 兜底
            print("[*] 尝试通过 TCP 流提取...")
            commands, raw = self.extract_redis_commands(pcap_path, tshark_path)
            if commands:
                print(f"[+] 从 TCP 流中解析到 {len(commands)} 条命令:")
                for direction, parts in commands:
                    print(f"    [{direction}] {self._format_command(parts)}")
                findings.append(AnalysisFinding(
                    finding_type=FindingType.INFO,
                    protocol=ProtocolType.REDIS,
                    title="Redis TCP流命令",
                    description=f"从 TCP 流中解析到 {len(commands)} 条命令",
                    data='\n'.join(f"[{d}] {self._format_command(p)}" for d, p in commands[:50]),
                    confidence=0.7,
                    is_flag=False
                ))
            print("=" * 60)
            return ProtocolAnalysisResult(
                protocol=ProtocolType.REDIS,
                packet_count=len(commands) if commands else 0,
                findings=findings,
                summary=f"TCP流命令: {len(commands)} 条" if commands else "未发现Redis流量"
            )

        # 只打印客户端命令
        client_cmds = [(d, c, s, ds) for d, c, s, ds in all_decoded if d == "C->S"]
        print(f"[+] 共解码 {len(all_decoded)} 条 Redis 交互 (其中客户端命令 {len(client_cmds)} 条)")
        for direction, cmd_str, src, dst in client_cmds:
            print(f"    [C->S] {cmd_str}")
        print()

        findings.append(AnalysisFinding(
            finding_type=FindingType.INFO,
            protocol=ProtocolType.REDIS,
            title="Redis 命令交互",
            description=f"共解码 {len(all_decoded)} 条交互, 客户端命令 {len(client_cmds)} 条",
            data='\n'.join(f"[C->S] {c}" for _, c, _, _ in client_cmds[:50]),
            confidence=0.9,
            is_flag=False
        ))

        # 2. 凭证
        if credentials:
            print("[阶段2] Redis 认证凭证")
            print("-" * 60)
            for cred in credentials:
                if 'username' in cred:
                    print(f"[+] AUTH 凭证: {cred['username']} / {cred['password']}")
                else:
                    print(f"[+] AUTH 密码: {cred['password']}")
            print()

            cred_strs = []
            for cred in credentials:
                if 'username' in cred:
                    cred_strs.append(f"{cred['username']}:{cred['password']}")
                else:
                    cred_strs.append(cred['password'])
            findings.append(AnalysisFinding(
                finding_type=FindingType.CREDENTIAL,
                protocol=ProtocolType.REDIS,
                title="Redis AUTH 凭证",
                description=f"提取 {len(credentials)} 条 Redis 认证凭证",
                data='\n'.join(cred_strs),
                confidence=0.95,
                is_flag=False
            ))

        # 3. 写入的数据
        if key_values:
            print("[阶段3] Redis 写入数据")
            print("-" * 60)
            for kv in key_values:
                val_preview = kv['value']
                if len(val_preview) > 200:
                    val_preview = val_preview[:200] + f"... ({len(kv['value'])} 字符)"
                print(f"[+] {kv['cmd']} {kv['key']}")
                print(f"    值: {val_preview}")
            print()

            # 检查写入值中是否包含 flag
            for kv in key_values:
                if self.detect_flag_pattern(kv['value']):
                    findings.append(AnalysisFinding(
                        finding_type=FindingType.HIDDEN_DATA,
                        protocol=ProtocolType.REDIS,
                        title=f"Redis写入数据中发现FLAG ({kv['key']})",
                        description=f"{kv['cmd']} {kv['key']}",
                        data=kv['value'],
                        confidence=0.95,
                        is_flag=True
                    ))

            findings.append(AnalysisFinding(
                finding_type=FindingType.INFO,
                protocol=ProtocolType.REDIS,
                title="Redis 写入数据",
                description=f"捕获 {len(key_values)} 条写入操作",
                data='\n'.join(f"{kv['cmd']} {kv['key']} = {kv['value'][:100]}" for kv in key_values[:20]),
                confidence=0.8,
                is_flag=False
            ))

        # 4. 读取的 key
        if get_keys:
            print("[阶段4] Redis 读取请求")
            print("-" * 60)
            for g in get_keys:
                print(f"    {g['cmd']} {' '.join(g['args'])}")
            print()

        # 5. CONFIG 命令 (攻击检测)
        if config_cmds:
            print("[阶段5] CONFIG 命令 (可能为攻击行为)")
            print("-" * 60)
            for parts in config_cmds:
                cmd_line = ' '.join(parts)
                print(f"[!] {cmd_line}")

                # 检测常见攻击模式
                cmd_line_lower = cmd_line.lower()
                if "dir" in cmd_line_lower and ("set" in parts[1].lower() if len(parts) > 1 else False):
                    print("    [!] 检测到修改工作目录 — 可能为写文件攻击")
                if "dbfilename" in cmd_line_lower:
                    print("    [!] 检测到修改数据库文件名 — 可能为写 webshell / SSH key / 计划任务")
            print()

            findings.append(AnalysisFinding(
                finding_type=FindingType.ANOMALY,
                protocol=ProtocolType.REDIS,
                title="Redis CONFIG 命令 (疑似攻击)",
                description=f"检测到 {len(config_cmds)} 条 CONFIG 命令，可能为 Redis 未授权写入攻击",
                data='\n'.join(' '.join(p) for p in config_cmds),
                confidence=0.9,
                is_flag=False
            ))

        # 6. EVAL Lua 脚本
        if eval_cmds:
            print("[阶段6] Lua 脚本执行")
            print("-" * 60)
            for parts in eval_cmds:
                script = parts[1] if len(parts) > 1 else "(空)"
                print(f"[!] EVAL 脚本:")
                print(f"    {script}")
            print()

            findings.append(AnalysisFinding(
                finding_type=FindingType.ANOMALY,
                protocol=ProtocolType.REDIS,
                title="Redis EVAL Lua脚本",
                description=f"检测到 {len(eval_cmds)} 条 EVAL 命令",
                data='\n'.join(p[1] if len(p) > 1 else '(空)' for p in eval_cmds),
                confidence=0.8,
                is_flag=False
            ))

        # 7. 摘要
        print("=" * 60)
        summary_parts = [f"命令: {len(all_decoded)} 条", f"凭证: {len(credentials)} 条",
                         f"写入: {len(key_values)} 条"]
        print(f'[摘要] {" | ".join(summary_parts)}')
        if config_cmds:
            summary_parts.append(f"CONFIG命令: {len(config_cmds)} 条")
            print(f"       [!] 检测到 {len(config_cmds)} 条 CONFIG 命令，请关注是否存在 Redis 未授权写入攻击")
        print("=" * 60)

        return ProtocolAnalysisResult(
            protocol=ProtocolType.REDIS,
            packet_count=len(all_decoded),
            findings=findings,
            summary="; ".join(summary_parts),
            metadata={
                'credentials': credentials,
                'key_values': key_values,
                'get_keys': get_keys,
                'config_cmds': [' '.join(p) for p in config_cmds],
                'eval_cmds': [' '.join(p) for p in eval_cmds],
                'all_decoded_count': len(all_decoded),
                'client_cmd_count': len(client_cmds),
            }
        )



# ============================================================
# SMBAnalyzer
# ============================================================

class SMBAnalyzer(ProtocolAnalyzer):
    """SMB协议分析 (CTF向): NTLMSSP凭证提取、SMB/SMB2文件导出"""

    def __init__(self, output_dir: Optional[str] = None):
        self.output_dir = output_dir

    @property
    def protocol_type(self) -> ProtocolType:
        return ProtocolType.SMB

    def analyze(self, packets: List, **kwargs) -> ProtocolAnalysisResult:
        """SMB分析需要通过tshark从pcap提取，直接包分析不可用"""
        raise NotImplementedError(
            "SMBAnalyzer需要pcap文件路径, 请使用 analyze_pcap() 方法"
        )

    @staticmethod
    def _run_tshark(tshark_path, args):
        """执行 tshark 命令并返回 stdout"""
        cmd = [tshark_path] + args
        try:
            process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, encoding='utf-8'
            )
            stdout, stderr = process.communicate()
            return stdout
        except FileNotFoundError:
            print(f"[!] 无法找到tshark: {tshark_path}")
            return ""

    def extract_smb_credentials(self, pcap_file, tshark_path):
        """提取 NTLMSSP 凭证，区分 NTLMv1 和 NTLMv2

        策略：
        1. 先从 NTLMSSP_CHALLENGE 包中提取 Server Challenge
        2. 再从 NTLMSSP_AUTH 包中提取用户名、域、NT Response 等
        3. 将 Challenge 与 Auth 关联（按出现顺序配对）
        """

        # --- 步骤1: 提取所有 NTLMSSP_CHALLENGE 中的 Server Challenge ---
        challenge_stdout = self._run_tshark(tshark_path, [
            "-r", pcap_file,
            "-Y", "ntlmssp.messagetype == 0x00000002",
            "-T", "fields",
            "-e", "ntlmssp.ntlmserverchallenge",
        ])

        challenges = []
        for line in challenge_stdout.strip().splitlines():
            ch = line.strip().replace(":", "").replace(" ", "")
            if ch:
                challenges.append(ch)

        # --- 步骤2: 提取所有 NTLMSSP_AUTH 包的凭证字段 ---
        auth_stdout = self._run_tshark(tshark_path, [
            "-r", pcap_file,
            "-Y", "ntlmssp.messagetype == 0x00000003",
            "-T", "fields",
            "-e", "ntlmssp.auth.username",
            "-e", "ntlmssp.auth.domain",
            "-e", "ntlmssp.auth.ntresponse",
            "-e", "ntlmssp.auth.lmresponse",
            "-e", "ntlmssp.auth.sesskey",
        ])

        credentials = []
        auth_lines = [l for l in auth_stdout.strip().splitlines() if l.strip()]

        for idx, line in enumerate(auth_lines):
            fields = line.split('\t')
            if len(fields) < 4:
                continue

            username = fields[0]
            domain = fields[1]
            ntresponse = fields[2]
            lmresponse = fields[3] if len(fields) > 3 else ""
            session_key = fields[4] if len(fields) > 4 else ""

            if not username or not ntresponse:
                continue

            # 清理 hex 字符串
            nt_clean = ntresponse.replace(":", "").replace(" ", "")
            lm_clean = lmresponse.replace(":", "").replace(" ", "")
            sk_clean = session_key.replace(":", "").replace(" ", "")

            # 按顺序配对 challenge（每个 AUTH 对应前面最近的 CHALLENGE）
            challenge_clean = challenges[idx] if idx < len(challenges) else ""

            # NTLMv1: ntresponse == 24字节 == 48 hex字符
            if len(nt_clean) == 48:
                cred = {
                    'version': 'NTLMv1',
                    'username': username,
                    'domain': domain,
                    'lmresponse': lm_clean,
                    'ntresponse': nt_clean,
                    'challenge': challenge_clean,
                }
                credentials.append(cred)

                print(f"[+] NTLMv1 凭证")
                print(f"    用户名 : {username}")
                print(f"    域     : {domain}")
                print(f"    NT Hash: {nt_clean}")
                print(f"    LM Hash: {lm_clean}")
                print(f"    Challenge: {challenge_clean}")
                print(f"    [*] hashcat mode 5500 可破解")
                hashcat_line = f"{username}::{domain}:{lm_clean}:{nt_clean}:{challenge_clean}"
                print(f"    hashcat 格式: {hashcat_line}")
                print()

            # NTLMv2: ntresponse > 24字节
            elif len(nt_clean) > 48:
                ntproofstr = nt_clean[:32]
                ntresponse_rest = nt_clean[32:]

                cred = {
                    'version': 'NTLMv2',
                    'username': username,
                    'domain': domain,
                    'challenge': challenge_clean,
                    'ntproofstr': ntproofstr,
                    'ntresponse_rest': ntresponse_rest,
                    'session_key': sk_clean,
                }
                credentials.append(cred)

                hashcat_line = f"{username}::{domain}:{challenge_clean}:{ntproofstr}:{ntresponse_rest}"
                print(f"[+] NTLMv2 凭证 (加密认证，无法直接解密)")
                print(f"    用户名 : {username}")
                print(f"    域     : {domain}")
                print(f"    Challenge    : {challenge_clean}")
                print(f"    NTProofStr   : {ntproofstr}")
                if sk_clean:
                    print(f"    Session Key  : {sk_clean}")
                print(f"    [*] 使用 hashcat mode 5600 离线破解:")
                print(f"    {hashcat_line}")
                print()

        if not credentials:
            print("[*] 未发现 NTLMSSP 认证凭证")

        return credentials

    def extract_smb_files(self, pcap_file, tshark_path, output_dir):
        """用 tshark --export-objects 提取 SMB/SMB2 传输的文件"""
        os.makedirs(output_dir, exist_ok=True)
        total_files = []

        for proto in ("smb", "smb2"):
            proto_dir = os.path.join(output_dir, proto)
            os.makedirs(proto_dir, exist_ok=True)

            cmd = [tshark_path, "-r", pcap_file, "--export-objects", f"{proto},{proto_dir}"]
            try:
                process = subprocess.Popen(
                    cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    text=True, encoding='utf-8'
                )
                _, stderr = process.communicate()
            except FileNotFoundError:
                print(f"[!] 无法找到tshark: {tshark_path}")
                continue

            # 列出导出的文件
            exported = [f for f in os.listdir(proto_dir) if os.path.isfile(os.path.join(proto_dir, f))]
            if exported:
                print(f"[+] {proto.upper()} 导出 {len(exported)} 个文件 -> {proto_dir}")
                for fname in exported:
                    fpath = os.path.join(proto_dir, fname)
                    fsize = os.path.getsize(fpath)
                    print(f"    - {fname} ({fsize} bytes)")
                    total_files.append(fpath)
            else:
                # 空目录清理
                os.rmdir(proto_dir)

        if not total_files:
            print("[*] 未发现 SMB 传输文件")

        return total_files

    def analyze_pcap(self, pcap_path: str, **kwargs) -> ProtocolAnalysisResult:
        """SMB 完整分析入口"""
        findings = []
        extracted_files_list = []

        output_dir = kwargs.get('output_dir', self.output_dir)

        if not os.path.isfile(pcap_path):
            print(f"[!] 文件不存在: {pcap_path}")
            return ProtocolAnalysisResult(
                protocol=ProtocolType.SMB,
                packet_count=0,
                findings=[],
                summary="文件不存在"
            )

        from services.analysis_service import AnalysisService
        tshark_path = AnalysisService().find_tshark()
        if not tshark_path:
            return ProtocolAnalysisResult(
                protocol=ProtocolType.SMB,
                packet_count=0,
                findings=[AnalysisFinding(
                    finding_type=FindingType.INFO,
                    protocol=ProtocolType.SMB,
                    title="tshark未找到",
                    description="未找到tshark，请安装Wireshark或将tshark加入PATH",
                    confidence=1.0,
                    is_flag=False
                )],
                summary="tshark不可用"
            )

        if not output_dir:
            pcap_filename = os.path.splitext(os.path.basename(pcap_path))[0]
            PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent
            output_dir = str(PROJECT_ROOT / 'output' / 'smb' / pcap_filename)

        print(f"[*] 正在分析 SMB 流量: {pcap_path}")
        print("=" * 60)

        # 1. 凭证提取
        print("[阶段1] NTLMSSP 凭证提取")
        print("-" * 60)
        credentials = self.extract_smb_credentials(pcap_path, tshark_path)

        for cred in credentials:
            version = cred.get('version', '')
            username = cred.get('username', '')
            domain = cred.get('domain', '')
            if version == 'NTLMv1':
                hashcat_line = f"{username}::{domain}:{cred.get('lmresponse','')}:{cred.get('ntresponse','')}:{cred.get('challenge','')}"
                findings.append(AnalysisFinding(
                    finding_type=FindingType.CREDENTIAL,
                    protocol=ProtocolType.SMB,
                    title=f"NTLMv1 凭证 ({username})",
                    description=f"用户: {username} | 域: {domain} | hashcat -m 5500",
                    data=hashcat_line,
                    confidence=0.95,
                    is_flag=False
                ))
            elif version == 'NTLMv2':
                hashcat_line = f"{username}::{domain}:{cred.get('challenge','')}:{cred.get('ntproofstr','')}:{cred.get('ntresponse_rest','')}"
                findings.append(AnalysisFinding(
                    finding_type=FindingType.CREDENTIAL,
                    protocol=ProtocolType.SMB,
                    title=f"NTLMv2 凭证 ({username})",
                    description=f"用户: {username} | 域: {domain} | hashcat -m 5600",
                    data=hashcat_line,
                    confidence=0.95,
                    is_flag=False
                ))

        print()

        # 2. 文件提取
        print("[阶段2] SMB 文件导出")
        print("-" * 60)
        files = self.extract_smb_files(pcap_path, tshark_path, output_dir)
        extracted_files_list.extend(files)

        if files:
            findings.append(AnalysisFinding(
                finding_type=FindingType.FILE_EXTRACTION,
                protocol=ProtocolType.SMB,
                title="SMB 文件导出",
                description=f"从 SMB/SMB2 流量中导出 {len(files)} 个文件",
                data='\n'.join(os.path.basename(f) for f in files),
                confidence=0.9,
                is_flag=False
            ))

        # 3. 摘要
        print()
        print("=" * 60)
        summary_parts = [f"凭证: {len(credentials)} 条", f"文件: {len(files)} 个"]
        print(f'[摘要] {" | ".join(summary_parts)}')
        if files:
            summary_parts.append(f"保存至: {output_dir}")
            print(f"       文件保存至: {output_dir}")
        if not files and any(c['version'] == 'NTLMv2' for c in credentials):
            print("[*] 提示: 检测到 NTLMv2 加密会话，文件传输已加密，无法直接导出")
            print("    请先使用 hashcat -m 5600 破解凭证密码，再用密码解密流量后重新导出")
        print("=" * 60)

        return ProtocolAnalysisResult(
            protocol=ProtocolType.SMB,
            packet_count=len(credentials) + len(files),
            findings=findings,
            summary="; ".join(summary_parts),
            extracted_files=extracted_files_list,
            output_dir=output_dir,
            metadata={
                'credentials': credentials,
                'files': [os.path.basename(f) for f in files],
            }
        )



# ============================================================
# SSHAnalyzer
# ============================================================

class SSHAnalyzer(ProtocolAnalyzer):
    """SSH协议流量分析 (CTF向): 会话元数据、算法协商、私钥解密、暴力破解检测"""

    def __init__(self, key_file: Optional[str] = None, output_dir: Optional[str] = None):
        self.key_file = key_file
        self.output_dir = output_dir

    @property
    def protocol_type(self) -> ProtocolType:
        return ProtocolType.SSH

    def analyze(self, packets: List, **kwargs) -> ProtocolAnalysisResult:
        """SSH分析需要通过tshark从pcap提取，直接包分析不可用"""
        raise NotImplementedError(
            "SSHAnalyzer需要pcap文件路径, 请使用 analyze_pcap() 方法"
        )

    @staticmethod
    def _run_tshark(tshark_path, args):
        """执行 tshark 命令并返回 stdout"""
        cmd = [tshark_path] + args
        try:
            process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, encoding='utf-8'
            )
            stdout, stderr = process.communicate()
            return stdout
        except FileNotFoundError:
            print(f"[!] 无法找到tshark: {tshark_path}")
            return ""

    def extract_ssh_sessions(self, pcap_file, tshark_path):
        """提取 SSH 会话元数据: banner、IP、端口、算法协商"""

        sessions = []

        # --- 提取 SSH banner (版本号) ---
        banner_stdout = self._run_tshark(tshark_path, [
            "-r", pcap_file,
            "-Y", "ssh.protocol",
            "-T", "fields",
            "-e", "ip.src",
            "-e", "ip.dst",
            "-e", "tcp.srcport",
            "-e", "tcp.dstport",
            "-e", "ssh.protocol",
        ])

        banners = []
        for line in banner_stdout.strip().splitlines():
            fields = line.split('\t')
            if len(fields) >= 5:
                banners.append({
                    'src_ip': fields[0],
                    'dst_ip': fields[1],
                    'src_port': fields[2],
                    'dst_port': fields[3],
                    'banner': fields[4],
                })

        if banners:
            print(f"[+] SSH Banner 信息 ({len(banners)} 条)")
            for b in banners:
                print(f"    {b['src_ip']}:{b['src_port']} -> {b['dst_ip']}:{b['dst_port']}")
                print(f"      版本: {b['banner']}")
            print()

        # --- 提取密钥交换算法协商 ---
        kex_stdout = self._run_tshark(tshark_path, [
            "-r", pcap_file,
            "-Y", "ssh.kex.algorithms",
            "-T", "fields",
            "-e", "ip.src",
            "-e", "ssh.kex.algorithms",
            "-e", "ssh.encryption_algorithms_client_to_server",
            "-e", "ssh.mac_algorithms_client_to_server",
            "-e", "ssh.hostkey_type",
        ])

        kex_info = []
        for line in kex_stdout.strip().splitlines():
            fields = line.split('\t')
            if len(fields) >= 2:
                info = {
                    'src_ip': fields[0],
                    'kex_algorithms': fields[1] if len(fields) > 1 else "",
                    'encryption': fields[2] if len(fields) > 2 else "",
                    'mac': fields[3] if len(fields) > 3 else "",
                    'hostkey_type': fields[4] if len(fields) > 4 else "",
                }
                kex_info.append(info)

        if kex_info:
            print(f"[+] 密钥交换算法协商 ({len(kex_info)} 条)")
            for k in kex_info:
                print(f"    来源: {k['src_ip']}")
                if k['kex_algorithms']:
                    print(f"      KEX算法    : {k['kex_algorithms']}")
                if k['encryption']:
                    print(f"      加密算法   : {k['encryption']}")
                if k['mac']:
                    print(f"      MAC算法    : {k['mac']}")
                if k['hostkey_type']:
                    print(f"      主机密钥类型: {k['hostkey_type']}")
            print()

            # 检测弱算法
            weak_kex = ["diffie-hellman-group1-sha1", "diffie-hellman-group-exchange-sha1"]
            weak_enc = ["arcfour", "arcfour128", "arcfour256", "aes128-cbc", "3des-cbc", "blowfish-cbc"]
            weak_mac = ["hmac-md5", "hmac-sha1-96", "hmac-md5-96"]

            for k in kex_info:
                all_algos = f"{k['kex_algorithms']},{k['encryption']},{k['mac']}"
                found_weak = []
                for w in weak_kex + weak_enc + weak_mac:
                    if w in all_algos:
                        found_weak.append(w)
                if found_weak:
                    print(f"    [!] 检测到弱算法: {', '.join(found_weak)}")
                    print()

        # --- 统计 SSH 会话 (TCP conversations on port 22) ---
        conv_stdout = self._run_tshark(tshark_path, [
            "-r", pcap_file,
            "-Y", "ssh",
            "-T", "fields",
            "-e", "ip.src",
            "-e", "ip.dst",
            "-e", "tcp.srcport",
            "-e", "tcp.dstport",
            "-e", "tcp.stream",
            "-e", "frame.time_relative",
        ])

        streams = defaultdict(list)
        for line in conv_stdout.strip().splitlines():
            fields = line.split('\t')
            if len(fields) >= 6:
                stream_id = fields[4]
                streams[stream_id].append({
                    'src_ip': fields[0],
                    'dst_ip': fields[1],
                    'src_port': fields[2],
                    'dst_port': fields[3],
                    'time': fields[5],
                })

        if streams:
            print(f"[+] SSH 会话统计 (共 {len(streams)} 个 TCP 流)")
            for sid, pkts in streams.items():
                first = pkts[0]
                last = pkts[-1]
                # 判断客户端 (源端口较大的一方)
                if int(first['src_port']) > int(first['dst_port']):
                    client = f"{first['src_ip']}:{first['src_port']}"
                    server = f"{first['dst_ip']}:{first['dst_port']}"
                else:
                    client = f"{first['dst_ip']}:{first['dst_port']}"
                    server = f"{first['src_ip']}:{first['src_port']}"
                try:
                    duration = float(last['time']) - float(first['time'])
                    print(f"    Stream #{sid}: {client} -> {server} | {len(pkts)} 包 | {duration:.2f}s")
                except ValueError:
                    print(f"    Stream #{sid}: {client} -> {server} | {len(pkts)} 包")
            print()

        return {'banners': banners, 'kex_info': kex_info, 'streams': streams}

    def decrypt_ssh_with_key(self, pcap_file, tshark_path, key_file):
        """使用 RSA 私钥尝试解密 SSH 会话"""

        if not os.path.isfile(key_file):
            print(f"[!] 私钥文件不存在: {key_file}")
            return ""

        # 读取私钥判断类型
        with open(key_file, 'r', errors='ignore') as f:
            key_head = f.read(256)

        if "RSA PRIVATE KEY" in key_head:
            print(f"[*] 检测到 RSA 私钥: {key_file}")
        elif "OPENSSH PRIVATE KEY" in key_head:
            print(f"[*] 检测到 OpenSSH 格式私钥: {key_file}")
            print("[!] 注意: Wireshark/tshark 仅支持传统 PEM 格式 RSA 私钥的解密")
            print("    如果解密失败，尝试转换: ssh-keygen -p -m PEM -f <key_file>")
        else:
            print(f"[*] 使用密钥文件: {key_file}")

        # 尝试用 tshark 配合私钥解密
        stdout = self._run_tshark(tshark_path, [
            "-r", pcap_file,
            "-o", f"ssh.keylog_file:{key_file}",
            "-Y", "ssh",
            "-T", "fields",
            "-e", "ssh.payload",
        ])

        payloads = [l.strip() for l in stdout.strip().splitlines() if l.strip()]

        if payloads:
            print(f"[+] 成功解密 {len(payloads)} 个 SSH 数据包")
            for i, p in enumerate(payloads[:20]):  # 最多显示前20条
                try:
                    text = bytes.fromhex(p.replace(":", "")).decode('utf-8', errors='replace')
                    print(f"    [{i}] {text}")
                except ValueError:
                    print(f"    [{i}] (hex) {p[:80]}...")
            if len(payloads) > 20:
                print(f"    ... 共 {len(payloads)} 条，仅显示前 20 条")
            print()
            return payloads
        else:
            print("[*] 未能通过私钥解密 SSH 流量")
            print("    可能原因:")
            print("    - 私钥与会话不匹配")
            print("    - 使用了 Diffie-Hellman 密钥交换 (前向保密)，私钥无法解密")
            print("    - 私钥格式不受 tshark 支持")
            print("    建议: 如果有 SSH keylog 文件，可配合 Wireshark 手动解密")
            print()
            return []

    def detect_bruteforce(self, pcap_file, tshark_path, threshold=10):
        """检测 SSH 暴力破解行为: 短时间内大量连接"""

        # 提取所有 SSH TCP SYN 包 (新连接)
        syn_stdout = self._run_tshark(tshark_path, [
            "-r", pcap_file,
            "-Y", "tcp.dstport == 22 && tcp.flags.syn == 1 && tcp.flags.ack == 0",
            "-T", "fields",
            "-e", "ip.src",
            "-e", "ip.dst",
            "-e", "frame.time_epoch",
        ])

        connections = []
        for line in syn_stdout.strip().splitlines():
            fields = line.split('\t')
            if len(fields) >= 3:
                connections.append({
                    'src_ip': fields[0],
                    'dst_ip': fields[1],
                    'time': float(fields[2]) if fields[2] else 0,
                })

        if not connections:
            print("[*] 未发现 SSH 连接请求")
            return {}

        # 按源 IP 统计连接数
        src_counter = Counter(c['src_ip'] for c in connections)

        print(f"[+] SSH 连接统计 (共 {len(connections)} 次连接请求)")
        for ip, count in src_counter.most_common():
            print(f"    {ip}: {count} 次连接")

        # 暴力破解检测
        bruteforce_ips = {ip: count for ip, count in src_counter.items() if count >= threshold}

        if bruteforce_ips:
            print()
            print(f"[!] 疑似暴力破解 (阈值: {threshold} 次连接)")
            for ip, count in sorted(bruteforce_ips.items(), key=lambda x: -x[1]):
                # 计算该 IP 的连接时间跨度
                times = [c['time'] for c in connections if c['src_ip'] == ip]
                duration = max(times) - min(times) if len(times) > 1 else 0
                rate = count / duration if duration > 0 else count

                target_ips = set(c['dst_ip'] for c in connections if c['src_ip'] == ip)
                print(f"    来源: {ip}")
                print(f"      连接次数: {count}")
                print(f"      时间跨度: {duration:.1f}s")
                print(f"      频率: {rate:.1f} 次/秒")
                print(f"      目标: {', '.join(target_ips)}")

            # 检测是否有成功连接 (有后续数据传输的流)
            print()
            print("[*] 检测是否有成功登录的会话...")

            hasdata_stdout = self._run_tshark(tshark_path, [
                "-r", pcap_file,
                "-Y", "ssh && tcp.len > 0",
                "-T", "fields",
                "-e", "tcp.stream",
                "-e", "ip.src",
                "-e", "ip.dst",
            ])

            stream_packets = defaultdict(int)
            stream_ips = {}
            for line in hasdata_stdout.strip().splitlines():
                fields = line.split('\t')
                if len(fields) >= 3:
                    sid = fields[0]
                    stream_packets[sid] += 1
                    if sid not in stream_ips:
                        stream_ips[sid] = (fields[1], fields[2])

            # 数据包较多的流可能是成功登录的会话
            successful = [(sid, cnt) for sid, cnt in stream_packets.items() if cnt > 20]
            if successful:
                print(f"[+] 发现 {len(successful)} 个疑似成功登录的会话 (数据包 > 20)")
                for sid, cnt in sorted(successful, key=lambda x: -x[1]):
                    ips = stream_ips.get(sid, ("?", "?"))
                    print(f"    Stream #{sid}: {ips[0]} <-> {ips[1]} | {cnt} 个数据包")
            else:
                print("[*] 未发现明显成功登录的会话 (所有连接可能均被拒绝)")
        else:
            print(f"\n[*] 未检测到暴力破解行为 (所有来源均低于 {threshold} 次连接)")

        print()
        return {'connections': connections, 'bruteforce_ips': bruteforce_ips}

    def analyze_pcap(self, pcap_path: str, **kwargs) -> ProtocolAnalysisResult:
        """SSH 完整分析入口"""
        findings = []

        key_file = kwargs.get('key_file', self.key_file)

        if not os.path.isfile(pcap_path):
            print(f"[!] 文件不存在: {pcap_path}")
            return ProtocolAnalysisResult(
                protocol=ProtocolType.SSH,
                packet_count=0,
                findings=[],
                summary="文件不存在"
            )

        from services.analysis_service import AnalysisService
        tshark_path = AnalysisService().find_tshark()
        if not tshark_path:
            return ProtocolAnalysisResult(
                protocol=ProtocolType.SSH,
                packet_count=0,
                findings=[AnalysisFinding(
                    finding_type=FindingType.INFO,
                    protocol=ProtocolType.SSH,
                    title="tshark未找到",
                    description="未找到tshark，请安装Wireshark或将tshark加入PATH",
                    confidence=1.0,
                    is_flag=False
                )],
                summary="tshark不可用"
            )

        print(f"[*] 正在分析 SSH 流量: {pcap_path}")
        print("=" * 60)

        # 1. 会话元数据
        print("[阶段1] SSH 会话元数据提取")
        print("-" * 60)
        session_info = self.extract_ssh_sessions(pcap_path, tshark_path)

        banners = session_info.get('banners', [])
        kex_info = session_info.get('kex_info', [])
        streams = session_info.get('streams', {})

        if banners:
            banner_strs = [f"{b['src_ip']}:{b['src_port']} -> {b['banner']}" for b in banners]
            findings.append(AnalysisFinding(
                finding_type=FindingType.INFO,
                protocol=ProtocolType.SSH,
                title="SSH Banner",
                description=f"捕获 {len(banners)} 条 SSH Banner",
                data='\n'.join(banner_strs),
                confidence=0.9,
                is_flag=False
            ))

        if kex_info:
            # 检测弱算法
            weak_kex = ["diffie-hellman-group1-sha1", "diffie-hellman-group-exchange-sha1"]
            weak_enc = ["arcfour", "arcfour128", "arcfour256", "aes128-cbc", "3des-cbc", "blowfish-cbc"]
            weak_mac = ["hmac-md5", "hmac-sha1-96", "hmac-md5-96"]
            all_weak_found = []
            for k in kex_info:
                all_algos = f"{k['kex_algorithms']},{k['encryption']},{k['mac']}"
                for w in weak_kex + weak_enc + weak_mac:
                    if w in all_algos and w not in all_weak_found:
                        all_weak_found.append(w)

            if all_weak_found:
                findings.append(AnalysisFinding(
                    finding_type=FindingType.ANOMALY,
                    protocol=ProtocolType.SSH,
                    title="SSH 弱加密算法",
                    description=f"检测到 {len(all_weak_found)} 种弱算法",
                    data=', '.join(all_weak_found),
                    confidence=0.85,
                    is_flag=False
                ))

        # 2. 暴力破解检测
        print("[阶段2] SSH 暴力破解检测")
        print("-" * 60)
        brute_info = self.detect_bruteforce(pcap_path, tshark_path)

        bruteforce_ips = brute_info.get('bruteforce_ips', {})
        if bruteforce_ips:
            for ip, count in bruteforce_ips.items():
                findings.append(AnalysisFinding(
                    finding_type=FindingType.ANOMALY,
                    protocol=ProtocolType.SSH,
                    title=f"SSH 暴力破解 ({ip})",
                    description=f"来源 {ip} 发起 {count} 次 SSH 连接",
                    data=f"{ip}: {count} 次连接",
                    confidence=0.9,
                    is_flag=False
                ))

        # 3. 私钥解密
        decrypted = []
        if key_file:
            print("[阶段3] SSH 私钥解密")
            print("-" * 60)
            decrypted = self.decrypt_ssh_with_key(pcap_path, tshark_path, key_file)
            if decrypted:
                # 尝试解码并检查 flag
                decoded_texts = []
                for p in decrypted:
                    try:
                        text = bytes.fromhex(p.replace(":", "")).decode('utf-8', errors='replace')
                        decoded_texts.append(text)
                    except ValueError:
                        pass

                combined = '\n'.join(decoded_texts)
                is_flag = self.detect_flag_pattern(combined)
                findings.append(AnalysisFinding(
                    finding_type=FindingType.HIDDEN_DATA,
                    protocol=ProtocolType.SSH,
                    title="SSH 解密数据",
                    description=f"使用私钥解密 {len(decrypted)} 个数据包",
                    data=combined[:2000] if len(combined) > 2000 else combined,
                    confidence=0.95,
                    is_flag=is_flag
                ))

        # 4. 摘要
        print("=" * 60)
        banner_count = len(banners)
        stream_count = len(streams)
        brute_count = len(bruteforce_ips)

        summary_parts = [f"SSH会话: {stream_count} 个", f"Banner: {banner_count} 条",
                         f"疑似爆破IP: {brute_count} 个"]
        print(f'[摘要] {" | ".join(summary_parts)}')

        if key_file and decrypted:
            summary_parts.append(f"已解密数据包: {len(decrypted)} 个")
            print(f"       已解密数据包: {len(decrypted)} 个")
        elif key_file and not decrypted:
            summary_parts.append("私钥解密: 失败")
            print("       私钥解密: 失败")
        else:
            print("       提示: 如有私钥文件，可使用 -k 参数尝试解密会话")
        print("=" * 60)

        return ProtocolAnalysisResult(
            protocol=ProtocolType.SSH,
            packet_count=stream_count,
            findings=findings,
            summary="; ".join(summary_parts),
            metadata={
                'session_info': {
                    'banners': banners,
                    'kex_info': kex_info,
                    'streams': dict(streams),
                },
                'bruteforce_ips': bruteforce_ips,
                'decrypted_count': len(decrypted),
            }
        )


# ============================================================
# PcapRepairTool (不继承 ProtocolAnalyzer)
# ============================================================

class PcapRepairTool:
    """PCAP修复工具: 从损坏的cap文件重建标准PCAP"""

    PCAP_GLOBAL_HEADER = (
        b'\xd4\xc3\xb2\xa1\x02\x00\x04\x00'
        b'\x00\x00\x00\x00\x00\x00\x00\x00'
        b'\xff\xff\x00\x00\x01\x00\x00\x00'
    )

    def __init__(self, output_dir: Optional[str] = None):
        self.output_dir = output_dir

    def repair(self, input_path: str, output_path: Optional[str] = None) -> Dict[str, Any]:
        """修复损坏的PCAP文件

        Returns:
            dict: {success: bool, output_path: str, packet_count: int, message: str}
        """
        if not output_path:
            if self.output_dir:
                os.makedirs(self.output_dir, exist_ok=True)
                pcap_name = os.path.splitext(os.path.basename(input_path))[0]
                output_path = os.path.join(self.output_dir, f"fixed_{pcap_name}.pcap")
            else:
                base_dir = pathlib.Path(__file__).resolve().parent.parent / "output" / "fix_pcap_output"
                base_dir.mkdir(parents=True, exist_ok=True)
                pcap_name = os.path.splitext(os.path.basename(input_path))[0]
                output_path = str(base_dir / f"fixed_{pcap_name}.pcap")

        try:
            with open(input_path, 'rb') as f:
                raw_data = f.read()

            first_packet_pos = raw_data.find(b'\x08\x00\x45')
            if first_packet_pos == -1:
                first_packet_pos = 128
            else:
                first_packet_pos -= 12

            fixed_pcap = bytearray(self.PCAP_GLOBAL_HEADER)

            pos = first_packet_pos
            packet_count = 0
            file_size = len(raw_data)

            while pos < file_size - 60:
                try:
                    next_sig = raw_data.find(b'\x08\x00\x45', pos + 14)

                    if next_sig == -1:
                        current_incl_len = file_size - pos
                    else:
                        packet_raw_end = next_sig - 12
                        current_incl_len = packet_raw_end - pos

                    if 40 <= current_incl_len <= 1514:
                        p_header = struct.pack('<IIII', 0, 0, current_incl_len, current_incl_len)
                        fixed_pcap.extend(p_header)
                        fixed_pcap.extend(raw_data[pos:pos + current_incl_len])
                        packet_count += 1
                        pos += current_incl_len
                    else:
                        pos += 1
                except Exception:
                    pos += 1
                    continue

            if packet_count > 0:
                with open(output_path, 'wb') as f:
                    f.write(fixed_pcap)
                return {
                    'success': True,
                    'output_path': output_path,
                    'packet_count': packet_count,
                    'message': f'成功重组 {packet_count} 个数据包'
                }
            else:
                return {
                    'success': False,
                    'output_path': None,
                    'packet_count': 0,
                    'message': '未能识别到有效的以太网帧数据'
                }

        except Exception as e:
            return {
                'success': False,
                'output_path': None,
                'packet_count': 0,
                'message': f'修复异常: {e}'
            }


# ============================================================
# ProtocolAnalyzerManager
# ============================================================

class ProtocolAnalyzerManager:

    def __init__(self):
        self._analyzers: Dict[ProtocolType, ProtocolAnalyzer] = {}
        self._utilities: Dict[str, Any] = {}
        self._register_default_analyzers()

    def _register_default_analyzers(self):
        self.register(ICMPAnalyzer())
        self.register(DNSCovertChannelAnalyzer())
        self.register(FTPAnalyzer())
        self.register(MMSAnalyzer())
        self.register(BluetoothAnalyzer())
        self.register(SMTPAnalyzer())
        self.register(CobaltStrikeAnalyzer())
        self.register(USBAnalyzer())
        self.register(TLSAnalyzer())
        self.register(RDPAnalyzer())
        self.register(RedisAnalyzer())
        self.register(SMBAnalyzer())
        self.register(SSHAnalyzer())
        self.register_utility("pcap_repair", PcapRepairTool())

    def register(self, analyzer: ProtocolAnalyzer):
        self._analyzers[analyzer.protocol_type] = analyzer

    def get_analyzer(self, protocol: ProtocolType) -> Optional[ProtocolAnalyzer]:
        return self._analyzers.get(protocol)

    def register_utility(self, name: str, utility: Any):
        self._utilities[name] = utility

    def get_utility(self, name: str) -> Optional[Any]:
        return self._utilities.get(name)

    def analyze_protocol(self, protocol: ProtocolType, packets: List) -> Optional[ProtocolAnalysisResult]:
        analyzer = self.get_analyzer(protocol)
        if analyzer:
            return analyzer.analyze(packets)
        return None

    def analyze_pcap(self, protocol: ProtocolType, pcap_path: str, **kwargs) -> Optional[ProtocolAnalysisResult]:
        """按协议分析pcap文件"""
        analyzer = self.get_analyzer(protocol)
        if analyzer:
            return analyzer.analyze_pcap(pcap_path, **kwargs)
        return None

    def analyze_all(self, packets: List) -> Dict[ProtocolType, ProtocolAnalysisResult]:
        results = {}
        for protocol, analyzer in self._analyzers.items():
            if protocol == ProtocolType.USB:
                continue  # USB需要pcap路径，跳过
            try:
                result = analyzer.analyze(packets)
                if result and result.packet_count > 0:
                    results[protocol] = result
            except Exception as e:
                logger.error(f"{protocol.value}协议分析异常: {e}")
        return results

    def analyze_all_pcap(self, pcap_path: str, **kwargs) -> Dict[ProtocolType, ProtocolAnalysisResult]:
        """对pcap文件运行所有注册分析器（只读取一次pcap）"""
        from utils import read_pcap

        # 读取一次 pcap，共享给所有分析器
        cap = read_pcap(pcap_path)
        packets = list(cap)
        cap.close()

        results = {}
        for protocol, analyzer in self._analyzers.items():
            try:
                if protocol == ProtocolType.USB:
                    # USB 需要 tshark，必须走 analyze_pcap
                    result = analyzer.analyze_pcap(pcap_path, **kwargs)
                elif protocol == ProtocolType.COBALT_STRIKE:
                    # CS analyze_pcap 有完整4阶段，优先使用
                    result = analyzer.analyze_pcap(pcap_path, **kwargs)
                elif protocol == ProtocolType.TLS:
                    # TLS 需要 tshark，必须走 analyze_pcap
                    result = analyzer.analyze_pcap(pcap_path, **kwargs)
                elif protocol == ProtocolType.RDP:
                    # RDP 需要 tshark，必须走 analyze_pcap
                    result = analyzer.analyze_pcap(pcap_path, **kwargs)
                elif protocol == ProtocolType.REDIS:
                    # Redis 需要 tshark，必须走 analyze_pcap
                    result = analyzer.analyze_pcap(pcap_path, **kwargs)
                elif protocol == ProtocolType.SMB:
                    # SMB 需要 tshark，必须走 analyze_pcap
                    result = analyzer.analyze_pcap(pcap_path, **kwargs)
                elif protocol == ProtocolType.SSH:
                    # SSH 需要 tshark，必须走 analyze_pcap
                    result = analyzer.analyze_pcap(pcap_path, **kwargs)
                else:
                    # 其余分析器复用已加载的 packets
                    result = analyzer.analyze(packets, **kwargs)

                if result and result.packet_count > 0:
                    results[protocol] = result
            except NotImplementedError:
                logger.debug(f"{protocol.value}分析器不支持此调用方式")
            except Exception as e:
                logger.error(f"{protocol.value}协议分析异常: {e}")
        return results


# ============================================================
# 便捷函数
# ============================================================

def analyze_icmp(packets: List) -> ProtocolAnalysisResult:
    return ICMPAnalyzer().analyze(packets)


def analyze_dns(packets: List, **kwargs) -> ProtocolAnalysisResult:
    return DNSCovertChannelAnalyzer(**kwargs).analyze(packets)


def analyze_ftp(packets: List, **kwargs) -> ProtocolAnalysisResult:
    return FTPAnalyzer(**kwargs).analyze(packets)


def analyze_mms(packets: List, **kwargs) -> ProtocolAnalysisResult:
    return MMSAnalyzer(**kwargs).analyze(packets)


def analyze_bluetooth(packets: List, **kwargs) -> ProtocolAnalysisResult:
    return BluetoothAnalyzer(**kwargs).analyze(packets)


def analyze_smtp(packets: List, **kwargs) -> ProtocolAnalysisResult:
    return SMTPAnalyzer(**kwargs).analyze(packets)


def analyze_tls_pcap(pcap_path: str, **kwargs) -> ProtocolAnalysisResult:
    return TLSAnalyzer(**kwargs).analyze_pcap(pcap_path, **kwargs)


def analyze_rdp_pcap(pcap_path: str, **kwargs) -> ProtocolAnalysisResult:
    return RDPAnalyzer(**kwargs).analyze_pcap(pcap_path, **kwargs)


def analyze_redis_pcap(pcap_path: str, **kwargs) -> ProtocolAnalysisResult:
    return RedisAnalyzer(**kwargs).analyze_pcap(pcap_path, **kwargs)


def analyze_smb_pcap(pcap_path: str, **kwargs) -> ProtocolAnalysisResult:
    return SMBAnalyzer(**kwargs).analyze_pcap(pcap_path, **kwargs)


def analyze_ssh_pcap(pcap_path: str, **kwargs) -> ProtocolAnalysisResult:
    return SSHAnalyzer(**kwargs).analyze_pcap(pcap_path, **kwargs)


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
