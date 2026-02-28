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
import pathlib
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
    MMS = "mms"
    USB = "usb"
    BLUETOOTH = "bluetooth"
    SMTP = "smtp"
    COBALT_STRIKE = "cobalt_strike"
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

        # 状态追踪
        open_inv_to_name = {}   # InvokeID -> 文件名 (72 Request)
        frsm_to_name = {}       # FRSMID -> 文件名 (72 Response)
        read_inv_to_name = {}   # InvokeID -> 文件名 (73 Request)

        for pkt in packets:
            try:
                layer_names = [l.layer_name for l in pkt.layers] if hasattr(pkt, 'layers') else []
                if 'mms' not in layer_names:
                    continue

                packet_count += 1
                mms = pkt.mms
                inv_id = getattr(mms, "invokeid", None)

                # 文件打开请求 (Confirmed-RequestPDU, 72)
                if hasattr(mms, "confirmedservicerequest") and int(mms.confirmedservicerequest) == 72:
                    if hasattr(mms, "filename_item"):
                        try:
                            raw_fname = mms.filename_item.fields[0].get_default_value()
                            fname = os.path.basename(str(raw_fname))
                            if inv_id:
                                open_inv_to_name[inv_id] = fname
                        except Exception:
                            pass

                # 绑定FRSMID (Confirmed-ResponsePDU, 72)
                elif hasattr(mms, "confirmedserviceresponse") and int(mms.confirmedserviceresponse) == 72:
                    if inv_id in open_inv_to_name:
                        fname = open_inv_to_name.pop(inv_id)
                        if hasattr(mms, "frsmid"):
                            f_id = str(mms.frsmid)
                            frsm_to_name[f_id] = fname

                # 文件读取请求 (Confirmed-RequestPDU, 73)
                elif hasattr(mms, "confirmedservicerequest") and int(mms.confirmedservicerequest) == 73:
                    if hasattr(mms, "fileread"):
                        f_id = str(mms.fileread)
                        if f_id in frsm_to_name:
                            fname = frsm_to_name[f_id]
                            if inv_id:
                                read_inv_to_name[inv_id] = fname

                # 提取文件数据 (Confirmed-ResponsePDU, 73)
                elif hasattr(mms, "confirmedserviceresponse") and int(mms.confirmedserviceresponse) == 73:
                    if inv_id in read_inv_to_name:
                        fname = read_inv_to_name.pop(inv_id)

                        if hasattr(mms, "filedata"):
                            raw_val = str(mms.filedata).replace(":", "").replace(" ", "")
                            try:
                                data_to_save = binascii.unhexlify(raw_val)
                            except Exception:
                                data_to_save = raw_val.encode('utf-8')

                            if output_dir:
                                file_path = os.path.join(output_dir, fname)
                                with open(file_path, "ab") as f:
                                    f.write(data_to_save)
                                extracted_files.append(file_path)

                            is_flag = "flag" in fname.lower()
                            decoded_content = data_to_save.decode(errors='ignore') if is_flag else None

                            finding_type = FindingType.HIDDEN_DATA if is_flag else FindingType.FILE_EXTRACTION
                            findings.append(AnalysisFinding(
                                finding_type=finding_type,
                                protocol=ProtocolType.MMS,
                                title=f"MMS文件提取: {fname}",
                                description=f"InvokeID: {inv_id}, 文件: {fname} ({len(data_to_save)} bytes)",
                                data=decoded_content or f"[{len(data_to_save)} bytes]",
                                confidence=0.95 if is_flag else 0.8,
                                is_flag=is_flag
                            ))

            except Exception:
                continue

        summary_parts = []
        if extracted_files:
            summary_parts.append(f"提取 {len(extracted_files)} 个文件")
        flags = [f for f in findings if f.is_flag]
        if flags:
            summary_parts.append(f"发现FLAG文件: {flags[0].data[:80] if flags[0].data else ''}")
        summary_parts.append(f"共 {packet_count} 个MMS包")

        return ProtocolAnalysisResult(
            protocol=ProtocolType.MMS,
            packet_count=packet_count,
            findings=findings,
            summary="; ".join(summary_parts),
            extracted_files=extracted_files,
            output_dir=output_dir
        )



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


# ProtocolAnalyzerManager

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


# 便捷函数

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
