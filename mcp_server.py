#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TingLan MCP Server v1.0

给Claude/AI用的流量分析接口
主要功能就是analyze_pcap，丢个pcap进去自动跑检测

其他工具:
- auto_decode: 解码用的
- detect_attack: 查攻击
- analyze_entropy: 看熵值
- identify_file_type: 识别文件头
- analyze_php_ast: PHP语法树分析

需要装 mcp pyshark，还有wireshark的tshark
"""

from __future__ import annotations

import os
import sys
import json
import time
import traceback
import shutil
from dataclasses import asdict, is_dataclass
from typing import Any, Dict, List, Optional

try:
    from mcp.server.fastmcp import FastMCP  # type: ignore
except ModuleNotFoundError as e:  # pragma: no cover
    FastMCP = None  # type: ignore
    _MCP_IMPORT_ERROR = e
else:
    _MCP_IMPORT_ERROR = None


# 路径处理
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
for p in [PROJECT_ROOT, os.path.join(PROJECT_ROOT, "core"), os.path.join(PROJECT_ROOT, "models")]:
    if p not in sys.path:
        sys.path.insert(0, p)

# 导入核心模块
try:
    from models.detection_result import (
        DetectionResult,
        DetectionType,
        ProtocolStats,
        AnalysisSummary,
        ExtractedFile,
    )
except Exception:
    from detection_result import (  # type: ignore
        DetectionResult,
        DetectionType,
        ProtocolStats,
        AnalysisSummary,
        ExtractedFile,
    )

# Webshell 检测
try:
    from webshell_detect import WebShellDetector  # type: ignore
except Exception:
    try:
        from core.webshell_detect import WebShellDetector  # type: ignore
    except Exception:
        WebShellDetector = None

# 自动解码引擎
try:
    from auto_decoder import AutoDecoder, auto_decode_text  # type: ignore
except Exception:
    try:
        from core.auto_decoder import AutoDecoder, auto_decode_text  # type: ignore
    except Exception:
        AutoDecoder = None
        auto_decode_text = None

# 攻击检测器
try:
    from attack_detector import AttackDetector, detect_attack as _detect_attack  # type: ignore
except Exception:
    try:
        from core.attack_detector import AttackDetector, detect_attack as _detect_attack  # type: ignore
    except Exception:
        AttackDetector = None
        _detect_attack = None

# 信息熵分析
try:
    from entropy_analyzer import EntropyAnalyzer, MeaningfulnessAnalyzer  # type: ignore
except Exception:
    try:
        from core.entropy_analyzer import EntropyAnalyzer, MeaningfulnessAnalyzer  # type: ignore
    except Exception:
        EntropyAnalyzer = None
        MeaningfulnessAnalyzer = None

# 文件类型识别
try:
    from file_restorer import FileRestorer  # type: ignore
except Exception:
    try:
        from core.file_restorer import FileRestorer  # type: ignore
    except Exception:
        FileRestorer = None

# 协议分析（ICMP 隐写）
try:
    from protocol_analyzer import ICMPAnalyzer  # type: ignore
except Exception:
    try:
        from core.protocol_analyzer import ICMPAnalyzer  # type: ignore
    except Exception:
        ICMPAnalyzer = None

# PHP AST 分析
try:
    from ast_engine import PHPASTEngine  # type: ignore
except Exception:
    try:
        from core.ast_engine import PHPASTEngine  # type: ignore
    except Exception:
        PHPASTEngine = None


MCP_SERVER_VERSION = "v1.0"

mcp = FastMCP("TingLan") if FastMCP else None  # type: ignore

# 当 mcp 依赖不存在时的处理
if mcp is None:  # pragma: no cover
    def _no_mcp_tool_decorator(*args, **kwargs):
        def _wrap(fn):
            return fn
        return _wrap
    class _NoMCP:
        tool = staticmethod(_no_mcp_tool_decorator)
        def run(self):
            raise SystemExit("缺少依赖 mcp。请先执行: pip install mcp")
    mcp = _NoMCP()  # type: ignore


# 辅助函数
def _jsonable(obj: Any) -> Any:
    """转JSON格式，处理dataclass/enum/bytes这些"""
    if obj is None:
        return None
    if is_dataclass(obj):
        return {k: _jsonable(v) for k, v in asdict(obj).items()}
    if hasattr(obj, "value") and not isinstance(obj, (str, int, float, bool, dict, list)):
        try:
            return obj.value
        except Exception:
            pass
    if isinstance(obj, (bytes, bytearray)):
        return obj[:256].hex()
    if isinstance(obj, dict):
        return {str(k): _jsonable(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_jsonable(x) for x in obj]
    return obj


def _find_tshark(explicit: Optional[str] = None) -> str:
    """找tshark，优先用传入的路径"""
    if explicit:
        if os.path.exists(explicit):
            return explicit
        raise FileNotFoundError(f"tshark_path 指定的路径不存在: {explicit}")

    found = shutil.which("tshark")
    if found:
        return found

    candidates = [
        r"C:\Program Files\Wireshark\tshark.exe",
        r"C:\Program Files (x86)\Wireshark\tshark.exe",
        r"D:\Program Files\Wireshark\tshark.exe",
        r"E:\internet_safe\wireshark\tshark.exe",
        "/usr/bin/tshark",
        "/usr/local/bin/tshark",
        "/opt/homebrew/bin/tshark",
    ]
    for p in candidates:
        if os.path.exists(p):
            return p

    raise FileNotFoundError("未找到 TShark。请安装 Wireshark 并确保包含 TShark 组件。")


def _load_packets_pdml(pcap_path: str, tshark_path: str, max_packets: int = 0):
    """用tshark读PCAP，返回PDML格式的packet列表"""
    import subprocess
    import xml.etree.ElementTree as ET

    if not os.path.exists(pcap_path):
        raise FileNotFoundError(f"PCAP 文件不存在: {pcap_path}")

    cmd = [tshark_path, '-r', pcap_path, '-T', 'pdml']
    if max_packets > 0:
        cmd.extend(['-c', str(max_packets)])

    result = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8', errors='ignore')
    if result.returncode != 0:
        raise RuntimeError(f"TShark 执行失败: {result.stderr}")

    root = ET.fromstring(result.stdout)
    packets = list(root.findall('packet'))
    return packets, len(packets)


def _pdml_hex_to_str(hex_data: str) -> Optional[str]:
    """PDML的hex值转字符串"""
    if not hex_data:
        return None
    try:
        clean = str(hex_data).replace(':', '').replace(' ', '').replace('0x', '')
        if not clean or len(clean) < 2:
            return None
        if len(clean) % 2 != 0:
            clean = clean[:-1]
        return bytes.fromhex(clean).decode('utf-8', errors='ignore')
    except (ValueError, UnicodeDecodeError):
        return None


# 核心分析

def _protocol_stats(packets: List[Any]) -> Dict[str, int]:
    """统计各协议的包数量"""
    protocol_counts: Dict[str, int] = {}
    protos = ["http", "tcp", "udp", "icmp", "arp", "ftp", "ssh", "smtp", "dns", "tls"]

    for pkt in packets:
        try:
            for proto_elem in pkt.findall('proto'):
                proto_name = proto_elem.get('name', '').lower()
                if proto_name in protos:
                    protocol_counts[proto_name.upper()] = protocol_counts.get(proto_name.upper(), 0) + 1
        except Exception:
            continue

    return protocol_counts


def _detect_webshell(packets: List[Any]) -> List[DetectionResult]:
    """找Webshell（蚁剑/菜刀/冰蝎/哥斯拉）"""
    if WebShellDetector is None:
        return []

    class HTTPLayer:
        def __init__(self):
            self.request_method = None
            self.request_full_uri = None
            self.file_data = None

    class TCPPacket:
        def __init__(self):
            self.stream = None
            self.srcport = None
            self.dstport = None

    class IPPacket:
        def __init__(self):
            self.src = None
            self.dst = None

    class Packet:
        def __init__(self, number: int):
            self.number = number
            self.http = HTTPLayer()
            self.tcp = TCPPacket()
            self.ip = IPPacket()

    def _field_show(field_elem, default=""):
        return field_elem.get("show", default) if field_elem is not None else default

    def _field_value(field_elem, default=""):
        return field_elem.get("value", default) if field_elem is not None else default

    def _is_http_response(http_proto) -> bool:
        if http_proto is None:
            return False
        for field_elem in http_proto.iter("field"):
            name = field_elem.get("name", "")
            if name in ("http.response.code", "http.response", "http.response.line"):
                return True
        return False

    def _extract_tcp_ip(pkt_elem, packet_obj):
        for proto_elem in pkt_elem.findall("proto"):
            proto_name = (proto_elem.get("name") or "").lower()
            if proto_name == "tcp":
                for f in proto_elem.findall("field"):
                    n = f.get("name", "")
                    if n == "tcp.stream":
                        try:
                            packet_obj.tcp.stream = int(_field_show(f, "0"))
                        except:
                            packet_obj.tcp.stream = None
                    elif n == "tcp.srcport":
                        packet_obj.tcp.srcport = _field_show(f, "")
                    elif n == "tcp.dstport":
                        packet_obj.tcp.dstport = _field_show(f, "")
            elif proto_name == "ip":
                for f in proto_elem.findall("field"):
                    n = f.get("name", "")
                    if n == "ip.src":
                        packet_obj.ip.src = _field_show(f, "")
                    elif n == "ip.dst":
                        packet_obj.ip.dst = _field_show(f, "")

    request_list: List[Any] = []
    response_by_stream: Dict[int, List[Any]] = {}

    for idx, pkt in enumerate(packets, start=1):
        try:
            http_proto = None
            for proto_elem in pkt.findall("proto"):
                if (proto_elem.get("name") or "").lower() == "http":
                    http_proto = proto_elem
                    break
            if http_proto is None:
                continue

            is_response = _is_http_response(http_proto)
            p = Packet(number=idx)
            _extract_tcp_ip(pkt, p)

            for f in http_proto.iter("field"):
                n = f.get("name", "")
                if n == "http.request.method":
                    p.http.request_method = _field_show(f, "")
                elif n in ("http.request.full_uri", "http.request.uri"):
                    p.http.request_full_uri = _field_show(f, "")
                elif n == "http.file_data":
                    hex_val = _field_value(f, "")
                    converted = _pdml_hex_to_str(hex_val)
                    if converted and len(converted) > 0:
                        p.http.file_data = converted
                    else:
                        p.http.file_data = _field_show(f, "")

            if is_response:
                p.http.request_method = None
                stream_id = p.tcp.stream
                if stream_id is not None:
                    if stream_id not in response_by_stream:
                        response_by_stream[stream_id] = []
                    response_by_stream[stream_id].append(p)
            else:
                if p.http.request_full_uri is None:
                    p.http.request_full_uri = ""
                if p.http.request_method:
                    request_list.append(p)
        except Exception:
            continue

    if not request_list:
        return []

    paired: List[Dict] = []
    for req in request_list:
        response = None
        stream_id = req.tcp.stream
        if stream_id is not None and stream_id in response_by_stream:
            resps = response_by_stream[stream_id]
            for resp in resps:
                if resp.number > req.number:
                    response = resp
                    break
            if response is None and resps:
                response = resps[-1]
        paired.append({'packet': req, 'response': response})

    results: List[DetectionResult] = []
    tool_map = {
        "antsword": DetectionType.ANTSWORD,
        "caidao": DetectionType.CAIDAO,
        "behinder": DetectionType.BEHINDER,
        "godzilla": DetectionType.GODZILLA,
    }

    try:
        detector = WebShellDetector()
        detector.enable_ast(True)  # 启用 AST 语义分析，减少误报
        for pkt_pair in paired:
            packet = pkt_pair.get('packet')
            if not packet:
                continue

            all_detections = []
            for tool_name in ['antsword', 'caidao', 'behinder', 'godzilla']:
                detect_fn = getattr(detector, f'_detect_{tool_name}', None)
                if detect_fn is None:
                    continue
                try:
                    det_result = detect_fn(pkt_pair)
                    if det_result:
                        all_detections.append((tool_name, det_result))
                except Exception:
                    continue

            if not all_detections:
                continue

            all_detections.sort(key=lambda x: x[1].get('total_weight', 0), reverse=True)
            best_tool, best_raw = all_detections[0]

            try:
                det_type = tool_map[best_tool]
                dr = DetectionResult.from_webshell_result(best_raw, det_type)
                dr.source_ip = best_raw.get("source_ip", "") or getattr(packet.ip, 'src', '') or dr.source_ip
                dr.dest_ip = best_raw.get("dest_ip", "") or getattr(packet.ip, 'dst', '') or dr.dest_ip
                dr.packet_number = packet.number
                results.append(dr)
            except Exception:
                continue
    except Exception:
        return []

    return results


def _detect_attacks_in_packets(packets: List[Any]) -> List[Dict]:
    """跑攻击检测，扫HTTP请求"""
    if AttackDetector is None:
        return []

    attacks = []
    detector = AttackDetector()

    for idx, pkt in enumerate(packets, start=1):
        try:
            http_proto = None
            for proto_elem in pkt.findall("proto"):
                if (proto_elem.get("name") or "").lower() == "http":
                    http_proto = proto_elem
                    break
            if http_proto is None:
                continue

            # 提取请求体
            file_data = None
            uri = ""
            method = ""
            for f in http_proto.iter("field"):
                n = f.get("name", "")
                if n == "http.file_data":
                    hex_val = f.get("value", "")
                    file_data = _pdml_hex_to_str(hex_val) or f.get("show", "")
                elif n == "http.request.method":
                    method = f.get("show", "")
                elif n in ("http.request.full_uri", "http.request.uri"):
                    uri = f.get("show", "")

            # 只扫请求（有method的），跳过响应
            if not method:
                continue

            if file_data and len(file_data) > 10:
                result = detector.detect(
                    file_data.encode('utf-8', errors='ignore'),
                    method=method,
                    uri=uri
                )
                if result.get('detected') and result.get('total_weight', 0) >= 50:
                    attacks.append({
                        'packet_number': idx,
                        'attack_type': result.get('detection_type', 'unknown'),
                        'threat_level': result.get('threat_level', 'info'),
                        'weight': result.get('total_weight', 0),
                        'method': method,
                        'uri': uri[:150],
                        'indicators': result.get('indicators', [])[:5],
                    })
        except Exception:
            continue

    return attacks


def _analyze_icmp_stego(packets: List[Any], pcap_path: str, tshark_path: str) -> Dict:
    """ICMP隐写检测"""
    if ICMPAnalyzer is None:
        return {"available": False}

    # 看看有没有ICMP包
    icmp_count = 0
    for pkt in packets:
        for proto_elem in pkt.findall("proto"):
            if proto_elem.get("name", "").lower() == "icmp":
                icmp_count += 1
                break

    if icmp_count < 5:
        return {"available": False, "icmp_count": icmp_count}

    try:
        import pyshark
        cap = pyshark.FileCapture(pcap_path, tshark_path=tshark_path)
        pyshark_packets = list(cap)
        cap.close()

        analyzer = ICMPAnalyzer()
        result = analyzer.analyze(pyshark_packets)

        findings = []
        for f in result.findings:
            findings.append({
                "type": f.finding_type.value,
                "title": f.title,
                "data": f.data,
                "confidence": f.confidence,
                "is_flag": f.is_flag,
            })

        return {
            "available": True,
            "icmp_count": result.packet_count,
            "findings": findings,
            "possible_flags": result.get_flags(),
            "summary": result.summary,
        }
    except Exception as e:
        return {"available": False, "error": str(e)}


def _auto_decode_suspicious_data(data_list: List[str]) -> List[Dict]:
    """自动解码可疑数据，最多处理10条"""
    if AutoDecoder is None or not data_list:
        return []

    decoded_results = []
    decoder = AutoDecoder()

    for data in data_list[:10]:  # 最多处理10条
        if len(data) < 20:
            continue
        try:
            result = decoder.decode_text(data)
            if result.total_layers > 0 and result.is_meaningful:
                decoded_results.append({
                    "original": data[:100] + ("..." if len(data) > 100 else ""),
                    "decoded": result.final_text[:200],
                    "chain": result.decode_chain,
                    "layers": result.total_layers,
                    "flags": result.flags_found,
                })
        except Exception:
            continue

    return decoded_results


# MCP接口
@mcp.tool()
def analyze_pcap(
    pcap_path: str,
    tshark_path: Optional[str] = None,
    max_packets: int = 0,
) -> Dict[str, Any]:
    """
    分析 pcap/pcapng 文件（同步）

    Args:
        pcap_path: PCAP 文件路径（本机路径）
        tshark_path: 可选，显式指定 tshark 路径
        max_packets: 只分析前 N 个包（0 表示不限制；用于大文件/快速预览）

    detail_level:
        - brief: 仅返回精炼摘要（默认，适合直接喂给 AI）
        - standard: 返回较完整的摘要（仍会做截断与限量）
        - full: 返回完整 full_summary（可能较大）

    persist_session:
        是否把分析缓存落盘到 .sessions/<analysis_id>.json。
        v3.2 默认 False，避免占用磁盘并减少后续手动清理负担。

    session_ttl_minutes:
        内存 session 索引有效期（到期自动清理；若持久化了文件也会尽力删除）。

    Returns:
        analysis_id: 会话ID（用于按需获取细节）
        brief: 精炼摘要（LLM 友好）
        available_sections: 可按需获取的细节分区
        expires_at: 该 analysis_id 的过期时间戳
        full_summary: 仅当 detail_level=full 时返回
    """
    t0 = time.time()
    warnings: List[str] = []

    try:
        tshark = _find_tshark(tshark_path)
        packets, total = _load_packets_pdml(pcap_path, tshark, max_packets=max_packets)
    except Exception as e:
        return {"ok": False, "error": str(e), "traceback": traceback.format_exc()}

    # 1. 协议统计
    proto_counts = {}
    try:
        proto_counts = _protocol_stats(packets)
    except Exception as e:
        warnings.append(f"协议统计失败: {e}")

    # 2. Webshell 检测
    webshell_results = []
    try:
        webshell_results = _detect_webshell(packets)
    except Exception as e:
        warnings.append(f"Webshell 检测异常: {e}")

    # 3. 攻击检测（自动）
    attack_results = []
    try:
        attack_results = _detect_attacks_in_packets(packets)
    except Exception as e:
        warnings.append(f"攻击检测异常: {e}")

    # 4. ICMP 隐写分析（如果有 ICMP 流量）
    icmp_analysis = {"available": False}
    if proto_counts.get("ICMP", 0) >= 5:
        try:
            icmp_analysis = _analyze_icmp_stego(packets, pcap_path, tshark)
        except Exception as e:
            warnings.append(f"ICMP 分析异常: {e}")

    # 5. 自动解码可疑数据（从 webshell 检测结果中提取）
    suspicious_data = []
    for ws in webshell_results[:5]:
        if hasattr(ws, 'indicator') and ws.indicator:
            suspicious_data.append(ws.indicator)

    decoded_data = []
    try:
        decoded_data = _auto_decode_suspicious_data(suspicious_data)
    except Exception as e:
        warnings.append(f"自动解码异常: {e}")

    # 构建结果
    analysis_time = time.time() - t0

    # 威胁摘要
    webshell_brief = []
    for ws in webshell_results[:20]:
        webshell_brief.append({
            "type": _jsonable(ws.detection_type),
            "threat_level": _jsonable(ws.threat_level),
            "confidence": ws.confidence,
            "weight": ws.total_weight,
            "method": ws.method,
            "uri": (ws.uri or "")[:150],
            "source_ip": ws.source_ip,
            "dest_ip": ws.dest_ip,
            "packet_number": ws.packet_number,
            "command": (ws.decoded_command or "")[:100] if hasattr(ws, 'decoded_command') else "",
        })

    # 协议统计格式化
    proto_list = []
    for proto, count in sorted(proto_counts.items(), key=lambda x: -x[1]):
        pct = (count / total * 100.0) if total else 0.0
        proto_list.append({"protocol": proto, "count": count, "percentage": round(pct, 1)})

    # 威胁计数
    detection_counts: Dict[str, int] = {}
    for ws in webshell_results:
        t = _jsonable(ws.detection_type)
        detection_counts[t] = detection_counts.get(t, 0) + 1
    for atk in attack_results:
        t = atk.get('attack_type', 'unknown')
        detection_counts[t] = detection_counts.get(t, 0) + 1

    result = {
        "ok": True,
        "version": MCP_SERVER_VERSION,
        "file_path": pcap_path,
        "total_packets": total,
        "analysis_time": round(analysis_time, 2),

        # 协议统计
        "protocol_stats": proto_list[:10],

        # 威胁检测
        "threat_count": len(webshell_results) + len(attack_results),
        "detection_counts": detection_counts,

        # Webshell 检测
        "webshell_detections": webshell_brief,

        # 攻击检测
        "attack_detections": attack_results[:20],

        # ICMP 隐写分析
        "icmp_analysis": icmp_analysis,

        # 自动解码结果
        "auto_decoded": decoded_data,

        "warnings": warnings,
    }

    return result


@mcp.tool()
def auto_decode(
    data: str,
    crib: Optional[str] = None,
    max_depth: int = 10,
) -> Dict[str, Any]:
    """
    自动解码数据（CyberChef 风格）

    支持多层嵌套解码，自动识别编码类型：
    - Base64, Base32, Base58
    - Hex (各种格式)
    - URL 编码
    - Binary, Octal, Decimal
    - HTML Entity
    - Morse 码
    - Gzip, Zlib 压缩
    - ROT13

    Args:
        data: 待解码的数据（字符串）
        crib: 已知明文模式（正则表达式，如 "flag\\{.*\\}"），用于指导解码
        max_depth: 最大递归深度（默认 10）

    Returns:
        ok: 是否成功
        final_text: 解码后的最终文本
        decode_chain: 解码链路（如 "base64 -> hex -> url"）
        flags_found: 找到的 flag 列表
        confidence: 置信度
        is_meaningful: 结果是否有意义
    """
    if AutoDecoder is None or auto_decode_text is None:
        return {"ok": False, "error": "auto_decoder 模块不可用"}

    try:
        result = auto_decode_text(data, crib=crib)
        return {
            "ok": True,
            "final_text": result.final_text,
            "decode_chain": result.decode_chain,
            "total_layers": result.total_layers,
            "flags_found": result.flags_found,
            "confidence": result.confidence,
            "is_meaningful": result.is_meaningful,
            "detected_content_type": result.detected_content_type,
        }
    except Exception as e:
        return {"ok": False, "error": str(e), "traceback": traceback.format_exc()}


@mcp.tool()
def detect_attack(
    data: str,
    attack_type: Optional[str] = None,
) -> Dict[str, Any]:
    """
    检测 OWASP Top 10 攻击签名

    支持检测：
    - SQL Injection（联合注入、盲注、时间盲注等）
    - XSS（脚本注入、事件处理器、JavaScript URI）
    - XXE（XML 外部实体注入）
    - Command Injection（命令注入、反弹 Shell）
    - Path Traversal（目录遍历）
    - File Upload（恶意文件上传、Webshell）
    - SSTI（服务端模板注入）
    - Deserialization（反序列化漏洞）
    - SSRF（服务端请求伪造）

    Args:
        data: 待检测的数据（URL、请求体、参数值等）
        attack_type: 可选，仅检测特定类型（sqli/xss/xxe/command_injection/path_traversal 等）

    Returns:
        ok: 是否成功
        detected: 是否检测到攻击
        risk_level: 风险等级（info/low/medium/high/critical）
        confidence: 置信度
        attack_types: 检测到的攻击类型列表
        total_weight: 总权重分值
        matches: 匹配的签名列表
    """
    if AttackDetector is None:
        return {"ok": False, "error": "attack_detector 模块不可用"}

    try:
        detector = AttackDetector()
        result = detector.detect(data.encode('utf-8', errors='ignore'))

        matches_brief = []
        for ind in result.get('indicators', [])[:20]:
            matches_brief.append({
                "name": ind.get('name', ''),
                "weight": ind.get('weight', 0),
                "matched_text": (ind.get('matched_text') or '')[:100],
                "description": ind.get('description', ''),
            })

        return {
            "ok": True,
            "detected": result.get('detected', False),
            "risk_level": result.get('threat_level', 'info'),
            "confidence": result.get('confidence', 'none'),
            "attack_type": result.get('detection_type', 'unknown'),
            "total_weight": result.get('total_weight', 0),
            "match_count": len(result.get('indicators', [])),
            "matches": matches_brief,
        }
    except Exception as e:
        return {"ok": False, "error": str(e), "traceback": traceback.format_exc()}


@mcp.tool()
def analyze_entropy(
    data: str,
    include_details: bool = True,
) -> Dict[str, Any]:
    """
    分析数据的信息熵和统计学特征

    用于检测：
    - 加密/混淆数据（高熵值）
    - 异常流量特征
    - 免杀 Webshell
    - Base64 等编码数据

    Args:
        data: 待分析的数据
        include_details: 是否包含详细的统计信息

    Returns:
        ok: 是否成功
        entropy: Shannon 信息熵值（0-8）
        entropy_level: 熵值等级（normal/medium/high/critical）
        special_char_ratio: 特殊字符比例
        is_likely_base64: 是否可能是 Base64
        total_weight: 统计学异常权重
        confidence: 置信度
        recommendation: 建议
    """
    if EntropyAnalyzer is None or MeaningfulnessAnalyzer is None:
        return {"ok": False, "error": "entropy_analyzer 模块不可用"}

    try:
        analyzer = MeaningfulnessAnalyzer()
        result = analyzer.analyze(data.encode('utf-8', errors='ignore'))

        entropy = result.get("entropy", 0.0)
        entropy_class = result.get("entropy_class", "empty")

        # 判断熵值等级
        if entropy >= 7.5:
            entropy_level = "critical"
        elif entropy >= 7.0:
            entropy_level = "high"
        elif entropy >= 5.5:
            entropy_level = "medium"
        else:
            entropy_level = "normal"

        return {
            "ok": True,
            "entropy": round(entropy, 3),
            "entropy_level": entropy_level,
            "entropy_class": entropy_class,
            "printable_ratio": round(result.get("printable_ratio", 0.0), 3),
            "is_english": result.get("is_english", False),
            "chi_squared": round(result.get("chi_squared", 0.0), 2) if result.get("chi_squared") != float('inf') else None,
            "detected_encoding": result.get("detected_encoding"),
            "encoding_confidence": round(result.get("encoding_confidence", 0.0), 2),
            "confidence_score": round(result.get("confidence_score", 0.0), 2),
            "is_meaningful": result.get("is_meaningful", False),
        }
    except Exception as e:
        return {"ok": False, "error": str(e), "traceback": traceback.format_exc()}


@mcp.tool()
def identify_file_type(
    data_hex: str,
) -> Dict[str, Any]:
    """
    识别二进制数据的文件类型（基于 Magic Number）

    支持 200+ 种文件格式：
    - 压缩文件：ZIP, RAR, 7Z, GZ, BZ2, TAR
    - 图像：JPG, PNG, GIF, BMP, WEBP, TIFF
    - 音频：MP3, WAV, OGG, FLAC
    - 视频：MP4, MKV, AVI, FLV
    - 文档：PDF, DOC, DOCX, RTF
    - 可执行：EXE, ELF, Mach-O, Java Class
    - 数据库：SQLite
    - 网络：PCAP, PCAPNG
    - 脚本：PHP, XML, Shell

    Args:
        data_hex: 二进制数据的十六进制表示（至少前 16 字节）

    Returns:
        ok: 是否成功
        detected: 是否识别到文件类型
        extension: 文件扩展名
        description: 文件类型描述
        mime_type: MIME 类型
        category: 文件类别
    """
    if FileRestorer is None:
        return {"ok": False, "error": "file_restorer 模块不可用"}

    try:
        clean_hex = data_hex.replace(' ', '').replace(':', '').replace('0x', '')
        data = bytes.fromhex(clean_hex)

        restorer = FileRestorer()
        sig = restorer.detect_file_type(data)

        if sig is None:
            return {
                "ok": True,
                "detected": False,
                "message": "未识别到已知的文件类型",
            }

        return {
            "ok": True,
            "detected": True,
            "extension": sig.extension,
            "description": sig.description,
            "mime_type": sig.mime_type,
            "category": sig.category,
        }
    except Exception as e:
        return {"ok": False, "error": str(e), "traceback": traceback.format_exc()}


@mcp.tool()
def analyze_php_ast(
    code: str,
) -> Dict[str, Any]:
    """
    PHP AST 语义分析（Webshell 检测增强）

    功能：
    - 污点追踪（Taint Tracking）：识别用户输入是否流入危险函数
    - 混淆检测：字符串拼接、变量函数、超全局变量混淆
    - 语义分析：基于数据流而非字符串匹配

    检测的危险函数：
    - 代码执行：eval, assert, create_function, call_user_func
    - 命令执行：system, exec, shell_exec, passthru, popen
    - 文件操作：include, require, file_put_contents
    - 反序列化：unserialize

    Args:
        code: PHP 代码字符串

    Returns:
        ok: 是否成功
        is_likely_webshell: 是否可能是 Webshell
        obfuscation_score: 混淆评分（0.0-1.0）
        confidence_adjustment: 权重调整值
        dangerous_calls: 危险函数调用列表
        taint_sources: 污点来源列表
        findings: 语义分析发现
    """
    if PHPASTEngine is None:
        return {"ok": False, "error": "ast_engine 模块不可用"}

    try:
        engine = PHPASTEngine()
        result = engine.analyze(code)

        dangerous_calls_brief = []
        for c in result.dangerous_calls[:20]:
            dangerous_calls_brief.append({
                "function": c.function_name,
                "is_tainted": c.is_tainted,
                "severity": c.severity,
                "obfuscation": c.obfuscation_method,
                "resolved_name": c.resolved_name,
            })

        findings_brief = []
        for f in result.findings[:20]:
            findings_brief.append({
                "type": f.type,
                "severity": f.severity,
                "description": f.description,
                "code_context": (f.code_context or "")[:200],
            })

        return {
            "ok": True,
            "is_likely_webshell": result.is_likely_webshell,
            "obfuscation_score": result.obfuscation_score,
            "confidence_adjustment": result.confidence_adjustment,
            "dangerous_calls": dangerous_calls_brief,
            "taint_sources": list(result.taint_sources)[:20],
            "findings": findings_brief,
        }
    except Exception as e:
        return {"ok": False, "error": str(e), "traceback": traceback.format_exc()}


def main():
    mcp.run()


if __name__ == "__main__":
    main()
