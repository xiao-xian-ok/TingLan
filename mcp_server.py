#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
听澜 MCP Server v4.1
流量分析工具集，支持 Webshell/攻击检测、协议分析、文件提取等
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


PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
for p in [PROJECT_ROOT, os.path.join(PROJECT_ROOT, "core"), os.path.join(PROJECT_ROOT, "models")]:
    if p not in sys.path:
        sys.path.insert(0, p)

def _import(name, *attrs):
    """尝试从多个路径导入模块"""
    for prefix in ['', 'core.']:
        try:
            mod = __import__(prefix + name, fromlist=attrs or [''])
            if attrs:
                return tuple(getattr(mod, a, None) for a in attrs)
            return mod
        except: pass
    return (None,) * len(attrs) if attrs else None
# Models
try:
    from models.detection_result import DetectionResult, DetectionType, ProtocolStats, AnalysisSummary, ExtractedFile
except:
    from detection_result import DetectionResult, DetectionType, ProtocolStats, AnalysisSummary, ExtractedFile

# Core modules
WebShellDetector = _import('webshell_detect', 'WebShellDetector')[0]
AutoDecoder, auto_decode_text = _import('auto_decoder', 'AutoDecoder', 'auto_decode_text')
AttackDetector, _detect_attack = _import('attack_detector', 'AttackDetector', 'detect_attack')
EntropyAnalyzer, MeaningfulnessAnalyzer = _import('entropy_analyzer', 'EntropyAnalyzer', 'MeaningfulnessAnalyzer')
FileRestorer = _import('file_restorer', 'FileRestorer')[0]
ICMPAnalyzer = _import('protocol_analyzer', 'ICMPAnalyzer')[0]
PHPASTEngine = _import('ast_engine', 'PHPASTEngine')[0]
TsharkProcessHandler, StreamConfig, OutputFormat = _import('tshark_stream', 'TsharkProcessHandler', 'StreamConfig', 'OutputFormat')
analyze_and_extract_ftp = _import('ftp_analyzer', 'analyze_and_extract_ftp')[0]
extract_smtp_forensics = _import('SMTP_analyzer', 'extract_smtp_forensics')[0]
analyze_usb_traffic = _import('usb_analyzer', 'analyze_usb_traffic')[0]
extract_bluetooth_data = _import('bluetooth_analyzer', 'extract_bluetooth_data')[0]
fix_cap_to_pcap = _import('fix_pcap', 'fix_cap_to_pcap')[0]


MCP_SERVER_VERSION = "v4.1"
mcp = FastMCP("tinglan") if FastMCP else None

if mcp is None:
    def _no_mcp(*a, **kw):
        def _w(fn): return fn
        return _w
    class _NoMCP:
        tool = staticmethod(_no_mcp)
        def run(self): raise SystemExit("缺少 mcp 依赖")
    mcp = _NoMCP()


def _jsonable(obj):
    """转换为JSON可序列化结构"""
    if obj is None: return None
    if is_dataclass(obj):
        return {k: _jsonable(v) for k, v in asdict(obj).items()}
    if hasattr(obj, "value") and not isinstance(obj, (str, int, float, bool, dict, list)):
        try: return obj.value
        except: pass
    if isinstance(obj, (bytes, bytearray)): return obj[:256].hex()
    if isinstance(obj, dict): return {str(k): _jsonable(v) for k, v in obj.items()}
    if isinstance(obj, list): return [_jsonable(x) for x in obj]
    return obj


def _find_tshark(explicit=None):
    """查找tshark路径"""
    if explicit:
        if os.path.exists(explicit): return explicit
        raise FileNotFoundError(f"tshark不存在: {explicit}")

    found = shutil.which("tshark")
    if found: return found

    for p in [r"C:\Program Files\Wireshark\tshark.exe",
              r"C:\Program Files (x86)\Wireshark\tshark.exe",
              r"D:\Program Files\Wireshark\tshark.exe",
              r"E:\internet_safe\wireshark\tshark.exe",
              "/usr/bin/tshark", "/usr/local/bin/tshark", "/opt/homebrew/bin/tshark"]:
        if os.path.exists(p): return p
    raise FileNotFoundError("未找到TShark")


def _protocol_stats_fast(pcap_path, tshark_path):
    """快速协议统计（tshark -z io,phs）"""
    import subprocess
    counts, total = {}, 0
    try:
        result = subprocess.run(
            [tshark_path, "-r", pcap_path, "-q", "-z", "io,phs"],
            capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=120
        )
        for line in result.stdout.split('\n'):
            line = line.strip()
            if not line or 'frames:' not in line: continue
            parts = line.split()
            if len(parts) < 2: continue
            chain = parts[0]
            for part in parts:
                if part.startswith('frames:'):
                    cnt = int(part.replace('frames:', ''))
                    proto = chain.split(':')[-1].upper() if chain else "UNKNOWN"
                    if total == 0 and proto in ("FRAME", "ETH"): total = cnt
                    elif proto == "FRAME": total = cnt
                    if proto not in ("FRAME", "ETH", "DATA"): counts[proto] = cnt
                    break
        if total == 0 and counts: total = max(counts.values())
    except: pass
    return counts, total


def _detect_webshell_ek(pcap_path, tshark_path, max_packets=0):
    """EK格式Webshell检测"""
    if not WebShellDetector or not TsharkProcessHandler: return []

    results = []
    type_map = {"antsword": DetectionType.ANTSWORD, "caidao": DetectionType.CAIDAO,
                "behinder": DetectionType.BEHINDER, "godzilla": DetectionType.GODZILLA}
    try:
        handler = TsharkProcessHandler(tshark_path)
        config = StreamConfig(pcap_path=pcap_path, display_filter='http',
                              output_format=OutputFormat.EK, disable_name_resolution=True, line_buffered=True)

        http_pkts = []
        limit = max_packets if max_packets > 0 else 10000
        for wrapper in handler.stream_pyshark_compatible(config):
            if wrapper.has_layer('http'): http_pkts.append(wrapper)
            if len(http_pkts) >= limit: break
        handler.stop()

        if not http_pkts: return []

        detector = WebShellDetector()
        detector.enable_ast(True)
        det_results = detector.detect(http_pkts, show_all_suspicious=True)

        for tool in ['antsword', 'caidao', 'behinder', 'godzilla']:
            for r in det_results.get(tool, []):
                try:
                    dr = DetectionResult.from_webshell_result(r, type_map[tool])
                    dr.source_ip = r.get("source_ip", "") or dr.source_ip
                    dr.dest_ip = r.get("dest_ip", "") or dr.dest_ip
                    dr.packet_number = r.get("packet_number") or r.get("packet_index") or dr.packet_number
                    results.append(dr)
                except: continue

        for r in det_results.get('suspicious', []):
            try:
                dr = DetectionResult.from_webshell_result(r, DetectionType.ANTSWORD)
                dr.confidence = "suspicious"
                dr.source_ip = r.get("source_ip", "") or dr.source_ip
                dr.dest_ip = r.get("dest_ip", "") or dr.dest_ip
                dr.packet_number = r.get("packet_number") or r.get("packet_index") or dr.packet_number
                results.append(dr)
            except: continue
    except: return []
    return results


def _detect_attacks_ek(pcap_path, tshark_path, max_packets=0):
    """tshark -T fields 格式攻击检测"""
    if not AttackDetector: return []
    import subprocess, csv, io

    attacks = []
    try:
        cmd = [tshark_path, "-r", pcap_path, "-Y", "http.request", "-T", "fields",
               "-e", "frame.number", "-e", "http.request.method", "-e", "http.request.uri",
               "-e", "http.host", "-e", "http.content_type", "-e", "http.user_agent",
               "-e", "http.file_data", "-e", "ip.src", "-e", "ip.dst",
               "-E", "separator=|", "-E", "quote=d"]

        result = subprocess.run(cmd, capture_output=True, text=True,
                                encoding='utf-8', errors='replace', timeout=300)

        detector = AttackDetector()
        seen = set()
        limit = max_packets if max_packets > 0 else 10000

        for line in result.stdout.strip().split('\n'):
            if not line.strip(): continue
            try:
                fields = next(csv.reader(io.StringIO(line), delimiter='|', quotechar='"'))
                if len(fields) < 7: continue

                frame, method, uri = fields[0].strip(), fields[1].strip(), fields[2].strip()
                content_type, file_data = fields[4].strip(), fields[6].strip()
                if not method: continue

                key = f"{method}:{uri[:100]}:{len(file_data)}"
                if key in seen: continue
                seen.add(key)

                body = file_data.encode('utf-8', errors='ignore') if file_data else None
                if not body and '?' in uri: body = uri.split('?', 1)[1].encode('utf-8', errors='ignore')
                if not body: body = uri.encode('utf-8', errors='ignore')
                if not body or len(body) < 3: continue

                det = detector.detect(data=body, method=method, uri=uri, content_type=content_type)
                if det.get('detected') and det.get('total_weight', 0) >= 20:
                    attacks.append({
                        "packet_number": int(frame) if frame.isdigit() else 0,
                        "attack_type": det.get("attack_types", ["unknown"])[0] if det.get("attack_types") else "unknown",
                        "threat_level": det.get("risk_level", "low"),
                        "weight": det.get("total_weight", 0),
                        "method": method, "uri": uri[:200],
                        "indicators": det.get("matches", [])[:5],
                    })
                if len(attacks) >= limit: break
            except: continue
    except Exception as e:
        print(f"[MCP] _detect_attacks_ek error: {e}")
    return attacks


def _analyze_icmp_stego_direct(pcap_path, tshark_path):
    """ICMP隐写分析"""
    if not ICMPAnalyzer: return {"available": False}
    try:
        import pyshark
        cap = pyshark.FileCapture(pcap_path, tshark_path=tshark_path, display_filter='icmp')
        pkts = list(cap)
        cap.close()

        if len(pkts) < 5: return {"available": False, "icmp_count": len(pkts)}

        result = ICMPAnalyzer().analyze(pkts)
        findings = [{"type": f.finding_type.value, "title": f.title, "data": f.data,
                     "confidence": f.confidence, "is_flag": f.is_flag} for f in result.findings]
        return {"available": True, "icmp_count": result.packet_count, "findings": findings,
                "possible_flags": result.get_flags(), "summary": result.summary}
    except Exception as e:
        return {"available": False, "error": str(e)}


def _auto_decode_suspicious_data(data_list):
    """自动解码可疑数据"""
    if not AutoDecoder or not data_list: return []
    decoded, decoder = [], AutoDecoder()
    for data in data_list[:10]:
        if len(data) < 20: continue
        try:
            r = decoder.decode_text(data)
            if r.total_layers > 0 and r.is_meaningful:
                decoded.append({"original": data[:100] + ("..." if len(data) > 100 else ""),
                                "decoded": r.final_text[:200], "chain": r.decode_chain,
                                "layers": r.total_layers, "flags": r.flags_found})
        except: continue
    return decoded


@mcp.tool()
def analyze_pcap(
    pcap_path: str,
    tshark_path: Optional[str] = None,
    max_packets: int = 0,
) -> Dict[str, Any]:
    """
    分析 pcap/pcapng 文件（同步）

    智能一站式分析，自动根据流量内容调用相关分析模块。

    Args:
        pcap_path: PCAP 文件路径（本机路径）
        tshark_path: 可选，显式指定 tshark 路径
        max_packets: 只分析前 N 个包（0 表示使用默认值 10000；用于大文件/快速预览）

    自动执行的分析：
        1. 协议统计（HTTP/TCP/UDP/ICMP/DNS/FTP/SMTP/USB/蓝牙等）
        2. Webshell 检测（蚁剑/菜刀/冰蝎/哥斯拉）
        3. OWASP 攻击检测（SQLi/XSS/RCE/XXE 等）
        4. ICMP 隐写分析（如果 ICMP 包 ≥ 5 个）
        5. 自动解码可疑数据
        6. FTP 分析（如果有 FTP 流量）- 提取凭据和文件
        7. SMTP 分析（如果有 SMTP 流量）- 提取认证和邮件
        8. USB 分析（如果有 USB 流量）- 还原键盘/鼠标数据
        9. 蓝牙分析（如果有蓝牙流量）- 提取 OBEX/L2CAP/GATT 数据

    Returns:
        ok: 是否成功
        version: MCP Server 版本
        total_packets: 总包数
        analysis_time: 分析耗时（秒）
        protocol_stats: 协议统计
        threat_count: 威胁总数
        webshell_detections: Webshell 检测结果
        attack_detections: 攻击检测结果
        icmp_analysis: ICMP 隐写分析结果
        auto_decoded: 自动解码结果
        ftp_analysis: FTP 分析结果
        smtp_analysis: SMTP 分析结果
        usb_analysis: USB 分析结果
        bluetooth_analysis: 蓝牙分析结果
        warnings: 分析过程中的警告
    """
    t0 = time.time()
    warnings: List[str] = []
    packets = None  # 延迟加载PDML，只在需要时才加载

    try:
        tshark = _find_tshark(tshark_path)
    except Exception as e:
        return {"ok": False, "error": str(e), "traceback": traceback.format_exc()}

    # 1. 协议统计（使用快速方法，与 GUI 对齐）
    proto_counts = {}
    total = 0
    try:
        proto_counts, total = _protocol_stats_fast(pcap_path, tshark)
    except Exception as e:
        warnings.append(f"协议统计失败: {e}")

    # 2. Webshell 检测（使用 EK 格式，与 GUI 对齐）
    webshell_results = []
    try:
        webshell_results = _detect_webshell_ek(pcap_path, tshark, max_packets=max_packets)
    except Exception as e:
        warnings.append(f"Webshell 检测异常: {e}")

    # 3. 攻击检测（使用与 GUI 相同的 tshark 格式）
    attack_results = []
    try:
        attack_results = _detect_attacks_ek(pcap_path, tshark, max_packets=max_packets)
    except Exception as e:
        warnings.append(f"攻击检测异常: {e}")

    # 4. ICMP 隐写分析（如果有 ICMP 流量）
    icmp_analysis = {"available": False}
    if proto_counts.get("ICMP", 0) >= 5:
        try:
            # 直接使用pyshark进行ICMP分析，不需要PDML
            icmp_analysis = _analyze_icmp_stego_direct(pcap_path, tshark)
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

    # 6. FTP 分析（如果有 FTP 流量）
    ftp_analysis = {"available": False}
    if proto_counts.get("FTP", 0) >= 1:
        try:
            import pyshark
            cap = pyshark.FileCapture(pcap_path, tshark_path=tshark)
            packets_list = list(cap)
            cap.close()

            credentials = []
            files = []
            current_user = None

            for pkt in packets_list:
                if 'FTP' in pkt:
                    try:
                        ftp = pkt.ftp
                        if hasattr(ftp, 'request_command'):
                            cmd = ftp.request_command.upper()
                            arg = getattr(ftp, 'request_arg', '').strip()
                            if cmd == 'USER':
                                current_user = arg
                            elif cmd == 'PASS' and current_user:
                                credentials.append({"username": current_user, "password": arg})
                            elif cmd in ['RETR', 'STOR']:
                                files.append({"command": cmd, "filename": arg})
                    except:
                        continue

            ftp_analysis = {
                "available": True,
                "credentials": credentials[:10],
                "files": files[:20],
            }
        except Exception as e:
            warnings.append(f"FTP 分析异常: {e}")

    # 7. SMTP 分析（如果有 SMTP 流量）
    smtp_analysis = {"available": False}
    if proto_counts.get("SMTP", 0) >= 1:
        try:
            import pyshark
            import base64
            import re

            cap = pyshark.FileCapture(pcap_path, tshark_path=tshark)

            credentials = []
            emails = []
            auth_stage = 0
            current_sender = None

            def safe_decode_b64(b64_str):
                try:
                    clean = re.sub(r'^[CS]:\s*', '', b64_str).strip()
                    missing = len(clean) % 4
                    if missing:
                        clean += '=' * (4 - missing)
                    return base64.b64decode(clean).decode('utf-8', errors='ignore')
                except:
                    return None

            for packet in cap:
                msg = ""
                if 'SMTP' in packet:
                    msg = getattr(packet.smtp, 'command_line', "") or ""
                if not msg:
                    continue
                raw_line = msg.strip()

                if "AUTH LOGIN" in raw_line.upper():
                    auth_stage = 1
                elif auth_stage == 1:
                    u = safe_decode_b64(raw_line)
                    if u:
                        credentials.append({"username": u})
                        auth_stage = 2
                elif auth_stage == 2:
                    p = safe_decode_b64(raw_line)
                    if p:
                        credentials.append({"password": p})
                        auth_stage = 0
                elif "MAIL FROM:" in raw_line.upper():
                    current_sender = raw_line[10:].split(' ')[0].strip('<>')
                    emails.append({"sender": current_sender})

            cap.close()

            smtp_analysis = {
                "available": True,
                "credentials": credentials[:10],
                "emails_found": len(emails),
            }
        except Exception as e:
            warnings.append(f"SMTP 分析异常: {e}")

    # 8. USB 分析（如果有 USB 流量）
    usb_analysis = {"available": False}
    if proto_counts.get("USB", 0) >= 1 and analyze_usb_traffic is not None:
        try:
            kb_content, mouse_trace = analyze_usb_traffic(pcap_path)
            usb_analysis = {
                "available": True,
                "keyboard_data": kb_content if kb_content else "",
                "mouse_point_count": len(mouse_trace) if mouse_trace else 0,
            }
        except Exception as e:
            warnings.append(f"USB 分析异常: {e}")

    # 9. 蓝牙分析（如果有蓝牙流量）
    bluetooth_analysis = {"available": False}
    if proto_counts.get("BLUETOOTH", 0) >= 1:
        try:
            import pyshark
            cap = pyshark.FileCapture(pcap_path, tshark_path=tshark)

            obex_count = 0
            l2cap_count = 0
            gatt_count = 0

            for packet in cap:
                if 'OBEX' in packet:
                    obex_count += 1
                if 'BT-L2CAP' in packet:
                    l2cap_count += 1
                if 'BTATT' in packet:
                    gatt_count += 1

            cap.close()

            bluetooth_analysis = {
                "available": True,
                "obex_count": obex_count,
                "l2cap_count": l2cap_count,
                "gatt_count": gatt_count,
            }
        except Exception as e:
            warnings.append(f"蓝牙分析异常: {e}")

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

        # FTP 分析
        "ftp_analysis": ftp_analysis,

        # SMTP 分析
        "smtp_analysis": smtp_analysis,

        # USB 分析
        "usb_analysis": usb_analysis,

        # 蓝牙分析
        "bluetooth_analysis": bluetooth_analysis,

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


@mcp.tool()
def analyze_ftp(
    pcap_path: str,
    tshark_path: Optional[str] = None,
) -> Dict[str, Any]:
    """
    分析 FTP 流量

    提取 FTP 登录凭据和传输文件信息。

    Args:
        pcap_path: PCAP 文件路径
        tshark_path: 可选，显式指定 tshark 路径

    Returns:
        ok: 是否成功
        credentials: 发现的用户名/密码列表
        files: 传输的文件信息列表
        commands: FTP 命令序列
    """
    if analyze_and_extract_ftp is None:
        return {"ok": False, "error": "ftp_analyzer 模块不可用"}

    try:
        if not os.path.exists(pcap_path):
            return {"ok": False, "error": f"文件不存在: {pcap_path}"}

        # 导入 pyshark 读取
        import pyshark
        tshark = _find_tshark(tshark_path)
        cap = pyshark.FileCapture(pcap_path, tshark_path=tshark)
        packets = list(cap)
        cap.close()

        credentials = []
        files = []
        commands = []
        current_user = None
        current_filename = None

        for pkt in packets:
            if 'FTP' in pkt:
                try:
                    ftp = pkt.ftp
                    if hasattr(ftp, 'request_command'):
                        cmd = ftp.request_command.upper()
                        arg = getattr(ftp, 'request_arg', '').strip()
                        commands.append(f"{cmd} {arg}".strip())

                        if cmd == 'USER':
                            current_user = arg
                        elif cmd == 'PASS' and current_user:
                            credentials.append({
                                "username": current_user,
                                "password": arg
                            })
                        elif cmd in ['RETR', 'STOR']:
                            current_filename = arg
                            files.append({
                                "command": cmd,
                                "filename": arg,
                                "type": "download" if cmd == "RETR" else "upload"
                            })

                    if hasattr(ftp, 'response_code') and ftp.response_code == '230':
                        # 登录成功
                        pass
                except Exception:
                    continue

        return {
            "ok": True,
            "credentials": credentials,
            "files": files,
            "commands": commands[:50],  # 限制命令数量
            "total_commands": len(commands),
        }
    except Exception as e:
        return {"ok": False, "error": str(e), "traceback": traceback.format_exc()}


@mcp.tool()
def analyze_smtp(
    pcap_path: str,
    tshark_path: Optional[str] = None,
) -> Dict[str, Any]:
    """
    分析 SMTP 邮件流量

    提取邮件发送者、接收者、主题和认证信息。

    Args:
        pcap_path: PCAP 文件路径
        tshark_path: 可选，显式指定 tshark 路径

    Returns:
        ok: 是否成功
        credentials: SMTP 认证信息
        emails: 邮件列表 [{sender, receiver, subject}]
        mail_count: 邮件总数
    """
    if extract_smtp_forensics is None:
        return {"ok": False, "error": "SMTP_analyzer 模块不可用"}

    try:
        if not os.path.exists(pcap_path):
            return {"ok": False, "error": f"文件不存在: {pcap_path}"}

        import pyshark
        import base64
        import re

        tshark = _find_tshark(tshark_path)
        cap = pyshark.FileCapture(pcap_path, tshark_path=tshark)

        credentials = []
        emails = []
        auth_stage = 0
        current_sender = None
        current_receiver = None
        collecting_data = False
        mail_buffer = []

        def safe_decode(b64_str):
            try:
                clean_str = re.sub(r'^[CS]:\s*', '', b64_str).strip()
                missing = len(clean_str) % 4
                if missing:
                    clean_str += '=' * (4 - missing)
                return base64.b64decode(clean_str).decode('utf-8', errors='ignore')
            except:
                return None

        for packet in cap:
            msg = ""
            if 'SMTP' in packet:
                msg = getattr(packet.smtp, 'command_line', "") or getattr(packet.smtp, 'response_line', "")
            if not msg and 'TCP' in packet and hasattr(packet.tcp, 'payload'):
                try:
                    msg = bytes.fromhex(packet.tcp.payload.replace(':', '')).decode('utf-8', errors='ignore')
                except:
                    continue
            if not msg:
                continue

            raw_line = msg.replace('\\xd\\xa', '').replace('\r', '').replace('\n', '').strip()
            if not raw_line:
                continue

            # 认证追踪
            if "AUTH LOGIN" in raw_line.upper():
                auth_stage = 1
                continue
            if auth_stage == 1:
                u = safe_decode(raw_line)
                if u:
                    credentials.append({"type": "username", "value": u})
                    auth_stage = 2
                    continue
            if auth_stage == 2:
                p = safe_decode(raw_line)
                if p:
                    credentials.append({"type": "password", "value": p})
                    auth_stage = 0
                    continue

            # 发件人/收件人
            if "MAIL FROM:" in raw_line.upper():
                current_sender = raw_line[10:].split(' ')[0].strip('<>')
            elif "RCPT TO:" in raw_line.upper():
                current_receiver = raw_line[8:].strip('<>')

            # 邮件内容
            if "DATA" in raw_line.upper():
                collecting_data = True
                mail_buffer = []
                continue

            if collecting_data:
                if raw_line == ".":
                    collecting_data = False
                    subject = "NoSubject"
                    for line in mail_buffer:
                        if line.upper().startswith("SUBJECT:"):
                            subject = line[8:].strip()
                            break
                    emails.append({
                        "sender": current_sender or "Unknown",
                        "receiver": current_receiver or "Unknown",
                        "subject": subject
                    })
                else:
                    mail_buffer.append(raw_line)

        cap.close()

        return {
            "ok": True,
            "credentials": credentials,
            "emails": emails[:20],
            "mail_count": len(emails),
        }
    except Exception as e:
        return {"ok": False, "error": str(e), "traceback": traceback.format_exc()}


@mcp.tool()
def analyze_usb(
    pcap_path: str,
    tshark_path: Optional[str] = None,
) -> Dict[str, Any]:
    """
    分析 USB 流量（键盘/鼠标）

    还原 USB 键盘输入和鼠标轨迹。

    Args:
        pcap_path: PCAP 文件路径
        tshark_path: 可选，显式指定 tshark 路径

    Returns:
        ok: 是否成功
        keyboard_data: 还原的键盘输入
        mouse_trace: 鼠标轨迹点列表
        mouse_point_count: 鼠标轨迹点数
    """
    if analyze_usb_traffic is None:
        return {"ok": False, "error": "usb_analyzer 模块不可用"}

    try:
        if not os.path.exists(pcap_path):
            return {"ok": False, "error": f"文件不存在: {pcap_path}"}

        # 直接调用 usb_analyzer 的函数
        kb_content, mouse_trace = analyze_usb_traffic(pcap_path)

        return {
            "ok": True,
            "keyboard_data": kb_content if kb_content else "",
            "mouse_trace": mouse_trace[:500] if mouse_trace else [],  # 限制点数
            "mouse_point_count": len(mouse_trace) if mouse_trace else 0,
        }
    except Exception as e:
        return {"ok": False, "error": str(e), "traceback": traceback.format_exc()}


@mcp.tool()
def analyze_bluetooth(
    pcap_path: str,
    tshark_path: Optional[str] = None,
) -> Dict[str, Any]:
    """
    分析蓝牙流量（OBEX/L2CAP/GATT）

    提取蓝牙文件传输和协议数据。

    Args:
        pcap_path: PCAP 文件路径
        tshark_path: 可选，显式指定 tshark 路径

    Returns:
        ok: 是否成功
        obex_files: OBEX 传输的文件列表
        l2cap_count: L2CAP 记录数量
        gatt_count: GATT 属性记录数量
    """
    if extract_bluetooth_data is None:
        return {"ok": False, "error": "bluetooth_analyzer 模块不可用"}

    try:
        if not os.path.exists(pcap_path):
            return {"ok": False, "error": f"文件不存在: {pcap_path}"}

        import pyshark
        import re

        tshark = _find_tshark(tshark_path)
        cap = pyshark.FileCapture(pcap_path, tshark_path=tshark)

        obex_files = []
        l2cap_count = 0
        gatt_count = 0
        obex_sessions = {}

        def clean_hex(raw_hex):
            if not raw_hex:
                return ""
            return re.sub(r'[^0-9a-fA-F]', '', str(raw_hex))

        for packet in cap:
            try:
                session_id = f"{packet.bluetooth.src}_{packet.bluetooth.dst}" if hasattr(packet, 'bluetooth') else "unknown"
            except:
                session_id = "unknown"

            if 'OBEX' in packet:
                obex = packet.obex
                if session_id not in obex_sessions:
                    obex_sessions[session_id] = {'filename': None, 'size': 0}

                if hasattr(obex, 'name'):
                    filename = str(obex.name)
                    obex_sessions[session_id]['filename'] = filename
                    obex_files.append({"filename": filename, "session": session_id})

            elif 'BT-L2CAP' in packet:
                l2cap_count += 1

            elif 'BTATT' in packet:
                gatt_count += 1

        cap.close()

        return {
            "ok": True,
            "obex_files": obex_files[:20],
            "l2cap_count": l2cap_count,
            "gatt_count": gatt_count,
        }
    except Exception as e:
        return {"ok": False, "error": str(e), "traceback": traceback.format_exc()}


@mcp.tool()
def decrypt_webshell(
    encrypted_data: str,
    shell_type: str = "auto",
    custom_key: Optional[str] = None,
) -> Dict[str, Any]:
    """
    解密 Webshell 加密流量（冰蝎/哥斯拉）

    Args:
        encrypted_data: 加密的数据（Base64 编码）
        shell_type: 类型 "behinder"/"godzilla"/"auto"（自动检测）
        custom_key: 可选，自定义密钥

    Returns:
        ok: 是否成功
        decrypted: 解密后的明文
        key_used: 使用的密钥
        shell_type: 检测到的 Shell 类型
    """
    try:
        import base64
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import unpad

        # 默认密钥
        BEHINDER_KEYS = ["e45e329feb5d925b"]  # md5("rebeyond")[:16]
        GODZILLA_KEYS = ["3c6e0b8a9c15224a"]

        if custom_key:
            BEHINDER_KEYS.insert(0, custom_key)
            GODZILLA_KEYS.insert(0, custom_key)

        # 尝试 Base64 解码
        try:
            encrypted_bytes = base64.b64decode(encrypted_data)
        except:
            return {"ok": False, "error": "Base64 解码失败"}

        decrypted = None
        key_used = None
        detected_type = None

        # 尝试冰蝎解密 (AES-128-CBC)
        if shell_type in ["auto", "behinder"]:
            for key in BEHINDER_KEYS:
                try:
                    key_bytes = key.encode('utf-8')[:16]
                    iv = key_bytes  # 冰蝎使用 key 作为 IV
                    cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
                    decrypted_bytes = unpad(cipher.decrypt(encrypted_bytes), AES.block_size)
                    decrypted = decrypted_bytes.decode('utf-8', errors='ignore')
                    key_used = key
                    detected_type = "behinder"
                    break
                except:
                    continue

        # 尝试哥斯拉解密 (XOR + Base64)
        if decrypted is None and shell_type in ["auto", "godzilla"]:
            for key in GODZILLA_KEYS:
                try:
                    key_bytes = key.encode('utf-8')
                    # 哥斯拉使用 XOR
                    xored = bytes([encrypted_bytes[i] ^ key_bytes[i % len(key_bytes)] for i in range(len(encrypted_bytes))])
                    # 尝试 Base64 解码
                    decrypted = base64.b64decode(xored).decode('utf-8', errors='ignore')
                    key_used = key
                    detected_type = "godzilla"
                    break
                except:
                    continue

        if decrypted:
            return {
                "ok": True,
                "decrypted": decrypted[:2000],  # 限制长度
                "key_used": key_used,
                "shell_type": detected_type,
            }
        else:
            return {
                "ok": False,
                "error": "解密失败，无法使用已知密钥解密",
            }

    except ImportError:
        return {"ok": False, "error": "缺少 pycryptodome 依赖，请执行: pip install pycryptodome"}
    except Exception as e:
        return {"ok": False, "error": str(e), "traceback": traceback.format_exc()}


@mcp.tool()
def fix_pcap(
    pcap_path: str,
    output_path: Optional[str] = None,
) -> Dict[str, Any]:
    """
    修复损坏的 PCAP 文件

    将非标准 .cap 文件重组为标准 .pcap 格式。

    Args:
        pcap_path: 待修复的文件路径
        output_path: 可选，修复后的文件保存路径

    Returns:
        ok: 是否成功
        output_file: 修复后的文件路径
        packets_recovered: 恢复的包数量
    """
    if fix_cap_to_pcap is None:
        return {"ok": False, "error": "fix_pcap 模块不可用"}

    try:
        if not os.path.exists(pcap_path):
            return {"ok": False, "error": f"文件不存在: {pcap_path}"}

        import struct

        # 标准 PCAP 全局头
        PCAP_GLOBAL_HEADER = b'\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x01\x00\x00\x00'

        with open(pcap_path, 'rb') as f:
            raw_data = f.read()

        # 查找第一个 IPv4 包
        first_packet_pos = raw_data.find(b'\x08\x00\x45')
        if first_packet_pos == -1:
            first_packet_pos = 128
        else:
            first_packet_pos -= 12  # 回退到 MAC 地址

        fixed_pcap = bytearray(PCAP_GLOBAL_HEADER)
        pos = first_packet_pos
        packet_count = 0
        file_size = len(raw_data)

        while pos < file_size - 60:
            try:
                next_sig = raw_data.find(b'\x08\x00\x45', pos + 14)
                if next_sig == -1:
                    current_len = file_size - pos
                else:
                    current_len = next_sig - 12 - pos

                if 40 <= current_len <= 1514:
                    p_header = struct.pack('<IIII', 0, 0, current_len, current_len)
                    fixed_pcap.extend(p_header)
                    fixed_pcap.extend(raw_data[pos:pos + current_len])
                    packet_count += 1
                    pos += current_len
                else:
                    pos += 1
            except:
                pos += 1

        if packet_count > 0:
            # 确定输出路径
            if output_path is None:
                base_name = os.path.splitext(os.path.basename(pcap_path))[0]
                output_dir = os.path.join(PROJECT_ROOT, "output", "fix_pcap_output")
                os.makedirs(output_dir, exist_ok=True)
                output_path = os.path.join(output_dir, f"fixed_{base_name}.pcap")

            with open(output_path, 'wb') as f:
                f.write(fixed_pcap)

            return {
                "ok": True,
                "output_file": output_path,
                "packets_recovered": packet_count,
                "original_size": len(raw_data),
                "fixed_size": len(fixed_pcap),
            }
        else:
            return {
                "ok": False,
                "error": "未能识别有效的以太网帧数据",
            }

    except Exception as e:
        return {"ok": False, "error": str(e), "traceback": traceback.format_exc()}


@mcp.tool()
def extract_files(
    pcap_path: str,
    tshark_path: Optional[str] = None,
    protocol: str = "http",
) -> Dict[str, Any]:
    """
    从流量中提取文件

    使用 TShark 的 --export-objects 功能提取 HTTP/IMF/SMB/TFTP 等协议的文件。

    Args:
        pcap_path: PCAP 文件路径
        tshark_path: 可选，显式指定 tshark 路径
        protocol: 协议类型 (http/imf/smb/tftp)

    Returns:
        ok: 是否成功
        files: 提取的文件列表
        output_dir: 文件输出目录
    """
    try:
        if not os.path.exists(pcap_path):
            return {"ok": False, "error": f"文件不存在: {pcap_path}"}

        import subprocess

        tshark = _find_tshark(tshark_path)

        # 创建输出目录
        base_name = os.path.splitext(os.path.basename(pcap_path))[0]
        output_dir = os.path.join(PROJECT_ROOT, "output", "extracted_files", base_name, protocol)
        os.makedirs(output_dir, exist_ok=True)

        # 执行 tshark 提取
        cmd = [tshark, '-r', pcap_path, '--export-objects', f'{protocol},{output_dir}']
        result = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8', errors='ignore')

        # 列出提取的文件
        files = []
        if os.path.exists(output_dir):
            for filename in os.listdir(output_dir):
                filepath = os.path.join(output_dir, filename)
                if os.path.isfile(filepath):
                    files.append({
                        "filename": filename,
                        "size": os.path.getsize(filepath),
                        "path": filepath,
                    })

        return {
            "ok": True,
            "files": files[:50],
            "total_files": len(files),
            "output_dir": output_dir,
        }

    except Exception as e:
        return {"ok": False, "error": str(e), "traceback": traceback.format_exc()}


def main():
    mcp.run()


if __name__ == "__main__":
    main()
