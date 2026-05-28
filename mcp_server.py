#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
听澜 MCP Server v1.0
流量分析工具集
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
analyze_usb_traffic = _import('usb_analyzer', 'analyze_usb_traffic')[0]
fix_cap_to_pcap = _import('fix_pcap', 'fix_cap_to_pcap')[0]
list_rtp_streams = _import('rtp_analyzer', 'list_rtp_streams')[0]
export_rtp_stream = _import('rtp_analyzer', 'export_rtp_stream')[0]
DNSCovertChannelAnalyzer = _import('protocol_analyzer', 'DNSCovertChannelAnalyzer')[0]
CobaltStrikeAnalyzer = _import('protocol_analyzer', 'CobaltStrikeAnalyzer')[0]


MCP_SERVER_VERSION = "v1.0"
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
              r"D:\Wireshark\tshark.exe",
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
        try:
            for wrapper in handler.stream_pyshark_compatible(config):
                if wrapper.has_layer('http'): http_pkts.append(wrapper)
                if len(http_pkts) >= limit: break
        finally:
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
               "-E", "separator=\t", "-E", "quote=d"]

        result = subprocess.run(cmd, capture_output=True, text=True,
                                encoding='utf-8', errors='replace', timeout=300)

        detector = AttackDetector()
        seen = set()
        limit = max_packets if max_packets > 0 else 10000

        for line in result.stdout.strip().split('\n'):
            if not line.strip(): continue
            try:
                fields = next(csv.reader(io.StringIO(line), delimiter='\t', quotechar='"'))
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


def _analyze_icmp(pcap_path, tshark_path):
    """ICMP隐写分析"""
    if not ICMPAnalyzer: return {"available": False, "error": "ICMPAnalyzer not loaded"}

    def _capture():
        import asyncio
        asyncio.set_event_loop(asyncio.new_event_loop())
        import pyshark
        cap = pyshark.FileCapture(pcap_path, tshark_path=tshark_path, display_filter='icmp')
        pkts = []
        try:
            for pkt in cap:
                pkts.append(pkt)
                if len(pkts) > 2000: break
        finally:
            cap.close()
        return pkts

    try:
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=1) as pool:
            pkts = pool.submit(_capture).result(timeout=60)
        if len(pkts) < 5: return {"available": False, "icmp_count": len(pkts)}
        result = ICMPAnalyzer().analyze(pkts)
        return {
            "available": True, "icmp_count": result.packet_count,
            "findings": [{"type": f.finding_type.value, "title": f.title, "data": f.data,
                          "confidence": f.confidence, "is_flag": f.is_flag} for f in result.findings],
            "possible_flags": result.get_flags(), "summary": result.summary
        }
    except Exception as e:
        import traceback
        return {"available": False, "error": str(e), "trace": traceback.format_exc()}


def _analyze_ftp_sub(pcap_path, tshark_path):
    """FTP 子分析（线程安全，避免 pyshark 事件循环冲突）"""
    def _capture():
        import asyncio
        asyncio.set_event_loop(asyncio.new_event_loop())
        import pyshark
        cap = pyshark.FileCapture(pcap_path, tshark_path=tshark_path, display_filter='ftp')
        credentials = []
        files = []
        commands = []
        current_user = None
        try:
            pkt_count = 0
            for pkt in cap:
                pkt_count += 1
                if pkt_count > 5000: break
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
                                credentials.append({"username": current_user, "password": arg})
                            elif cmd in ['RETR', 'STOR']:
                                files.append({"command": cmd, "filename": arg,
                                              "type": "download" if cmd == "RETR" else "upload"})
                        if hasattr(ftp, 'response_code') and ftp.response_code == '230':
                            pass
                    except Exception:
                        continue
        finally:
            cap.close()
        return credentials, files, commands

    try:
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=1) as pool:
            credentials, files, commands = pool.submit(_capture).result(timeout=60)
        return {
            "available": True,
            "credentials": credentials[:10],
            "files": files[:20],
            "commands": commands[:50],
            "total_commands": len(commands),
        }
    except Exception as e:
        return {"available": False, "error": str(e)}


def _analyze_smtp_sub(pcap_path, tshark_path):
    """SMTP 子分析（线程安全，避免 pyshark 事件循环冲突）"""
    def _capture():
        import asyncio
        asyncio.set_event_loop(asyncio.new_event_loop())
        import pyshark
        import base64
        import re

        cap = pyshark.FileCapture(pcap_path, tshark_path=tshark_path, display_filter='smtp')

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

        try:
            pkt_count = 0
            for packet in cap:
                pkt_count += 1
                if pkt_count > 5000: break
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

                if "MAIL FROM:" in raw_line.upper():
                    current_sender = raw_line[10:].split(' ')[0].strip('<>')
                elif "RCPT TO:" in raw_line.upper():
                    current_receiver = raw_line[8:].strip('<>')

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
        finally:
            cap.close()
        return credentials, emails

    try:
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=1) as pool:
            credentials, emails = pool.submit(_capture).result(timeout=60)
        return {
            "available": True,
            "credentials": credentials[:10],
            "emails": emails[:20],
            "mail_count": len(emails),
        }
    except Exception as e:
        return {"available": False, "error": str(e)}


def _analyze_bluetooth_sub(pcap_path, tshark_path):
    """蓝牙子分析（线程安全，避免 pyshark 事件循环冲突）"""
    def _capture():
        import asyncio
        asyncio.set_event_loop(asyncio.new_event_loop())
        import pyshark
        import re

        cap = pyshark.FileCapture(pcap_path, tshark_path=tshark_path, display_filter='bluetooth')

        obex_files = []
        l2cap_count = 0
        gatt_count = 0
        obex_sessions = {}

        def clean_hex(raw_hex):
            if not raw_hex:
                return ""
            return re.sub(r'[^0-9a-fA-F]', '', str(raw_hex))

        try:
            pkt_count = 0
            for packet in cap:
                pkt_count += 1
                if pkt_count > 5000: break
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
        finally:
            cap.close()
        return obex_files, l2cap_count, gatt_count

    try:
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=1) as pool:
            obex_files, l2cap_count, gatt_count = pool.submit(_capture).result(timeout=60)
        return {
            "available": True,
            "obex_files": obex_files[:20],
            "l2cap_count": l2cap_count,
            "gatt_count": gatt_count,
        }
    except Exception as e:
        return {"available": False, "error": str(e)}


def _detect_trigger_domain(pkts):
    """从DNS包中自动检测触发结算的域名。
    策略1：找数据查询（首标签>20字符且像编码数据）的公共父域名，如果它也作为裸查询出现。
    策略2：如果父域名是TLD(com/net等)，则在裸查询中找非常见域名的短域名（settlement信号）。"""
    from collections import Counter
    all_queries = []
    for pkt in pkts[:500]:
        try:
            qry = getattr(pkt.dns, 'qry_name', None)
            if not qry:
                qry = pkt.dns.get_field_value("qry_name") if hasattr(pkt.dns, 'get_field_value') else None
            if qry:
                all_queries.append(qry.lower())
        except Exception:
            continue

    if not all_queries:
        return None

    domain_counts = Counter(all_queries)
    TLDS = {'com', 'net', 'org', 'cn', 'io', 'cc', 'info', 'xyz', 'top', 'co'}

    # 识别数据载荷查询：首标签>20字符且看起来像编码数据
    data_parents = Counter()
    for qry in all_queries:
        parts = qry.split('.')
        if len(parts) >= 2:
            first_label = parts[0]
            parent = '.'.join(parts[1:])
            if len(first_label) > 20 and _looks_encoded(first_label):
                data_parents[parent] += 1

    if not data_parents:
        # 降低阈值再试：首标签>10字符
        for qry in all_queries:
            parts = qry.split('.')
            if len(parts) >= 3:
                first_label = parts[0]
                parent = '.'.join(parts[1:])
                if len(first_label) > 10 and _looks_encoded(first_label):
                    data_parents[parent] += 1

    if not data_parents:
        return None

    top_parent, top_count = data_parents.most_common(1)[0]

    # 检查父域名是否仅是TLD
    parent_parts = top_parent.split('.')
    is_tld_only = len(parent_parts) == 1 and parent_parts[0] in TLDS

    if not is_tld_only and top_count >= 3:
        # 策略1：父域名本身就是触发域名（如 i6ov08.dnslog.cn）
        if domain_counts.get(top_parent, 0) >= 1:
            return top_parent
        # 即使没有裸查询，足够多的数据查询也说明它是通道域名
        if top_count >= 10:
            return top_parent

    # 策略2：父域名是TLD或策略1未匹配，在裸查询中找settlement信号
    # settlement域名特征：短域名，出现多次，不是常见大站
    COMMON_DOMAINS = {
        'google.com', 'microsoft.com', 'baidu.com', 'qq.com', 'taobao.com',
        'alibaba.com', 'amazon.com', 'facebook.com', 'apple.com', 'github.com',
        'dangdang.com', 'jd.com', 'tmall.com', 'sina.com', 'sohu.com',
        'weibo.com', '163.com', '126.com', 'bilibili.com', 'zhihu.com',
        'douyin.com', 'tiktok.com', 'youtube.com', 'twitter.com', 'instagram.com',
    }

    candidates = []
    for domain, count in domain_counts.items():
        if count < 2:
            continue
        parts = domain.split('.')
        # 排除有长编码前缀的数据查询
        if len(parts[0]) > 20:
            continue
        # 排除常见域名及其子域名
        base = '.'.join(parts[-2:]) if len(parts) >= 2 else domain
        if base in COMMON_DOMAINS:
            continue
        # 排除纯TLD
        if domain in TLDS:
            continue
        # 倾向于选择短域名（2-3段）
        if len(parts) <= 4:
            candidates.append((domain, count))

    if candidates:
        # 按出现次数排序，次数相同则选较短的
        candidates.sort(key=lambda x: (-x[1], len(x[0])))
        return candidates[0][0]

    return None


def _looks_encoded(s):
    """判断字符串是否看起来像编码数据（hex或base64）"""
    if not s:
        return False
    # 纯hex
    if all(c in '0123456789abcdefABCDEF' for c in s):
        return True
    # base64样式（字母数字混合，可能包含-_+/）
    alnum_count = sum(1 for c in s if c.isalnum())
    if alnum_count / len(s) > 0.9:
        return True
    return False


def _detect_dns_encode_mode(pkts, trigger_domain=None):
    """从DNS包中采样子域名前缀，自动判断编码模式（hex/base64）。
    hex特征：前缀全部为0-9a-f；base64特征：包含大写字母或-_符号。"""
    prefixes = []
    for pkt in pkts[:200]:
        try:
            qry = getattr(pkt.dns, 'qry_name', None)
            if not qry:
                qry = pkt.dns.get_field_value("qry_name") if hasattr(pkt.dns, 'get_field_value') else None
            if not qry:
                continue
            if trigger_domain and qry.lower() == trigger_domain.lower():
                continue
            prefix = qry.split('.')[0]
            if len(prefix) > 4:
                prefixes.append(prefix)
        except Exception:
            continue

    if not prefixes:
        return "hex"  # 默认

    hex_count = 0
    b64_count = 0
    for p in prefixes:
        is_pure_hex = all(c in '0123456789abcdefABCDEF' for c in p)
        has_upper = any(c.isupper() for c in p)
        has_b64_special = any(c in '-_+/' for c in p)

        if is_pure_hex and not has_upper:
            hex_count += 1
        elif has_upper or has_b64_special:
            b64_count += 1
        else:
            hex_count += 1

    detected = "hex" if hex_count >= b64_count else "base64"
    return detected


def _enhanced_dns_decode(pkts, trigger_domain, decode_mode):
    """增强解码：从去重包列表中提取唯一前缀，去除子集重传，按触发域名分段解码。
    返回解码后的文本，或 None。"""
    import base64 as b64_mod

    # 1. 按顺序提取事件序列：prefix 或 trigger
    events = []  # list of ('data', prefix) or ('trigger',)
    seen_prefix = set()
    trigger_lower = trigger_domain.lower() if trigger_domain else ""
    for pkt in pkts:
        try:
            if not hasattr(pkt, 'dns'):
                continue
            qry = pkt.dns.get_field_value("qry_name") if hasattr(pkt.dns, 'get_field_value') else getattr(pkt.dns, 'qry_name', None)
            if not qry:
                continue
            qry_lower = qry.lower().removesuffix('.localdomain')
            if trigger_lower and qry_lower == trigger_lower:
                events.append(('trigger',))
                continue
            prefix = qry.split('.')[0]
            if len(prefix) <= 4:
                continue
            # 检查是否像编码数据
            if decode_mode == "hex":
                if not all(c in '0123456789abcdefABCDEF' for c in prefix):
                    continue
            else:
                if not all(c.isalnum() or c in '-_' for c in prefix):
                    continue
            if prefix not in seen_prefix:
                seen_prefix.add(prefix)
                events.append(('data', prefix))
        except Exception:
            continue

    if not events:
        return None

    # 2. 收集所有唯一前缀（用于子集检测）
    all_prefixes = [e[1] for e in events if e[0] == 'data']

    # 3. 去除子集重传：如果短前缀是长前缀的开头子串，标记为子集
    subset_prefixes = set()
    for i, p in enumerate(all_prefixes):
        for j, q in enumerate(all_prefixes):
            if i != j and len(q) > len(p) and q.startswith(p):
                subset_prefixes.add(p)
                break

    # 4. 按 trigger 分段，每段内拼接后解码
    segments = []
    current_buffer = []
    for event in events:
        if event[0] == 'trigger':
            if current_buffer:
                decoded = _decode_buffer(''.join(current_buffer), decode_mode)
                if decoded and decoded.strip():
                    segments.append(decoded.strip())
                current_buffer = []
        else:
            prefix = event[1]
            if prefix not in subset_prefixes:
                current_buffer.append(prefix)

    # 收尾
    if current_buffer:
        decoded = _decode_buffer(''.join(current_buffer), decode_mode)
        if decoded and decoded.strip():
            segments.append(decoded.strip())

    if not segments:
        return None
    return '\n'.join(segments)


def _decode_buffer(buffer, decode_mode):
    """解码单段 buffer"""
    import base64 as b64_mod
    try:
        if decode_mode == "hex":
            if len(buffer) % 2 != 0:
                buffer = buffer[:-1]
            raw_b64 = bytes.fromhex(buffer)
            return b64_mod.b64decode(raw_b64).decode("gb2312", errors='ignore')
        else:
            safe_b64 = buffer.replace('-', '+').replace('_', '/')
            padding = len(safe_b64) % 4
            if padding:
                safe_b64 += '=' * (4 - padding)
            return b64_mod.b64decode(safe_b64).decode("gb2312", errors='ignore')
    except Exception:
        return None


def _analyze_dns_covert(pcap_path, tshark_path, decode_mode="auto", trigger_domain="auto"):
    """DNS隐蔽通道分析（线程安全，避免 pyshark 事件循环冲突）
    trigger_domain='auto' 时自动从流量中检测触发域名。"""
    if not DNSCovertChannelAnalyzer:
        return {"ok": False, "error": "DNSCovertChannelAnalyzer not loaded"}

    def _capture():
        import asyncio
        asyncio.set_event_loop(asyncio.new_event_loop())
        import pyshark
        cap = pyshark.FileCapture(pcap_path, tshark_path=tshark_path, display_filter='dns')
        pkts = []
        try:
            for pkt in cap:
                pkts.append(pkt)
                if len(pkts) > 5000: break
        finally:
            cap.close()
        return pkts

    try:
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=1) as pool:
            pkts = pool.submit(_capture).result(timeout=120)

        if not pkts:
            return {"ok": True, "available": False, "dns_count": 0, "message": "未发现DNS包"}

        # 自动检测触发域名
        actual_trigger = trigger_domain
        auto_detected_trigger = None
        if trigger_domain == "auto":
            detected = _detect_trigger_domain(pkts)
            if detected:
                actual_trigger = detected
                auto_detected_trigger = detected
            else:
                actual_trigger = "bnh0.com"  # 回退默认

        # 自动检测编码模式
        actual_mode = decode_mode
        auto_detected_mode = None
        if decode_mode == "auto":
            actual_mode = _detect_dns_encode_mode(pkts, actual_trigger)
            auto_detected_mode = actual_mode

        # 预处理：按 qry_name 去重数据查询，保留所有触发域名包
        # 核心分析器使用 (stream_index, qry_name) 去重，但 DNS 重传会产生不同 stream_index
        # 导致同一查询被重复加入 buffer，引起解码错误
        seen_qry = set()
        deduped_pkts = []
        trigger_lower = actual_trigger.lower() if actual_trigger else ""
        for pkt in pkts:
            try:
                if not hasattr(pkt, 'dns'):
                    continue
                qry = pkt.dns.get_field_value("qry_name") if hasattr(pkt.dns, 'get_field_value') else getattr(pkt.dns, 'qry_name', None)
                if not qry:
                    continue
                qry_normalized = qry.lower().removesuffix('.localdomain')
                # 触发域名不去重（保留所有结算信号）
                if trigger_lower and qry_normalized == trigger_lower:
                    deduped_pkts.append(pkt)
                    continue
                # 数据查询按名称去重
                if qry_normalized not in seen_qry:
                    seen_qry.add(qry_normalized)
                    deduped_pkts.append(pkt)
            except Exception:
                deduped_pkts.append(pkt)

        analyzer = DNSCovertChannelAnalyzer(decode_mode=actual_mode, trigger_domain=actual_trigger)
        result = analyzer.analyze(deduped_pkts, decode_mode=actual_mode, trigger_domain=actual_trigger)

        # 增强解码：提取唯一前缀 → 去除子集重传 → 拼接 → 解码
        # 核心分析器的 buffer 拼接可能受重传子集干扰，这里独立计算一份清洁结果
        import base64 as b64_mod
        enhanced_decoded = _enhanced_dns_decode(deduped_pkts, actual_trigger, actual_mode)

        resp = {
            "ok": True,
            "available": True,
            "dns_count": result.packet_count,
            "decode_mode": actual_mode,
            "trigger_domain": actual_trigger,
            "findings": [f.to_dict() for f in result.findings],
            "summary": result.summary,
        }

        # Flag 提取：优先从增强解码结果中提取
        import re as _re
        all_flags = []
        partial_flags = []
        if enhanced_decoded:
            resp["enhanced_decoded"] = enhanced_decoded
            # 完整 flag: flag{...}
            flags_in_enhanced = _re.findall(r'flag\{[^}]+\}', enhanced_decoded, _re.IGNORECASE)
            all_flags.extend(flags_in_enhanced)
            # 不完整 flag: flag{... 到行尾
            if not flags_in_enhanced:
                partial = _re.findall(r'flag\{[^\n}]+', enhanced_decoded, _re.IGNORECASE)
                partial_flags.extend(partial)

        # TXT 指令中也可能包含 flag 片段
        txt_data = ""
        for f in result.findings:
            d = f.to_dict()
            if 'TXT' in d.get('title', ''):
                txt_data = d.get('data', '')
                txt_flags = _re.findall(r'flag\{[^}]+\}', txt_data, _re.IGNORECASE)
                all_flags.extend(txt_flags)

        # 尝试拼接不完整 flag：从 TXT 指令中找续接部分
        if partial_flags and txt_data:
            for pf in partial_flags:
                # 在 TXT 中查找看起来像后半段的十六进制+}
                continuations = _re.findall(r'[0-9a-fA-F]+\}', txt_data)
                for cont in continuations:
                    combined = pf + cont
                    if _re.match(r'flag\{[0-9a-fA-F]+\}$', combined, _re.IGNORECASE):
                        all_flags.append(combined)
                        break

        # 去重
        seen_flags = set()
        unique_flags = []
        for f in all_flags:
            if f not in seen_flags:
                seen_flags.add(f)
                unique_flags.append(f)

        # 如果增强解码没找到 flag，回退到核心分析器结果
        if not unique_flags:
            core_flags = result.get_flags()
            if core_flags:
                for f in core_flags:
                    clean_flags = _re.findall(r'flag\{[^}]+\}', f, _re.IGNORECASE)
                    unique_flags.extend(clean_flags)

        resp["possible_flags"] = unique_flags if unique_flags else []
        if auto_detected_mode:
            resp["auto_detected_mode"] = auto_detected_mode
        if auto_detected_trigger:
            resp["auto_detected_trigger"] = auto_detected_trigger
        return resp
    except Exception as e:
        import traceback as tb
        return {"ok": False, "error": str(e), "trace": tb.format_exc()}


def _analyze_cobalt_strike(pcap_path, tshark_path, key_file_path=None):
    """Cobalt Strike C2分析（线程安全，避免 pyshark 事件循环冲突）"""
    if not CobaltStrikeAnalyzer:
        return {"ok": False, "error": "CobaltStrikeAnalyzer not loaded"}

    def _capture():
        import asyncio
        asyncio.set_event_loop(asyncio.new_event_loop())
        import pyshark
        cap = pyshark.FileCapture(pcap_path, tshark_path=tshark_path, display_filter='http')
        pkts = []
        try:
            for pkt in cap:
                pkts.append(pkt)
                if len(pkts) > 5000: break
        finally:
            cap.close()
        return pkts

    try:
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=1) as pool:
            pkts = pool.submit(_capture).result(timeout=120)

        if not pkts:
            return {"ok": True, "available": False, "http_count": 0, "message": "未发现HTTP包"}

        analyzer = CobaltStrikeAnalyzer(key_file_path=key_file_path)

        # Stage 1: Cookie提取（始终执行）
        stage1_result = analyzer.analyze(pkts)
        cookies = stage1_result.metadata.get('cookies', [])
        findings = [f.to_dict() for f in stage1_result.findings]

        if not cookies:
            return {
                "ok": True,
                "available": True,
                "http_count": stage1_result.packet_count,
                "cookies_found": 0,
                "findings": findings,
                "summary": "未发现CS Metadata Cookie",
            }

        # Stage 2-4: 仅当提供 key_file_path 时执行完整解密
        # 注意：不能调用 analyzer.analyze_pcap()，因为它内部调用 list(cap) 会触发事件循环冲突
        if key_file_path and os.path.exists(key_file_path):
            base_name = os.path.splitext(os.path.basename(pcap_path))[0]
            output_dir = os.path.join(PROJECT_ROOT, "output", "cs_analysis", base_name)

            # Stage 2: 提取 RSA 私钥
            private_pem = analyzer._extract_keys_from_java_keystore(key_file_path)
            if not private_pem:
                findings.append({
                    "finding_type": "info", "protocol": "cobalt_strike",
                    "title": "密钥提取失败",
                    "description": f"无法从 {key_file_path} 提取RSA私钥 (需要 javaobj-py3)",
                    "confidence": 0.9, "is_flag": False
                })
                return {
                    "ok": True, "available": True,
                    "http_count": stage1_result.packet_count,
                    "cookies_found": len(cookies), "cookies": cookies[:10],
                    "findings": findings,
                    "summary": f"提取 {len(cookies)} 个Cookie, 密钥提取失败",
                }

            # 保存 PEM
            os.makedirs(output_dir, exist_ok=True)
            priv_path = os.path.join(output_dir, "cs_private.pem")
            with open(priv_path, "wb") as f:
                f.write(private_pem)
            extracted_files = [priv_path]

            # Stage 3: RSA解密Cookie → 解析Metadata
            try:
                from cryptography.hazmat.primitives import serialization
                from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
                import base64 as b64

                private_key = serialization.load_pem_private_key(private_pem, password=None)
            except ImportError:
                return {
                    "ok": True, "available": True,
                    "http_count": stage1_result.packet_count,
                    "cookies_found": len(cookies),
                    "findings": findings,
                    "summary": f"提取 {len(cookies)} 个Cookie, 缺少 cryptography 包",
                }
            except Exception as e:
                return {
                    "ok": True, "available": True,
                    "http_count": stage1_result.packet_count,
                    "cookies_found": len(cookies),
                    "findings": findings,
                    "summary": f"提取 {len(cookies)} 个Cookie, PEM加载失败: {e}",
                }

            sessions = []
            for idx, cookie_b64 in enumerate(cookies):
                try:
                    ciphertext = b64.b64decode(cookie_b64)
                    plaintext = private_key.decrypt(ciphertext, asym_padding.PKCS1v15())
                    session_info = analyzer._parse_metadata(plaintext)

                    if session_info:
                        # 转为JSON安全格式（去掉 bytes 字段）
                        safe_session = {k: v for k, v in session_info.items()
                                        if k not in ('aes_key', 'hmac_key')}
                        sessions.append(safe_session)

                        meta_str = (
                            f"Beacon ID: {session_info['bid']}, "
                            f"PID: {session_info['pid']}, "
                            f"Host: {session_info['host']}, "
                            f"User: {session_info['username']}@{session_info['pc_name']}, "
                            f"Arch: {session_info['barch']}, "
                            f"AES Key: {session_info['aes_key_hex']}"
                        )
                        findings.append({
                            "finding_type": "c2_communication", "protocol": "cobalt_strike",
                            "title": f"CS Session #{idx+1} Metadata",
                            "description": meta_str, "data": meta_str,
                            "confidence": 0.95, "is_flag": False
                        })
                except Exception:
                    continue

            summary_parts = [f"提取 {len(cookies)} 个Cookie", f"解密 {len(sessions)} 个Session"]
            if sessions:
                summary_parts.append(f"Beacon IDs: {', '.join(str(s['bid']) for s in sessions)}")

            return {
                "ok": True, "available": True,
                "http_count": stage1_result.packet_count,
                "cookies_found": len(cookies),
                "sessions_decrypted": len(sessions),
                "sessions": sessions,
                "findings": findings,
                "summary": "; ".join(summary_parts),
                "extracted_files": extracted_files,
            }

        return {
            "ok": True,
            "available": True,
            "http_count": stage1_result.packet_count,
            "cookies_found": len(cookies),
            "cookies": cookies[:10],
            "findings": findings,
            "summary": f"提取 {len(cookies)} 个Cookie, 未提供密钥文件",
        }
    except Exception as e:
        import traceback as tb
        return {"ok": False, "error": str(e), "trace": tb.format_exc()}


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
def analyze_pcap(pcap_path: str, tshark_path: Optional[str] = None, max_packets: int = 0) -> Dict[str, Any]:
    """
    分析pcap文件,自动检测Webshell、攻击、ICMP隐写、FTP/SMTP/USB/蓝牙流量。
    返回 recommended_actions 字段，根据实际检测结果动态列出建议的后续分析步骤（含工具名、参数和优先级），
    调用方应按 priority（high→medium→low）顺序依次执行建议的工具调用以完成深入分析。

    pcap_path: 文件路径
    tshark_path: tshark路径（可选）
    max_packets: 最大包数，0表示默认10000
    """
    t0 = time.time()
    warnings: List[str] = []

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
            icmp_analysis = _analyze_icmp(pcap_path, tshark)
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
            ftp_analysis = _analyze_ftp_sub(pcap_path, tshark)
        except Exception as e:
            warnings.append(f"FTP 分析异常: {e}")

    # 7. SMTP 分析（如果有 SMTP 流量）
    smtp_analysis = {"available": False}
    if proto_counts.get("SMTP", 0) >= 1:
        try:
            smtp_analysis = _analyze_smtp_sub(pcap_path, tshark)
        except Exception as e:
            warnings.append(f"SMTP 分析异常: {e}")

    # 8. USB 分析（如果有 USB 流量）
    usb_analysis = {"available": False}
    if proto_counts.get("USB", 0) >= 1 and analyze_usb_traffic is not None:
        try:
            kb_content, mouse_trace = analyze_usb_traffic(pcap_path, tshark)
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
            bluetooth_analysis = _analyze_bluetooth_sub(pcap_path, tshark)
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

    # 构建 recommended_actions —— 根据分析结果动态生成后续操作建议
    recommended_actions = []

    # 规则 1: 检测到 Webshell → 建议提取 HTTP 文件
    if webshell_results:
        recommended_actions.append({
            "tool": "extract_files",
            "reason": f"检测到 {len(webshell_results)} 个Webshell，建议提取HTTP文件进行深入分析",
            "params": {"pcap_path": pcap_path, "protocol": "http"},
            "priority": "high"
        })

    # 规则 2: 检测到 FTP 文件传输 → 建议独立 FTP 分析
    if ftp_analysis.get("available") and ftp_analysis.get("files"):
        recommended_actions.append({
            "tool": "analyze_ftp",
            "reason": f"发现 {len(ftp_analysis['files'])} 个FTP文件传输，建议深入分析并提取文件",
            "params": {"pcap_path": pcap_path},
            "priority": "medium"
        })

    # 规则 3: SMTP 有凭据 → 建议独立 SMTP 分析
    if smtp_analysis.get("available") and smtp_analysis.get("credentials"):
        recommended_actions.append({
            "tool": "analyze_smtp",
            "reason": "发现SMTP认证凭据，建议深入分析提取邮件内容和附件",
            "params": {"pcap_path": pcap_path},
            "priority": "medium"
        })

    # 规则 4: 蓝牙 OBEX 文件 → 建议独立蓝牙分析
    if bluetooth_analysis.get("available") and bluetooth_analysis.get("obex_files"):
        recommended_actions.append({
            "tool": "analyze_bluetooth",
            "reason": f"发现 {len(bluetooth_analysis['obex_files'])} 个蓝牙OBEX文件传输",
            "params": {"pcap_path": pcap_path},
            "priority": "medium"
        })

    # 规则 5: USB 鼠标轨迹 → 建议绘制轨迹图
    if usb_analysis.get("available") and usb_analysis.get("mouse_point_count", 0) > 50:
        recommended_actions.append({
            "tool": "analyze_usb",
            "reason": f"发现 {usb_analysis['mouse_point_count']} 个鼠标轨迹点，建议绘制轨迹图查看隐藏信息",
            "params": {"pcap_path": pcap_path},
            "priority": "medium"
        })

    # 规则 6: 有 MMS 协议 → 建议 MMS 分析
    if proto_counts.get("MMS", 0) >= 1:
        recommended_actions.append({
            "tool": "analyze_mms",
            "reason": "检测到MMS协议流量，建议提取文件传输数据",
            "params": {"pcap_path": pcap_path},
            "priority": "medium"
        })

    # 规则 7: 有 SMB 协议 → 建议 SMB 文件提取
    if proto_counts.get("SMB", 0) >= 1 or proto_counts.get("SMB2", 0) >= 1:
        recommended_actions.append({
            "tool": "extract_files",
            "reason": "检测到SMB协议流量，建议提取SMB共享文件",
            "params": {"pcap_path": pcap_path, "protocol": "smb"},
            "priority": "medium"
        })

    # 规则 8: 有 TFTP 协议 → 建议 TFTP 文件提取
    if proto_counts.get("TFTP", 0) >= 1:
        recommended_actions.append({
            "tool": "extract_files",
            "reason": "检测到TFTP协议流量，建议提取TFTP传输文件",
            "params": {"pcap_path": pcap_path, "protocol": "tftp"},
            "priority": "medium"
        })

    # 规则 9: Webshell 加密流量 → 建议解密
    if any(_jsonable(ws.detection_type) in ('behinder', 'godzilla') for ws in webshell_results):
        recommended_actions.append({
            "tool": "decrypt_webshell",
            "reason": "检测到冰蝎/哥斯拉加密Webshell流量，建议尝试解密",
            "params": {},
            "priority": "high"
        })

    # 规则 10: 有 HTTP 但没 Webshell → 也建议提取 HTTP 文件（低优先级）
    if proto_counts.get("HTTP", 0) >= 5 and not webshell_results:
        recommended_actions.append({
            "tool": "extract_files",
            "reason": f"检测到 {proto_counts['HTTP']} 个HTTP包，建议提取HTTP传输文件",
            "params": {"pcap_path": pcap_path, "protocol": "http"},
            "priority": "low"
        })

    # 规则 11: RTP 流量 → 建议 RTP 分析
    if proto_counts.get("RTP", 0) >= 1:
        recommended_actions.append({
            "tool": "analyze_rtp",
            "reason": "检测到RTP音视频流量，建议提取音视频流信息",
            "params": {"pcap_path": pcap_path},
            "priority": "medium"
        })

    # 规则 12: 大量 DNS → 建议 DNS 隐蔽通道分析
    if proto_counts.get("DNS", 0) >= 50:
        recommended_actions.append({
            "tool": "analyze_dns_covert",
            "reason": f"检测到 {proto_counts['DNS']} 个DNS包，建议分析DNS隐蔽通道",
            "params": {"pcap_path": pcap_path},
            "priority": "medium"
        })

    # 规则 13: HTTP 但无 Webshell/攻击 → 可能 CS C2
    if proto_counts.get("HTTP", 0) >= 10 and not webshell_results and not attack_results:
        recommended_actions.append({
            "tool": "analyze_cobalt_strike",
            "reason": "检测到HTTP流量但未发现Web攻击，建议排查Cobalt Strike C2通信",
            "params": {"pcap_path": pcap_path},
            "priority": "low"
        })

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

        # 后续操作建议
        "recommended_actions": recommended_actions,

        "warnings": warnings,
    }

    return result


@mcp.tool()
def auto_decode(data: str, crib: Optional[str] = None, max_depth: int = 10) -> Dict[str, Any]:
    """自动解码数据，支持Base64/Hex/URL/Gzip等多层嵌套"""
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
def detect_attack(data: str, attack_type: Optional[str] = None) -> Dict[str, Any]:
    """检测OWASP攻击签名：SQLi/XSS/XXE/RCE/SSRF/目录穿越等"""
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
def analyze_entropy(data: str, include_details: bool = True) -> Dict[str, Any]:
    """分析数据的信息熵，检测加密/混淆数据"""
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
def identify_file_type(data_hex: str) -> Dict[str, Any]:
    """识别文件类型（Magic Number），支持200+格式"""
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
def analyze_php_ast(code: str) -> Dict[str, Any]:
    """PHP AST语义分析，污点追踪检测Webshell"""
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
def analyze_ftp(pcap_path: str, tshark_path: Optional[str] = None) -> Dict[str, Any]:
    """分析FTP流量,提取凭据和文件传输信息。返回登录凭据(用户名/密码)、传输文件列表(文件名/上传或下载)和FTP命令记录"""
    try:
        if not os.path.exists(pcap_path):
            return {"ok": False, "error": f"文件不存在: {pcap_path}"}

        tshark = _find_tshark(tshark_path)
        result = _analyze_ftp_sub(pcap_path, tshark)
        if not result.get("available"):
            return {"ok": False, "error": result.get("error", "FTP 分析失败")}
        return {
            "ok": True,
            "credentials": result["credentials"],
            "files": result["files"],
            "commands": result.get("commands", []),
            "total_commands": result.get("total_commands", 0),
        }
    except Exception as e:
        return {"ok": False, "error": str(e), "traceback": traceback.format_exc()}


@mcp.tool()
def analyze_smtp(pcap_path: str, tshark_path: Optional[str] = None) -> Dict[str, Any]:
    """分析SMTP邮件流量,提取认证和邮件内容。返回认证凭据(用户名/密码)、邮件列表(发件人/收件人/主题)"""
    try:
        if not os.path.exists(pcap_path):
            return {"ok": False, "error": f"文件不存在: {pcap_path}"}

        tshark = _find_tshark(tshark_path)
        result = _analyze_smtp_sub(pcap_path, tshark)
        if not result.get("available"):
            return {"ok": False, "error": result.get("error", "SMTP 分析失败")}
        return {
            "ok": True,
            "credentials": result["credentials"],
            "emails": result["emails"],
            "mail_count": result["mail_count"],
        }
    except Exception as e:
        return {"ok": False, "error": str(e), "traceback": traceback.format_exc()}


@mcp.tool()
def analyze_usb(pcap_path: str, tshark_path: Optional[str] = None) -> Dict[str, Any]:
    """分析USB流量，还原键盘输入和鼠标轨迹"""
    if analyze_usb_traffic is None:
        return {"ok": False, "error": "usb_analyzer 模块不可用"}

    try:
        if not os.path.exists(pcap_path):
            return {"ok": False, "error": f"文件不存在: {pcap_path}"}

        tshark = _find_tshark(tshark_path)
        kb_content, mouse_trace = analyze_usb_traffic(pcap_path, tshark_path=tshark)

        return {
            "ok": True,
            "keyboard_data": kb_content if kb_content else "",
            "mouse_trace": mouse_trace[:500] if mouse_trace else [],  # 限制点数
            "mouse_point_count": len(mouse_trace) if mouse_trace else 0,
        }
    except Exception as e:
        return {"ok": False, "error": str(e), "traceback": traceback.format_exc()}


@mcp.tool()
def analyze_bluetooth(pcap_path: str, tshark_path: Optional[str] = None) -> Dict[str, Any]:
    """分析蓝牙流量,提取OBEX/L2CAP/GATT数据。能识别OBEX文件传输(文件名+会话),统计L2CAP和GATT交互次数"""
    try:
        if not os.path.exists(pcap_path):
            return {"ok": False, "error": f"文件不存在: {pcap_path}"}

        tshark = _find_tshark(tshark_path)
        result = _analyze_bluetooth_sub(pcap_path, tshark)
        if not result.get("available"):
            return {"ok": False, "error": result.get("error", "蓝牙分析失败")}
        return {
            "ok": True,
            "obex_files": result["obex_files"],
            "l2cap_count": result["l2cap_count"],
            "gatt_count": result["gatt_count"],
        }
    except Exception as e:
        return {"ok": False, "error": str(e), "traceback": traceback.format_exc()}


@mcp.tool()
def analyze_mms(pcap_path: str, tshark_path: Optional[str] = None) -> Dict[str, Any]:
    """分析MMS协议流量,追踪InvokeID提取文件传输数据。适用于工控/SCADA流量,提取文件内容预览和文件名"""
    try:
        if not os.path.exists(pcap_path):
            return {"ok": False, "error": f"文件不存在: {pcap_path}"}

        def _capture():
            import asyncio
            asyncio.set_event_loop(asyncio.new_event_loop())
            import pyshark

            tshark = _find_tshark(tshark_path)
            cap = pyshark.FileCapture(pcap_path, tshark_path=tshark, display_filter='mms')

            open_inv_to_name = {}
            frsm_to_name = {}
            read_inv_to_name = {}
            extracted_files = []

            try:
                for pkt in cap:
                    try:
                        if 'mms' not in [l.layer_name for l in pkt.layers]:
                            continue
                        mms = pkt.mms
                        inv_id = getattr(mms, "invokeid", None)

                        if hasattr(mms, "confirmedservicerequest") and int(mms.confirmedservicerequest) == 72:
                            if hasattr(mms, "filename_item"):
                                try:
                                    raw_fname = mms.filename_item.fields[0].get_default_value()
                                    fname = os.path.basename(str(raw_fname))
                                    if inv_id:
                                        open_inv_to_name[inv_id] = fname
                                except:
                                    pass

                        elif hasattr(mms, "confirmedserviceresponse") and int(mms.confirmedserviceresponse) == 72:
                            if inv_id in open_inv_to_name:
                                fname = open_inv_to_name.pop(inv_id)
                                if hasattr(mms, "frsmid"):
                                    frsm_to_name[str(mms.frsmid)] = fname

                        elif hasattr(mms, "confirmedservicerequest") and int(mms.confirmedservicerequest) == 73:
                            if hasattr(mms, "fileread"):
                                f_id = str(mms.fileread)
                                if f_id in frsm_to_name and inv_id:
                                    read_inv_to_name[inv_id] = frsm_to_name[f_id]

                        elif hasattr(mms, "confirmedserviceresponse") and int(mms.confirmedserviceresponse) == 73:
                            if inv_id in read_inv_to_name:
                                fname = read_inv_to_name.pop(inv_id)
                                if hasattr(mms, "filedata"):
                                    import binascii
                                    raw_val = str(mms.filedata).replace(":", "").replace(" ", "")
                                    try:
                                        data = binascii.unhexlify(raw_val)
                                    except:
                                        data = raw_val.encode('utf-8')
                                    extracted_files.append({
                                        "filename": fname,
                                        "size": len(data),
                                        "content_preview": data.decode(errors='ignore')[:200],
                                        "is_flag": "flag" in fname.lower(),
                                    })
                    except Exception:
                        continue
            finally:
                cap.close()
            return extracted_files

        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=1) as pool:
            extracted_files = pool.submit(_capture).result(timeout=120)

        return {
            "ok": True,
            "extracted_files": extracted_files,
            "file_count": len(extracted_files),
        }
    except Exception as e:
        return {"ok": False, "error": str(e), "traceback": traceback.format_exc()}


@mcp.tool()
def analyze_rtp(pcap_path: str, tshark_path: Optional[str] = None, export: bool = False) -> Dict[str, Any]:
    """分析RTP音视频流量,列出所有RTP流(SSRC/编码/媒体类型/时长)。当export=True时导出音频为WAV文件。
    RTP分析使用tshark,支持PCMU/PCMA/G722/G729等编码的自动转码。

    pcap_path: pcap文件路径
    tshark_path: tshark路径(可选)
    export: 是否导出音视频文件(默认False)
    """
    if list_rtp_streams is None:
        return {"ok": False, "error": "rtp_analyzer 模块不可用"}

    try:
        if not os.path.exists(pcap_path):
            return {"ok": False, "error": f"文件不存在: {pcap_path}"}

        tshark = _find_tshark(tshark_path)
        streams = list_rtp_streams(pcap_path, tshark)

        if not streams:
            return {"ok": True, "streams": [], "stream_count": 0, "message": "未发现RTP流"}

        streams_brief = []
        for s in streams:
            streams_brief.append({
                "ssrc": s.ssrc,
                "src_addr": s.src_addr,
                "dst_addr": s.dst_addr,
                "codec_name": s.codec_name,
                "media_type": s.media_type,
                "sample_rate": s.sample_rate,
                "packets": s.packets,
                "lost": s.lost,
                "max_jitter": s.max_jitter,
                "duration_sec": s.duration_sec,
            })

        exported_files = []
        if export and export_rtp_stream is not None:
            base_name = os.path.splitext(os.path.basename(pcap_path))[0]
            output_dir = os.path.join(PROJECT_ROOT, "output", "rtp_export", base_name)
            os.makedirs(output_dir, exist_ok=True)

            for s in streams:
                try:
                    out_path = export_rtp_stream(pcap_path, tshark, s, output_dir)
                    exported_files.append({
                        "ssrc": s.ssrc,
                        "codec": s.codec_name,
                        "path": out_path,
                    })
                except Exception as e:
                    exported_files.append({
                        "ssrc": s.ssrc,
                        "codec": s.codec_name,
                        "error": str(e),
                    })

        result = {
            "ok": True,
            "streams": streams_brief,
            "stream_count": len(streams_brief),
        }
        if exported_files:
            result["exported_files"] = exported_files
        return result

    except Exception as e:
        return {"ok": False, "error": str(e), "traceback": traceback.format_exc()}


@mcp.tool()
def analyze_dns_covert(pcap_path: str, tshark_path: Optional[str] = None,
                       decode_mode: str = "auto", trigger_domain: str = "auto") -> Dict[str, Any]:
    """分析DNS隐蔽通道流量,提取子域名编码数据、TXT指令和域名统计。
    支持hex(Hex→Base64→GB2312)和base64(Base64→GB2312)两种解码模式。
    decode_mode='auto'时自动检测编码模式。
    trigger_domain='auto'时自动从流量中检测触发结算的域名。

    pcap_path: pcap文件路径
    tshark_path: tshark路径(可选)
    decode_mode: 解码模式,'hex'或'base64'或'auto'(默认auto,自动检测)
    trigger_domain: 触发结算的域名(默认auto,自动检测)
    """
    if DNSCovertChannelAnalyzer is None:
        return {"ok": False, "error": "DNSCovertChannelAnalyzer 模块不可用"}

    try:
        if not os.path.exists(pcap_path):
            return {"ok": False, "error": f"文件不存在: {pcap_path}"}

        tshark = _find_tshark(tshark_path)
        result = _analyze_dns_covert(pcap_path, tshark, decode_mode=decode_mode,
                                     trigger_domain=trigger_domain)
        return result

    except Exception as e:
        return {"ok": False, "error": str(e), "traceback": traceback.format_exc()}


@mcp.tool()
def analyze_cobalt_strike(pcap_path: str, tshark_path: Optional[str] = None,
                          key_file_path: Optional[str] = None) -> Dict[str, Any]:
    """分析Cobalt Strike C2流量,提取HTTP Cookie中的Metadata。
    无key_file_path时仅提取Cookie和基本findings;
    有key_file_path时执行完整解密(RSA解密→Metadata解析→Session存储),返回Beacon ID/AES密钥/主机信息。

    pcap_path: pcap文件路径
    tshark_path: tshark路径(可选)
    key_file_path: .cobaltstrike.beacon_keys文件路径(可选)
    """
    if CobaltStrikeAnalyzer is None:
        return {"ok": False, "error": "CobaltStrikeAnalyzer 模块不可用"}

    try:
        if not os.path.exists(pcap_path):
            return {"ok": False, "error": f"文件不存在: {pcap_path}"}

        tshark = _find_tshark(tshark_path)
        result = _analyze_cobalt_strike(pcap_path, tshark, key_file_path=key_file_path)
        return result

    except Exception as e:
        return {"ok": False, "error": str(e), "traceback": traceback.format_exc()}


@mcp.tool()
def decrypt_webshell(encrypted_data: str, shell_type: str = "auto", custom_key: Optional[str] = None) -> Dict[str, Any]:
    """解密冰蝎/哥斯拉加密流量"""
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
def fix_pcap(pcap_path: str, output_path: Optional[str] = None) -> Dict[str, Any]:
    """修复损坏的PCAP文件"""
    if fix_cap_to_pcap is None:
        return {"ok": False, "error": "fix_pcap 模块不可用"}

    try:
        if not os.path.exists(pcap_path):
            return {"ok": False, "error": f"文件不存在: {pcap_path}"}

        import struct

        # 标准 PCAP 全局头
        PCAP_GLOBAL_HEADER = b'\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x01\x00\x00\x00'

        with open(pcap_path, 'rb') as f:
            raw_data = f.read(500 * 1024 * 1024)  # 最大读取 500MB

        # 查找第一个 IPv4 包
        first_packet_pos = raw_data.find(b'\x08\x00\x45')
        if first_packet_pos == -1:
            first_packet_pos = 128
        else:
            first_packet_pos = max(0, first_packet_pos - 12)  # 回退到 MAC 地址，但不能为负

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
            else:
                # 路径安全校验：防止路径穿越
                real_output = os.path.realpath(output_path)
                allowed_dirs = [
                    os.path.realpath(PROJECT_ROOT),
                    os.path.realpath(os.path.dirname(pcap_path)),
                ]
                if not any(real_output.startswith(d + os.sep) or real_output.startswith(d + "/") for d in allowed_dirs):
                    return {"ok": False, "error": f"输出路径不在允许的目录内，仅允许项目根目录或源文件所在目录"}
                ext = os.path.splitext(real_output)[1].lower()
                if ext not in ('.pcap', '.pcapng'):
                    return {"ok": False, "error": f"输出文件扩展名必须为 .pcap 或 .pcapng，当前为: {ext}"}
                os.makedirs(os.path.dirname(real_output), exist_ok=True)

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
def extract_files(pcap_path: str, tshark_path: Optional[str] = None, protocol: str = "http") -> Dict[str, Any]:
    """从流量提取文件(HTTP/IMF/SMB/TFTP)。可用 protocol 参数指定协议类型(http/imf/smb/tftp/dicom)。当 analyze_pcap 的 recommended_actions 提示时应调用此工具"""
    try:
        if not os.path.exists(pcap_path):
            return {"ok": False, "error": f"文件不存在: {pcap_path}"}

        # 校验 protocol 参数，防止命令注入
        ALLOWED_PROTOCOLS = {"http", "imf", "smb", "tftp", "dicom"}
        if protocol.lower() not in ALLOWED_PROTOCOLS:
            return {"ok": False, "error": f"不支持的协议: {protocol}，允许: {', '.join(sorted(ALLOWED_PROTOCOLS))}"}
        protocol = protocol.lower()

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
