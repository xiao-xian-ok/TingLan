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
import importlib
import threading
import re
import hashlib
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
_detection_models = importlib.import_module("models.detection_result")
DetectionResult = _detection_models.DetectionResult
DetectionType = _detection_models.DetectionType
ProtocolStats = _detection_models.ProtocolStats
AnalysisSummary = _detection_models.AnalysisSummary
ExtractedFile = _detection_models.ExtractedFile

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


MCP_SERVER_VERSION = "v1.1"
mcp = FastMCP("tinglan") if FastMCP else None

if mcp is None:
    def _no_mcp(*a, **kw):
        def _w(fn): return fn
        return _w
    class _NoMCP:
        tool = staticmethod(_no_mcp)
        def run(self): raise SystemExit("缺少 mcp 依赖")
    mcp = _NoMCP()


# ============================================================
# 日志 / 错误 / 路径校验 / 装饰器 (Critical fixes scaffold)
# ============================================================
import logging
import logging.handlers
import uuid
import atexit
import functools
import inspect
from core.safe_paths import iter_safe_child_files, safe_unique_path
from core.tshark_fields import parse_quoted_fields, separator_arg

LOG_DIR = os.path.join(PROJECT_ROOT, "logs")
try:
    os.makedirs(LOG_DIR, exist_ok=True)
except OSError:
    pass

logger = logging.getLogger("tinglan.mcp")
logger.setLevel(logging.DEBUG)
logger.propagate = False

if not logger.handlers:
    try:
        _file_h = logging.handlers.RotatingFileHandler(
            os.path.join(LOG_DIR, "mcp.log"),
            maxBytes=5 * 1024 * 1024, backupCount=5, encoding="utf-8")
        _file_h.setFormatter(logging.Formatter(
            "%(asctime)s %(levelname)s [%(name)s] %(message)s"))
        logger.addHandler(_file_h)
    except OSError as _e:
        pass
    _stderr_h = logging.StreamHandler(sys.stderr)
    _stderr_h.setLevel(logging.INFO)
    _stderr_h.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
    logger.addHandler(_stderr_h)


# 常量
_TSHARK_DEFAULT_TIMEOUT = 300
_MAX_FIX_PCAP_SIZE = 256 * 1024 * 1024  # 256MB,防全量读入内存 + O(n²) 扫描挂死
_ALLOWED_READ_EXTS = {".pcap", ".pcapng", ".cap"}
_ALLOWED_WRITE_EXTS = {".pcap", ".pcapng"}


def _safe_read_path(path: str) -> str:
    """校验读取的 pcap 路径。拒绝符号链接、非常规文件、非法扩展名。返 realpath。"""
    if not path or not isinstance(path, str):
        raise ValueError("路径不能为空")
    if os.path.islink(path):
        raise ValueError(f"拒绝符号链接: {path}")
    real = os.path.realpath(path)
    if not os.path.exists(real):
        raise FileNotFoundError(f"文件不存在: {path}")
    if not os.path.isfile(real):
        raise ValueError(f"不是常规文件: {path}")
    ext = os.path.splitext(real)[1].lower()
    if ext not in _ALLOWED_READ_EXTS:
        raise ValueError(
            f"不允许的扩展名 {ext!r},仅允许: {', '.join(sorted(_ALLOWED_READ_EXTS))}"
        )
    return real


def _safe_read_path_loose(path: str) -> str:
    """宽松路径校验:exists + realpath + 拒符号链接 + 常规文件,不限扩展名。
    用于 key_file_path 等非 pcap 文件(扩展名不在白名单内)。"""
    if not path or not isinstance(path, str):
        raise ValueError("路径不能为空")
    if os.path.islink(path):
        raise ValueError(f"拒绝符号链接: {path}")
    real = os.path.realpath(path)
    if not os.path.exists(real):
        raise FileNotFoundError(f"文件不存在: {path}")
    if not os.path.isfile(real):
        raise ValueError(f"不是常规文件: {path}")
    return real


def _safe_write_path(path: str, base_dirs: List[str]) -> str:
    """校验输出路径必须在 base_dirs 内,扩展名 ∈ {.pcap, .pcapng}。返 realpath。"""
    if not path or not isinstance(path, str):
        raise ValueError("输出路径不能为空")
    real = os.path.realpath(path)
    bases = [os.path.realpath(b) for b in base_dirs if b]
    allowed = any(
        real == b or real.startswith(b + os.sep) or real.startswith(b + "/")
        for b in bases
    )
    if not allowed:
        raise ValueError(
            f"输出路径不在允许目录内: {real}"
        )
    ext = os.path.splitext(real)[1].lower()
    if ext not in _ALLOWED_WRITE_EXTS:
        raise ValueError(f"输出扩展名必须为 .pcap 或 .pcapng,当前: {ext!r}")
    parent = os.path.dirname(real)
    if parent:
        try:
            os.makedirs(parent, exist_ok=True)
        except OSError as e:
            raise ValueError(f"无法创建输出目录: {e}") from e
    return real


def _new_error_id() -> str:
    return uuid.uuid4().hex[:12]


def _error_response(exc: Exception, error_id: str,
                    hint: Optional[str] = None) -> Dict[str, Any]:
    """统一错误响应。不含 traceback,客户端去 logs/mcp.log grep error_id。"""
    msg = str(exc) or exc.__class__.__name__
    resp: Dict[str, Any] = {"ok": False, "error": msg, "error_id": error_id}
    if hint:
        resp["hint"] = hint
    return resp


def _local_error(exc: Exception) -> Dict[str, Any]:
    """供 tool 内部 try/except 使用的本地错误返回。日志含 traceback,响应不含。"""
    error_id = _new_error_id()
    logger.exception("tool internal error id=%s", error_id)
    return {"ok": False,
            "error": str(exc) or exc.__class__.__name__,
            "error_id": error_id}


def pcap_tool(*, read_paths=(), write_paths=(), requires_modules=()):
    """MCP tool 包装器:统一处理路径校验、必需模块检查、异常包装、日志记录。

    read_paths: 参数名列表,这些参数会被 _safe_read_path 校验;
                元素可为 ("参数名", "any_ext") 元组 = 宽松模式(_safe_read_path_loose,不限扩展名)
    write_paths: [(参数名, base_from_param)] 列表;base 允许目录 = [PROJECT_ROOT, dirname(base_from)]
    requires_modules: [(module_obj, 中文标签)] 列表;任一为 None 则早返 error
    """
    def decorator(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            error_id = _new_error_id()

            # 阶段 1:模块依赖 + 入参解析 + 路径校验
            try:
                for mod, label in requires_modules:
                    if mod is None:
                        logger.warning("tool %s 模块不可用: %s id=%s",
                                       fn.__name__, label, error_id)
                        return {"ok": False,
                                "error": f"模块不可用: {label}",
                                "error_id": error_id}

                sig = inspect.signature(fn)
                bound = sig.bind_partial(*args, **kwargs)
                bound.apply_defaults()
                params = dict(bound.arguments)

                for spec in read_paths:
                    if isinstance(spec, tuple):
                        p_name, mode = spec
                        strict = mode != "any_ext"
                    else:
                        p_name, strict = spec, True
                    if p_name not in params or not params[p_name]:
                        continue
                    if strict:
                        params[p_name] = _safe_read_path(params[p_name])
                    else:
                        params[p_name] = _safe_read_path_loose(params[p_name])

                for spec in write_paths:
                    if isinstance(spec, tuple):
                        p_name, base_from = spec
                    else:
                        p_name, base_from = spec, None
                    if p_name not in params or not params[p_name]:
                        continue
                    bases = [PROJECT_ROOT]
                    if base_from and base_from in params and params[base_from]:
                        bases.append(os.path.dirname(params[base_from]))
                    params[p_name] = _safe_write_path(params[p_name], bases)

            except (FileNotFoundError, ValueError) as e:
                logger.warning("tool %s validation failed id=%s: %s",
                               fn.__name__, error_id, e)
                return _error_response(e, error_id)

            # 阶段 2:执行业务逻辑(业务里的 ValueError 不再被当成路径错)
            try:
                return fn(**params)
            except Exception as e:
                logger.exception("tool %s failed id=%s", fn.__name__, error_id)
                return _error_response(e, error_id)
        return wrapper
    return decorator


# 临时目录清理(C6)
try:
    from core.temp_cleanup import cleanup_stale_dirs, cleanup_own_dirs
    cleanup_stale_dirs(24)               # 启动清 24h 前残留
    atexit.register(cleanup_own_dirs)    # 退出清自己 PID
except Exception as _e:
    logger.warning("temp_cleanup 初始化失败: %s", _e)


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


def _is_num(v) -> bool:
    """数字类型校验,排除 bool(True 是 int 子类)与字符串。"""
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def _is_int(v) -> bool:
    """整数类型校验,排除 bool。"""
    return isinstance(v, int) and not isinstance(v, bool)


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
               "-E", separator_arg(), "-E", "quote=d"]

        result = subprocess.run(cmd, capture_output=True, text=True,
                                encoding='utf-8', errors='replace', timeout=300)

        detector = AttackDetector()
        seen = set()
        limit = max_packets if max_packets > 0 else 10000

        for line in result.stdout.strip().split('\n'):
            if not line.strip(): continue
            try:
                fields = parse_quoted_fields(line)
                if len(fields) < 7: continue

                frame, method, uri = fields[0].strip(), fields[1].strip(), fields[2].strip()
                content_type, file_data = fields[4].strip(), fields[6].strip()
                if not method: continue

                # 先构造 body:file_data 为冒号分隔 hex,还原明文;失败回退 URI 派生
                body = _http_body_from_file_data(file_data)
                if not body and '?' in uri: body = uri.split('?', 1)[1].encode('utf-8', errors='ignore')
                if not body: body = uri.encode('utf-8', errors='ignore')
                if not body or len(body) < 3: continue

                # 去重 key 基于内容指纹(body 必须先于 key 构造,防 URI 派生请求算出 md5(b"") 相同 key 被误合并)
                key = f"{method}:{uri[:100]}:{hashlib.md5(body).hexdigest()[:16]}"
                if key in seen: continue
                seen.add(key)

                det = detector.detect(data=body, method=method, uri=uri, content_type=content_type)
                if det.get('detected') and det.get('total_weight', 0) >= 20:
                    attacks.append({
                        "packet_number": int(frame) if frame.isdigit() else 0,
                        "attack_type": det.get("detection_type") or "unknown",  # detect() 字段名是 detection_type
                        "threat_level": det.get("threat_level", "info"),
                        "weight": det.get("total_weight", 0),
                        "method": method, "uri": uri[:200],
                        "indicators": det.get("indicators", [])[:5],
                        # AST/语义字段:detect() 返回的真实键
                        "entropy": det.get("entropy"),
                        "decode_chain": det.get("decode_chain"),
                        "ast_findings": det.get("ast_findings", [])[:10],
                        "tainted_sinks": det.get("tainted_sinks", [])[:5],
                        "obfuscation_score": det.get("obfuscation_score"),
                    })
                if len(attacks) >= limit: break
            except: continue
    except Exception as e:
        logger.warning("_detect_attacks_ek error: %s", e)
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
        return {"available": False, **_local_error(e)}


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
        return _local_error(e)


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
            # 注意：这里保持当前线程内逐包处理，避免 pyshark 事件循环冲突。
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
        return _local_error(e)


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
@pcap_tool(read_paths=["pcap_path"])
def analyze_pcap(pcap_path: str, tshark_path: Optional[str] = None, max_packets: int = 0) -> Dict[str, Any]:
    """
    分析pcap文件,自动检测Webshell、攻击、ICMP隐写、FTP/SMTP/USB/蓝牙流量。
    返回 recommended_actions 字段，根据实际检测结果动态列出建议的后续分析步骤（含工具名、参数和优先级），
    调用方应按 priority（high→medium→low）顺序依次执行建议的工具调用以完成深入分析。

    工具边界（按问题选最短路径，不要无意义走完整流程）：
    本工具为总入口：协议全景 + 已知攻击 + 后续建议，一般性问题优先本工具，一步出结果。
    仅需已知攻击汇总表格 → 用 summarize_detections；
    寻找隐藏/加密/未知异常数据（熵扫描）→ 用 scan_pcap_entropy（TCP/UDP 载荷熵）。
    无需在调用本工具之前先做熵扫描。

    深挖与研判（本工具之后，汇报前必做）：
    深挖：零检出但流量可疑时，优先 scan_pcap_entropy 熵分析 → dequeue_packet 取数 → auto_decode。
    禁用 Bash tshark 盲扫；仅两类场景允许 Bash：定向全流提取（dequeue 按流取数无法满足时）、自定义字段查询。
    研判：不得只罗列检测项 —— 必须按 MITRE 战术串联攻击链、评估危害等级、给出处置建议；
    依据不足（证据截断、类型 unknown）时，先 get_packet_data/dequeue 补证或 WebSearch 查 CVE 再下结论。

    pcap_path: 文件路径
    tshark_path: tshark路径（可选）
    max_packets: 最大包数，0表示默认10000
    """
    if not _is_int(max_packets) or max_packets < 0:
        return {"ok": False, "error": "max_packets 必须是非负整数"}
    t0 = time.time()
    warnings: List[str] = []

    try:
        tshark = _find_tshark(tshark_path)
    except Exception as e:
        return _local_error(e)

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
@pcap_tool(requires_modules=[(AutoDecoder, "auto_decoder"), (auto_decode_text, "auto_decoder")])
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
        return _local_error(e)


@mcp.tool()
@pcap_tool(requires_modules=[(AttackDetector, "attack_detector")])
def detect_attack(data: str, method: str = "GET", uri: str = "/",
                  content_type: str = "") -> Dict[str, Any]:
    """检测OWASP攻击签名：SQLi/XSS/XXE/RCE/SSRF/目录穿越等。
    method/uri/content_type 为请求上下文参数,检测器按上下文判定提升准确率。"""
    if AttackDetector is None:
        return {"ok": False, "error": "attack_detector 模块不可用"}

    try:
        detector = AttackDetector()
        result = detector.detect(data.encode('utf-8', errors='ignore'),
                                 method=method or "GET", uri=uri or "/",
                                 content_type=content_type or "")

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
            # AST/语义字段
            "entropy": result.get("entropy"),
            "decode_chain": result.get("decode_chain"),
            "ast_findings": result.get("ast_findings", [])[:10],
            "tainted_sinks": result.get("tainted_sinks", [])[:5],
            "obfuscation_score": result.get("obfuscation_score"),
        }
    except Exception as e:
        return _local_error(e)


@mcp.tool()
@pcap_tool(requires_modules=[(EntropyAnalyzer, "entropy_analyzer"), (MeaningfulnessAnalyzer, "entropy_analyzer")])
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
        return _local_error(e)


@mcp.tool()
@pcap_tool(requires_modules=[(FileRestorer, "file_restorer")])
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
        return _local_error(e)


@mcp.tool()
@pcap_tool(requires_modules=[(PHPASTEngine, "ast_engine")])
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
        return _local_error(e)


@mcp.tool()
@pcap_tool(read_paths=["pcap_path"])
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
        return _local_error(e)


@mcp.tool()
@pcap_tool(read_paths=["pcap_path"])
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
        return _local_error(e)


@mcp.tool()
@pcap_tool(read_paths=["pcap_path"], requires_modules=[(analyze_usb_traffic, "usb_analyzer")])
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
        return _local_error(e)


@mcp.tool()
@pcap_tool(read_paths=["pcap_path"])
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
        return _local_error(e)


@mcp.tool()
@pcap_tool(read_paths=["pcap_path"])
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
        return _local_error(e)


@mcp.tool()
@pcap_tool(read_paths=["pcap_path"], requires_modules=[(list_rtp_streams, "rtp_analyzer")])
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
        return _local_error(e)


@mcp.tool()
@pcap_tool(read_paths=["pcap_path"], requires_modules=[(DNSCovertChannelAnalyzer, "protocol_analyzer")])
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
        return _local_error(e)


@mcp.tool()
@pcap_tool(read_paths=["pcap_path", ("key_file_path", "any_ext")],
           requires_modules=[(CobaltStrikeAnalyzer, "protocol_analyzer")])
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
        return _local_error(e)


@mcp.tool()
@pcap_tool()
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
        return _local_error(e)


@mcp.tool()
@pcap_tool(read_paths=["pcap_path"], write_paths=[("output_path", "pcap_path")], requires_modules=[(fix_cap_to_pcap, "fix_pcap")])
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

        # C4: 拒收超过 1GB 的文件,避免一次性 read 撑爆内存
        try:
            file_size = os.path.getsize(pcap_path)
        except OSError as e:
            return {"ok": False, "error": f"无法读取文件大小: {e}"}
        if file_size > _MAX_FIX_PCAP_SIZE:
            return {"ok": False,
                    "error": f"文件超过 1GB 上限 ({file_size/1024/1024:.0f} MB),请用 Wireshark 先拆分"}

        with open(pcap_path, 'rb') as f:
            raw_data = f.read()

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
                    # 无下一个 IPv4 特征:剩余 40~1514 字节收尾为最后一包,否则放弃尾部垃圾
                    # (直接 break 而非 pos += 1 步进,消除 O(n²))
                    if 40 <= file_size - pos <= 1514:
                        current_len = file_size - pos
                    else:
                        break
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
                if not any(real_output == d or real_output.startswith(d + os.sep) or real_output.startswith(d + "/") for d in allowed_dirs):
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
        return _local_error(e)


@mcp.tool()
@pcap_tool(read_paths=["pcap_path"])
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

        # 创建输出目录(拼 pcap 路径 hash,防不同目录同名 pcap 互相覆盖)
        base_name = os.path.splitext(os.path.basename(pcap_path))[0]
        path_hash = hashlib.md5(os.path.realpath(pcap_path).encode("utf-8")).hexdigest()[:8]
        output_dir = os.path.join(PROJECT_ROOT, "output", "extracted_files", f"{base_name}_{path_hash}", protocol)
        os.makedirs(output_dir, exist_ok=True)

        # 执行 tshark 提取 (C5: 加超时,防止恶意 pcap 挂死)
        cmd = [tshark, '-r', pcap_path, '--export-objects', f'{protocol},{output_dir}']
        try:
            result = subprocess.run(cmd, capture_output=True, text=True,
                                    encoding='utf-8', errors='ignore',
                                    timeout=_TSHARK_DEFAULT_TIMEOUT)
        except subprocess.TimeoutExpired:
            return {"ok": False,
                    "error": f"tshark 超时 ({_TSHARK_DEFAULT_TIMEOUT}s),文件可能损坏或过大"}

        # 列出提取的文件
        files = []
        if os.path.exists(output_dir):
            for filepath, safe_name in iter_safe_child_files(output_dir):
                try:
                    current_name = os.path.basename(filepath)
                    if current_name != safe_name:
                        target, safe_name = safe_unique_path(output_dir, safe_name)
                        os.replace(filepath, target)
                        filepath = target
                    files.append({
                        "filename": safe_name,
                        "size": os.path.getsize(filepath),
                        "path": filepath,
                    })
                except Exception as e:
                    logger.warning("skip unsafe extracted file %s: %s", filepath, e)

        return {
            "ok": True,
            "files": files[:50],
            "total_files": len(files),
            "output_dir": output_dir,
        }

    except Exception as e:
        return _local_error(e)


# ============================================================
# 熵异常队列存储层(任务一)
# 纯索引零载荷:JSON 仅存帧号/流号/熵值等指针,绝不存载荷片段。
# 运行期以内存为准,变更后原子落盘(tmp → os.replace)。
# ============================================================

_ENTROPY_QUEUE_PREFIX = "entropy_"
_ENTROPY_QUEUE_FILE_RE = re.compile(r"^entropy_\d{8}_\d{6}_[0-9a-f]{8}\.json$")
_MAX_ENTROPY_QUEUES = 32
_MAX_ENTROPY_QUEUE_FILE_SIZE = 10 * 1024 * 1024  # 单队列 JSON 大小上限,防恶意大文件

# 内存态(唯一真相)
_entropy_queues: Dict[str, Dict[str, Any]] = {}            # queue_id -> queue dict
_entropy_index: Dict[Tuple[str, int], Set[str]] = {}       # (pcap_realpath, frame_num) -> {queue_id}
_peek_counts: Dict[str, Dict[int, int]] = {}               # queue_id -> {frame_num: peek次数}
_entropy_lock = threading.RLock()


def _entropy_queue_path(queue_id: str) -> str:
    """队列文件路径。queue_id 必须已通过正则白名单,禁止外部输入拼接路径。"""
    return os.path.join(PROJECT_ROOT, "output", queue_id + ".json")


def _entropy_save_locked(queue: Dict[str, Any]) -> None:
    """原子写:临时文件 + os.replace,防止半截 JSON。调用方须已持有锁。"""
    try:
        os.makedirs(os.path.join(PROJECT_ROOT, "output"), exist_ok=True)
        tmp = os.path.join(PROJECT_ROOT, "output", uuid.uuid4().hex + ".tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(queue, f, ensure_ascii=False)
        os.replace(tmp, _entropy_queue_path(queue["queue_id"]))
    except Exception as e:
        logger.warning("entropy queue persist failed id=%s: %s", queue.get("queue_id"), e)


def _entropy_index_add_locked(pcap_path: str, frame_num: int, queue_id: str) -> None:
    key = (pcap_path, frame_num)
    _entropy_index.setdefault(key, set()).add(queue_id)


def _entropy_index_remove_locked(queue: Dict[str, Any]) -> None:
    """按队列所有条目清理倒排索引。调用方须已持有锁。
    注意:必须在队列从 _entropy_queues 移除前/后都能工作,直接使用传入的队列数据。"""
    pcap_path = queue.get("pcap_path", "")
    for e in queue.get("queue", []):
        key = (pcap_path, e["frame_num"])
        holders = _entropy_index.get(key)
        if holders:
            holders.discard(queue["queue_id"])
            if not holders:
                _entropy_index.pop(key, None)


def _entropy_queue_delete_locked(queue_id: str) -> None:
    """删除队列:内存 + 倒排索引 + 磁盘文件。调用方须已持有锁。"""
    queue = _entropy_queues.pop(queue_id, None)
    if queue:
        _entropy_index_remove_locked(queue)
    _peek_counts.pop(queue_id, None)
    try:
        os.remove(_entropy_queue_path(queue_id))
    except OSError:
        pass


def _entropy_evict_locked() -> None:
    """全局容量 FIFO 驱逐:超过上限时删除最旧队列。调用方须已持有锁。"""
    while len(_entropy_queues) >= _MAX_ENTROPY_QUEUES:
        oldest = min(_entropy_queues.values(), key=lambda q: q.get("created_at", 0))
        _entropy_queue_delete_locked(oldest["queue_id"])


def _entropy_validate_queue(q: Any) -> bool:
    """加载时 schema 校验,防篡改/损坏 JSON 导致异常。"""
    if not isinstance(q, dict):
        return False
    for f in ("queue_id", "created_at", "pcap_path", "queue"):
        if not isinstance(q.get(f), (str, int, float, list)):
            return False
    if not isinstance(q.get("queue"), list):
        return False
    for e in q["queue"]:
        if not isinstance(e, dict):
            return False
        if not isinstance(e.get("frame_num"), int):
            return False
        if not isinstance(e.get("entropy"), (int, float)):
            return False
        if not isinstance(e.get("proto"), str):
            return False
    return True


def _entropy_load_on_startup() -> None:
    """启动恢复:扫描 output/entropy_*.json,校验后载入内存并重建倒排索引。
    失效(pcap 不存在)/损坏/超限文件跳过并日志警告,不阻断启动。"""
    out_dir = os.path.join(PROJECT_ROOT, "output")
    try:
        files = [f for f in os.listdir(out_dir) if _ENTROPY_QUEUE_FILE_RE.match(f)]
    except OSError:
        return
    for fname in sorted(files):
        path = os.path.join(out_dir, fname)
        queue_id = fname[:-len(".json")]
        try:
            if os.path.islink(path) or not os.path.isfile(path):
                logger.warning("entropy queue skip non-regular: %s", fname)
                continue
            if os.path.getsize(path) > _MAX_ENTROPY_QUEUE_FILE_SIZE:
                logger.warning("entropy queue skip oversized: %s", fname)
                continue
            with open(path, "r", encoding="utf-8") as f:
                q = json.load(f)
            if not _entropy_validate_queue(q) or q.get("queue_id") != queue_id:
                logger.warning("entropy queue skip invalid schema: %s", fname)
                continue
            real = os.path.realpath(q.get("pcap_path", ""))
            if not os.path.isfile(real):
                logger.warning("entropy queue skip missing pcap: %s -> %s", fname, q.get("pcap_path"))
                continue
            q["pcap_path"] = real
            with _entropy_lock:
                if len(_entropy_queues) >= _MAX_ENTROPY_QUEUES:
                    _entropy_evict_locked()
                _entropy_queues[queue_id] = q
                for e in q.get("queue", []):
                    _entropy_index_add_locked(real, e["frame_num"], queue_id)
        except Exception as e:
            logger.warning("entropy queue load failed %s: %s", fname, e)


_entropy_load_on_startup()


def _aggregate_flows(queue: Dict[str, Any]) -> List[Dict[str, Any]]:
    """队列内流聚合摘要(不重扫 pcap):按 (proto, stream_idx) 分组。
    UDP 无 tcp.stream,统一归入 stream=None 一组。"""
    groups: Dict[Tuple[str, int], List[Dict[str, Any]]] = {}
    for e in queue.get("queue", []):
        key = (e["proto"], e["stream_idx"])
        groups.setdefault(key, []).append(e)
    flows = []
    for (proto, sidx), items in sorted(groups.items(), key=lambda kv: -len(kv[1])):
        entropies = [i["entropy"] for i in items]
        lens = [i["len"] for i in items]
        flows.append({
            "stream": sidx if sidx >= 0 else None,
            "proto": proto,
            "count": len(items),
            "entropy_range": f"{min(entropies):.2f}-{max(entropies):.2f}",
            "avg_len": round(sum(lens) / len(lens), 1) if lens else 0,
            "sample_frame_num": items[0]["frame_num"],  # 该流队内熵最高的代表包
        })
    return flows


def _fetch_frame_data(pcap_path: str, frame_num: int, tshark_path: Optional[str] = None,
                      payload_max_bytes: int = 16384) -> Dict[str, Any]:
    """按帧号从原始 pcap 实时提取单包数据。pcap_path 每次使用前重新校验
    (_safe_read_path),防止队列 JSON 被篡改后指向任意文件。"""
    try:
        pcap_path = _safe_read_path(pcap_path)
    except (FileNotFoundError, ValueError) as e:
        return {"ok": False, "error": str(e)}
    import subprocess
    try:
        tshark = _find_tshark(tshark_path)
    except Exception as e:
        return {"ok": False, "error": str(e)}
    cmd = [tshark, "-r", pcap_path, "-Y", f"frame.number=={int(frame_num)}", "-T", "fields",
           "-e", "frame.time_relative", "-e", "frame.len", "-e", "ip.src", "-e", "ip.dst",
           "-e", "ip.proto", "-e", "tcp.srcport", "-e", "tcp.dstport",
           "-e", "udp.srcport", "-e", "udp.dstport", "-e", "tcp.stream",
           "-e", "http.request.method", "-e", "http.request.uri",
           "-e", "tcp.payload", "-e", "udp.payload",
           "-E", separator_arg(), "-E", "quote=d"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True,
                                encoding="utf-8", errors="replace", timeout=120)
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "tshark 超时"}
    line = result.stdout.strip().split("\n")[0] if result.stdout.strip() else ""
    if not line:
        return {"ok": False, "error": f"未找到帧 {frame_num}"}
    fields = parse_quoted_fields(line, 14)
    payload_hex = ""
    for i, fname in ((12, "tcp.payload"), (13, "udp.payload")):
        if fields[i]:
            payload_hex = fields[i].replace(":", "")
            break
    try:
        raw = bytes.fromhex(payload_hex) if payload_hex else b""
    except ValueError:
        raw = b""
    truncated = len(raw) > payload_max_bytes
    import base64
    payload_b64 = base64.b64encode(raw[:payload_max_bytes] if truncated else raw).decode("ascii")
    return {
        "ok": True,
        "frame_num": int(frame_num),
        "time_relative": float(fields[0]) if fields[0] else 0.0,
        "frame_len": int(fields[1]) if fields[1].isdigit() else 0,
        "src": fields[2], "dst": fields[3],
        "ip_proto": fields[4],
        "srcport": fields[5] or fields[7],
        "dstport": fields[6] or fields[8],
        "tcp_stream": int(fields[9]) if fields[9].isdigit() else -1,
        "http_method": fields[10], "http_uri": fields[11],
        "payload_base64": payload_b64,
        "payload_len": len(raw),
        "truncated": truncated,
    }


# ============================================================
# 任务一:熵异常发现
# ============================================================

@mcp.tool()
@pcap_tool(read_paths=["pcap_path"])
def scan_pcap_entropy(pcap_path: str, tshark_path: Optional[str] = None,
                      threshold: float = 7.0, max_results: int = 50,
                      max_packets: int = 0, preview_len: int = 0) -> Dict[str, Any]:
    """扫描pcap全量TCP/UDP载荷的信息熵,按熵降序保留高异常包,存入队列供后续按包取数。

    队列只存索引(帧号/熵/流号),不含任何载荷内容。返回 queue_id + 流聚合摘要,
    配合 list_entropy_queues / dequeue_packet 使用。

    pcap_path: 文件路径
    tshark_path: tshark路径(可选)
    threshold: 熵阈值,仅保留高于此值的包(0~8)
    max_results: 最多保留多少异常包(太多时只留最高熵的,上限500)
    max_packets: 最多扫描多少包,0表示全部
    preview_len: 保留参数(索引零载荷,不再返回载荷预览)

    流程引导(建议按序执行,可依据流量情况裁剪):
    1. scan 之后先调 list_entropy_queues 看流聚合摘要,判断是否加密流/C2流
    2. 再 dequeue_packet 逐包取数,载荷用 auto_decode 解码、detect_attack 判定类型
    3. 最后 summarize_detections 汇总已知攻击并渲染表格
    阈值经验:7.0 抓加密/压缩;5.5 左右可抓 URL/Base64 编码型异常;扫出 0 条时先降阈值重扫,
    仍为 0 且流量含 USB/蓝牙/DNS 等非 TCP/UDP 协议时,改用对应专用工具(熵扫描仅覆盖 TCP/UDP)。
    """
    if not _is_num(threshold) or not (0.0 <= threshold <= 8.0):
        return {"ok": False, "error": "threshold 必须是 0~8 之间的数字"}
    if not _is_int(max_results) or not (1 <= max_results <= 500):
        return {"ok": False, "error": "max_results 必须是 1~500 之间的整数"}
    if not _is_int(max_packets) or max_packets < 0:
        return {"ok": False, "error": "max_packets 必须是非负整数"}

    try:
        tshark = _find_tshark(tshark_path)
    except Exception as e:
        return _local_error(e)

    import subprocess as _sp
    cmd = [tshark, "-r", pcap_path, "-T", "fields",
           "-e", "frame.number", "-e", "frame.time_relative", "-e", "ip.proto",
           "-e", "tcp.stream", "-e", "tcp.payload", "-e", "udp.payload",
           "-E", separator_arg(), "-E", "quote=d"]

    try:
        proc = _sp.Popen(cmd, stdout=_sp.PIPE, stderr=_sp.DEVNULL,
                         text=True, encoding="utf-8", errors="replace")
    except Exception as e:
        return _local_error(e)

    # top-N 截断:(-entropy, frame_num, seq) 堆(前两项相同时比 seq 整数,不会比较 dict)
    # + entries_by_seq 配套容器(淘汰条目必须同步移除,防回查错乱)
    import heapq
    heap: List[tuple] = []
    entries_by_seq: Dict[int, Dict[str, Any]] = {}
    seq = 0
    scanned = 0
    start = time.time()
    try:
        for line in proc.stdout:
            scanned += 1
            if max_packets > 0 and scanned > max_packets:
                break
            if time.time() - start > _TSHARK_DEFAULT_TIMEOUT:
                break
            fields = parse_quoted_fields(line, 6)
            ip_proto = fields[2].strip() if len(fields) > 2 else ""
            if ip_proto not in ("6", "17"):
                continue
            payload_hex = (fields[4] if ip_proto == "6" else fields[5]).strip()
            if not payload_hex:
                continue
            try:
                payload = bytes.fromhex(payload_hex.replace(":", ""))
            except ValueError:
                continue
            if not payload:
                continue
            entropy = EntropyAnalyzer().calculate_entropy(payload)
            if entropy < threshold:
                continue
            try:
                frame_num = int(fields[0])
            except ValueError:
                continue
            timestamp = float(fields[1]) if fields[1] else 0.0
            stream = int(fields[3]) if fields[3].isdigit() else -1
            entry = {
                "frame_num": frame_num,
                "entropy": round(entropy, 4),
                "proto": "TCP" if ip_proto == "6" else "UDP",
                "len": len(payload),
                "stream_idx": stream,
                "timestamp": timestamp,
            }
            if len(heap) < max_results:
                heapq.heappush(heap, (-entropy, frame_num, seq))
            else:
                old = heapq.heappushpop(heap, (-entropy, frame_num, seq))
                if old is not None:
                    entries_by_seq.pop(old[2], None)  # 淘汰条目从容器同步删除
            entries_by_seq[seq] = entry
            seq += 1
    finally:
        if proc.poll() is None:
            proc.kill()
        proc.stdout.close()

    # 恢复熵降序(堆不保证顺序)
    heap.sort(key=lambda t: (-t[0], t[1]))
    kept = [entries_by_seq[t[2]] for t in heap]
    for i, e in enumerate(kept):
        e["position"] = i

    qid = _ENTROPY_QUEUE_PREFIX + time.strftime("%Y%m%d_%H%M%S") + "_" + uuid.uuid4().hex[:8]
    queue = {
        "queue_id": qid,
        "created_at": time.time(),
        "pcap_path": pcap_path,
        "pcap_size_mb": round(os.path.getsize(pcap_path) / 1024 / 1024, 1),
        "total_packets_scanned": scanned,
        "threshold_used": threshold,
        "queue": kept,
    }
    with _entropy_lock:
        _entropy_evict_locked()
        _entropy_queues[qid] = queue
        _entropy_save_locked(queue)
        for e in kept:
            _entropy_index_add_locked(pcap_path, e["frame_num"], qid)

    return {
        "ok": True,
        "queue_id": qid,
        "total_packets_scanned": scanned,
        "saved_count": len(kept),
        "top_entropy": kept[0]["entropy"] if kept else 0.0,
        "top_flows": _aggregate_flows(queue),
        "note": "队列仅存索引(帧号/熵/流号),载荷请用 dequeue_packet 或 get_packet_data 实时提取",
    }


@mcp.tool()
def list_entropy_queues() -> Dict[str, Any]:
    """列出所有熵异常队列:队列ID、创建时间、剩余条目数、关联pcap、流聚合摘要。
    流摘要为队列内聚合(不重扫pcap),用于识别高熵加密流。每条流含样例帧号(sample_frame_num)。

    流程引导:scan 之后调用本工具确认目标流。若某流(stream)大量高熵包集中,
    用 dequeue_packet(stream_idx=N) 按流依次取数 —— 无需知道帧号;
    仅当需要整条流的完整重组内容时,才用 Bash 执行 tshark -r <pcap> -Y "tcp.stream eq N" 提取。
    stream 为 null 的行是 UDP 聚合组(无 tcp.stream),对应 dequeue 的 stream_idx=-1。"""
    with _entropy_lock:
        queues = []
        for qid, q in sorted(_entropy_queues.items(), key=lambda kv: kv[1].get("created_at", 0)):
            queues.append({
                "queue_id": qid,
                "created_at": round(q.get("created_at", 0), 2),
                "remaining": len(q.get("queue", [])),
                "pcap_path": q.get("pcap_path", ""),
                "pcap_size_mb": q.get("pcap_size_mb", 0),
                "top_flows": _aggregate_flows(q),
            })
    return {"ok": True, "queue_count": len(queues), "queues": queues}


@mcp.tool()
def dequeue_packet(queue_id: str, position: Optional[int] = None, frame_num: Optional[int] = None,
                   stream_idx: Optional[int] = None, remove: bool = True,
                   tshark_path: Optional[str] = None,
                   payload_max_bytes: int = 16384) -> Dict[str, Any]:
    """从熵异常队列取一个包并实时提取完整载荷(Base64)。

    queue_id: 队列ID(scan_pcap_entropy 返回)
    position: 条目索引(0-based,队列按熵降序);不传时按 frame_num/stream_idx 定位,都没有则取队首
    frame_num: 精确帧号匹配(队列消费导致索引位移时用它)
    stream_idx: 按流取数,弹出该流在队内剩余的第一个条目(熵最高的那个);
                -1 表示 UDP 组(无 tcp.stream 的包);该流条目取尽后返回明确错误
    remove: True=弹出该条目;False=仅窥探(不移除)
    tshark_path: tshark路径(可选)
    payload_max_bytes: 返回载荷上限(超出截断并标记 truncated)

    建议流程:先 list_entropy_queues 看流摘要(含样例帧号) → 按流或按包取数 → remove=True 推进队列。
    注意:frame_num / stream_idx / position 三者最多指定一个,同时传多个会报错。

    流程引导:取到载荷后按序深挖 ——
    1. auto_decode 解码(URL/Base64/Gzip 多层嵌套)
    2. detect_attack 判定攻击类型;载荷为 PHP 代码时 analyze_php_ast 确认 webshell
    3. 载荷含版本指纹(如 Server: Apache/2.4.39)时,用 WebSearch 查对应 CVE 及利用条件
    4. 需要全量证据时调 get_packet_data(提高 payload_max_bytes)
    5. remove=True 会消费条目,确认分析完毕再消费;peek 仅供快速查看,连续 peek 会被警告
    """
    if not _ENTROPY_QUEUE_FILE_RE.match(queue_id + ".json"):
        return {"ok": False, "error": "非法的 queue_id 格式"}
    # ① 互斥检查:frame_num / stream_idx / position 最多指定一个
    if sum(p is not None for p in (frame_num, stream_idx, position)) > 1:
        return {"ok": False, "error": "frame_num / stream_idx / position 只能指定一个定位参数"}
    # ② 默认化:position 未指定 → 队首
    if position is None:
        position = 0
    # ③ 类型校验(互斥/默认化之后再校验,避免 None 被误拒)
    if not _is_int(position) or position < 0:
        return {"ok": False, "error": "position 必须是非负整数"}
    if frame_num is not None and (not _is_int(frame_num) or frame_num <= 0):
        return {"ok": False, "error": "frame_num 必须是正整数"}
    if stream_idx is not None and (not _is_int(stream_idx) or stream_idx < -1):
        return {"ok": False, "error": "stream_idx 必须是 >= -1 的整数(-1 表示 UDP 组)"}
    if not isinstance(remove, bool):
        return {"ok": False, "error": "remove 必须是布尔值"}
    if not _is_int(payload_max_bytes) or not (1 <= payload_max_bytes <= 1024 * 1024):
        return {"ok": False, "error": "payload_max_bytes 必须是 1~1048576 之间的整数"}

    with _entropy_lock:
        queue = _entropy_queues.get(queue_id)
        if not queue:
            return {"ok": False, "error": f"队列不存在或已被清空: {queue_id}"}
        item = None
        if frame_num is not None:
            for e in queue["queue"]:
                if e["frame_num"] == frame_num:
                    item = e
                    break
            if item is None:
                return {"ok": False, "error": f"队列中无帧 {frame_num}"}
        elif stream_idx is not None:
            for e in queue["queue"]:
                if e["stream_idx"] == stream_idx:
                    item = e
                    break
            if item is None:
                return {"ok": False, "error": f"队列中已无 stream_idx={stream_idx} 的条目"}
        else:
            if position >= len(queue["queue"]):
                return {"ok": False, "error": f"position {position} 越界(剩余 {len(queue['queue'])} 条)"}
            item = queue["queue"][position]
        target = dict(item)
        peek_hint = ""
        if not remove:
            cnt = _peek_counts.setdefault(queue_id, {}).get(target["frame_num"], 0) + 1
            _peek_counts[queue_id][target["frame_num"]] = cnt
            peek_hint = f"HINT: 该条目已窥探 {cnt} 次,请用 remove=True 消费"
            if cnt >= 3:
                peek_hint = f"WARNING: 已连续窥探 {cnt} 次,条目未消费。确认后用 dequeue(remove=True) 或 dequeue(frame_num={target['frame_num']}) 推进队列"

    result = _fetch_frame_data(queue["pcap_path"], target["frame_num"],
                               tshark_path=tshark_path, payload_max_bytes=payload_max_bytes)
    if not result.get("ok"):
        return {"ok": False, "error": result.get("error", "取数失败"), "frame_num": target["frame_num"]}

    if remove:
        with _entropy_lock:
            q = _entropy_queues.get(queue_id)
            if q:
                q["queue"] = [e for e in q["queue"] if e["frame_num"] != target["frame_num"]]
                _peek_counts.pop(queue_id, None)
                if not q["queue"]:
                    _entropy_queue_delete_locked(queue_id)
                else:
                    # 同步清理倒排索引,防止已消费帧被误标 in_entropy_queue
                    key = (q["pcap_path"], target["frame_num"])
                    holders = _entropy_index.get(key)
                    if holders:
                        holders.discard(queue_id)
                        if not holders:
                            _entropy_index.pop(key, None)
                    _entropy_save_locked(q)

    resp = {
        "ok": True,
        "queue_id": queue_id,
        "entropy": target["entropy"],
        "proto": target["proto"],
        "payload_len": target["len"],
        "stream_idx": target["stream_idx"],
        "packet": result,
    }
    if peek_hint:
        resp["hint"] = peek_hint
    return resp


@mcp.tool()
@pcap_tool(read_paths=["pcap_path"])
def get_packet_data(pcap_path: str, frame_num: int, tshark_path: Optional[str] = None,
                    payload_max_bytes: int = 16384) -> Dict[str, Any]:
    """无状态取包:不依赖队列,直接按帧号从 pcap 提取单包完整数据(Base64)。
    用于 AI 独立抽查或队列外的取证。

    流程引导:与 dequeue_packet 相同 —— 取到载荷后 auto_decode 解码 → detect_attack 判定
    → 版本信息 WebSearch 查 CVE → 综合研判。适合对 summarize_detections 中证据被截断的行补拉全量。"""
    if not _is_int(frame_num) or frame_num <= 0:
        return {"ok": False, "error": "frame_num 必须是正整数"}
    if not _is_int(payload_max_bytes) or not (1 <= payload_max_bytes <= 1024 * 1024):
        return {"ok": False, "error": "payload_max_bytes 必须是 1~1048576 之间的整数"}
    return _fetch_frame_data(pcap_path, frame_num, tshark_path=tshark_path,
                             payload_max_bytes=payload_max_bytes)


# ============================================================
# 任务二:已知攻击汇总
# ============================================================

# 检测类型 → (MITRE tactic, technique)。静态映射表,15 类。
_TACTIC_MAP: Dict[str, Tuple[str, str]] = {
    "sqli": ("Initial Access", "T1190 (Exploit Public-Facing Application)"),
    "xss": ("Initial Access", "T1189 (Drive-by Compromise)"),
    "rce": ("Execution", "T1203 (Exploit Client Execution)"),
    "xxe": ("Initial Access", "T1190 (Exploit Public-Facing Application)"),
    "ssrf": ("Initial Access", "T1190 (Exploit Public-Facing Application)"),
    "path_traversal": ("Initial Access", "T1190 (Exploit Public-Facing Application)"),
    "lfi": ("Initial Access", "T1190 (Exploit Public-Facing Application)"),
    "command_injection": ("Execution", "T1059 (Command and Scripting Interpreter)"),
    "deserialization": ("Execution", "T1203 (Exploit Client Execution)"),
    "file_upload": ("Initial Access", "T1190 (Exploit Public-Facing Application)"),
    "encrypted_http": ("Command and Control", "T1071.001 (Application Layer Protocol: Web)"),
    "antsword": ("Persistence", "T1505.003 (Web Shell)"),
    "caidao": ("Persistence", "T1505.003 (Web Shell)"),
    "behinder": ("Persistence", "T1505.003 (Web Shell)"),
    "godzilla": ("Persistence", "T1505.003 (Web Shell)"),
    "unknown": ("Unknown", ""),
}

_RULE_DESC_MAP: Dict[str, str] = {
    "sqli": "SQL注入:恶意查询注入数据库操作",
    "xss": "跨站脚本:注入恶意脚本执行",
    "rce": "远程代码执行:服务端执行攻击者代码",
    "xxe": "XML外部实体注入:读取本地文件或发起SSRF",
    "ssrf": "服务端请求伪造:探测内网或内部服务",
    "path_traversal": "目录穿越:读取服务器任意文件",
    "lfi": "本地文件包含:包含服务器本地文件",
    "command_injection": "命令注入:拼接执行系统命令",
    "deserialization": "反序列化攻击:构造恶意对象链执行代码",
    "file_upload": "文件上传攻击:上传恶意文件(如WebShell)",
    "encrypted_http": "可疑加密HTTP:高熵载荷疑似加密C2通信",
    "antsword": "蚁剑 WebShell 连接",
    "caidao": "菜刀(China Chopper)WebShell 连接",
    "behinder": "冰蝎加密 WebShell 连接",
    "godzilla": "哥斯拉加密 WebShell 连接",
    "unknown": "未分类的可疑请求",
}


def _http_body_from_file_data(file_data: str) -> Optional[bytes]:
    """tshark -e http.file_data 输出冒号分隔 hex,还原明文。
    先清冒号再截断(40000 hex 字符 = 20000 字节,保证偶数位不 ValueError);
    失败返回 None,由调用方回退 URI 派生。"""
    if not file_data:
        return None
    try:
        return bytes.fromhex(file_data.replace(":", "")[:40000])
    except ValueError:
        return None


def _looks_readable(data: bytes) -> bool:
    """熵 < 6.0 且近无 null = 文本(兼容 ASCII/UTF-8/GBK 中文);
    密文(熵高)或结构化二进制(含 null)判为不可读。"""
    if not data:
        return False
    if EntropyAnalyzer is not None and EntropyAnalyzer().calculate_entropy(data) >= 6.0:
        return False
    return data.count(0) / len(data) < 0.001


def _hex_to_text(raw: bytes) -> str:
    """tshark 字节字段还原为可读文本。双情形:
    A. 输入是 hex 文本(如旧数据流 b"3c:3f:70")→ fromhex 后按可读性还原或保留 hex;
    B. 输入是原始 bytes(L1 后明文 body 的常态)→ 可读(含中文)则 decode 显示,密文/二进制显示 hex。"""
    if not raw:
        return ""
    # 情形A:尝试 hex 文本解码
    try:
        clean = raw.decode("ascii", errors="ignore").replace(":", "")
        decoded = bytes.fromhex(clean)
    except ValueError:
        decoded = None
    if decoded:
        if _looks_readable(decoded):
            return decoded.decode("utf-8", errors="replace")
        return clean  # hex 文本形式的密文 → 保留 hex
    # 情形B:原始 bytes 输入
    if _looks_readable(raw):
        return raw.decode("utf-8", errors="replace")
    return raw.hex()  # 密文/二进制 → 显示 hex,可复制可分析


def _decode_payload_for_summary(raw_text: str) -> Tuple[str, bool]:
    """统一解码链路:复用 AutoDecoder(URL→Base64→Gzip 多层)。
    解出有意义返回 (明文, True);解不出返回 (原文 + [raw], False)。"""
    if not raw_text:
        return "", False
    try:
        r = auto_decode_text(raw_text)
        if r and r.total_layers > 0 and r.is_meaningful:
            return r.final_text[:2000], True
    except Exception:
        pass
    return raw_text[:2000] + " [raw]", False


def _collect_attacks_with_evidence(pcap_path: str, tshark_path: str,
                                   max_packets: int = 0) -> List[Dict[str, Any]]:
    """攻击检测(一次 tshark -T fields 调用),返回带原始载荷和帧号的结果。
    逻辑与 _detect_attacks_ek 一致,但保留 evidence/frame_number 供汇总表使用。"""
    import subprocess
    attacks = []
    try:
        cmd = [tshark_path, "-r", pcap_path, "-Y", "http.request", "-T", "fields",
               "-e", "frame.number", "-e", "http.request.method", "-e", "http.request.uri",
               "-e", "http.host", "-e", "http.content_type", "-e", "http.user_agent",
               "-e", "http.file_data", "-e", "ip.src", "-e", "ip.dst",
               "-E", separator_arg(), "-E", "quote=d"]
        result = subprocess.run(cmd, capture_output=True, text=True,
                                encoding="utf-8", errors="replace", timeout=300)
        detector = AttackDetector()
        seen = set()
        limit = max_packets if max_packets > 0 else 10000
        for line in result.stdout.strip().split("\n"):
            if not line.strip():
                continue
            try:
                fields = parse_quoted_fields(line)
                if len(fields) < 7:
                    continue
                frame = fields[0].strip()
                method, uri = fields[1].strip(), fields[2].strip()
                content_type, file_data = fields[4].strip(), fields[6].strip()
                if not method:
                    continue
                # 先构造 body:file_data 为冒号分隔 hex,还原明文;失败回退 URI 派生
                body = _http_body_from_file_data(file_data)
                if not body and "?" in uri:
                    body = uri.split("?", 1)[1].encode("utf-8", errors="ignore")
                if not body:
                    body = uri.encode("utf-8", errors="ignore")
                if not body or len(body) < 3:
                    continue
                # 去重 key 基于内容指纹(body 必须先于 key 构造)
                key = f"{method}:{uri[:100]}:{hashlib.md5(body).hexdigest()[:16]}"
                if key in seen:
                    continue
                seen.add(key)
                det = detector.detect(data=body, method=method, uri=uri, content_type=content_type)
                if det.get("detected") and det.get("total_weight", 0) >= 20:
                    atype = det.get("detection_type") or "unknown"  # detect() 字段名是 detection_type
                    attacks.append({
                        "frame_number": int(frame) if frame.isdigit() else 0,
                        "detection_type": atype,
                        "threat_level": det.get("threat_level", "info"),
                        "weight": det.get("total_weight", 0),
                        "method": method,
                        "uri": uri[:200],
                        "src": fields[7].strip(),
                        "dst": fields[8].strip(),
                        "body": body[:20000],
                        "indicators": det.get("indicators", [])[:5],
                        # AST/语义字段:detect() 返回的真实键
                        "entropy": det.get("entropy"),
                        "decode_chain": det.get("decode_chain"),
                        "ast_findings": det.get("ast_findings", [])[:10],
                        "tainted_sinks": det.get("tainted_sinks", [])[:5],
                        "obfuscation_score": det.get("obfuscation_score"),
                    })
                if len(attacks) >= limit:
                    break
            except Exception:
                continue
    except Exception as e:
        logger.warning("_collect_attacks_with_evidence error: %s", e)
    return attacks


@mcp.tool()
@pcap_tool(read_paths=["pcap_path"])
def summarize_detections(pcap_path: str, tshark_path: Optional[str] = None,
                         max_packets: int = 0) -> Dict[str, Any]:
    """汇总 pcap 的全部已知检测(WebShell + OWASP攻击签名),输出统一表格行。

    每行: frame_number / signature_id / detection_type / action_type
          (exec_command=可解码为命令 | data_attack=仅攻击载荷) /
          decoded(统一解码,解不出带[raw]) / evidence(长度+200字符预览) /
          tactic / technique / rule_description / group_count / in_entropy_queue。
    同源重复告警按(源+目的+命令/类型+URI)分组去重,保留组内最早包并计 group_count。
    in_entropy_queue 交叉标记:仅当该帧号也出现在同 pcap 的熵异常队列时生效。

    返回的 rows 供 AI 渲染攻击告警表,并据 tactic 写一段总览攻击链。

    流程引导:拿到 rows 后按序完成报告 ——
    1. 渲染攻击告警表:exec_command 行表头用"执行命令",data_attack 行用"攻击载荷/向量"
    2. 据 tactic/technique 列写一段总览攻击链(如 Initial Access(SQLi) → Persistence(WebShell))
    3. in_entropy_queue=true 的行可与熵队列交叉分析(高熵+攻击签名 = 高危)
    4. 证据被截断(evidence_len>200)的行,用 get_packet_data 或 dequeue_packet 拉全量载荷深挖
    5. 本工具未覆盖的协议(FTP/SMTP/USB/蓝牙/MMS/RTP/DNS隐蔽通道/CS C2),用对应专用工具分析
    6. 汇报前的综合研判(危害评估/处置建议)要求见 analyze_pcap 描述,此处不再重复
    """
    if not _is_int(max_packets) or max_packets < 0:
        return {"ok": False, "error": "max_packets 必须是非负整数"}
    try:
        tshark = _find_tshark(tshark_path)
    except Exception as e:
        return _local_error(e)

    # 1. 攻击检测(自带 evidence)
    attacks = _collect_attacks_with_evidence(pcap_path, tshark, max_packets=max_packets)
    # 2. WebShell 检测(复用现有 EK 链路)
    #    TODO(N3优化):WebShellDetector 目前吃 pyshark wrapper,待其支持 fields 输入后可合并为一次 tshark 调用
    webshells = _detect_webshell_ek(pcap_path, tshark, max_packets=max_packets)

    rows: List[Dict[str, Any]] = []

    for atk in attacks:
        decoded, is_decoded = _decode_payload_for_summary(atk["body"].decode("utf-8", errors="ignore"))
        rows.append({
            "frame_number": atk["frame_number"],
            "detection_type": atk["detection_type"],
            "action_type": "data_attack",
            "decoded": decoded,
            "evidence": _hex_to_text(atk["body"][:200]),
            "evidence_len": len(atk["body"]),  # body 已是明文,直接取真实字节数
            "method": atk["method"],
            "uri": atk["uri"],
            "src": atk["src"],
            "dst": atk["dst"],
            "weight": atk["weight"],
            "threat_level": atk.get("threat_level", "info"),
            "entropy": atk.get("entropy"),
            "decode_chain": atk.get("decode_chain"),
            "ast_findings": atk.get("ast_findings", [])[:5],
            "tainted_sinks": atk.get("tainted_sinks", [])[:5],
            "obfuscation_score": atk.get("obfuscation_score"),
        })

    for ws in webshells:
        try:
            frame_number = ws.packet_number or 0
            # 解码命令:优先检测器 payloads 里的 decoded_content,再走统一解码
            decoded = ""
            for p in (getattr(ws, "payloads", None) or []):
                if getattr(p, "decoded_content", ""):
                    decoded = p.decoded_content
                    break
            if not decoded:
                raw_payload = getattr(ws, "payload", None) or {}
                if isinstance(raw_payload, dict):
                    raw_text = json.dumps(raw_payload, ensure_ascii=False)[:2000]
                else:
                    raw_text = str(raw_payload)[:2000]
                decoded, _ = _decode_payload_for_summary(raw_text)
            evidence = getattr(ws, "indicator", "") or ""
            rows.append({
                "frame_number": frame_number,
                "detection_type": _jsonable(ws.detection_type),
                "action_type": "exec_command",
                "decoded": decoded,
                "evidence": evidence[:200],
                "evidence_len": len(evidence),
                "method": getattr(ws, "method", ""),
                "uri": getattr(ws, "uri", "") or "",
                "src": getattr(ws, "source_ip", "") or "",
                "dst": getattr(ws, "dest_ip", "") or "",
                "weight": getattr(ws, "total_weight", 0),
            })
        except Exception as e:
            logger.warning("summarize webshell row failed: %s", e)

    # 3. 分组去重:同源同目标的重复告警只留组内最早包
    groups: Dict[Tuple, List[Dict[str, Any]]] = {}
    for row in rows:
        if row["action_type"] == "exec_command":
            key = (row["src"], row["dst"], row["decoded"])
        else:
            key = (row["src"], row["dst"], row["detection_type"], row["uri"])
        groups.setdefault(key, []).append(row)

    merged: List[Dict[str, Any]] = []
    for group in groups.values():
        group.sort(key=lambda r: r["frame_number"])
        first = dict(group[0])
        first["group_count"] = len(group)
        merged.append(first)
    merged.sort(key=lambda r: r["frame_number"])

    # 4. 补 tactic / signature_id / 熵队列交叉标记
    pcap_real = os.path.realpath(pcap_path)
    final_rows = []
    for i, row in enumerate(merged):
        dt = row["detection_type"]
        tactic, technique = _TACTIC_MAP.get(dt, _TACTIC_MAP["unknown"])
        with _entropy_lock:
            in_queue = bool(_entropy_index.get((pcap_real, row["frame_number"])))
        final_rows.append({
            "signature_id": f"sig-{row['frame_number']}-{dt}-{i}",
            "frame_number": row["frame_number"],
            "detection_type": dt,
            "action_type": row["action_type"],
            "decoded": row["decoded"][:500],
            "evidence": row["evidence"],
            "evidence_len": row["evidence_len"],
            "method": row["method"],
            "uri": row["uri"],
            "src": row["src"],
            "dst": row["dst"],
            "weight": row["weight"],
            "threat_level": row.get("threat_level", "info"),
            "tactic": tactic,
            "technique": technique,
            "rule_description": _RULE_DESC_MAP.get(dt, "未分类的可疑请求"),
            "group_count": row["group_count"],
            "in_entropy_queue": in_queue,
            "entropy": row.get("entropy"),
            "decode_chain": row.get("decode_chain"),
            "ast_findings": row.get("ast_findings", [])[:5],
            "tainted_sinks": row.get("tainted_sinks", [])[:5],
            "obfuscation_score": row.get("obfuscation_score"),
        })

    return {
        "ok": True,
        "total_rows": len(final_rows),
        "rows": final_rows,
        "note": "交叉标记 in_entropy_queue 仅在同一 pcap 文件内有效;完整载荷请用 dequeue_packet 或 get_packet_data 提取",
    }


def main():
    mcp.run()


if __name__ == "__main__":
    main()
