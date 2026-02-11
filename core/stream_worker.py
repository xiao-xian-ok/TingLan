# stream_worker.py - 后台分析工作线程

import sys
import os
import gc
import time
import shlex
import logging
import threading
import weakref
from typing import Optional, Dict, List, Any, Set
from dataclasses import dataclass, field
from collections import deque

from PySide6.QtCore import QThread, Signal, QObject, QMutex, QMutexLocker

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CORE_PATH = os.path.join(PROJECT_ROOT, "core")
for path in [PROJECT_ROOT, CORE_PATH]:
    if path not in sys.path:
        sys.path.insert(0, path)

from core.tshark_stream import (
    TsharkProcessHandler,
    StreamConfig,
    OutputFormat,
    PacketData,
    PacketWrapper,
    TsharkError,
    TsharkNotFoundError,
    TsharkProcessError,
    TsharkPermissionError,
    get_protocol_stats
)

from models.detection_result import (
    DetectionResult,
    DetectionType,
    ThreatLevel,
    ProtocolStats,
    AnalysisSummary,
    ExtractedFile,
    ProtocolFinding,
    AutoDecodingResult,
    FileRecoveryResult
)

logger = logging.getLogger(__name__)


class ResourceLimits:
    MAX_DETECTIONS = 5000
    MAX_MEMORY_MB = 1024
    GC_INTERVAL = 100               # 每N个包触发一次GC
    BATCH_SIZE = 50
    FLUSH_INTERVAL_MS = 200
    MAX_QUEUE_SIZE = 1000
    PROGRESS_THROTTLE_MS = 100


@dataclass
class ThrottleConfig:
    batch_size: int = ResourceLimits.BATCH_SIZE
    flush_interval_ms: int = ResourceLimits.FLUSH_INTERVAL_MS
    max_queue_size: int = ResourceLimits.MAX_QUEUE_SIZE


class ResultBuffer:
    """线程安全的结果缓冲器，发送后立即清空，用deque限制大小"""

    def __init__(self, config: ThrottleConfig = None):
        self.config = config or ThrottleConfig()
        self._buffer: deque = deque(maxlen=self.config.max_queue_size)
        self._lock = threading.Lock()
        self._last_flush_time = time.time()
        self._total_flushed = 0

    def add(self, item: Any) -> Optional[List[Any]]:
        """添加项目，达到阈值时返回批次并清空"""
        with self._lock:
            self._buffer.append(item)

            current_time = time.time()
            elapsed_ms = (current_time - self._last_flush_time) * 1000
            should_flush = (
                len(self._buffer) >= self.config.batch_size or
                elapsed_ms >= self.config.flush_interval_ms
            )

            if should_flush:
                return self._flush_internal()

        return None

    def flush(self) -> List[Any]:
        with self._lock:
            return self._flush_internal()

    def _flush_internal(self) -> List[Any]:
        items = list(self._buffer)
        self._buffer.clear()
        self._last_flush_time = time.time()
        self._total_flushed += len(items)
        return items

    @property
    def size(self) -> int:
        with self._lock:
            return len(self._buffer)

    @property
    def total_flushed(self) -> int:
        return self._total_flushed

    def clear(self):
        with self._lock:
            self._buffer.clear()


class ProgressThrottler:
    """进度信号节流，防止发太快把UI卡住"""

    def __init__(self, interval_ms: int = ResourceLimits.PROGRESS_THROTTLE_MS):
        self._interval_ms = interval_ms
        self._last_emit_time = 0.0
        self._last_percent = -1

    def should_emit(self, percent: int) -> bool:
        current_time = time.time()
        elapsed_ms = (current_time - self._last_emit_time) * 1000

        if percent >= 100:
            self._last_emit_time = current_time
            self._last_percent = percent
            return True

        if elapsed_ms >= self._interval_ms and percent != self._last_percent:
            self._last_emit_time = current_time
            self._last_percent = percent
            return True

        return False


@dataclass
class AnalysisOptions:
    detect_webshell: bool = True
    detect_owasp: bool = True
    extract_files: bool = True
    auto_decode: bool = True
    file_recovery: bool = True
    custom_keys: Dict[str, str] = field(default_factory=dict)
    throttle: ThrottleConfig = field(default_factory=ThrottleConfig)
    max_detections: int = ResourceLimits.MAX_DETECTIONS


class StreamAnalysisWorker(QThread):
    """流式分析工作线程，带信号节流、内存回收、进度节流、结果上限"""

    progress = Signal(int, str)                # (百分比, 状态消息)
    batchResultsReady = Signal(list)           # 批量检测结果
    singleResultReady = Signal(object)         # 单条检测结果(兼容旧接口)
    protocolFindingFound = Signal(object)
    decodingResultFound = Signal(object)
    fileRecovered = Signal(object)
    finished = Signal(object)                  # AnalysisSummary
    error = Signal(str)
    cancelled = Signal()

    def __init__(
        self,
        pcap_path: str,
        options: AnalysisOptions = None,
        tshark_path: Optional[str] = None
    ):
        super().__init__()
        self.pcap_path = pcap_path
        self.options = options or AnalysisOptions()
        self.tshark_path = tshark_path or self._find_tshark_robust()

        self._handler: Optional[TsharkProcessHandler] = None
        self._is_cancelled = False

        self._result_buffer = ResultBuffer(self.options.throttle)
        self._progress_throttler = ProgressThrottler()

        self._packet_count = 0
        self._detection_count = 0
        self._start_time = 0.0

        self._seen_keys: Set[str] = set()
        self._gc_counter = 0

    def _find_tshark_robust(self) -> Optional[str]:
        """在常见位置找tshark"""
        import shutil

        tshark = shutil.which("tshark")
        if tshark:
            return tshark

        if sys.platform == "win32":
            common_paths = [
                r"E:\internet_safe\wireshark\tshark.exe",
                r"C:\Program Files\Wireshark\tshark.exe",
                r"C:\Program Files (x86)\Wireshark\tshark.exe",
                r"D:\Program Files\Wireshark\tshark.exe",
                r"D:\Wireshark\tshark.exe",
                os.path.join(os.environ.get("ProgramFiles", ""), "Wireshark", "tshark.exe"),
                os.path.join(os.environ.get("ProgramFiles(x86)", ""), "Wireshark", "tshark.exe"),
            ]
        else:
            common_paths = [
                "/usr/bin/tshark",
                "/usr/local/bin/tshark",
                "/opt/wireshark/bin/tshark",
            ]

        for path in common_paths:
            if path and os.path.exists(path):
                if os.access(path, os.X_OK) or sys.platform == "win32":
                    return path

        wireshark_path = os.environ.get("WIRESHARK_PATH")
        if wireshark_path:
            tshark_path = os.path.join(wireshark_path, "tshark.exe" if sys.platform == "win32" else "tshark")
            if os.path.exists(tshark_path):
                return tshark_path

        return None

    def cancel(self):
        self._is_cancelled = True
        if self._handler:
            self._handler.stop()

    def run(self):
        self._start_time = time.time()
        self._is_cancelled = False

        try:
            self._emit_progress(0, "正在初始化流式分析引擎...")

            if not self.tshark_path:
                self.error.emit(
                    "未找到 TShark！\n\n"
                    "请安装 Wireshark: https://www.wireshark.org/download.html\n\n"
                    "或设置环境变量 WIRESHARK_PATH 指向 Wireshark 安装目录"
                )
                return

            if not os.path.exists(self.tshark_path):
                self.error.emit(f"TShark 路径无效: {self.tshark_path}")
                return

            self._handler = TsharkProcessHandler(self.tshark_path)

            if self._is_cancelled:
                self.cancelled.emit()
                return

            summary = self._run_analysis()

            if self._is_cancelled:
                self.cancelled.emit()
                return

            self.finished.emit(summary)

        except TsharkNotFoundError as e:
            self.error.emit(f"未找到 TShark！\n{str(e)}")
        except TsharkPermissionError as e:
            self.error.emit(f"权限不足: {str(e)}\n\n请以管理员权限运行或检查文件访问权限")
        except TsharkProcessError as e:
            self.error.emit(f"TShark 执行错误: {str(e)}")
        except TsharkError as e:
            self.error.emit(f"TShark 错误: {str(e)}")
        except MemoryError:
            self.error.emit("内存不足！请关闭其他程序后重试，或分析较小的 PCAP 文件")
        except Exception as e:
            import traceback
            self.error.emit(f"分析错误: {str(e)}\n\n{traceback.format_exc()}")
        finally:
            self._flush_remaining_results()
            self._cleanup()

    def _emit_progress(self, percent: int, message: str):
        if self._progress_throttler.should_emit(percent):
            self.progress.emit(percent, message)

    def _flush_remaining_results(self):
        remaining = self._result_buffer.flush()
        if remaining:
            self.batchResultsReady.emit(remaining)

    def _cleanup(self):
        if self._handler:
            self._handler.stop()
            self._handler = None

        self._result_buffer.clear()
        self._seen_keys.clear()
        gc.collect()

        logger.debug(f"Worker 清理完成: 处理 {self._packet_count} 包, 发现 {self._detection_count} 威胁")

    def _trigger_gc_if_needed(self):
        self._gc_counter += 1
        if self._gc_counter >= ResourceLimits.GC_INTERVAL:
            gc.collect(0)  # 只回收0代，快
            self._gc_counter = 0

    def _run_analysis(self) -> AnalysisSummary:
        results: List[DetectionResult] = []
        protocol_findings: List[ProtocolFinding] = []
        decoding_results: List[AutoDecodingResult] = []
        recovered_files: List[FileRecoveryResult] = []
        extracted_files: List[ExtractedFile] = []

        # 协议统计
        self._emit_progress(5, "【阶段1/6】协议分级统计...")
        protocol_counts, total_packets = self._run_protocol_stats()

        if self._is_cancelled:
            return self._build_summary(results, [], protocol_findings, decoding_results, recovered_files, extracted_files, total_packets)

        # HTTP流式分析
        self._emit_progress(15, "【阶段2/6】HTTP 流式分析...")
        http_results = self._run_http_stream_analysis(total_packets)
        results.extend(http_results)

        if self._is_cancelled:
            return self._build_summary(results, [], protocol_findings, decoding_results, recovered_files, extracted_files, total_packets)

        # ICMP隐写检测
        self._emit_progress(45, "【阶段3/6】ICMP 隐写检测...")
        icmp_findings = self._run_icmp_analysis()
        protocol_findings.extend(icmp_findings)

        if self._is_cancelled:
            return self._build_summary(results, [], protocol_findings, decoding_results, recovered_files, extracted_files, total_packets)

        # HTTP对象提取
        self._emit_progress(60, "【阶段4/6】HTTP 对象提取...")
        extracted_files = self._export_http_objects()

        if self._is_cancelled:
            return self._build_summary(results, [], protocol_findings, decoding_results, recovered_files, extracted_files, total_packets)

        # 自动解码
        if self.options.auto_decode:
            self._emit_progress(75, f"【阶段5/6】自动解码 ({len(results)} 条结果)...")
            decoding_results = self._run_auto_decoding(results)

        if self._is_cancelled:
            return self._build_summary(results, [], protocol_findings, decoding_results, recovered_files, extracted_files, total_packets)

        # 文件还原
        if self.options.file_recovery:
            self._emit_progress(88, f"【阶段6/6】文件还原 ({len(extracted_files)} 个文件)...")
            recovered_files = self._run_file_recovery(extracted_files)

        self._emit_progress(95, "生成分析报告...")
        protocol_stats = self._build_protocol_stats(protocol_counts, total_packets)

        return self._build_summary(
            results, protocol_stats, protocol_findings,
            decoding_results, recovered_files, extracted_files, total_packets
        )

    def _run_protocol_stats(self) -> tuple:
        try:
            return get_protocol_stats(self.pcap_path, self.tshark_path)
        except Exception as e:
            logger.warning(f"协议统计失败: {e}")
            return {}, 0

    def _run_http_stream_analysis(self, total_packets: int) -> List[DetectionResult]:
        """HTTP流式分析，带信号节流和结果上限"""
        logger.debug(f"_run_http_stream_analysis: total_packets={total_packets}")
        results: List[DetectionResult] = []
        limit_reached = False

        try:
            from core.attack_detector import AttackDetector
            detector = AttackDetector()

            config = StreamConfig(
                pcap_path=self.pcap_path,
                display_filter="http.request",
                output_format=OutputFormat.EK,
                disable_name_resolution=True,
                line_buffered=True
            )
            logger.debug(f"StreamConfig: {config.pcap_path}, filter={config.display_filter}")

            http_count = 0
            last_progress_time = time.time()

            for packet in self._handler.stream_packets(config):
                if self._is_cancelled:
                    break

                self._packet_count += 1
                http_count += 1

                if http_count % 50 == 0:
                    logger.debug(f"已处理 {http_count} 个 HTTP 请求, 检测到 {len(results)} 威胁")

                self._trigger_gc_if_needed()

                current_time = time.time()
                if current_time - last_progress_time >= 0.5:
                    pct = min(15 + int((http_count / max(total_packets, 1)) * 28), 43)
                    self._emit_progress(pct, f"HTTP分析中... ({http_count} 请求, {len(results)} 威胁)")
                    last_progress_time = current_time

                # 去重
                dedup_key = f"{packet.http_method}:{packet.http_uri[:100] if packet.http_uri else ''}:{len(packet.http_request_body)}"
                if dedup_key in self._seen_keys:
                    del packet
                    continue
                self._seen_keys.add(dedup_key)

                if len(results) >= self.options.max_detections:
                    if not limit_reached:
                        limit_reached = True
                        logger.warning(f"检测结果已达上限 {self.options.max_detections}，跳过后续检测")
                    del packet
                    continue

                detection = self._detect_packet(detector, packet)
                del packet  # 检测完释放

                if detection:
                    results.append(detection)
                    self._detection_count += 1

                    batch = self._result_buffer.add(detection)
                    if batch:
                        self.batchResultsReady.emit(batch)

            remaining = self._result_buffer.flush()
            if remaining:
                self.batchResultsReady.emit(remaining)

            self._seen_keys.clear()

            self._emit_progress(43, f"HTTP分析完成: {http_count} 请求, {len(results)} 威胁")

        except TsharkError as e:
            self._emit_progress(43, f"HTTP分析警告: {str(e)[:40]}")
            raise
        except Exception as e:
            logger.warning(f"HTTP流式分析异常: {e}")

        return results

    def _detect_packet(self, detector, packet: PacketData) -> Optional[DetectionResult]:
        try:
            body = packet.http_request_body
            if not body and packet.http_uri and '?' in packet.http_uri:
                query = packet.http_uri.split('?', 1)[1]
                body = query.encode('utf-8', errors='replace')
            if not body:
                body = (packet.http_uri or '').encode('utf-8', errors='replace')

            if not body:
                return None

            detection = detector.detect(
                data=body,
                method=packet.http_method,
                uri=packet.http_uri,
                content_type=packet.http_content_type
            )

            if detection.get('detected', False) and detection.get('total_weight', 0) >= 20:
                raw_headers = f"{packet.http_method} {packet.http_uri} HTTP/1.1\r\n"
                raw_headers += f"Host: {packet.http_host}\r\n"
                if packet.http_user_agent:
                    raw_headers += f"User-Agent: {packet.http_user_agent}\r\n"
                if packet.http_content_type:
                    raw_headers += f"Content-Type: {packet.http_content_type}\r\n"
                raw_headers += "\r\n"

                try:
                    raw_body_str = body.decode('utf-8', errors='replace')
                except Exception:
                    raw_body_str = repr(body)[:1000]

                detection['raw_request_headers'] = raw_headers
                detection['raw_request_body'] = raw_body_str[:5000]
                detection['raw_http_request'] = (raw_headers + raw_body_str)[:10000]
                detection['frame_number'] = packet.frame_number
                detection['src_ip'] = packet.src_ip
                detection['dst_ip'] = packet.dst_ip

                return DetectionResult.from_attack_result(detection)

        except Exception as e:
            logger.debug(f"检测失败: {e}")

        return None

    def _run_icmp_analysis(self) -> List[ProtocolFinding]:
        import re

        findings: List[ProtocolFinding] = []

        try:
            config = StreamConfig(
                pcap_path=self.pcap_path,
                display_filter="icmp",
                output_format=OutputFormat.EK
            )

            all_data = bytearray()
            packet_numbers = []
            icmp_count = 0

            for packet in self._handler.stream_packets(config):
                if self._is_cancelled:
                    break

                icmp_count += 1

                layers = packet.raw_ek_data.get('layers', {})
                data_layer = layers.get('data', {})

                data_hex = None
                for key in ['data_data_data', 'data_data', 'data']:
                    if key in data_layer:
                        data_hex = data_layer[key]
                        if isinstance(data_hex, list):
                            data_hex = data_hex[0] if data_hex else None
                        break

                if data_hex:
                    try:
                        all_data.extend(bytes.fromhex(data_hex.replace(":", "")))
                        packet_numbers.append(packet.frame_number)
                    except Exception:
                        pass

                del packet

                if len(all_data) > 1024 * 1024:  # 1MB上限
                    break

            if icmp_count == 0:
                self._emit_progress(50, "未发现ICMP流量")
                return findings

            if len(all_data) > 4:
                try:
                    text = bytes(all_data).decode('utf-8', errors='ignore')
                    printable_ratio = sum(1 for c in text if c.isprintable() or c in '\r\n\t') / max(len(text), 1)

                    if printable_ratio > 0.7:
                        flag_match = re.search(r'(flag\{[^}]+\}|ctf\{[^}]+\})', text, re.IGNORECASE)

                        pf = ProtocolFinding(
                            protocol="ICMP",
                            finding_type="FLAG发现" if flag_match else "隐写数据",
                            description=f"在 {len(packet_numbers)} 个ICMP包中发现隐藏数据",
                            data=text[:500],
                            confidence=0.9 if flag_match else 0.7,
                            packet_range=(packet_numbers[0] if packet_numbers else 0,
                                          packet_numbers[-1] if packet_numbers else 0),
                            is_flag=bool(flag_match)
                        )
                        findings.append(pf)
                        self.protocolFindingFound.emit(pf)
                except Exception:
                    pass

            all_data.clear()
            packet_numbers.clear()

            self._emit_progress(55, f"ICMP分析完成: {icmp_count} 包, {len(findings)} 发现")

        except Exception as e:
            logger.debug(f"ICMP分析异常: {e}")

        return findings

    def _export_http_objects(self) -> List[ExtractedFile]:
        """委托给AnalysisService做智能提取"""
        try:
            from services.analysis_service import AnalysisService
            service = AnalysisService()
            service._tshark_path = self._handler.tshark_path

            self._emit_progress(62, "HTTP 对象智能提取中...")
            extracted_files = service.extract_http_objects(self.pcap_path)

            self._emit_progress(70, f"智能提取了 {len(extracted_files)} 个HTTP对象")
            return extracted_files

        except Exception as e:
            logger.warning(f"智能HTTP对象提取失败，回退到基础提取: {e}")
            return self._export_http_objects_fallback()

    def _export_http_objects_fallback(self) -> List[ExtractedFile]:
        """基础HTTP对象导出，兜底用"""
        import tempfile
        import subprocess

        extracted_files = []
        export_dir = tempfile.mkdtemp(prefix="tinglan_http_")

        try:
            cmd = [
                self._handler.tshark_path,
                "-r", self.pcap_path,
                "-q",
                "--export-objects", f"http,{export_dir}"
            ]

            popen_kwargs = {
                "capture_output": True,
                "timeout": 120,
                "encoding": "utf-8",
                "errors": "replace",
            }

            if sys.platform == "win32":
                popen_kwargs["creationflags"] = 0x08000000

            result = subprocess.run(cmd, **popen_kwargs)

            if result.returncode != 0 and result.stderr:
                logger.warning(f"HTTP对象导出警告: {result.stderr[:200]}")

            if os.path.exists(export_dir):
                for filename in os.listdir(export_dir):
                    filepath = os.path.join(export_dir, filename)
                    if os.path.isfile(filepath):
                        ext = os.path.splitext(filename)[1].lower()
                        content_type = self._guess_content_type(ext)

                        if content_type == "text/html":
                            continue

                        ef = ExtractedFile(
                            file_path=filepath,
                            file_name=filename,
                            file_type=self._get_file_type(ext),
                            file_size=os.path.getsize(filepath),
                            source_packet=0,
                            content_type=content_type,
                            pcap_path=self.pcap_path
                        )
                        extracted_files.append(ef)

                        if len(extracted_files) >= 100:
                            break

            self._emit_progress(70, f"提取了 {len(extracted_files)} 个HTTP对象")

        except subprocess.TimeoutExpired:
            logger.warning("HTTP对象导出超时")
        except Exception as e:
            logger.warning(f"HTTP对象导出异常: {e}")

        return extracted_files

    def _guess_content_type(self, ext: str) -> str:
        content_types = {
            ".html": "text/html", ".htm": "text/html",
            ".php": "application/x-php", ".js": "application/javascript",
            ".css": "text/css", ".json": "application/json",
            ".xml": "application/xml", ".png": "image/png",
            ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
            ".gif": "image/gif", ".ico": "image/x-icon",
            ".txt": "text/plain", ".pdf": "application/pdf",
            ".zip": "application/zip",
        }
        return content_types.get(ext, "application/octet-stream")

    def _get_file_type(self, ext: str) -> str:
        if ext in {".png", ".jpg", ".jpeg", ".gif", ".ico", ".bmp", ".webp"}:
            return "image"
        elif ext in {".pdf", ".doc", ".docx", ".xls", ".xlsx"}:
            return "document"
        elif ext in {".zip", ".rar", ".7z", ".tar", ".gz"}:
            return "archive"
        elif ext in {".php", ".js", ".css", ".html", ".xml", ".json"}:
            return "code"
        return "other"

    def _run_auto_decoding(self, detections: List[DetectionResult]) -> List[AutoDecodingResult]:
        results: List[AutoDecodingResult] = []

        try:
            from core.auto_decoder import MultiLayerDecoder
            decoder = MultiLayerDecoder()

            total = len(detections)
            for i, detection in enumerate(detections):
                if self._is_cancelled:
                    break

                if i % 10 == 0:
                    pct = 75 + int((i / max(total, 1)) * 10)
                    self._emit_progress(pct, f"自动解码 {i+1}/{total}...")

                payloads_to_decode = []

                if detection.raw_result and isinstance(detection.raw_result, dict):
                    raw_body = detection.raw_result.get('raw_request_body', '')
                    if raw_body and len(raw_body) > 10:
                        payloads_to_decode.append(("request_body", str(raw_body)[:5000]))

                for source, data in payloads_to_decode:
                    try:
                        decode_result = decoder.decode_http_payload(data)

                        if decode_result.total_layers > 0 or decode_result.flags_found:
                            auto_result = AutoDecodingResult(
                                source=source,
                                original_data=data[:500],
                                final_data=decode_result.final_text[:1000],
                                decode_chain=decode_result.decode_chain,
                                total_layers=decode_result.total_layers,
                                is_meaningful=decode_result.is_meaningful,
                                confidence=decode_result.confidence,
                                detected_type=decode_result.detected_content_type,
                                flags_found=decode_result.flags_found,
                                associated_detection_id=detection.id
                            )
                            results.append(auto_result)
                            self.decodingResultFound.emit(auto_result)
                    except Exception as e:
                        logger.debug(f"解码失败: {e}")

            self._emit_progress(85, f"自动解码完成: {len(results)} 个结果")

        except Exception as e:
            logger.warning(f"自动解码异常: {e}")

        return results

    def _run_file_recovery(self, extracted_files: List[ExtractedFile]) -> List[FileRecoveryResult]:
        results: List[FileRecoveryResult] = []

        try:
            from core.file_restorer import FileRestorer
            restorer = FileRestorer()

            total = len(extracted_files)
            for i, ef in enumerate(extracted_files):
                if self._is_cancelled:
                    break

                if i % 20 == 0:
                    pct = 88 + int((i / max(total, 1)) * 6)
                    self._emit_progress(pct, f"文件分析 {i+1}/{total}...")

                if not os.path.exists(ef.file_path):
                    continue

                try:
                    with open(ef.file_path, 'rb') as f:
                        data = f.read(8192)

                    if not data:
                        continue

                    recovery = restorer.restore_file(data)

                    if recovery.detected:
                        file_result = FileRecoveryResult(
                            detected=True,
                            extension=recovery.extension,
                            description=recovery.description,
                            mime_type=recovery.mime_type,
                            category=recovery.category,
                            confidence=recovery.confidence,
                            size=ef.file_size,
                            offset=0,
                            source_packet=ef.source_packet,
                            saved_path=ef.file_path,
                            data_preview=self._format_hex_preview(data[:256])
                        )
                        results.append(file_result)
                        self.fileRecovered.emit(file_result)

                except Exception as e:
                    logger.debug(f"文件还原失败 {ef.file_path}: {e}")

            self._emit_progress(94, f"文件还原完成: {len(results)} 个文件")

        except Exception as e:
            logger.warning(f"文件还原异常: {e}")

        return results

    def _format_hex_preview(self, data: bytes) -> str:
        lines = []
        for i in range(0, min(len(data), 256), 16):
            chunk = data[i:i+16]
            offset = f"{i:04x}"
            hex_part = " ".join(f"{b:02x}" for b in chunk)
            ascii_part = "".join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
            lines.append(f"{offset}  {hex_part:<48}  |{ascii_part}|")
        return '\n'.join(lines)

    def _build_protocol_stats(self, protocol_counts: Dict[str, int], total: int) -> List[ProtocolStats]:
        stats = []
        for proto, count in sorted(protocol_counts.items(), key=lambda x: -x[1]):
            pct = (count / total * 100) if total > 0 else 0
            stats.append(ProtocolStats(proto, count, pct))
        return stats

    def _build_summary(
        self,
        detections: List[DetectionResult],
        protocol_stats: List[ProtocolStats],
        protocol_findings: List[ProtocolFinding],
        decoding_results: List[AutoDecodingResult],
        recovered_files: List[FileRecoveryResult],
        extracted_files: List[ExtractedFile],
        total_packets: int
    ) -> AnalysisSummary:
        analysis_time = time.time() - self._start_time

        summary = AnalysisSummary(
            file_path=self.pcap_path,
            total_packets=total_packets,
            protocol_stats=protocol_stats,
            detections=detections,
            extracted_files=extracted_files,
            protocol_findings=protocol_findings,
            decoding_results=decoding_results,
            recovered_files=recovered_files,
            analysis_time=analysis_time
        )

        summary.update_confidence_counts()

        self._emit_progress(100, f"分析完成，耗时 {analysis_time:.2f}秒")
        return summary


class StreamAnalysisController(QObject):
    """分析控制器，负责批量信号转发和worker生命周期管理"""

    analysisStarted = Signal()
    analysisProgress = Signal(int, str)
    detectionFound = Signal(object)          # 单条(兼容)
    batchDetectionsFound = Signal(list)      # 批量
    protocolFindingFound = Signal(object)
    decodingResultFound = Signal(object)
    fileRecovered = Signal(object)
    analysisFinished = Signal(object)
    analysisError = Signal(str)
    analysisCancelled = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self._worker: Optional[StreamAnalysisWorker] = None
        self._current_file: str = ""
        self._is_running = False

    @property
    def is_running(self) -> bool:
        return self._is_running and self._worker is not None and self._worker.isRunning()

    @property
    def current_file(self) -> str:
        return self._current_file

    def startAnalysis(self, pcap_path: str, options: Dict = None):
        if self.is_running:
            self.stopAnalysis()
            if self._worker:
                self._worker.wait(3000)

        self._current_file = pcap_path
        self._is_running = True

        analysis_options = AnalysisOptions(
            detect_webshell=options.get("detect_webshell", True) if options else True,
            detect_owasp=options.get("detect_owasp", True) if options else True,
            extract_files=options.get("extract_images", True) if options else True,
            auto_decode=options.get("auto_decode", True) if options else True,
            file_recovery=options.get("file_recovery", True) if options else True,
            custom_keys=options.get("custom_keys", {}) if options else {},
            max_detections=options.get("max_detections", ResourceLimits.MAX_DETECTIONS) if options else ResourceLimits.MAX_DETECTIONS
        )

        self._worker = StreamAnalysisWorker(pcap_path, analysis_options)

        self._worker.progress.connect(self.analysisProgress.emit)
        self._worker.batchResultsReady.connect(self._onBatchResults)
        self._worker.protocolFindingFound.connect(self.protocolFindingFound.emit)
        self._worker.decodingResultFound.connect(self.decodingResultFound.emit)
        self._worker.fileRecovered.connect(self.fileRecovered.emit)
        self._worker.finished.connect(self._onFinished)
        self._worker.error.connect(self._onError)
        self._worker.cancelled.connect(self._onCancelled)

        self.analysisStarted.emit()
        self._worker.start()

    def _onBatchResults(self, results: List[DetectionResult]):
        # 只发批量信号，不逐个发，避免信号风暴
        self.batchDetectionsFound.emit(results)

    def stopAnalysis(self):
        if self._worker:
            self._worker.cancel()

    def _onFinished(self, summary: AnalysisSummary):
        self._is_running = False
        self.analysisFinished.emit(summary)

    def _onError(self, error_msg: str):
        self._is_running = False
        self.analysisError.emit(error_msg)

    def _onCancelled(self):
        self._is_running = False
        self.analysisCancelled.emit()
