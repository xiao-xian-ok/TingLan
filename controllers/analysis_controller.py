# analysis_controller.py
# 分析流程控制器，串联各个分析阶段

import sys
import os
import time
import queue
import threading
import subprocess
import csv
import io
import logging
import re
from typing import Optional, Dict, List, Tuple
from dataclasses import dataclass

from PySide6.QtCore import QObject, Signal, QThread

logger = logging.getLogger(__name__)

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CORE_PATH = os.path.join(PROJECT_ROOT, "core")

for path in [PROJECT_ROOT, CORE_PATH]:
    if path not in sys.path:
        sys.path.insert(0, path)

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

from services.interfaces import IAnalysisService


@dataclass
class HTTPPacketData:
    frame_number: int
    method: str
    uri: str
    host: str
    content_type: str
    user_agent: str
    file_data: bytes  # 请求体
    src_ip: str
    dst_ip: str


@dataclass
class ICMPPacketData:
    frame_number: int
    icmp_type: int
    icmp_code: int
    icmp_data: bytes
    src_ip: str
    dst_ip: str


class AnalysisWorker(QThread):
    """异步分析工作线程"""

    # 信号
    progress = Signal(int, str)           # (百分比, 状态消息)
    resultReady = Signal(object)          # 单条检测结果
    imageExtracted = Signal(object)       # 提取的图片
    protocolFindingFound = Signal(object) # ProtocolFinding
    decodingResultFound = Signal(object)  # AutoDecodingResult
    fileRecovered = Signal(object)        # FileRecoveryResult
    finished = Signal(object)             # AnalysisSummary
    error = Signal(str)                   # 错误消息

    def __init__(self, pcap_path: str, options: Dict = None, service: IAnalysisService = None):
        super().__init__()
        self.pcap_path = pcap_path
        self.options = options or {
            "detect_webshell": True,
            "extract_images": True,
            "protocol_stats": True
        }
        self._is_cancelled = False
        self._service = service

        # 队列缓冲机制
        self._result_queue = queue.Queue()
        self._protocol_finding_queue = queue.Queue()
        self._decoding_result_queue = queue.Queue()
        self._file_recovery_queue = queue.Queue()
        self._emit_thread: Optional[threading.Thread] = None
        self._stop_emit = False

    def cancel(self):
        self._is_cancelled = True
        self._stop_emit = True

    def _start_emit_thread(self):
        self._stop_emit = False
        self._emit_thread = threading.Thread(target=self._emit_loop, daemon=True)
        self._emit_thread.start()

    def _emit_loop(self):
        """从队列取结果并发送信号"""
        while not self._stop_emit:
            try:
                result = self._result_queue.get(timeout=0.1)
                self.resultReady.emit(result)
                time.sleep(0.01)
            except queue.Empty:
                pass

            try:
                finding = self._protocol_finding_queue.get_nowait()
                self.protocolFindingFound.emit(finding)
            except queue.Empty:
                pass

            try:
                decoding = self._decoding_result_queue.get_nowait()
                self.decodingResultFound.emit(decoding)
            except queue.Empty:
                pass

            try:
                recovery = self._file_recovery_queue.get_nowait()
                self.fileRecovered.emit(recovery)
            except queue.Empty:
                pass

    def _queue_result(self, result):
        self._result_queue.put(result)

    def _queue_protocol_finding(self, finding: ProtocolFinding):
        self._protocol_finding_queue.put(finding)

    def _queue_decoding_result(self, result: AutoDecodingResult):
        self._decoding_result_queue.put(result)

    def _queue_file_recovery(self, recovery: FileRecoveryResult):
        self._file_recovery_queue.put(recovery)

    def _flush_queue(self):
        for q, emit_func in [
            (self._result_queue, self.resultReady.emit),
            (self._protocol_finding_queue, self.protocolFindingFound.emit),
            (self._decoding_result_queue, self.decodingResultFound.emit),
            (self._file_recovery_queue, self.fileRecovered.emit),
        ]:
            while not q.empty():
                try:
                    item = q.get_nowait()
                    emit_func(item)
                except queue.Empty:
                    break

    def _find_tshark(self) -> Optional[str]:
        import shutil
        tshark_path = shutil.which("tshark")
        if tshark_path:
            return tshark_path

        possible_paths = [
            r"E:\internet_safe\wireshark\tshark.exe",
            r"C:\Program Files\Wireshark\tshark.exe",
            r"C:\Program Files (x86)\Wireshark\tshark.exe",
            r"D:\Program Files\Wireshark\tshark.exe",
            r"D:\Wireshark\tshark.exe",
        ]
        for path in possible_paths:
            if os.path.exists(path):
                return path
        return None

    def run(self):
        self._start_emit_thread()

        try:
            if self._service:
                self._run_with_service()
            else:
                self._run_internal()
        finally:
            self._stop_emit = True

    def _run_with_service(self):
        try:
            summary = self._service.analyze_pcap(
                self.pcap_path,
                self.options,
                on_progress=lambda pct, msg: self.progress.emit(pct, msg),
                on_detection=self._queue_result
            )
            self._stop_emit = True
            self._flush_queue()
            self.finished.emit(summary)
        except Exception as e:
            import traceback
            self.error.emit(f"分析错误: {str(e)}\n{traceback.format_exc()}")

    def _run_internal(self):
        """内置 tshark 实现"""
        start_time = time.time()

        try:
            self.progress.emit(0, "正在初始化分析引擎...")

            # 查找 tshark
            tshark_path = self._find_tshark()
            if not tshark_path:
                raise FileNotFoundError(
                    "未找到 TShark！请安装 Wireshark：https://www.wireshark.org/download.html"
                )

            # 添加 tshark 目录到 PATH
            tshark_dir = os.path.dirname(tshark_path)
            if tshark_dir not in os.environ.get("PATH", ""):
                os.environ["PATH"] = tshark_dir + os.pathsep + os.environ.get("PATH", "")

            if self._is_cancelled:
                return

            # 阶段1: 协议统计
            self.progress.emit(5, "【阶段1/8】正在进行协议分级统计...")
            protocol_counts, total = self._run_protocol_stats(tshark_path)

            if self._is_cancelled:
                return

            # 阶段2: HTTP提取
            self.progress.emit(15, "【阶段2/8】正在提取HTTP对象...")
            extracted_files = self._export_http_objects(tshark_path)

            if self._is_cancelled:
                return

            # 阶段3: ICMP隐写
            self.progress.emit(25, "【阶段3/8】正在进行ICMP隐写检测...")
            protocol_findings = self._run_icmp_analysis(tshark_path)

            if self._is_cancelled:
                return

            # 阶段4: OWASP检测
            results = []
            has_file_upload = False
            self.progress.emit(40, "【阶段4/8】正在进行OWASP漏洞检测...")
            owasp_results = self._run_owasp_detection(tshark_path)
            results.extend(owasp_results)

            # 检查是否有文件上传
            for r in owasp_results:
                if hasattr(r, 'detection_type') and r.detection_type.value == 'file_upload':
                    has_file_upload = True
                    break

            if self._is_cancelled:
                return

            # 阶段5: Webshell
            if self.options.get("detect_webshell", True) and has_file_upload:
                self.progress.emit(65, "【阶段5/8】发现文件上传，启动Webshell检测...")
                webshell_results = self._run_webshell_detection(tshark_path)
                results.extend(webshell_results)
            else:
                self.progress.emit(65, "【阶段5/8】未发现文件上传，跳过Webshell检测")

            if self._is_cancelled:
                return

            # 阶段6: 解码
            self.progress.emit(75, f"【阶段6/8】正在对 {len(results)} 条结果执行自动解码...")
            decoding_results = self._run_auto_decoding(results)

            if self._is_cancelled:
                return

            # 阶段7: 文件还原
            self.progress.emit(85, "【阶段7/8】正在进行文件还原...")
            recovered_files = self._run_file_recovery(extracted_files)

            if self._is_cancelled:
                return

            # 阶段8: 生成报告
            self._stop_emit = True
            self._flush_queue()

            self.progress.emit(95, "【阶段8/8】正在生成分析报告...")

            protocol_stats = []
            for proto, count in sorted(protocol_counts.items(), key=lambda x: -x[1]):
                pct = (count / total * 100) if total > 0 else 0
                protocol_stats.append(ProtocolStats(proto, count, pct))

            analysis_time = time.time() - start_time

            summary = AnalysisSummary(
                file_path=self.pcap_path,
                total_packets=total,
                protocol_stats=protocol_stats,
                detections=results,
                extracted_files=extracted_files,
                protocol_findings=protocol_findings,
                decoding_results=decoding_results,
                recovered_files=recovered_files,
                analysis_time=analysis_time
            )

            summary.update_confidence_counts()

            self.progress.emit(100, f"分析完成，耗时 {analysis_time:.2f}秒")
            self.finished.emit(summary)

        except Exception as e:
            import traceback
            self.error.emit(f"分析错误: {str(e)}\n{traceback.format_exc()}")
        finally:
            self._stop_emit = True

    def _run_protocol_stats(self, tshark_path: str) -> Tuple[Dict[str, int], int]:
        """tshark -z io,phs 协议统计"""
        protocol_counts: Dict[str, int] = {}
        total = 0

        try:
            cmd = [tshark_path, "-r", self.pcap_path, "-q", "-z", "io,phs"]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='replace',
                timeout=120
            )

            lines = result.stdout.split('\n')
            for line in lines:
                line = line.strip()
                if not line or 'frames:' not in line:
                    continue

                parts = line.split()
                if len(parts) >= 2:
                    protocol_chain = parts[0]

                    for part in parts:
                        if part.startswith('frames:'):
                            count = int(part.replace('frames:', ''))
                            protocols = protocol_chain.split(':')
                            top_protocol = protocols[-1].upper() if protocols else "UNKNOWN"

                            if total == 0 and top_protocol in ("FRAME", "ETH"):
                                total = count
                            elif top_protocol == "FRAME":
                                total = count

                            if top_protocol not in ("FRAME", "ETH", "DATA"):
                                protocol_counts[top_protocol] = count
                            break

            if total == 0 and protocol_counts:
                total = max(protocol_counts.values())

            self.progress.emit(12, f"协议统计完成: {len(protocol_counts)} 种协议, {total} 个数据包")

        except subprocess.TimeoutExpired:
            self.progress.emit(12, "协议统计超时，继续...")
        except Exception as e:
            self.progress.emit(12, f"协议统计警告: {str(e)[:30]}")

        return protocol_counts, total

    def _export_http_objects(self, tshark_path: str) -> List[ExtractedFile]:
        """tshark 导出 HTTP 对象"""
        import tempfile

        extracted_files = []
        export_dir = tempfile.mkdtemp(prefix="tinglan_http_")

        try:
            cmd = [
                tshark_path, "-r", self.pcap_path, "-q",
                "--export-objects", f"http,{export_dir}"
            ]

            subprocess.run(cmd, capture_output=True, timeout=60)

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

            self.progress.emit(22, f"提取了 {len(extracted_files)} 个HTTP对象")

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

    def _run_icmp_analysis(self, tshark_path: str) -> List[ProtocolFinding]:
        """提取 ICMP 数据做隐写分析"""
        findings: List[ProtocolFinding] = []

        try:
            cmd = [
                tshark_path, "-r", self.pcap_path,
                "-Y", "icmp",
                "-T", "fields",
                "-e", "frame.number",
                "-e", "icmp.type",
                "-e", "icmp.code",
                "-e", "data.data",
                "-e", "ip.src",
                "-e", "ip.dst",
                "-E", "separator=|"
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='replace',
                timeout=120
            )

            icmp_packets = []
            lines = result.stdout.strip().split('\n')

            for i, line in enumerate(lines):
                if not line.strip():
                    continue

                if self._is_cancelled:
                    break

                if i % 100 == 0:
                    self.progress.emit(25 + int((i / max(len(lines), 1)) * 12),
                                       f"ICMP分析中... ({i}/{len(lines)})")

                parts = line.split('|')
                if len(parts) >= 4:
                    try:
                        icmp_data = ICMPPacketData(
                            frame_number=int(parts[0]) if parts[0] else 0,
                            icmp_type=int(parts[1]) if parts[1] else 0,
                            icmp_code=int(parts[2]) if parts[2] else 0,
                            icmp_data=bytes.fromhex(parts[3].replace(':', '')) if parts[3] else b'',
                            src_ip=parts[4] if len(parts) > 4 else '',
                            dst_ip=parts[5] if len(parts) > 5 else ''
                        )
                        icmp_packets.append(icmp_data)
                    except Exception:
                        continue

            if not icmp_packets:
                self.progress.emit(37, "未发现ICMP流量")
                return findings

            self.progress.emit(35, f"正在分析 {len(icmp_packets)} 个ICMP包...")

            findings = self._analyze_icmp_data(icmp_packets)

            self.progress.emit(38, f"ICMP分析完成，发现 {len(findings)} 处")

        except subprocess.TimeoutExpired:
            self.progress.emit(38, "ICMP分析超时")
        except Exception as e:
            logger.warning(f"ICMP分析异常: {e}")
            self.progress.emit(38, f"ICMP分析警告: {str(e)[:30]}")

        return findings

    def _analyze_icmp_data(self, packets: List[ICMPPacketData]) -> List[ProtocolFinding]:
        """分析 ICMP 数据包，查找隐写数据"""
        findings = []

        # 收集所有 ICMP data
        all_data = b''
        for pkt in packets:
            if pkt.icmp_data:
                all_data += pkt.icmp_data

        if len(all_data) < 4:
            return findings

        # 尝试解码
        try:
            # 检查是否是可打印文本
            try:
                text = all_data.decode('utf-8', errors='ignore')
                printable_ratio = sum(1 for c in text if c.isprintable() or c in '\r\n\t') / len(text)

                if printable_ratio > 0.7:
                    # 检测 flag
                    flag_match = re.search(r'(flag\{[^}]+\}|ctf\{[^}]+\})', text, re.IGNORECASE)

                    pf = ProtocolFinding(
                        protocol="ICMP",
                        finding_type="隐写数据" if not flag_match else "FLAG发现",
                        description=f"在 {len(packets)} 个ICMP包中发现隐藏数据",
                        data=text[:500],
                        confidence=0.9 if flag_match else 0.7,
                        packet_range=(packets[0].frame_number, packets[-1].frame_number),
                        is_flag=bool(flag_match)
                    )
                    findings.append(pf)
                    self._queue_protocol_finding(pf)
            except Exception:
                pass

        except Exception as e:
            logger.debug(f"ICMP数据分析异常: {e}")

        return findings

    def _run_owasp_detection(self, tshark_path: str) -> List[DetectionResult]:
        """提取 HTTP 数据做 OWASP 检测"""
        results: List[DetectionResult] = []

        try:
            from core.attack_detector import AttackDetector

            cmd = [
                tshark_path, "-r", self.pcap_path,
                "-Y", "http.request",
                "-T", "fields",
                "-e", "frame.number",
                "-e", "http.request.method",
                "-e", "http.request.uri",
                "-e", "http.host",
                "-e", "http.content_type",
                "-e", "http.user_agent",
                "-e", "http.file_data",
                "-e", "ip.src",
                "-e", "ip.dst",
                "-E", "separator=|",
                "-E", "quote=d"
            ]

            self.progress.emit(42, "正在提取HTTP请求数据...")

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='replace',
                timeout=300  # 5分钟超时
            )

            lines = result.stdout.strip().split('\n')
            total_lines = len([l for l in lines if l.strip()])

            self.progress.emit(45, f"发现 {total_lines} 个HTTP请求，开始OWASP检测...")

            detector = AttackDetector()
            detection_count = 0
            seen_uris = set()

            for i, line in enumerate(lines):
                if not line.strip():
                    continue

                if self._is_cancelled:
                    break

                # 每 50 个包更新进度
                if i % 50 == 0:
                    progress = 45 + int((i / max(total_lines, 1)) * 18)
                    self.progress.emit(min(progress, 63),
                                       f"OWASP检测中... ({i}/{total_lines}, 发现{detection_count}个威胁)")

                try:
                    http_data = self._parse_http_line(line)
                    if not http_data:
                        continue

                    # 去重
                    dedup_key = f"{http_data.method}:{http_data.uri[:100]}:{len(http_data.file_data)}"
                    if dedup_key in seen_uris:
                        continue
                    seen_uris.add(dedup_key)

                    body = http_data.file_data
                    if not body and '?' in http_data.uri:
                        query = http_data.uri.split('?', 1)[1]
                        body = query.encode('utf-8', errors='ignore')
                    if not body:
                        body = http_data.uri.encode('utf-8', errors='ignore')

                    # 执行检测
                    detection = detector.detect(
                        data=body,
                        method=http_data.method,
                        uri=http_data.uri,
                        content_type=http_data.content_type
                    )

                    if detection.get('detected', False) and detection.get('total_weight', 0) >= 20:
                        raw_headers = f"{http_data.method} {http_data.uri} HTTP/1.1\r\n"
                        raw_headers += f"Host: {http_data.host}\r\n"
                        if http_data.user_agent:
                            raw_headers += f"User-Agent: {http_data.user_agent}\r\n"
                        if http_data.content_type:
                            raw_headers += f"Content-Type: {http_data.content_type}\r\n"
                        raw_headers += "\r\n"

                        try:
                            raw_body_str = body.decode('utf-8', errors='replace')
                        except Exception:
                            raw_body_str = repr(body)

                        detection['raw_request_headers'] = raw_headers
                        detection['raw_request_body'] = raw_body_str
                        detection['raw_http_request'] = raw_headers + raw_body_str
                        detection['frame_number'] = http_data.frame_number
                        detection['src_ip'] = http_data.src_ip
                        detection['dst_ip'] = http_data.dst_ip

                        det_result = DetectionResult.from_attack_result(detection)
                        results.append(det_result)
                        self._queue_result(det_result)
                        detection_count += 1

                except Exception as e:
                    logger.debug(f"OWASP单包检测异常: {e}")
                    continue

            self.progress.emit(63, f"OWASP检测完成: {detection_count} 个威胁 ({total_lines} 个请求)")

        except subprocess.TimeoutExpired:
            self.progress.emit(63, "OWASP检测超时")
        except Exception as e:
            logger.error(f"OWASP检测异常: {e}")
            self.progress.emit(63, f"OWASP检测异常: {str(e)[:30]}")

        return results

    def _parse_http_line(self, line: str) -> Optional[HTTPPacketData]:
        """解析 tshark HTTP 输出行"""
        if not line.strip():
            return None

        try:
            # 使用 CSV reader 处理带引号的字段
            reader = csv.reader(io.StringIO(line), delimiter='|', quotechar='"')
            fields = next(reader)

            if len(fields) < 7:
                return None

            # 解析 file_data (十六进制)
            file_data = b''
            if len(fields) > 6 and fields[6]:
                try:
                    file_data = bytes.fromhex(fields[6].replace(':', ''))
                except Exception:
                    pass

            return HTTPPacketData(
                frame_number=int(fields[0]) if fields[0] else 0,
                method=fields[1] if len(fields) > 1 else '',
                uri=fields[2] if len(fields) > 2 else '',
                host=fields[3] if len(fields) > 3 else '',
                content_type=fields[4] if len(fields) > 4 else '',
                user_agent=fields[5] if len(fields) > 5 else '',
                file_data=file_data,
                src_ip=fields[7] if len(fields) > 7 else '',
                dst_ip=fields[8] if len(fields) > 8 else ''
            )
        except Exception:
            return None

    def _run_webshell_detection(self, tshark_path: str) -> List[DetectionResult]:
        """从 POST 数据检测 Webshell"""
        results: List[DetectionResult] = []

        try:
            from core.webshell_detect import WebShellDetector

            cmd = [
                tshark_path, "-r", self.pcap_path,
                "-Y", "http.request.method == POST",
                "-T", "fields",
                "-e", "frame.number",
                "-e", "http.request.method",
                "-e", "http.request.uri",
                "-e", "http.host",
                "-e", "http.content_type",
                "-e", "http.file_data",
                "-E", "separator=|"
            ]

            self.progress.emit(67, "正在提取POST请求进行Webshell检测...")

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='replace',
                timeout=120
            )

            lines = [l for l in result.stdout.strip().split('\n') if l.strip()]

            if not lines:
                self.progress.emit(73, "未发现POST请求")
                return results

            self.progress.emit(70, f"发现 {len(lines)} 个POST请求，进行Webshell分析...")

            # 简化的 Webshell 检测
            detector = WebShellDetector()
            detection_count = 0

            for i, line in enumerate(lines):
                if self._is_cancelled:
                    break

                if i % 20 == 0:
                    self.progress.emit(70 + int((i / max(len(lines), 1)) * 3),
                                       f"Webshell检测中... ({i}/{len(lines)})")

                try:
                    parts = line.split('|')
                    if len(parts) < 6:
                        continue

                    uri = parts[2] if len(parts) > 2 else ''
                    content_type = parts[4] if len(parts) > 4 else ''
                    file_data_hex = parts[5] if len(parts) > 5 else ''

                    if not file_data_hex:
                        continue

                    try:
                        body = bytes.fromhex(file_data_hex.replace(':', ''))
                    except Exception:
                        continue

                    # 使用 WebShellDetector 的权重检测逻辑
                    # 这里简化处理，直接检查常见特征
                    body_str = body.decode('utf-8', errors='ignore')

                    # 蚁剑特征
                    if '@ini_set' in body_str or '@eval(' in body_str or 'base64_decode' in body_str:
                        from models.detection_result import DetectionType, ThreatLevel

                        det = DetectionResult(
                            detection_type=DetectionType.ANTSWORD,
                            threat_level=ThreatLevel.HIGH,
                            confidence=0.85,
                            uri=uri,
                            method="POST",
                            description="检测到疑似蚁剑Webshell特征",
                            payload={'body': body_str[:500]},
                            raw_result={'content_type': content_type}
                        )
                        results.append(det)
                        self._queue_result(det)
                        detection_count += 1

                except Exception as e:
                    logger.debug(f"Webshell单包检测异常: {e}")
                    continue

            self.progress.emit(73, f"Webshell检测完成: {detection_count} 个威胁")

        except Exception as e:
            logger.warning(f"Webshell检测异常: {e}")
            self.progress.emit(73, f"Webshell检测警告: {str(e)[:30]}")

        return results

    def _run_auto_decoding(self, detections: List[DetectionResult]) -> List[AutoDecodingResult]:
        from core.auto_decoder import AutoDecoder, MultiLayerDecoder
        from urllib.parse import urlparse, parse_qs, unquote

        results: List[AutoDecodingResult] = []

        try:
            decoder = AutoDecoder()
            multi_decoder = MultiLayerDecoder()

            total = len(detections)
            for i, detection in enumerate(detections):
                if self._is_cancelled:
                    return results

                if total > 0 and i % 5 == 0:
                    sub_progress = 75 + int((i / total) * 8)
                    self.progress.emit(sub_progress, f"自动解码 {i+1}/{total}...")

                payloads_to_decode = []

                # 收集载荷
                if detection.payloads:
                    for payload in detection.payloads:
                        if payload.decoded_content:
                            payloads_to_decode.append((f"payload:{payload.param_name}", payload.decoded_content))

                if detection.payload and isinstance(detection.payload, dict):
                    for key, value in detection.payload.items():
                        if isinstance(value, dict):
                            decoded = value.get('decoded', '')
                            if decoded:
                                payloads_to_decode.append((f"param:{key}", str(decoded)))

                if detection.raw_result and isinstance(detection.raw_result, dict):
                    raw_body = detection.raw_result.get('raw_request_body', '')
                    if raw_body and len(raw_body) > 10:
                        payloads_to_decode.append(("request_body", str(raw_body)))

                # 解码
                for source, data in payloads_to_decode:
                    if self._is_cancelled:
                        return results

                    try:
                        decode_result = multi_decoder.decode_http_payload(data[:5000])

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
                            self._queue_decoding_result(auto_result)
                    except Exception as e:
                        logger.debug(f"解码失败 {source}: {e}")

            self.progress.emit(83, f"自动解码完成: {len(results)} 个结果")

        except Exception as e:
            logger.error(f"自动解码异常: {e}")

        return results

    def _run_file_recovery(self, extracted_files: List[ExtractedFile]) -> List[FileRecoveryResult]:
        from core.file_restorer import FileRestorer

        results: List[FileRecoveryResult] = []

        try:
            restorer = FileRestorer()

            total = len(extracted_files)
            for i, ef in enumerate(extracted_files):
                if self._is_cancelled:
                    return results

                if total > 0 and i % 10 == 0:
                    sub_progress = 85 + int((i / total) * 8)
                    self.progress.emit(sub_progress, f"文件分析 {i+1}/{total}...")

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
                        self._queue_file_recovery(file_result)

                except IOError as e:
                    logger.debug(f"无法读取文件 {ef.file_path}: {e}")

            self.progress.emit(93, f"文件还原完成: {len(results)} 个文件")

        except Exception as e:
            logger.error(f"文件还原异常: {e}")

        return results

    def _format_hex_preview(self, data: bytes, max_bytes: int = 256) -> str:
        if not data:
            return ""

        lines = []
        data = data[:max_bytes]

        for i in range(0, len(data), 16):
            chunk = data[i:i+16]
            offset = f"{i:04x}"
            hex_left = " ".join(f"{b:02x}" for b in chunk[:8])
            hex_right = " ".join(f"{b:02x}" for b in chunk[8:])
            hex_part = f"{hex_left:<23}  {hex_right:<23}"
            ascii_part = "".join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
            lines.append(f"{offset}   {hex_part}  |{ascii_part}|")

        return '\n'.join(lines)


class AnalysisController(QObject):
    """分析控制器 - 串联UI和工作线程"""

    analysisStarted = Signal()
    analysisProgress = Signal(int, str)
    detectionFound = Signal(object)
    protocolFindingFound = Signal(object)
    decodingResultFound = Signal(object)
    fileRecovered = Signal(object)
    imageExtracted = Signal(object)
    analysisFinished = Signal(object)
    analysisError = Signal(str)
    analysisCancelled = Signal()

    def __init__(self, parent=None, service: IAnalysisService = None):
        super().__init__(parent)
        self.worker: Optional[AnalysisWorker] = None
        self._current_file: str = ""
        self._service = service

    @property
    def is_running(self) -> bool:
        return self.worker is not None and self.worker.isRunning()

    @property
    def current_file(self) -> str:
        return self._current_file

    def startAnalysis(self, pcap_path: str, options: Dict = None):
        if self.is_running:
            self.stopAnalysis()
            self.worker.wait(3000)

        self._current_file = pcap_path
        options = options or {
            "detect_webshell": True,
            "extract_images": True,
            "protocol_stats": True
        }

        self.worker = AnalysisWorker(pcap_path, options, service=self._service)

        self.worker.progress.connect(self.analysisProgress.emit)
        self.worker.resultReady.connect(self.detectionFound.emit)
        self.worker.protocolFindingFound.connect(self.protocolFindingFound.emit)
        self.worker.decodingResultFound.connect(self.decodingResultFound.emit)
        self.worker.fileRecovered.connect(self.fileRecovered.emit)
        self.worker.imageExtracted.connect(self.imageExtracted.emit)
        self.worker.finished.connect(self._onFinished)
        self.worker.error.connect(self._onError)

        self.analysisStarted.emit()
        self.worker.start()

    def stopAnalysis(self):
        if self.worker:
            self.worker.cancel()
            self.analysisCancelled.emit()

    def _onFinished(self, summary: AnalysisSummary):
        self.analysisFinished.emit(summary)

    def _onError(self, error_msg: str):
        self.analysisError.emit(error_msg)


def get_packet_hex_dump(pcap_path: str, packet_num: int = 0) -> tuple:
    possible_paths = [
        r"E:\internet_safe\wireshark\tshark.exe",
        r"C:\Program Files\Wireshark\tshark.exe",
        r"C:\Program Files (x86)\Wireshark\tshark.exe",
    ]

    tshark_path = None
    for path in possible_paths:
        if os.path.exists(path):
            tshark_path = path
            break

    if not tshark_path:
        return "", ["未找到 tshark"]

    try:
        filter_expr = f"frame.number == {packet_num}" if packet_num > 0 else "http"

        cmd = [
            tshark_path, "-r", pcap_path,
            "-Y", filter_expr, "-V", "-x", "-c", "1"
        ]

        result = subprocess.run(
            cmd, capture_output=True, text=True,
            encoding='utf-8', errors='replace', timeout=30
        )

        output = result.stdout
        if not output:
            return "", ["无数据"]

        protocol_layers = []
        hex_dump_lines = []
        in_hex_section = False

        for line in output.split('\n'):
            if line and len(line) >= 4:
                first_part = line[:4]
                if all(c in '0123456789abcdef' for c in first_part.lower()):
                    in_hex_section = True

            if in_hex_section:
                if line.strip():
                    hex_dump_lines.append(line)
            else:
                if line.startswith('>') or (line and not line.startswith(' ') and ':' in line):
                    clean_line = line.lstrip('> ').strip()
                    if clean_line and not clean_line.startswith('['):
                        protocol_layers.append(clean_line)
                elif line and not line.startswith(' ') and not line.startswith('\t'):
                    clean_line = line.strip()
                    if clean_line and ':' not in clean_line:
                        protocol_layers.append(clean_line)

        hex_dump = '\n'.join(hex_dump_lines)

        if not protocol_layers:
            protocol_layers = ["Frame", "Ethernet II", "Internet Protocol", "TCP"]

        return hex_dump, protocol_layers

    except subprocess.TimeoutExpired:
        return "", ["获取超时"]
    except Exception as e:
        return "", [f"错误: {str(e)}"]


def get_file_hex_content(file_path: str, max_bytes: int = 4096) -> str:
    try:
        with open(file_path, 'rb') as f:
            data = f.read(max_bytes)

        lines = []
        for i in range(0, len(data), 16):
            chunk = data[i:i+16]
            offset = f"{i:04x}"
            hex_left = " ".join(f"{b:02x}" for b in chunk[:8])
            hex_right = " ".join(f"{b:02x}" for b in chunk[8:])
            hex_part = f"{hex_left:<23}  {hex_right:<23}"
            ascii_part = "".join(chr(b) if 32 <= b < 127 else '·' for b in chunk)
            lines.append(f"{offset}   {hex_part}  {ascii_part}")

        if len(data) == max_bytes:
            lines.append(f"\n... (仅显示前 {max_bytes} 字节)")

        return '\n'.join(lines)
    except Exception as e:
        return f"读取文件失败: {str(e)}"
