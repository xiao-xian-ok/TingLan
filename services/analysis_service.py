# analysis_service.py
# 核心分析服务，调tshark跑各种分析任务

import os
import sys
import time
import subprocess
import tempfile
import shutil
import hashlib
import math
from collections import Counter
from typing import List, Dict, Optional, Callable, Tuple, Generator

from services.interfaces import IAnalysisService

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
    ExtractedFile
)

from core.tshark_stream import (
    TsharkProcessHandler,
    StreamConfig,
    OutputFormat,
    PacketData,
    PacketWrapper,
    TsharkError,
    TsharkNotFoundError,
    get_protocol_stats
)

from core.attack_detector import AttackDetector


class AnalysisService(IAnalysisService):

    def __init__(self):
        self._tshark_path = self.find_tshark()
        self._handler: Optional[TsharkProcessHandler] = None

    def find_tshark(self) -> Optional[str]:
        tshark_path = shutil.which("tshark")
        if tshark_path:
            return tshark_path

        possible_paths = [
            r"E:\internet_safe\wireshark\tshark.exe",
            r"C:\Program Files\Wireshark\tshark.exe",
            r"C:\Program Files (x86)\Wireshark\tshark.exe",
            r"D:\Program Files\Wireshark\tshark.exe",
            r"D:\Wireshark\tshark.exe",
            "/usr/bin/tshark",
            "/usr/local/bin/tshark",
        ]
        for path in possible_paths:
            if os.path.exists(path):
                return path
        return None

    def analyze_pcap(
        self,
        pcap_path: str,
        options: dict,
        on_progress: Optional[Callable[[int, str], None]] = None,
        on_detection: Optional[Callable[[DetectionResult], None]] = None
    ) -> AnalysisSummary:
        start_time = time.time()

        if not self._tshark_path:
            raise FileNotFoundError("未找到 tshark，请安装 Wireshark")

        # 设置环境
        tshark_dir = os.path.dirname(self._tshark_path)
        if tshark_dir not in os.environ.get("PATH", ""):
            os.environ["PATH"] = tshark_dir + os.pathsep + os.environ.get("PATH", "")

        def emit_progress(pct: int, msg: str):
            if on_progress:
                on_progress(pct, msg)

        emit_progress(0, "正在加载分析模块...")

        # 协议统计
        emit_progress(5, "正在进行协议分级统计...")
        protocol_counts, total = self._run_protocol_hierarchy_stats(pcap_path)

        # HTTP对象提取
        emit_progress(30, "正在提取HTTP对象...")
        extracted_files = self.extract_http_objects(pcap_path)

        # Webshell检测
        results = []
        if options.get("detect_webshell", True):
            emit_progress(50, "正在检测Webshell流量...")
            results = self._run_webshell_detection_stream(pcap_path, options, on_detection, on_progress)

        # 攻击检测
        if options.get("detect_attacks", True):
            emit_progress(70, "正在检测攻击行为...")
            attack_results = self._run_attack_detection(pcap_path, on_detection)
            results.extend(attack_results)

        # 构建摘要
        emit_progress(90, "正在生成分析报告...")

        protocol_stats = []
        for proto, count in sorted(protocol_counts.items(), key=lambda x: -x[1]):
            pct = (count / total * 100) if total > 0 else 0
            protocol_stats.append(ProtocolStats(proto, count, pct))

        analysis_time = time.time() - start_time

        summary = AnalysisSummary(
            file_path=pcap_path,
            total_packets=total,
            protocol_stats=protocol_stats,
            detections=results,
            extracted_files=extracted_files,
            analysis_time=analysis_time
        )

        emit_progress(100, f"分析完成，耗时 {analysis_time:.2f}秒")
        return summary

    def _run_protocol_hierarchy_stats(self, pcap_path: str) -> Tuple[Dict[str, int], int]:
        """用 tshark -z io,phs 做协议统计"""
        try:
            return get_protocol_stats(pcap_path, self._tshark_path)
        except Exception:
            return {}, 0

    def extract_http_objects(self, pcap_path: str) -> List[ExtractedFile]:
        """提取HTTP对象，区分真正的文件下载和普通HTTP流量"""
        if not self._tshark_path:
            return []

        extracted_files = []
        seen_hashes = set()  # 用于去重

        # 创建输出目录
        export_dir = tempfile.mkdtemp(prefix="tinglan_http_")

        print("[*] 分析 HTTP 响应元数据...")
        http_metadata = self._get_http_response_metadata(pcap_path)
        print(f"[*] 发现 {len(http_metadata)} 个 HTTP 响应")

        # 识别真正的文件下载
        real_file_downloads = self._identify_real_file_downloads(http_metadata)
        print(f"[*] 识别出 {len(real_file_downloads)} 个真正的文件下载")

        print("[*] 使用 tshark 导出 HTTP 对象...")
        try:
            cmd = [
                self._tshark_path,
                "-r", pcap_path,
                "-q",
                "--export-objects", f"http,{export_dir}"
            ]

            popen_kwargs = {
                "capture_output": True,
                "text": True,
                "encoding": 'utf-8',
                "errors": 'replace',
                "timeout": 120
            }

            if sys.platform == "win32":
                popen_kwargs["creationflags"] = 0x08000000  # CREATE_NO_WINDOW

            subprocess.run(cmd, **popen_kwargs)

            if os.path.exists(export_dir):
                files = os.listdir(export_dir)
                print(f"[*] tshark 导出了 {len(files)} 个原始对象")

                for filename in files:
                    filepath = os.path.join(export_dir, filename)
                    if not os.path.isfile(filepath):
                        continue

                    # 使用智能清洗过滤
                    ef = self._smart_filter_file(filepath, filename, pcap_path, real_file_downloads)
                    if ef:
                        file_hash = self._get_file_hash(filepath)
                        if file_hash not in seen_hashes:
                            seen_hashes.add(file_hash)
                            extracted_files.append(ef)
                            print(f"[+] 保留: {ef.file_name} ({ef.file_size} bytes, {ef.file_type})")

        except Exception as e:
            print(f"[!] tshark 导出异常: {e}")

        if real_file_downloads:
            print(f"[*] 补充提取已识别的文件下载...")
            for meta in real_file_downloads:
                try:
                    ef = self._extract_single_http_response(pcap_path, meta, export_dir)
                    if ef:
                        file_hash = self._get_file_hash(ef.file_path)
                        if file_hash not in seen_hashes:
                            seen_hashes.add(file_hash)
                            extracted_files.append(ef)
                            print(f"[+] 补充提取: {ef.file_name} ({ef.file_size} bytes)")
                except Exception:
                    continue

        extracted_files.sort(key=self._get_file_priority)

        print(f"[*] 共提取 {len(extracted_files)} 个有价值文件")

        if extracted_files:
            print("结果列表:")
            for ef in extracted_files[:20]:
                print(f"    - {ef.file_name} ({ef.file_type}, {ef.file_size} bytes)")
            if len(extracted_files) > 20:
                print(f"    ... 还有 {len(extracted_files) - 20} 个文件")

        return extracted_files[:200]

    def _get_http_response_metadata(self, pcap_path: str) -> List[Dict]:
        """获取所有 HTTP 响应的元数据"""
        metadata_list = []

        try:
            cmd = [
                self._tshark_path,
                "-r", pcap_path,
                "-Y", "http.response",
                "-T", "fields",
                "-e", "frame.number",
                "-e", "http.content_type",
                "-e", "http.content_length",
                "-e", "http.response.code",
                "-e", "http.content_disposition",
                "-e", "http.request.uri",
                "-e", "http.host",
                "-E", "separator=|||",
                "-E", "quote=n"
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='replace',
                timeout=60
            )

            for line in result.stdout.strip().split('\n'):
                if not line:
                    continue
                parts = line.split('|||')
                if len(parts) >= 4:
                    metadata_list.append({
                        "frame_number": int(parts[0]) if parts[0].isdigit() else 0,
                        "content_type": parts[1] if len(parts) > 1 else "",
                        "content_length": int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else 0,
                        "response_code": parts[3] if len(parts) > 3 else "",
                        "content_disposition": parts[4] if len(parts) > 4 else "",
                        "request_uri": parts[5] if len(parts) > 5 else "",
                        "host": parts[6] if len(parts) > 6 else "",
                    })

        except Exception as e:
            print(f"[!] 获取 HTTP 元数据异常: {e}")

        return metadata_list

    def _identify_real_file_downloads(self, metadata_list: List[Dict]) -> List[Dict]:
        """识别真正的文件下载"""
        real_downloads = []

        # Content-Type 黑名单
        CONTENT_TYPE_BLACKLIST = [
            'text/html',
            'text/css',
            'text/javascript',
            'application/javascript',
            'application/json',
            'application/xml',
            'application/x-www-form-urlencoded',
            'text/plain',  # 纯文本通常是 API 响应，除非很大
        ]

        # Content-Type 白名单
        CONTENT_TYPE_WHITELIST = [
            'application/zip',
            'application/x-zip-compressed',
            'application/x-rar-compressed',
            'application/x-7z-compressed',
            'application/gzip',
            'application/x-gzip',
            'application/x-tar',
            'application/octet-stream',
            'application/pdf',
            'application/x-msdownload',
            'application/x-executable',
            'application/x-php',
            'application/x-httpd-php',
            'application/vnd.ms-cab-compressed',
            'application/x-shockwave-flash',
            'application/java-archive',
            'image/png',
            'image/jpeg',
            'image/gif',
        ]

        # API 路径特征
        API_PATH_PATTERNS = [
            '/api/', '/v1/', '/v2/', '/v3/',
            '/login', '/logout', '/auth', '/oauth',
            '/user', '/admin', '/dashboard',
            '/ajax/', '/json/', '/xml/',
            '/status', '/health', '/ping',
            '/session', '/token', '/refresh',
            '.json', '.xml',
        ]

        for meta in metadata_list:
            ct = meta.get("content_type", "").lower()
            disp = meta.get("content_disposition", "").lower()
            uri = meta.get("request_uri", "").lower()
            code = meta.get("response_code", "")
            size = meta.get("content_length", 0)

            # 跳过错误响应
            if code.startswith(('4', '5')):
                continue

            # 跳过太小的响应（<500字节通常不是文件）
            if size < 500:
                continue

            # Content-Disposition: attachment 最可靠
            if 'attachment' in disp:
                real_downloads.append(meta)
                continue

            # Content-Type 白名单
            if any(wl in ct for wl in CONTENT_TYPE_WHITELIST):
                if not any(ap in uri for ap in API_PATH_PATTERNS):
                    if 'octet-stream' in ct and size < 1024:
                        continue
                    real_downloads.append(meta)
                    continue

            # 大文件且不在黑名单
            if size > 50 * 1024:
                if not any(bl in ct for bl in CONTENT_TYPE_BLACKLIST):
                    if not any(ap in uri for ap in API_PATH_PATTERNS):
                        real_downloads.append(meta)
                        continue

        return real_downloads

    def _smart_filter_file(self, filepath: str, filename: str, pcap_path: str,
                           real_downloads: List[Dict]) -> Optional[ExtractedFile]:
        """智能文件过滤 - Magic Number优先，恶意代码检测，扩展名伪装检测"""
        file_size = os.path.getsize(filepath)

        # 太小的跳过
        if file_size < 200:
            return None

        # 检测 Magic Number
        detected_type = self._detect_file_type_by_magic(filepath)
        filename_lower = filename.lower()
        ext = os.path.splitext(filename_lower)[1]

        # 扩展名伪装检测
        if detected_type:
            category = detected_type.get("category", "")
            real_extension = detected_type.get("extension", "")

            # 检测扩展名伪装
            is_disguised = self._is_extension_disguised(ext, real_extension)
            if is_disguised:
                print(f"[!] 发现扩展名伪装: {filename} (实际是 {real_extension})")
                detected_type["is_disguised"] = True
                detected_type["original_ext"] = ext

            # ZIP/RAR/7Z/EXE 等高价值文件
            if real_extension in ("zip", "rar", "7z", "gz", "exe", "elf", "pdf", "dll", "class"):
                return self._create_extracted_file(filepath, filename, pcap_path, detected_type)

            # PHP/脚本文件
            if category == "script":
                return self._create_extracted_file(filepath, filename, pcap_path, detected_type)

            # 可执行文件
            if category == "executable":
                return self._create_extracted_file(filepath, filename, pcap_path, detected_type)

            # CAB 文件：只保留大于 50KB 的
            if real_extension == "cab" and file_size > 50 * 1024:
                return self._create_extracted_file(filepath, filename, pcap_path, detected_type)

        # 恶意代码检测
        malware_result = self._detect_malicious_content(filepath, file_size)
        if malware_result:
            print(f"[!] 检测到可疑恶意代码: {filename} - {malware_result['reason']}")
            return self._create_extracted_file(filepath, filename, pcap_path, {
                "extension": malware_result.get("suggested_ext", "bin"),
                "mime_type": "application/x-suspicious",
                "category": "suspicious",
                "description": malware_result["reason"],
                "is_malicious": True
            })

        # 未知扩展名分析
        known_exts = {
            '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.cab',
            '.exe', '.dll', '.so', '.elf', '.bin', '.msi',
            '.php', '.jsp', '.asp', '.aspx', '.py', '.sh', '.bat', '.ps1', '.vbs', '.js',
            '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
            '.sql', '.db', '.sqlite', '.mdb',
            '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.ico', '.svg',
            '.txt', '.log', '.cfg', '.conf', '.ini', '.xml', '.json',
            '.html', '.htm', '.css',
        }

        if ext not in known_exts:
            unknown_result = self._analyze_unknown_file(filepath, file_size)
            if unknown_result:
                print(f"[+] 未知扩展名文件保留: {filename} - {unknown_result['reason']}")
                return self._create_extracted_file(filepath, filename, pcap_path, {
                    "extension": unknown_result.get("suggested_ext", ext.lstrip('.')),
                    "mime_type": "application/octet-stream",
                    "category": unknown_result.get("category", "unknown"),
                    "description": unknown_result["reason"]
                })

        # 文件名分析
        api_indicators = ['login', 'logout', 'auth', 'api', 'json', 'xml', 'status', 'ajax']
        if any(ind in filename_lower for ind in api_indicators):
            if not filename_lower.endswith(('.zip', '.rar', '.7z', '.exe', '.pdf', '.doc', '.xls')):
                return None

        # 过滤随机文件名
        if self._is_random_string(filename):
            if file_size < 10 * 1024:
                if not self._is_binary_file(filepath):
                    return None

        # 内容检查
        try:
            with open(filepath, 'rb') as f:
                header = f.read(512)

            header_lower = header.lower()

            html_markers = [b'<!doctype', b'<html', b'<head>', b'<body>', b'<title>']
            error_markers = [b'404', b'not found', b'forbidden', b'error', b'access denied']

            is_html = any(m in header_lower[:200] for m in html_markers)
            is_error = any(m in header_lower for m in error_markers)

            if is_html or is_error:
                return None

            json_markers = [b'{"', b'[{', b'"status":', b'"error":', b'"data":', b'"message":']
            is_json = any(m in header for m in json_markers)
            if is_json and file_size < 10 * 1024:
                return None

        except Exception:
            pass

        # 扩展名白名单
        valuable_exts = {
            '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2',
            '.exe', '.dll', '.so', '.elf', '.bin',
            '.php', '.jsp', '.asp', '.aspx', '.py', '.sh', '.bat', '.ps1',
            '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
            '.sql', '.db', '.sqlite', '.mdb',
            '.png', '.jpg', '.jpeg', '.gif', '.bmp',
            '.txt', '.log', '.cfg', '.conf', '.ini',
        }

        if ext in valuable_exts:
            if ext in {'.png', '.jpg', '.jpeg', '.gif', '.bmp'} and file_size < 1024:
                return None
            if ext in {'.txt', '.log', '.cfg', '.conf', '.ini'} and file_size < 500:
                return None
            return self._create_extracted_file(filepath, filename, pcap_path, detected_type)

        # 大文件特殊处理
        if file_size > 50 * 1024:
            try:
                with open(filepath, 'rb') as f:
                    sample = f.read(1024)
                non_printable = sum(1 for b in sample if b < 32 or b > 126)
                if non_printable > len(sample) * 0.3:
                    return self._create_extracted_file(filepath, filename, pcap_path, detected_type)
            except Exception:
                pass

        return None

    def _is_extension_disguised(self, file_ext: str, real_ext: str) -> bool:
        if not file_ext or not real_ext:
            return False

        file_ext = file_ext.lstrip('.').lower()
        real_ext = real_ext.lower()

        if file_ext == real_ext:
            return False

        image_exts = {'jpg', 'jpeg', 'png', 'gif', 'bmp', 'ico', 'svg', 'webp'}
        doc_exts = {'doc', 'docx', 'pdf', 'xls', 'xlsx', 'ppt', 'pptx', 'txt'}
        executable_exts = {'exe', 'dll', 'elf', 'so', 'class', 'jar'}
        script_exts = {'php', 'jsp', 'asp', 'aspx', 'py', 'sh', 'bat', 'ps1', 'vbs', 'js'}
        archive_exts = {'zip', 'rar', '7z', 'tar', 'gz', 'bz2', 'cab'}

        # 可执行文件伪装成图片/文档
        if real_ext in executable_exts and file_ext in (image_exts | doc_exts):
            return True

        # 脚本文件伪装成图片/文档
        if real_ext in script_exts and file_ext in (image_exts | doc_exts):
            return True

        # 压缩包伪装成图片
        if real_ext in archive_exts and file_ext in image_exts:
            return True

        return False

    def _detect_malicious_content(self, filepath: str, file_size: int) -> Optional[Dict]:
        try:
            with open(filepath, 'rb') as f:
                content = f.read(min(file_size, 50 * 1024))

            content_lower = content.lower()

            # PHP Webshell 特征
            php_webshell_patterns = [
                (b'<?php', b'eval(', 'PHP eval webshell'),
                (b'<?php', b'assert(', 'PHP assert webshell'),
                (b'<?php', b'system(', 'PHP system webshell'),
                (b'<?php', b'exec(', 'PHP exec webshell'),
                (b'<?php', b'shell_exec(', 'PHP shell_exec webshell'),
                (b'<?php', b'passthru(', 'PHP passthru webshell'),
                (b'<?php', b'popen(', 'PHP popen webshell'),
                (b'<?php', b'proc_open(', 'PHP proc_open webshell'),
                (b'<?php', b'base64_decode(', 'PHP base64 webshell'),
                (b'<?php', b'gzinflate(', 'PHP gzinflate webshell'),
                (b'<?php', b'str_rot13(', 'PHP rot13 webshell'),
                (b'<?php', b'$_POST[', 'PHP POST webshell'),
                (b'<?php', b'$_GET[', 'PHP GET webshell'),
                (b'<?php', b'$_REQUEST[', 'PHP REQUEST webshell'),
                (b'<?', b'@ini_set', 'AntSword/Caidao webshell'),
                (b'<?', b'@eval($_', 'One-liner webshell'),
            ]

            for marker1, marker2, reason in php_webshell_patterns:
                if marker1 in content_lower and marker2 in content_lower:
                    return {"reason": reason, "suggested_ext": "php", "category": "webshell"}

            # PowerShell 恶意代码
            ps_patterns = [
                (b'powershell', b'-encodedcommand', 'PowerShell encoded command'),
                (b'powershell', b'-nop', 'PowerShell no profile'),
                (b'powershell', b'downloadstring', 'PowerShell download'),
                (b'powershell', b'invoke-expression', 'PowerShell IEX'),
                (b'[system.convert]::frombase64', None, 'PowerShell base64'),
                (b'new-object system.net.webclient', None, 'PowerShell WebClient'),
            ]

            for pattern in ps_patterns:
                marker1, marker2, reason = pattern
                if marker1 in content_lower:
                    if marker2 is None or marker2 in content_lower:
                        return {"reason": reason, "suggested_ext": "ps1", "category": "script"}

            # VBScript 恶意代码
            vbs_patterns = [
                (b'wscript.shell', b'run', 'VBScript shell run'),
                (b'wscript.shell', b'exec', 'VBScript shell exec'),
                (b'scripting.filesystemobject', None, 'VBScript file operation'),
                (b'adodb.stream', None, 'VBScript stream'),
            ]

            for pattern in vbs_patterns:
                marker1, marker2, reason = pattern
                if marker1 in content_lower:
                    if marker2 is None or marker2 in content_lower:
                        return {"reason": reason, "suggested_ext": "vbs", "category": "script"}

            # Shell 脚本
            if content.startswith(b'#!/'):
                shell_dangers = [
                    b'curl ', b'wget ', b'/dev/tcp/', b'nc ', b'netcat ',
                    b'bash -i', b'/bin/sh', b'python -c', b'perl -e',
                    b'rm -rf', b'chmod 777', b'base64 -d',
                ]
                for danger in shell_dangers:
                    if danger in content_lower:
                        return {"reason": f"Shell script with {danger.decode()}", "suggested_ext": "sh", "category": "script"}

            # 批处理文件
            bat_patterns = [
                (b'@echo off', b'powershell', 'Batch with PowerShell'),
                (b'@echo off', b'certutil', 'Batch with certutil'),
                (b'@echo off', b'bitsadmin', 'Batch with bitsadmin'),
                (b'cmd /c', b'powershell', 'CMD with PowerShell'),
            ]

            for marker1, marker2, reason in bat_patterns:
                if marker1 in content_lower and marker2 in content_lower:
                    return {"reason": reason, "suggested_ext": "bat", "category": "script"}

            # 熵值分析
            entropy = self._calculate_entropy(content[:4096])
            if entropy > 7.5:
                if not content.startswith((b'PK', b'Rar!', b'\x1f\x8b', b'\x37\x7a')):
                    return {"reason": f"High entropy ({entropy:.2f}) - possibly encrypted", "suggested_ext": "bin", "category": "encrypted"}

            # JavaScript 恶意代码
            js_patterns = [
                (b'eval(', b'unescape(', 'JavaScript eval+unescape'),
                (b'eval(', b'fromcharcode', 'JavaScript eval+charcode'),
                (b'document.write(unescape', None, 'JavaScript document.write'),
                (b'activexobject', b'wscript.shell', 'JavaScript ActiveX shell'),
            ]

            for pattern in js_patterns:
                marker1, marker2, reason = pattern
                if marker1 in content_lower:
                    if marker2 is None or marker2 in content_lower:
                        return {"reason": reason, "suggested_ext": "js", "category": "script"}

        except Exception:
            pass

        return None

    def _analyze_unknown_file(self, filepath: str, file_size: int) -> Optional[Dict]:
        try:
            with open(filepath, 'rb') as f:
                content = f.read(min(file_size, 8192))

            non_printable = sum(1 for b in content[:1024] if b < 32 or b > 126)
            is_binary = non_printable > len(content[:1024]) * 0.3

            if is_binary and file_size > 1024:
                if b'This program' in content or b'PE\x00\x00' in content:
                    return {"reason": "Possible PE executable", "suggested_ext": "exe", "category": "executable"}
                if b'\x7fELF' in content[:100]:
                    return {"reason": "ELF executable", "suggested_ext": "elf", "category": "executable"}
                if file_size > 10 * 1024:
                    return {"reason": "Large binary file", "suggested_ext": "bin", "category": "binary"}

            script_markers = [
                (b'<?php', 'PHP script'),
                (b'<%@', 'JSP/ASP script'),
                (b'#!/', 'Shell script'),
                (b'import ', 'Python script'),
                (b'function ', 'JavaScript/PHP function'),
                (b'class ', 'Class definition'),
            ]

            for marker, desc in script_markers:
                if marker in content[:500]:
                    return {"reason": desc, "suggested_ext": "txt", "category": "script"}

        except Exception:
            pass

        return None

    def _is_binary_file(self, filepath: str) -> bool:
        try:
            with open(filepath, 'rb') as f:
                chunk = f.read(1024)
            non_printable = sum(1 for b in chunk if b < 32 or b > 126)
            return non_printable > len(chunk) * 0.3
        except Exception:
            return False

    def _calculate_entropy(self, data: bytes) -> float:
        if not data:
            return 0.0

        counter = Counter(data)
        length = len(data)

        entropy = 0.0
        for count in counter.values():
            if count > 0:
                probability = count / length
                entropy -= probability * math.log2(probability)

        return entropy

    def _is_random_string(self, filename: str) -> bool:
        name = os.path.splitext(filename)[0]
        if len(name) < 16:
            return False
        if all(c in '0123456789abcdefABCDEF' for c in name):
            return True
        if all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=' for c in name):
            return len(name) > 24
        return False

    def _detect_file_type_by_magic(self, filepath: str) -> Optional[Dict]:
        MAGIC_SIGNATURES = [
            # 压缩包
            (b'\x50\x4B\x03\x04', {"extension": "zip", "mime_type": "application/zip", "category": "archive", "description": "ZIP Archive"}),
            (b'\x50\x4B\x05\x06', {"extension": "zip", "mime_type": "application/zip", "category": "archive", "description": "ZIP Archive (empty)"}),
            (b'\x52\x61\x72\x21\x1A\x07', {"extension": "rar", "mime_type": "application/x-rar-compressed", "category": "archive", "description": "RAR Archive"}),
            (b'\x37\x7A\xBC\xAF\x27\x1C', {"extension": "7z", "mime_type": "application/x-7z-compressed", "category": "archive", "description": "7-Zip Archive"}),
            (b'\x1F\x8B\x08', {"extension": "gz", "mime_type": "application/gzip", "category": "archive", "description": "GZIP Archive"}),
            (b'\x42\x5A\x68', {"extension": "bz2", "mime_type": "application/x-bzip2", "category": "archive", "description": "BZIP2 Archive"}),
            (b'\x4D\x53\x43\x46', {"extension": "cab", "mime_type": "application/vnd.ms-cab-compressed", "category": "archive", "description": "Windows Cabinet"}),
            # 可执行文件
            (b'\x4D\x5A', {"extension": "exe", "mime_type": "application/x-msdownload", "category": "executable", "description": "Windows Executable"}),
            (b'\x7F\x45\x4C\x46', {"extension": "elf", "mime_type": "application/x-executable", "category": "executable", "description": "Linux ELF"}),
            (b'\xCA\xFE\xBA\xBE', {"extension": "class", "mime_type": "application/java-vm", "category": "executable", "description": "Java Class"}),
            # 文档
            (b'\x25\x50\x44\x46', {"extension": "pdf", "mime_type": "application/pdf", "category": "document", "description": "PDF Document"}),
            (b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1', {"extension": "doc", "mime_type": "application/msword", "category": "document", "description": "MS Office Document"}),
            # 图片
            (b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A', {"extension": "png", "mime_type": "image/png", "category": "image", "description": "PNG Image"}),
            (b'\xFF\xD8\xFF', {"extension": "jpg", "mime_type": "image/jpeg", "category": "image", "description": "JPEG Image"}),
            (b'\x47\x49\x46\x38', {"extension": "gif", "mime_type": "image/gif", "category": "image", "description": "GIF Image"}),
            (b'\x42\x4D', {"extension": "bmp", "mime_type": "image/bmp", "category": "image", "description": "BMP Image"}),
            # 脚本/代码
            (b'\x3C\x3F\x70\x68\x70', {"extension": "php", "mime_type": "application/x-php", "category": "script", "description": "PHP Script"}),
            (b'\x23\x21', {"extension": "sh", "mime_type": "text/x-shellscript", "category": "script", "description": "Shell Script"}),
            # 数据库
            (b'SQLite format 3', {"extension": "sqlite", "mime_type": "application/x-sqlite3", "category": "database", "description": "SQLite Database"}),
        ]

        try:
            with open(filepath, 'rb') as f:
                header = f.read(32)

            sorted_sigs = sorted(MAGIC_SIGNATURES, key=lambda x: len(x[0]), reverse=True)

            for magic, info in sorted_sigs:
                if header.startswith(magic):
                    return info

        except Exception:
            pass

        return None

    def _create_extracted_file(self, filepath: str, filename: str, pcap_path: str,
                               detected_type: Optional[Dict]) -> ExtractedFile:
        file_size = os.path.getsize(filepath)

        if detected_type:
            content_type = detected_type.get("mime_type", "application/octet-stream")
            file_type = detected_type.get("category", "other")
        else:
            ext = os.path.splitext(filename)[1].lower()
            content_type = self._guess_content_type(ext)
            file_type = self._get_file_type_from_content_type(content_type)

        return ExtractedFile(
            file_path=filepath,
            file_name=filename,
            file_type=file_type,
            file_size=file_size,
            source_packet=0,
            content_type=content_type,
            pcap_path=pcap_path
        )

    def _extract_single_http_response(self, pcap_path: str, meta: Dict, output_dir: str) -> Optional[ExtractedFile]:
        frame_num = meta.get("frame_number", 0)
        if frame_num == 0:
            return None

        try:
            cmd = [
                self._tshark_path,
                "-r", pcap_path,
                "-Y", f"frame.number == {frame_num}",
                "-T", "fields",
                "-e", "http.file_data",
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='replace',
                timeout=30
            )

            hex_data = result.stdout.strip()
            if not hex_data or len(hex_data) < 20:
                return None

            hex_data = hex_data.replace(':', '').replace(' ', '').replace('\n', '')
            file_data = bytes.fromhex(hex_data)

            if len(file_data) < 100:
                return None

            # 从 Content-Disposition 提取文件名
            disp = meta.get("content_disposition", "")
            filename = None
            if 'filename=' in disp:
                try:
                    start = disp.index('filename=') + 9
                    end = disp.find(';', start) if ';' in disp[start:] else len(disp)
                    filename = disp[start:end].strip('"\'')
                except Exception:
                    pass

            if not filename:
                ct = meta.get("content_type", "").lower()
                ext = self._get_extension_from_content_type(ct)
                filename = f"frame_{frame_num}.{ext}"

            filepath = os.path.join(output_dir, filename)

            with open(filepath, 'wb') as f:
                f.write(file_data)

            detected_type = self._detect_file_type_by_magic(filepath)
            return self._create_extracted_file(filepath, filename, pcap_path, detected_type)

        except Exception:
            return None

    def _get_extension_from_content_type(self, content_type: str) -> str:
        ext_map = {
            'application/zip': 'zip',
            'application/x-rar': 'rar',
            'application/x-7z-compressed': '7z',
            'application/gzip': 'gz',
            'application/pdf': 'pdf',
            'application/octet-stream': 'bin',
            'application/x-msdownload': 'exe',
            'image/png': 'png',
            'image/jpeg': 'jpg',
            'image/gif': 'gif',
        }
        for ct, ext in ext_map.items():
            if ct in content_type:
                return ext
        return 'bin'

    def _get_file_priority(self, ef: ExtractedFile) -> int:
        name_lower = ef.file_name.lower()

        if name_lower.endswith(('.zip', '.rar', '.7z', '.gz', '.tar')):
            return 0
        elif name_lower.endswith(('.exe', '.elf', '.dll')):
            return 1
        elif name_lower.endswith(('.php', '.jsp', '.asp', '.aspx', '.py', '.sh')):
            return 2
        elif ef.file_type == "document":
            return 3
        elif ef.file_type == "database":
            return 4
        elif name_lower.endswith('.cab'):
            return 8
        elif ef.file_type == "archive":
            return 5
        elif ef.file_type == "image":
            return 6
        else:
            return 7

    def _get_file_hash(self, filepath: str) -> str:
        try:
            with open(filepath, 'rb') as f:
                return hashlib.md5(f.read()).hexdigest()
        except Exception:
            return filepath

    def _guess_content_type(self, ext: str) -> str:
        content_types = {
            ".html": "text/html", ".htm": "text/html",
            ".php": "application/x-php", ".js": "application/javascript",
            ".css": "text/css", ".json": "application/json",
            ".xml": "application/xml", ".png": "image/png",
            ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
            ".gif": "image/gif", ".ico": "image/x-icon",
            ".txt": "text/plain", ".pdf": "application/pdf",
            ".zip": "application/zip", ".rar": "application/x-rar-compressed",
            ".7z": "application/x-7z-compressed", ".tar": "application/x-tar",
            ".gz": "application/gzip",
        }
        return content_types.get(ext, "application/octet-stream")

    def _get_file_type_from_content_type(self, content_type: str) -> str:
        ct = content_type.lower()

        if ct.startswith("image/"):
            return "image"
        elif ct.startswith("text/"):
            return "text"
        elif ct in ("application/pdf",):
            return "document"
        elif ct in ("application/zip", "application/x-rar-compressed",
                    "application/x-7z-compressed", "application/x-tar",
                    "application/gzip", "application/octet-stream"):
            return "archive"
        elif ct in ("application/x-php", "application/javascript",
                    "application/json", "application/xml"):
            return "code"
        else:
            return "other"

    # Webshell 检测

    def _run_webshell_detection_stream(
        self,
        pcap_path: str,
        options: dict,
        on_detection: Optional[Callable[[DetectionResult], None]] = None,
        on_progress: Optional[Callable[[int, str], None]] = None
    ) -> List[DetectionResult]:
        """用流式处理做 Webshell 检测"""
        results: List[DetectionResult] = []

        def emit_sub_progress(msg: str):
            if on_progress:
                on_progress(55, msg)

        try:
            sys.path.insert(0, CORE_PATH)
            from core.webshell_detect import WebShellDetector

            handler = TsharkProcessHandler(self._tshark_path)

            # 配置流式读取 (返回 PyShark 兼容的包装器)
            config = StreamConfig(
                pcap_path=pcap_path,
                display_filter='http',
                output_format=OutputFormat.EK,
                disable_name_resolution=True,
                line_buffered=True
            )

            # 收集 HTTP 包 (使用 PyShark 兼容包装器)
            http_packets = []
            for wrapper in handler.stream_pyshark_compatible(config):
                if wrapper.has_layer('http'):
                    http_packets.append(wrapper)

                # 限制内存使用
                if len(http_packets) >= 10000:
                    break

            handler.stop()

            if http_packets:
                try:
                    # 使用 WebShellDetector 统一检测
                    detector = WebShellDetector()

                    # 配置自定义密钥
                    if options.get("behinder_keys"):
                        detector.set_behinder_keys(options["behinder_keys"])
                        emit_sub_progress(f"已配置 {len(options['behinder_keys'])} 个冰蝎密钥")
                    if options.get("godzilla_keys"):
                        detector.set_godzilla_keys(options["godzilla_keys"])
                        emit_sub_progress(f"已配置 {len(options['godzilla_keys'])} 个哥斯拉密钥")

                    # 配置 AST 分析（默认禁用以提高性能）
                    if options.get("enable_ast", False):
                        detector.enable_ast(True)
                        emit_sub_progress("已启用 AST 语义分析")

                    emit_sub_progress("正在执行 Webshell 特征检测...")
                    detection_results = detector.detect(http_packets)

                    emit_sub_progress("正在处理检测结果...")
                    # 处理所有检测结果
                    for tool_name in ['antsword', 'caidao', 'behinder', 'godzilla']:
                        for r in detection_results.get(tool_name, []):
                            if tool_name == 'antsword':
                                det = DetectionResult.from_antsword_result(r)
                            elif tool_name == 'caidao':
                                det = DetectionResult.from_caidao_result(r)
                            elif tool_name == 'behinder':
                                det = DetectionResult.from_behinder_result(r)
                            elif tool_name == 'godzilla':
                                det = DetectionResult.from_godzilla_result(r)
                            else:
                                continue
                            results.append(det)
                            if on_detection:
                                on_detection(det)
                except Exception as e:
                    print(f"[!] Webshell检测异常: {e}")

        except TsharkNotFoundError as e:
            print(f"[!] TShark未找到: {e}")
        except TsharkError as e:
            print(f"[!] TShark错误: {e}")
        except Exception as e:
            print(f"[!] Webshell检测异常: {e}")

        return results

    # 攻击检测

    def _run_attack_detection(
        self,
        pcap_path: str,
        on_detection: Optional[Callable[[DetectionResult], None]] = None
    ) -> List[DetectionResult]:
        """OWASP Top 10 攻击检测"""
        results: List[DetectionResult] = []
        seen_signatures = set()

        try:
            from urllib.parse import unquote

            detector = AttackDetector()

            # 使用 TsharkProcessHandler 流式处理
            handler = TsharkProcessHandler(self._tshark_path)
            config = StreamConfig(
                pcap_path=pcap_path,
                display_filter='http.request',
                output_format=OutputFormat.EK,
                disable_name_resolution=True,
                line_buffered=True
            )

            for wrapper in handler.stream_pyshark_compatible(config):
                try:
                    if not wrapper.has_layer('http'):
                        continue

                    # 使用属性访问（__getattr__），不用下标访问（无 __getitem__）
                    http_layer = wrapper.http

                    # 获取基本信息
                    method = getattr(http_layer, 'request_method', '') or ''
                    uri = getattr(http_layer, 'request_uri', '') or getattr(http_layer, 'request_full_uri', '') or ''
                    host = getattr(http_layer, 'host', '') or ''

                    # 获取请求体
                    body = ''
                    file_data = getattr(http_layer, 'file_data', None)
                    if file_data:
                        body = str(file_data)

                    # 获取 IP 信息
                    source_ip = ''
                    dest_ip = ''
                    ip_layer = wrapper.ip
                    if ip_layer is not None:
                        src = getattr(ip_layer, 'src', None)
                        dst = getattr(ip_layer, 'dst', None)
                        source_ip = str(src) if src else ''
                        dest_ip = str(dst) if dst else ''

                    # 获取时间戳和包号
                    # PacketWrapper 没有 sniff_time，从 frame 层获取
                    timestamp = ''
                    frame_layer = wrapper.frame
                    if frame_layer is not None:
                        frame_time = getattr(frame_layer, 'time', None)
                        if frame_time:
                            timestamp = str(frame_time)
                    packet_number = wrapper.number or 0

                    # URL 解码 URI
                    try:
                        decoded_uri = unquote(uri)
                    except Exception:
                        decoded_uri = uri

                    data_to_check = f"{decoded_uri}\n{body}"
                    data_bytes = data_to_check.encode('utf-8', errors='replace')

                    attack_result = detector.detect(
                        data_bytes,
                        method=method,
                        uri=uri
                    )

                    if attack_result.get('detected') and attack_result.get('total_weight', 0) >= 20:
                        indicator_names = tuple(sorted(
                            ind.get('name', '') for ind in attack_result.get('indicators', [])
                        ))
                        attack_tags = tuple(sorted(attack_result.get('tags', [])))
                        dedup_key = (uri, attack_tags, indicator_names)

                        if dedup_key not in seen_signatures:
                            seen_signatures.add(dedup_key)

                            det = DetectionResult.from_attack_result(
                                attack_result=attack_result,
                                method=method,
                                uri=uri,
                                source_ip=source_ip,
                                dest_ip=dest_ip,
                                timestamp=timestamp,
                                packet_number=packet_number
                            )

                            results.append(det)
                            if on_detection:
                                on_detection(det)

                except AttributeError:
                    continue
                except Exception:
                    continue

            handler.stop()

        except Exception as e:
            print(f"[!] 攻击检测异常: {e}")

        return results

    def get_file_hex_content(self, file_path: str, max_bytes: int = 4096) -> str:
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

    def get_packet_detail(self, pcap_path: str, packet_num: int) -> Tuple[str, List[str]]:
        if not self._tshark_path:
            return "", ["未找到 tshark"]

        try:
            filter_expr = f"frame.number == {packet_num}" if packet_num > 0 else "http"

            cmd = [
                self._tshark_path,
                "-r", pcap_path,
                "-Y", filter_expr,
                "-V",
                "-x",
                "-c", "1"
            ]

            popen_kwargs = {
                "capture_output": True,
                "text": True,
                "encoding": 'utf-8',
                "errors": 'replace',
                "timeout": 30
            }

            if sys.platform == "win32":
                popen_kwargs["creationflags"] = 0x08000000

            result = subprocess.run(cmd, **popen_kwargs)

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
                protocol_layers = ["Frame", "Ethernet II", "Internet Protocol", "Transmission Control Protocol"]

            return hex_dump, protocol_layers

        except Exception as e:
            return "", [f"错误: {str(e)}"]


class StreamAnalysisService:
    """流式分析服务 - 生成器和回调两种模式"""

    def __init__(self):
        self._tshark_path = AnalysisService().find_tshark()

    def stream_http_packets(
        self,
        pcap_path: str,
        display_filter: str = "http"
    ) -> Generator[PacketWrapper, None, None]:
        """
        流式返回 HTTP 数据包

        Yields:
            PacketWrapper: PyShark 兼容的数据包包装器
        """
        handler = TsharkProcessHandler(self._tshark_path)
        config = StreamConfig(
            pcap_path=pcap_path,
            display_filter=display_filter,
            output_format=OutputFormat.EK
        )

        try:
            yield from handler.stream_pyshark_compatible(config)
        finally:
            handler.stop()

    def analyze_with_callback(
        self,
        pcap_path: str,
        on_packet: Callable[[PacketWrapper], None],
        on_progress: Optional[Callable[[int, str], None]] = None,
        display_filter: str = "http"
    ) -> int:
        """
        回调模式分析

        Args:
            pcap_path: PCAP 文件路径
            on_packet: 数据包回调
            on_progress: 进度回调
            display_filter: 显示过滤器

        Returns:
            处理的数据包数量
        """
        handler = TsharkProcessHandler(self._tshark_path)
        config = StreamConfig(
            pcap_path=pcap_path,
            display_filter=display_filter,
            output_format=OutputFormat.EK
        )

        count = 0
        last_progress_time = time.time()

        try:
            for wrapper in handler.stream_pyshark_compatible(config):
                on_packet(wrapper)
                count += 1

                # 进度更新
                if on_progress:
                    current_time = time.time()
                    if current_time - last_progress_time >= 0.5:
                        on_progress(count, f"已处理 {count} 个数据包")
                        last_progress_time = current_time

        finally:
            handler.stop()

        return count
