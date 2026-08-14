# payload_viewer.py
# 数据包详情查看，支持hex/文本/格式化等多种视图

import os
import sys
import json
import base64
import shutil
import binascii
import logging
from urllib.parse import unquote
from typing import Optional

logger = logging.getLogger(__name__)
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTextEdit, QLabel,
    QTabWidget, QPushButton, QScrollArea, QFrame, QSplitter,
    QStackedWidget, QTreeWidget, QTreeWidgetItem, QButtonGroup,
    QFileDialog, QMessageBox, QMenu, QDialog, QPlainTextEdit,
    QDialogButtonBox, QComboBox, QGridLayout, QProgressBar
)
from PySide6.QtCore import Qt, QByteArray, Signal, QTimer, QThread
from PySide6.QtGui import QFont, QColor, QPixmap, QImage, QAction

from models.detection_result import (
    DetectionResult, ExtractedFile, ProtocolFinding,
    AutoDecodingResult, FileRecoveryResult, AttackDetectionInfo,
    RTPStreamInfo
)
from core.display_safety import (
    format_binary_as_hex as _format_binary_as_hex,
    is_binary_or_corrupt_text,
    safe_display_text as _safe_display_text,
)
from core.protocol_display import format_protocol_raw_values
from core.tshark_locator import find_tshark


def is_binary_data(data: str, threshold: float = 0.3) -> bool:
    """检查是否为二进制数据"""
    return is_binary_or_corrupt_text(data, threshold=threshold)


def format_binary_as_hex(data: str, max_bytes: int = 4096) -> str:
    """Wireshark风格hex dump"""
    return _format_binary_as_hex(data, max_bytes=max_bytes)


def safe_display_text(data, max_length: int = 50000) -> str:
    """安全显示文本，二进制自动转hex"""
    return _safe_display_text(data, max_length=max_length)


class WiresharkStyleViewer(QFrame):
    """Wireshark风格的流量包查看器 - 分层展示"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._setupUI()

    def _setupUI(self):
        self.setStyleSheet("""
            WiresharkStyleViewer {
                background-color: white;
                border: 1px solid #E0E0E0;
                border-radius: 4px;
            }
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # 标题栏
        title_bar = QWidget()
        title_bar.setStyleSheet("background-color: #E8F4FD; border-bottom: 1px solid #BBDEFB;")
        title_layout = QHBoxLayout(title_bar)
        title_layout.setContentsMargins(10, 5, 10, 5)
        title = QLabel("Wireshark 视图")
        title.setStyleSheet("font-size: 12px; font-weight: bold; color: #1976D2;")
        title_layout.addWidget(title)
        title_layout.addStretch()
        layout.addWidget(title_bar)

        # 分层树 - 类似Wireshark的协议分层展示
        self.tree = QTreeWidget()
        self.tree.setHeaderHidden(True)
        self.tree.setIndentation(20)
        self.tree.setAnimated(False)
        self.tree.setAlternatingRowColors(True)
        self.tree.setStyleSheet("""
            QTreeWidget {
                border: none;
                background-color: #FAFAFA;
                font-family: "Consolas", "Courier New", monospace;
                font-size: 11px;
            }
            QTreeWidget::item {
                padding: 3px 0;
            }
            QTreeWidget::item:hover {
                background-color: #E3F2FD;
            }
            QTreeWidget::item:selected {
                background-color: #BBDEFB;
                color: #1565C0;
            }
        """)
        layout.addWidget(self.tree)

        # 底部：十六进制/原文本视图
        self.hex_view = QTextEdit()
        self.hex_view.setReadOnly(True)
        self.hex_view.setMaximumHeight(120)
        self.hex_view.setStyleSheet("""
            QTextEdit {
                border: none;
                border-top: 1px solid #E0E0E0;
                background-color: #F5F5F5;
                font-family: "Consolas", "Courier New", monospace;
                font-size: 10px;
                padding: 4px;
            }
        """)
        layout.addWidget(self.hex_view)

    def setContent(self, detection: DetectionResult):
        """设置Wireshark风格分层内容"""
        # 禁用更新，避免每个 QTreeWidgetItem 创建都触发布局重算
        self.tree.setUpdatesEnabled(False)
        self.hex_view.setUpdatesEnabled(False)
        try:
            self._buildContent(detection)
        finally:
            self.tree.setUpdatesEnabled(True)
            self.hex_view.setUpdatesEnabled(True)

    def _buildContent(self, detection: DetectionResult):
        """实际构建 Wireshark 视图内容（在 setUpdatesEnabled(False) 保护下调用）"""
        self.tree.clear()
        self.hex_view.clear()

        # Frame层
        frame_item = QTreeWidgetItem(self.tree, [f"Frame (检测项: {detection.detection_type.display_name})"])
        frame_item.setForeground(0, QColor("#1976D2"))
        QTreeWidgetItem(frame_item, [f"  时间戳: {detection.timestamp or 'N/A'}"])
        QTreeWidgetItem(frame_item, [f"  威胁等级: {detection.threat_level.display_name}"])
        QTreeWidgetItem(frame_item, [f"  检测指标: {detection.indicator or 'N/A'}"])

        # 置信度和权重（如果有）
        if hasattr(detection, 'total_weight') and detection.total_weight:
            QTreeWidgetItem(frame_item, [f"  总权重: {detection.total_weight}"])
        if hasattr(detection, 'confidence') and detection.confidence:
            QTreeWidgetItem(frame_item, [f"  置信度: {detection.confidence}"])
        if detection.tcp_stream >= 0:
            QTreeWidgetItem(frame_item, [f"  TCP Stream: {detection.tcp_stream}"])

        # IP层
        if detection.source_ip or detection.dest_ip:
            ip_item = QTreeWidgetItem(self.tree, ["Internet Protocol"])
            ip_item.setForeground(0, QColor("#388E3C"))
            QTreeWidgetItem(ip_item, [f"  源地址: {detection.source_ip or 'N/A'}"])
            QTreeWidgetItem(ip_item, [f"  目的地址: {detection.dest_ip or 'N/A'}"])

        # HTTP层
        if detection.method:
            http_item = QTreeWidgetItem(self.tree, ["Hypertext Transfer Protocol"])
            http_item.setForeground(0, QColor("#E65100"))
            QTreeWidgetItem(http_item, [f"  Request Method: {detection.method}"])
            QTreeWidgetItem(http_item, [f"  Request URI: {detection.uri or '/'}"])

        # 攻击命令摘要
        commands = self._extract_attack_commands(detection)
        if commands:
            cmd_item = QTreeWidgetItem(self.tree, [f"⚠ Attack Commands ({len(commands)})"])
            cmd_item.setForeground(0, QColor("#D32F2F"))
            for cmd in commands:
                QTreeWidgetItem(cmd_item, [f"  [{cmd['type']}] {cmd['command'][:100]}"])

        # Payload层
        if detection.payload:
            payload_item = QTreeWidgetItem(self.tree, ["Payload Data"])
            payload_item.setForeground(0, QColor("#7B1FA2"))
            if isinstance(detection.payload, dict):
                self._add_dict_items(payload_item, detection.payload)
            else:
                payload_str = str(detection.payload)
                for line in payload_str.split('\n')[:100]:
                    QTreeWidgetItem(payload_item, [f"  {line[:500]}"])

        # 解码后的载荷（新格式）
        if hasattr(detection, 'payloads') and detection.payloads:
            decoded_item = QTreeWidgetItem(self.tree, [f"Decoded Payloads ({len(detection.payloads)})"])
            decoded_item.setForeground(0, QColor("#00796B"))
            for payload in detection.payloads:
                param_item = QTreeWidgetItem(decoded_item, [f"  {payload.param_name} ({payload.payload_type})"])
                if payload.decoded_content:
                    content_preview = payload.decoded_content[:2000]
                    if len(payload.decoded_content) > 2000:
                        content_preview += "..."
                    QTreeWidgetItem(param_item, [f"    {content_preview}"])

        # HTTP Response 结构化展示
        if detection.response_data:
            resp_item = QTreeWidgetItem(self.tree, ["HTTP Response"])
            resp_item.setForeground(0, QColor("#C2185B"))
            resp_str = str(detection.response_data)

            if is_binary_data(resp_str):
                QTreeWidgetItem(resp_item, ["  [Binary Data - Hex Dump]"])
                hex_dump = format_binary_as_hex(resp_str, max_bytes=2048)
                for line in hex_dump.split('\n')[:100]:
                    QTreeWidgetItem(resp_item, [f"  {line}"])
            else:
                resp_lines = resp_str.split('\r\n')
                if resp_lines:
                    QTreeWidgetItem(resp_item, [f"  {resp_lines[0]}"])

                header_end = 0
                for i, line in enumerate(resp_lines[1:], 1):
                    if not line.strip():
                        header_end = i
                        break
                    if i <= 30:
                        QTreeWidgetItem(resp_item, [f"  {line[:500]}"])

                if header_end > 0 and header_end < len(resp_lines):
                    body_text = '\r\n'.join(resp_lines[header_end + 1:])
                    if body_text:
                        body_item = QTreeWidgetItem(resp_item, ["  Response Body"])
                        if is_binary_data(body_text):
                            hex_dump = format_binary_as_hex(body_text, max_bytes=2048)
                            for hl in hex_dump.split('\n')[:100]:
                                QTreeWidgetItem(body_item, [f"    {hl}"])
                        else:
                            for bl in body_text.split('\n')[:100]:
                                QTreeWidgetItem(body_item, [f"    {bl[:500]}"])

        elif hasattr(detection, 'response_sample') and detection.response_sample:
            sample_item = QTreeWidgetItem(self.tree, ["Response Sample"])
            sample_item.setForeground(0, QColor("#C2185B"))
            sample_str = str(detection.response_sample)
            if is_binary_data(sample_str):
                hex_dump = format_binary_as_hex(sample_str, max_bytes=2048)
                for line in hex_dump.split('\n')[:100]:
                    QTreeWidgetItem(sample_item, [f"  {line}"])
            else:
                for line in sample_str.split('\n')[:100]:
                    QTreeWidgetItem(sample_item, [f"  {line[:500]}"])

        # Raw结果（限制显示，避免大字典导致卡死）
        if detection.raw_result:
            raw_item = QTreeWidgetItem(self.tree, ["Raw Detection Result"])
            raw_item.setForeground(0, QColor("#455A64"))
            # 只展示关键字段的摘要，跳过大块原始数据
            self._add_dict_items_safe(raw_item, detection.raw_result)

        # 只展开前两级，不 expandAll()
        for i in range(self.tree.topLevelItemCount()):
            self.tree.topLevelItem(i).setExpanded(True)

        # 底部显示原始数据摘要（截断字典后再序列化，避免大字典卡死）
        raw_summary = self._truncate_dict_for_display(detection.raw_result or {})
        raw_text = json.dumps(raw_summary, ensure_ascii=False, indent=2, default=str)
        if len(raw_text) > 2000:
            raw_text = raw_text[:2000] + "\n... (截断)"
        self.hex_view.setPlainText(raw_text)

    def _add_dict_items(self, parent: QTreeWidgetItem, data: dict, depth: int = 0):
        """递归添加字典项到树中"""
        if depth > 3:
            return
        for key, value in data.items():
            if isinstance(value, dict):
                sub_item = QTreeWidgetItem(parent, [f"  {key}:"])
                self._add_dict_items(sub_item, value, depth + 1)
            elif isinstance(value, list):
                sub_item = QTreeWidgetItem(parent, [f"  {key}: [{len(value)} items]"])
                for i, v in enumerate(value[:10]):
                    v_str = str(v)[:200]
                    if is_binary_data(v_str):
                        v_str = "[Binary Data]"
                    QTreeWidgetItem(sub_item, [f"    [{i}]: {v_str}"])
            else:
                val_str = str(value)
                if is_binary_data(val_str):
                    val_str = f"[Binary Data, {len(val_str)} bytes]"
                elif len(val_str) > 200:
                    val_str = val_str[:200] + "..."
                QTreeWidgetItem(parent, [f"  {key}: {val_str}"])

    # 跳过的大块原始数据键名
    _RAW_SKIP_KEYS = {
        'raw_http_request', 'raw_http_response'
    }

    def _add_dict_items_safe(self, parent: QTreeWidgetItem, data: dict, depth: int = 0):
        """安全版递归添加字典项"""
        if depth > 2:
            return
        node_count = 0
        max_nodes = 100
        for key, value in data.items():
            if node_count >= max_nodes:
                QTreeWidgetItem(parent, [f"  ... 剩余 {len(data) - node_count} 项已省略"])
                break
            if key in self._RAW_SKIP_KEYS:
                val_len = len(str(value)) if value else 0
                QTreeWidgetItem(parent, [f"  {key}: [{val_len} chars]"])
                node_count += 1
                continue
            if isinstance(value, dict):
                sub_item = QTreeWidgetItem(parent, [f"  {key}:"])
                self._add_dict_items_safe(sub_item, value, depth + 1)
                node_count += 1
            elif isinstance(value, list):
                sub_item = QTreeWidgetItem(parent, [f"  {key}: [{len(value)} items]"])
                for i, v in enumerate(value[:5]):
                    v_str = str(v)[:500]
                    QTreeWidgetItem(sub_item, [f"    [{i}]: {v_str}"])
                if len(value) > 5:
                    QTreeWidgetItem(sub_item, [f"    ... 剩余 {len(value) - 5} 项"])
                node_count += 1
            else:
                val_str = str(value)
                if len(val_str) > 500:
                    val_str = val_str[:500] + "..."
                QTreeWidgetItem(parent, [f"  {key}: {val_str}"])
                node_count += 1

    def _truncate_dict_for_display(self, data: dict, max_val_len: int = 200) -> dict:
        """截断字典中的大值，避免 json.dumps 处理巨大字符串"""
        result = {}
        for key, value in data.items():
            if isinstance(value, dict):
                result[key] = self._truncate_dict_for_display(value, max_val_len)
            elif isinstance(value, list):
                result[key] = f"[{len(value)} items]"
            elif isinstance(value, str) and len(value) > max_val_len:
                result[key] = value[:max_val_len] + f"... ({len(value)} chars)"
            else:
                result[key] = value
        return result

    def _extract_attack_commands(self, detection: DetectionResult) -> list:
        """从检测结果中提取攻击者执行的命令"""
        import re
        commands = []

        # 收集所有参数的解码内容 {参数名: 解码内容}
        all_decoded = {}

        # 从payloads提取
        for payload in detection.payloads:
            if payload.decoded_content:
                all_decoded[payload.param_name] = payload.decoded_content

        # 从raw_result提取
        if detection.raw_result and isinstance(detection.raw_result, dict):
            raw_payloads = detection.raw_result.get('payloads', {})
            if isinstance(raw_payloads, dict):
                for param_name, info in raw_payloads.items():
                    if isinstance(info, dict):
                        decoded = info.get('decoded', info.get('decoded_content', ''))
                        if decoded and param_name not in all_decoded:
                            all_decoded[param_name] = str(decoded)

        # 旧格式payload兼容
        if detection.payload and isinstance(detection.payload, dict):
            for k, v in detection.payload.items():
                if k not in all_decoded:
                    if isinstance(v, dict):
                        decoded = v.get('decoded', v.get('decoded_content', ''))
                        if decoded:
                            all_decoded[k] = str(decoded)
                    elif isinstance(v, str) and len(v) > 10:
                        all_decoded[k] = v

        # 菜刀/蚁剑特殊处理
        # 菜刀结构: z0=PHP框架, z1=路径, z2=命令
        # 蚁剑结构: 类似，可能有多个参数
        tool_type = detection.detection_type.value

        if tool_type in ('caidao', 'antsword'):
            commands.extend(self._extract_caidao_commands(all_decoded))

        # 通用命令提取
        for param_name, text in all_decoded.items():
            # 跳过框架代码参数(z0)，它只是加载器
            if param_name in ('z0',) and tool_type == 'caidao':
                continue

            extracted = self._parse_commands_from_text(text, param_name)
            for cmd in extracted:
                # 避免重复
                if not any(c['command'] == cmd['command'] for c in commands):
                    commands.append(cmd)

        return commands

    def _extract_caidao_commands(self, all_decoded: dict) -> list:
        """菜刀/蚁剑命令提取: z0=框架, z1=路径, z2=命令"""
        commands = []

        # z1 通常是工作目录
        z1 = all_decoded.get('z1', '')
        if z1:
            # 判断是路径还是命令
            if z1.startswith('/') or z1.startswith('C:') or z1.startswith('D:'):
                commands.append({
                    'type': '工作目录',
                    'command': z1,
                    'description': '攻击者指定的工作路径'
                })
            else:
                commands.append({
                    'type': '参数(z1)',
                    'command': z1[:200],
                    'description': ''
                })

        # z2 通常是实际命令
        z2 = all_decoded.get('z2', '')
        if z2:
            # 分析z2的内容类型
            cmd_info = self._analyze_command_content(z2)
            commands.append(cmd_info)

        # z3及以后的参数
        for i in range(3, 10):
            zn = all_decoded.get(f'z{i}', '')
            if zn:
                cmd_info = self._analyze_command_content(zn, f'z{i}')
                commands.append(cmd_info)

        # 蚁剑可能用其他参数名
        for param_name, content in all_decoded.items():
            if param_name.startswith('_0x') or param_name.startswith('ant'):
                cmd_info = self._analyze_command_content(content, param_name)
                if cmd_info['command'] and cmd_info not in commands:
                    commands.append(cmd_info)

        return commands

    def _analyze_command_content(self, content: str, param_name: str = 'z2') -> dict:
        """分析命令内容的类型"""
        if not content:
            return {'type': '空', 'command': '', 'description': ''}

        content_lower = content.lower()
        content_display = content[:300] if len(content) > 300 else content

        # 判断命令类型
        # 系统命令
        shell_keywords = ['whoami', 'id', 'uname', 'ifconfig', 'ipconfig', 'netstat',
                          'cat ', 'type ', 'dir ', 'ls ', 'pwd', 'cd ', 'echo ',
                          'wget ', 'curl ', 'chmod ', 'net ', 'ping ', 'nslookup',
                          'powershell', 'cmd ', 'cmd.exe', '/c ', 'bash ', 'sh ']
        for kw in shell_keywords:
            if kw in content_lower:
                return {
                    'type': '系统命令',
                    'command': content_display,
                    'description': f'Shell命令执行 (参数:{param_name})'
                }

        # 文件读取
        if any(x in content_lower for x in ['/etc/passwd', '/etc/shadow', 'flag', '.conf', '.ini', '.php', '.asp']):
            return {
                'type': '文件读取',
                'command': content_display,
                'description': f'读取敏感文件 (参数:{param_name})'
            }

        # 目录列举
        if content.endswith('/') or content.endswith('\\') or content in ['/', 'C:\\', 'D:\\']:
            return {
                'type': '目录列举',
                'command': content_display,
                'description': f'列出目录内容 (参数:{param_name})'
            }

        # SQL语句
        if any(x in content_lower for x in ['select ', 'insert ', 'update ', 'delete ', 'drop ', 'union ']):
            return {
                'type': 'SQL命令',
                'command': content_display,
                'description': f'数据库操作 (参数:{param_name})'
            }

        # 文件上传/写入
        if any(x in content_lower for x in ['<?php', '<?=', '<script', 'eval(', 'base64_decode']):
            return {
                'type': '代码写入',
                'command': content_display[:150] + '...' if len(content) > 150 else content_display,
                'description': f'写入恶意代码 (参数:{param_name})'
            }

        # 默认
        return {
            'type': f'攻击参数({param_name})',
            'command': content_display,
            'description': ''
        }

    def _parse_commands_from_text(self, text: str, param_name: str = '') -> list:
        """从解码文本中识别攻击命令"""
        import re
        commands = []

        if not text:
            return commands

        # 系统命令执行
        # system("cmd"), exec("cmd"), shell_exec("cmd"), passthru("cmd")
        for func in ['system', 'exec', 'shell_exec', 'passthru', 'popen', 'proc_open']:
            pattern = rf'{func}\s*\(\s*["\'](.+?)["\']\s*\)'
            for m in re.finditer(pattern, text, re.IGNORECASE):
                commands.append({
                    'type': 'System Command',
                    'command': m.group(1),
                    'description': f'via {func}()'
                })

        # system($var) 形式 - 查找变量赋值
        for func in ['system', 'exec', 'shell_exec', 'passthru', 'popen']:
            pattern = rf'{func}\s*\(\s*\$(\w+)\s*\)'
            for m in re.finditer(pattern, text, re.IGNORECASE):
                var_name = m.group(1)
                # 查找变量赋值
                assign_pattern = rf'\${var_name}\s*=\s*["\'](.+?)["\']'
                assign_m = re.search(assign_pattern, text)
                if assign_m:
                    commands.append({
                        'type': 'System Command',
                        'command': assign_m.group(1),
                        'description': f'via ${var_name} -> {func}()'
                    })

        # 文件操作
        # file_get_contents, file_put_contents, fwrite, fopen
        for m in re.finditer(r'file_get_contents\s*\(\s*["\'](.+?)["\']\s*\)', text, re.IGNORECASE):
            commands.append({
                'type': 'File Read',
                'command': m.group(1),
                'description': '读取文件内容'
            })

        for m in re.finditer(r'file_put_contents\s*\(\s*["\'](.+?)["\']\s*,', text, re.IGNORECASE):
            commands.append({
                'type': 'File Write',
                'command': m.group(1),
                'description': '写入文件'
            })

        for m in re.finditer(r'fopen\s*\(\s*["\'](.+?)["\']\s*,\s*["\']([rwab+]+)["\']\s*\)', text, re.IGNORECASE):
            mode = m.group(2)
            desc = '读取文件' if 'r' in mode else '写入文件'
            commands.append({
                'type': 'File Operation',
                'command': f'{m.group(1)} (mode: {mode})',
                'description': desc
            })

        # 目录操作
        for func, desc in [('scandir', '列目录'), ('opendir', '打开目录'),
                           ('readdir', '读目录'), ('mkdir', '创建目录'),
                           ('rmdir', '删除目录'), ('unlink', '删除文件'),
                           ('rename', '重命名'), ('copy', '复制文件')]:
            for m in re.finditer(rf'{func}\s*\(\s*["\'](.+?)["\']\s*', text, re.IGNORECASE):
                commands.append({
                    'type': 'File System',
                    'command': m.group(1),
                    'description': desc
                })

        # 数据库操作
        for m in re.finditer(r'mysql_connect\s*\(\s*["\'](.+?)["\']\s*,', text, re.IGNORECASE):
            commands.append({'type': 'DB Connect', 'command': m.group(1), 'description': 'MySQL连接'})

        for m in re.finditer(r'mysql_query\s*\(\s*["\'](.+?)["\']\s*\)', text, re.IGNORECASE):
            commands.append({'type': 'SQL Query', 'command': m.group(1)[:200], 'description': 'SQL查询'})

        for m in re.finditer(r'mysqli_query\s*\(.+?,\s*["\'](.+?)["\']\s*\)', text, re.IGNORECASE):
            commands.append({'type': 'SQL Query', 'command': m.group(1)[:200], 'description': 'SQL查询'})

        # 直接的shell命令 (如 cd /; ls -la; whoami)
        shell_cmds = ['whoami', 'id', 'uname', 'ifconfig', 'ipconfig', 'netstat',
                      'cat ', 'ls ', 'dir ', 'pwd', 'cd ', 'wget ', 'curl ',
                      'chmod ', 'chown ', 'find ', 'grep ', 'ps ', 'kill ',
                      'net ', 'ping ', 'nslookup', 'type ', 'echo ',
                      'certutil', 'powershell', 'cmd /c', 'cmd.exe']
        text_lower = text.lower()
        for cmd in shell_cmds:
            if cmd in text_lower:
                # 提取包含该命令的完整行
                for line in text.split('\n'):
                    if cmd.strip() in line.lower():
                        clean_line = line.strip()
                        if clean_line and len(clean_line) < 300:
                            commands.append({
                                'type': 'Shell Command',
                                'command': clean_line,
                                'description': ''
                            })
                        break

        # eval/assert 代码执行
        for func in ['eval', 'assert', 'preg_replace']:
            pattern = rf'{func}\s*\(\s*(.{{10,100}}?)\s*\)'
            for m in re.finditer(pattern, text, re.IGNORECASE):
                content = m.group(1).strip('\'"')
                if len(content) > 5:
                    commands.append({
                        'type': 'Code Execution',
                        'command': content[:150],
                        'description': f'via {func}()'
                    })

        # 去重
        seen = set()
        unique_commands = []
        for cmd in commands:
            key = (cmd['type'], cmd['command'])
            if key not in seen:
                seen.add(key)
                unique_commands.append(cmd)

        return unique_commands

    def clear(self):
        self.tree.clear()
        self.hex_view.clear()


class _EvidenceWorker(QThread):
    """后台回原始 pcap 取被卸载的证据。

    和 _PacketLayersWorker 是同一个毛病、同一个解法：BurpStyleViewer.setContent()
    原来在 GUI 主线程上直接调 get_http_request_evidence()，而那个函数会起 tshark
    子进程把 pcap 从头读到目标帧。实测 174MB 的 webone.pcap：

        frame    500 ->  897 ms
        frame  20000 ->  411 ms
        frame 120000 -> 1883 ms
        frame 300000 -> 4069 ms

    也就是说点一条靠后的流量，界面要冻 4 秒。而且只在 Burp 视图下发生 ——
    Wireshark 视图不走这个函数，所以现象是"切到 Burp 就卡，切回去就不卡"。
    帧号越大越慢，pcap 越大越慢，放主线程就永远有卡死的可能。

    信号带上 DetectionResult 本身，主线程据此判断结果是否已经过期
    （用户可能已经点到别的条目上了）。
    """

    loaded = Signal(object, dict)   # (DetectionResult, evidence)
    failed = Signal(object, str)    # (DetectionResult, 错误信息)

    def __init__(self, detection, pcap_path: str, frame: int, parent=None):
        super().__init__(parent)
        self._detection = detection
        self._pcap_path = pcap_path
        self._frame = frame

    def run(self):
        try:
            from controllers.analysis_controller import get_http_request_evidence
            evidence = get_http_request_evidence(self._pcap_path, self._frame)
            self.loaded.emit(self._detection, dict(evidence or {}))
        except Exception as e:
            logger.debug(f"证据回取失败 frame#{self._frame}: {e}")
            self.failed.emit(self._detection, str(e))


class BurpStyleViewer(QFrame):
    """Burp风格的HTTP请求查看器"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._current_detection: Optional[DetectionResult] = None
        self._full_text = ""
        # 用集合而不是单个引用：连点是正常操作，单引用会让还在跑的前一个
        # QThread 失去最后一个 Python 引用被 GC，直接崩。(同 PacketHexViewer)
        self._workers = set()
        self._setupUI()

    def _setupUI(self):
        self.setStyleSheet("""
            BurpStyleViewer {
                background-color: white;
                border: 1px solid #E0E0E0;
                border-radius: 4px;
            }
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # 标题
        title_bar = QWidget()
        title_bar.setStyleSheet("background-color: #FFF3E0; border-bottom: 1px solid #FFCC80;")
        title_layout = QHBoxLayout(title_bar)
        title_layout.setContentsMargins(10, 5, 10, 5)
        title = QLabel("Burp Suite 视图")
        title.setStyleSheet("font-size: 12px; font-weight: bold; color: #E65100;")
        title_layout.addWidget(title)
        title_layout.addStretch()

        # 复制按钮
        copy_btn = QPushButton("复制")
        copy_btn.setStyleSheet("""
            QPushButton {
                background-color: #FF9800;
                color: white;
                border: none;
                border-radius: 3px;
                padding: 3px 10px;
                font-size: 11px;
            }
            QPushButton:hover {
                background-color: #F57C00;
            }
        """)
        copy_btn.clicked.connect(self._copyToClipboard)
        title_layout.addWidget(copy_btn)

        export_btn = QPushButton("导出完整")
        export_btn.setStyleSheet("""
            QPushButton {
                background-color: #43A047;
                color: white;
                border: none;
                border-radius: 3px;
                padding: 3px 10px;
                font-size: 11px;
            }
            QPushButton:hover {
                background-color: #2E7D32;
            }
        """)
        export_btn.clicked.connect(self._exportFullView)
        title_layout.addWidget(export_btn)

        layout.addWidget(title_bar)

        # 内容区域
        self.text_edit = QTextEdit()
        self.text_edit.setReadOnly(True)
        self.text_edit.setStyleSheet("""
            QTextEdit {
                border: none;
                background-color: #1E1E1E;
                color: #D4D4D4;
                font-family: "Consolas", "Courier New", monospace;
                font-size: 12px;
                padding: 8px;
            }
        """)
        layout.addWidget(self.text_edit)

    def setContent(self, detection: DetectionResult):
        """Burp Suite风格展示HTTP请求"""
        self._current_detection = detection
        self._full_text = ""
        lines = []

        # 证据被卸载过的条目，点开时回原始 pcap 取回来（后台线程，不阻塞界面）
        self._ensureEvidenceLoaded(detection)

        # 优先使用真实的 HTTP 请求数据
        raw_http = None
        if detection.raw_result and isinstance(detection.raw_result, dict):
            raw_http = detection.raw_result.get('raw_http_request', '')
            if detection.raw_result.get('_evidence_fetching'):
                # 取回来会自动刷新（_refreshIfCurrent）。不给提示的话这一屏
                # 看起来就像"没有证据"，而实际上正在读盘。
                raw_http = (f"{raw_http}\n"
                            "[正在回原始 pcap 取完整请求，稍候自动刷新…]")

        if raw_http:
            # 直接显示真实的 HTTP 请求
            lines.append(raw_http)
        else:
            # 回退: 构建请求 (使用可用的真实数据)
            # 请求行
            uri = detection.uri or "/"
            lines.append(f"{detection.method} {uri} HTTP/1.1")

            # 请求头
            # 尝试获取真实 Headers
            real_headers = None
            if detection.raw_result and isinstance(detection.raw_result, dict):
                real_headers = detection.raw_result.get('raw_request_headers', '')

            if real_headers:
                # 跳过第一行（请求行已经添加了）
                header_lines = real_headers.strip().split('\r\n')
                for h in header_lines[1:]:  # 跳过请求行
                    if h.strip():
                        lines.append(h)
            else:
                # 回退: 使用默认 Headers（标记为推断）
                lines.append("Host: [unknown]")
                lines.append("# Note: Headers below are inferred, not from actual packet")

            # 根据检测类型调整Content-Type
            is_encrypted = detection.detection_type.value in ('behinder', 'godzilla')
            if not real_headers:
                if is_encrypted:
                    lines.append("Content-Type: application/octet-stream")
                else:
                    lines.append("Content-Type: application/x-www-form-urlencoded")
                lines.append("Connection: close")

        # 空行分隔headers和body
        lines.append("")

        # 请求体
        # 优先从raw_result中取原始请求体
        raw_body = ""
        if detection.raw_result and isinstance(detection.raw_result, dict):
            raw_body = detection.raw_result.get('raw_request_body', '')

        if raw_body:
            lines.append(raw_body)
        elif detection.payloads:
            # 使用新格式的载荷
            params = []
            for payload in detection.payloads:
                if payload.param_name and payload.encoded_sample:
                    params.append(f"{payload.param_name}={payload.encoded_sample}")
            if params:
                lines.append("&".join(params))
        elif detection.payload:
            # 向后兼容
            if isinstance(detection.payload, dict):
                params = []
                for k, v in detection.payload.items():
                    if isinstance(v, dict):
                        val = v.get('encoded_sample', str(v)[:50])
                    else:
                        val = str(v)[:100]
                    params.append(f"{k}={val}")
                lines.append("&".join(params))
            else:
                payload_str = str(detection.payload)
                if len(payload_str) > 50000:
                    payload_str = payload_str[:50000] + "\n... (截断)"
                lines.append(payload_str)

        # 解密内容（冰蝎/哥斯拉）
        if detection.payloads:
            lines.append("")
            lines.append("# Decoded Payloads")
            for payload in detection.payloads:
                lines.append(f"#")
                lines.append(f"# [{payload.param_name}]")
                lines.append(f"#   Type: {payload.payload_type}")
                lines.append(f"#   Method: {payload.decode_method}")
                if payload.decoded_content:
                    lines.append(f"#   Content:")
                    for dc_line in payload.decoded_content.split('\n'):
                        lines.append(f"#     {dc_line}")

        # 响应数据
        restored_response = ""
        if detection.raw_result and isinstance(detection.raw_result, dict):
            try:
                from core.http_reassembly import reconstruct_http_response_from_fields
                if any(k in detection.raw_result for k in ("chunk-data", "chunk_data", "http.chunk_data")):
                    restored_response = reconstruct_http_response_from_fields(detection.raw_result)
            except Exception:
                restored_response = ""

        if restored_response:
            lines.append("")
            lines.append("HTTP Response")
            if len(restored_response) > 50000:
                restored_response = restored_response[:50000] + "\n... (截断)"
            lines.append(restored_response)
        elif detection.response_data:
            lines.append("")
            lines.append("HTTP Response")
            resp_str = str(detection.response_data)
            if is_binary_data(resp_str):
                lines.append("[Binary Data - Hex Dump]")
                lines.append(format_binary_as_hex(resp_str, max_bytes=4096))
            else:
                try:
                    from core.http_reassembly import (
                        format_http_body_for_display,
                        reconstruct_http_response_from_text_dump,
                    )
                    resp_str = reconstruct_http_response_from_text_dump(resp_str) or format_http_body_for_display(resp_str)
                except Exception:
                    pass
                if len(resp_str) > 50000:
                    resp_str = resp_str[:50000] + "\n... (截断)"
                lines.append(resp_str)
        elif hasattr(detection, 'response_sample') and detection.response_sample:
            lines.append("")
            lines.append("Response Sample")
            sample_str = str(detection.response_sample)
            if is_binary_data(sample_str):
                lines.append("[Binary Data - Hex Dump]")
                lines.append(format_binary_as_hex(sample_str, max_bytes=4096))
            else:
                try:
                    from core.http_reassembly import (
                        format_http_body_for_display,
                        reconstruct_http_response_from_text_dump,
                    )
                    sample_str = reconstruct_http_response_from_text_dump(sample_str) or format_http_body_for_display(sample_str)
                except Exception:
                    pass
                if len(sample_str) > 50000:
                    sample_str = sample_str[:50000] + "\n... (截断)"
                lines.append(sample_str)

        preview_text = '\n'.join(lines)
        self._full_text = self._buildFullExportText(detection, preview_text)
        self.text_edit.setPlainText(preview_text)

    def clear(self):
        self._current_detection = None
        self._full_text = ""
        self.text_edit.clear()

    def _copyToClipboard(self):
        from PySide6.QtWidgets import QApplication
        clipboard = QApplication.clipboard()
        clipboard.setText(self.text_edit.toPlainText())

    def _ensureEvidenceLoaded(self, detection: DetectionResult):
        """把被卸载的证据从原始 pcap 里取回来 —— **异步**。

        检测数超过 ResourceLimits.FULL_EVIDENCE_DETECTIONS 之后，stream_worker
        不再把原始报文留在内存里，只写一条带帧号的占位。以前没有任何代码去取，
        于是大流量 pcap 里 2000 条之后的证据在界面上就等于没了；后来补上了，
        但补成了**主线程同步调用** —— 那个函数要起 tshark 把 pcap 从头读到目标
        帧，174MB 的包实测能冻 4 秒（详见 _EvidenceWorker 的实测数据）。

        现在改成后台取：先原样渲染占位，取回来再刷新。取不到时保留占位并把原因
        写进去 —— 不能让"取失败"看起来像"本来就没有"。
        """
        raw = detection.raw_result if isinstance(detection.raw_result, dict) else None
        if not raw or not raw.get('evidence_lazy'):
            return
        if raw.get('_evidence_fetched') or raw.get('_evidence_fetching'):
            return

        pcap_path = raw.get('pcap_path') or ''
        frame = raw.get('frame_number') or getattr(detection, 'packet_number', 0)
        try:
            frame = int(frame or 0)
        except (TypeError, ValueError):
            frame = 0

        raw['_evidence_fetching'] = True
        worker = _EvidenceWorker(detection, pcap_path, frame)
        worker.loaded.connect(self._onEvidenceLoaded)
        worker.failed.connect(self._onEvidenceFailed)
        worker.finished.connect(lambda w=worker: self._workers.discard(w))
        self._workers.add(worker)
        worker.start()

    def _applyEvidence(self, detection: DetectionResult, evidence: dict):
        raw = detection.raw_result if isinstance(detection.raw_result, dict) else None
        if raw is None:
            return
        raw['_evidence_fetching'] = False
        raw['_evidence_fetched'] = True

        if evidence.get('error') or not evidence.get('full'):
            reason = evidence.get('error') or '未取到内容'
            raw['raw_http_request'] = (
                f"{raw.get('raw_http_request', '')}\n"
                f"[回原始 pcap 取证据失败：{reason}]")
            return

        raw['raw_request_headers'] = evidence['headers']
        raw['raw_request_body'] = evidence['body'][:50000]
        raw['raw_request_body_full'] = evidence['body']
        raw['raw_http_request'] = evidence['full'][:100000]
        raw['raw_http_request_full'] = evidence['full']
        raw['evidence_lazy'] = False

    def _onEvidenceLoaded(self, detection: DetectionResult, evidence: dict):
        self._applyEvidence(detection, evidence)
        self._refreshIfCurrent(detection)

    def _onEvidenceFailed(self, detection: DetectionResult, message: str):
        # 失败也标记成已取过：否则每点一次就再花几秒重试一遍。
        self._applyEvidence(detection, {'error': message})
        self._refreshIfCurrent(detection)

    def _refreshIfCurrent(self, detection: DetectionResult):
        """结果回来时用户可能已经点到别的条目上了，过期结果直接丢掉"""
        if detection is not self._current_detection:
            return
        self.setContent(detection)

    def isLoadingEvidence(self) -> bool:
        return any(w.isRunning() for w in self._workers)

    def waitForEvidence(self, timeout_ms: int = 15000) -> bool:
        """等待后台取证结束（测试和退出清理用）"""
        all_done = True
        for worker in list(self._workers):
            if not worker.wait(timeout_ms):
                all_done = False
        return all_done

    def shutdownWorkers(self, timeout_ms: int = 3000):
        """QThread 还在跑的时候被析构会直接崩，窗口关闭必须收干净"""
        for worker in list(self._workers):
            if worker.isRunning():
                worker.wait(timeout_ms)
        self._workers.clear()

    def _buildFullExportText(self, detection: DetectionResult, preview_text: str) -> str:
        """Return the non-preview Burp text when full request fields were preserved."""
        full_text = preview_text
        if not detection.raw_result or not isinstance(detection.raw_result, dict):
            return full_text

        raw_result = detection.raw_result
        raw_http = str(raw_result.get('raw_http_request', '') or '')
        raw_http_full = str(raw_result.get('raw_http_request_full', '') or '')
        raw_body = str(raw_result.get('raw_request_body', '') or '')
        raw_body_full = str(raw_result.get('raw_request_body_full', '') or '')
        if raw_http and raw_http_full and raw_http_full != raw_http:
            full_text = full_text.replace(raw_http, raw_http_full, 1)
            if raw_body:
                duplicate_body = raw_http_full + "\n\n" + raw_body
                full_text = full_text.replace(duplicate_body, raw_http_full, 1)
            return full_text

        if raw_body and raw_body_full and raw_body_full != raw_body:
            full_text = full_text.replace(raw_body, raw_body_full, 1)
        elif not raw_http_full and raw_body_full and 'raw_request_headers' in raw_result:
            headers = str(raw_result.get('raw_request_headers', '') or '')
            if headers:
                full_text = headers + raw_body_full

        return full_text

    def _exportFullView(self):
        text = self._full_text or self.text_edit.toPlainText()
        if not text:
            QMessageBox.information(self, "导出 Burp Suite 视图", "没有可导出的 Burp Suite 视图")
            return

        save_path, _ = QFileDialog.getSaveFileName(
            self,
            "导出 Burp Suite 视图",
            self._defaultExportName(),
            "Text Files (*.txt);;All Files (*)"
        )
        if not save_path:
            return

        if "." not in os.path.basename(save_path):
            save_path += ".txt"

        try:
            with open(save_path, "w", encoding="utf-8", newline="") as fp:
                fp.write(text)
            QMessageBox.information(self, "导出成功", f"Burp Suite 视图已导出到:\n{save_path}")
        except Exception as e:
            QMessageBox.critical(self, "导出失败", f"导出 Burp Suite 视图时出错:\n{str(e)}")

    def _defaultExportName(self) -> str:
        det = self._current_detection
        uri = det.uri if det else ""
        name = os.path.basename((uri or "").split("?", 1)[0].rstrip("/")) or "burp_request"
        safe_name = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in name)
        return f"{safe_name[:80]}_burp.txt"


class ImageViewer(QFrame):
    """图片查看器"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._setupUI()

    def _setupUI(self):
        self.setStyleSheet("""
            ImageViewer {
                background-color: #F5F5F5;
                border: 1px solid #E0E0E0;
                border-radius: 4px;
            }
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setAlignment(Qt.AlignCenter)

        # 图片标签
        self.image_label = QLabel()
        self.image_label.setAlignment(Qt.AlignCenter)
        self.image_label.setStyleSheet("background-color: white; border: 1px solid #DDD; padding: 10px;")
        layout.addWidget(self.image_label)

        # 信息标签
        self.info_label = QLabel()
        self.info_label.setAlignment(Qt.AlignCenter)
        self.info_label.setStyleSheet("color: #666; font-size: 12px; margin-top: 10px;")
        layout.addWidget(self.info_label)

    def setImage(self, image_data: bytes = None, file_path: str = None):
        """设置图片"""
        if image_data:
            pixmap = QPixmap()
            pixmap.loadFromData(QByteArray(image_data))
        elif file_path:
            pixmap = QPixmap(file_path)
        else:
            self.image_label.setText("无图片数据")
            self.info_label.setText("")
            return

        if pixmap.isNull():
            self.image_label.setText("无法加载图片")
            self.info_label.setText("")
            return

        # 缩放图片以适应显示区域
        scaled = pixmap.scaled(
            600, 400,
            Qt.KeepAspectRatio,
            Qt.SmoothTransformation
        )
        self.image_label.setPixmap(scaled)
        self.info_label.setText(f"原始尺寸: {pixmap.width()} x {pixmap.height()}")

    def clear(self):
        self.image_label.clear()
        self.image_label.setText("暂无图片")
        self.info_label.setText("")


class RawDataViewer(QFrame):
    """原始数据查看器（非HTTP流量）"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._setupUI()

    def _setupUI(self):
        self.setStyleSheet("""
            RawDataViewer {
                background-color: white;
                border: 1px solid #E0E0E0;
                border-radius: 4px;
            }
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # 标题
        title_bar = QWidget()
        title_bar.setStyleSheet("background-color: #E8E8E8; border-bottom: 1px solid #CCC;")
        title_layout = QHBoxLayout(title_bar)
        title_layout.setContentsMargins(10, 5, 10, 5)
        title = QLabel("原始数据")
        title.setStyleSheet("font-size: 12px; font-weight: bold; color: #333;")
        title_layout.addWidget(title)
        title_layout.addStretch()
        layout.addWidget(title_bar)

        # 内容
        self.text_edit = QTextEdit()
        self.text_edit.setReadOnly(True)
        self.text_edit.setStyleSheet("""
            QTextEdit {
                border: none;
                background-color: #FAFAFA;
                font-family: "Consolas", "Courier New", monospace;
                font-size: 12px;
                padding: 10px;
            }
        """)
        layout.addWidget(self.text_edit)

    def setContent(self, data):
        """设置原始数据"""
        if isinstance(data, dict):
            text = json.dumps(data, ensure_ascii=False, indent=2)
        else:
            text = str(data)
        self.text_edit.setPlainText(text)

    def clear(self):
        self.text_edit.clear()


def _load_packet_layers(pcap_path: str, packet_num: int):
    """回 pcap 取单帧的协议分层。

    单独抽成模块级函数是为了给后台线程一个明确的入口（也方便测试替换）。
    它内部会起一个 tshark 子进程，**绝不能在 GUI 主线程上调用**。
    """
    from controllers.analysis_controller import get_packet_hex_dump

    return get_packet_hex_dump(pcap_path, packet_num)


class _PacketLayersWorker(QThread):
    """后台取提取文件对应帧的协议分层。

    这活儿原来是在 PacketHexViewer.setContent() 里同步做的，也就是在 GUI 主线程上
    起 tshark 子进程：44MB 的 pcap 实测冻结 5.7 秒，166MB 冻结 29-31 秒。加上
    `-c N` 之后常规情况已降到几百毫秒，但帧号很大或磁盘很慢时仍然会是秒级 ——
    只要它还在主线程上，就总有卡死的可能。放后台是结构性的解法。

    信号带上 ExtractedFile 本身，主线程好据此判断结果是否已经过期（用户可能
    已经点到别的文件上了）。
    """

    loaded = Signal(object, list)   # (ExtractedFile, protocol_layers)
    failed = Signal(object, str)    # (ExtractedFile, 错误信息)

    def __init__(self, ef, parent=None):
        super().__init__(parent)
        self._ef = ef

    def run(self):
        try:
            _, layers = _load_packet_layers(self._ef.pcap_path, self._ef.source_packet)
            self.loaded.emit(self._ef, list(layers or []))
        except Exception as e:
            logger.debug(f"协议分层加载失败 frame#{self._ef.source_packet}: {e}")
            self.failed.emit(self._ef, str(e))


class PacketHexViewer(QFrame):
    """提取文件的hex查看器"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._current_ef = None
        # 用集合而不是单个 self._worker：连点提取文件是正常操作，单引用会让还在
        # 跑的前一个 QThread 失去最后一个 Python 引用被 GC，直接崩。
        self._workers = set()
        self._setupUI()

    def _setupUI(self):
        self.setStyleSheet("""
            PacketHexViewer {
                background-color: white;
                border: 1px solid #E0E0E0;
                border-radius: 4px;
            }
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # 使用 QSplitter 分隔上下两部分
        splitter = QSplitter(Qt.Vertical)

        # 上部：协议分层树
        self.tree = QTreeWidget()
        self.tree.setHeaderHidden(True)
        self.tree.setIndentation(20)
        self.tree.setAnimated(False)
        self.tree.setStyleSheet("""
            QTreeWidget {
                border: none;
                background-color: #FAFAFA;
                font-family: "Consolas", "Courier New", monospace;
                font-size: 11px;
            }
            QTreeWidget::item {
                padding: 4px 0;
            }
            QTreeWidget::item:hover {
                background-color: #E3F2FD;
            }
            QTreeWidget::item:selected {
                background-color: #BBDEFB;
                color: #1565C0;
            }
        """)
        splitter.addWidget(self.tree)

        # 下部：十六进制 dump 视图
        self.hex_view = QTextEdit()
        self.hex_view.setReadOnly(True)
        self.hex_view.setStyleSheet("""
            QTextEdit {
                border: none;
                border-top: 1px solid #E0E0E0;
                background-color: #1E1E1E;
                color: #D4D4D4;
                font-family: "Consolas", "Courier New", monospace;
                font-size: 11px;
                padding: 8px;
            }
        """)
        splitter.addWidget(self.hex_view)

        # 设置初始比例（上：下 = 2：3）
        splitter.setSizes([200, 300])

        layout.addWidget(splitter)

    def setContent(self, ef: ExtractedFile):
        """设置提取文件的内容

        分两段：本地文件的 hex（只读 4KB，毫秒级）当场做完，保证首屏立刻有东西；
        协议分层要起 tshark 子进程，扔后台线程，回来了再填。
        """
        self._current_ef = ef

        self.tree.setUpdatesEnabled(False)
        self.hex_view.setUpdatesEnabled(False)
        try:
            self.tree.clear()
            self.hex_view.clear()

            if not ef.lazy_loaded and ef.file_path:
                self._loadFileHexContent(ef)

            pending = self._needsLayerLookup(ef)
            self._displayProtocolLayers(ef, pending=pending)

            if ef.hex_dump:
                self.hex_view.setPlainText(ef.hex_dump)
            else:
                self.hex_view.setPlainText("无法获取十六进制数据")
        finally:
            self.tree.setUpdatesEnabled(True)
            self.hex_view.setUpdatesEnabled(True)

        if pending:
            self._startLayerLookup(ef)
        else:
            ef.lazy_loaded = True

    def _needsLayerLookup(self, ef: ExtractedFile) -> bool:
        if ef.lazy_loaded:
            return False
        return ef.source_packet > 0 and bool(ef.pcap_path)

    def _startLayerLookup(self, ef: ExtractedFile):
        worker = _PacketLayersWorker(ef)
        worker.loaded.connect(self._onLayersLoaded)
        worker.failed.connect(self._onLayersFailed)
        worker.finished.connect(lambda w=worker: self._workers.discard(w))
        self._workers.add(worker)
        worker.start()

    def _onLayersLoaded(self, ef: ExtractedFile, layers: list):
        ef.protocol_layers = layers
        ef.lazy_loaded = True
        self._refreshLayersIfCurrent(ef)

    def _onLayersFailed(self, ef: ExtractedFile, message: str):
        # 失败也标记成已加载：否则每点一次就再花几秒重试一遍。
        ef.protocol_layers = [f"协议分层获取失败: {message}"]
        ef.lazy_loaded = True
        self._refreshLayersIfCurrent(ef)

    def _refreshLayersIfCurrent(self, ef: ExtractedFile):
        """结果回来时用户可能已经点到别的文件上了，过期结果直接丢掉"""
        if ef is not self._current_ef:
            return
        self.tree.setUpdatesEnabled(False)
        try:
            self.tree.clear()
            self._displayProtocolLayers(ef, pending=False)
        finally:
            self.tree.setUpdatesEnabled(True)

    def isLoadingLayers(self) -> bool:
        return any(w.isRunning() for w in self._workers)

    def waitForLayers(self, deadline=None) -> bool:
        """等待后台加载结束（测试和退出清理用）"""
        all_done = True
        for worker in list(self._workers):
            finished = worker.wait(deadline) if deadline is not None else worker.wait()
            all_done = all_done and bool(finished)
        return all_done

    def renderedLayers(self) -> list:
        """当前树里实际渲染出来的文本，供测试断言"""
        out = []

        def walk(item):
            out.append(item.text(0))
            for i in range(item.childCount()):
                walk(item.child(i))

        for i in range(self.tree.topLevelItemCount()):
            walk(self.tree.topLevelItem(i))
        return out

    def shutdown(self):
        """等所有后台线程收尾。

        QThread 在还在跑的时候被析构会直接崩，关闭窗口前必须收干净。
        tshark 调用本身带超时，所以这里不会无限等下去。
        """
        for worker in list(self._workers):
            try:
                worker.loaded.disconnect()
                worker.failed.disconnect()
            except (RuntimeError, TypeError):
                pass
            worker.wait()
        self._workers.clear()

    def _loadFileHexContent(self, ef: ExtractedFile):
        """读本地提取文件的前若干字节做 hex dump（不碰 pcap，很快）"""
        from controllers.analysis_controller import get_file_hex_content

        ef.hex_dump = get_file_hex_content(ef.file_path, max_bytes=4096)

    def _displayProtocolLayers(self, ef: ExtractedFile, pending: bool = False):
        """显示协议分层信息"""
        # 文件信息层
        file_item = QTreeWidgetItem(self.tree, [f"File: {ef.file_name}"])
        file_item.setForeground(0, QColor("#1976D2"))
        QTreeWidgetItem(file_item, [f"  类型: {ef.content_type}"])
        QTreeWidgetItem(file_item, [f"  大小: {self._format_size(ef.file_size)}"])
        QTreeWidgetItem(file_item, [f"  分类: {ef.file_type}"])

        # 如果有协议层信息
        if ef.protocol_layers:
            proto_item = QTreeWidgetItem(self.tree, ["Protocol Layers"])
            proto_item.setForeground(0, QColor("#388E3C"))
            for layer in ef.protocol_layers:
                QTreeWidgetItem(proto_item, [f"  > {layer}"])
        elif pending:
            proto_item = QTreeWidgetItem(self.tree, ["Protocol Layers"])
            proto_item.setForeground(0, QColor("#9E9E9E"))
            QTreeWidgetItem(proto_item, ["  正在从 pcap 解析…"])

        # 源信息
        if ef.source_packet > 0:
            src_item = QTreeWidgetItem(self.tree, ["Source"])
            src_item.setForeground(0, QColor("#E65100"))
            QTreeWidgetItem(src_item, [f"  Frame Number: {ef.source_packet}"])
            if ef.pcap_path:
                import os
                QTreeWidgetItem(src_item, [f"  PCAP: {os.path.basename(ef.pcap_path)}"])

        # 只展开前两级，不 expandAll()
        for i in range(self.tree.topLevelItemCount()):
            self.tree.topLevelItem(i).setExpanded(True)

    def _format_size(self, size: int) -> str:
        """格式化文件大小"""
        if size < 1024:
            return f"{size} B"
        elif size < 1024 * 1024:
            return f"{size / 1024:.1f} KB"
        else:
            return f"{size / (1024 * 1024):.2f} MB"

    def clear(self):
        # 置空当前文件，后台加载回来时才知道结果已经没人要了
        self._current_ef = None
        self.tree.clear()
        self.hex_view.clear()


class ProtocolFindingViewer(QFrame):
    """协议分析发现查看器 - 展示ICMP隐写等协议分析结果"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._setupUI()

    def _setupUI(self):
        self.setStyleSheet("""
            ProtocolFindingViewer {
                background-color: white;
                border: 1px solid #E0E0E0;
                border-radius: 4px;
            }
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # 标题栏
        title_bar = QWidget()
        title_bar.setStyleSheet("background-color: #F3E5F5; border-bottom: 1px solid #CE93D8;")
        title_layout = QHBoxLayout(title_bar)
        title_layout.setContentsMargins(10, 5, 10, 5)
        self.title_label = QLabel("协议分析")
        self.title_label.setStyleSheet("font-size: 12px; font-weight: bold; color: #7B1FA2;")
        title_layout.addWidget(self.title_label)
        title_layout.addStretch()
        layout.addWidget(title_bar)

        # 使用 QSplitter 分隔上下两部分
        splitter = QSplitter(Qt.Vertical)

        # 上部：分析结果树
        self.tree = QTreeWidget()
        self.tree.setHeaderHidden(True)
        self.tree.setIndentation(20)
        self.tree.setAnimated(False)
        self.tree.setAlternatingRowColors(True)
        self.tree.setStyleSheet("""
            QTreeWidget {
                border: none;
                background-color: #FAFAFA;
                font-family: "Consolas", "Courier New", monospace;
                font-size: 11px;
            }
            QTreeWidget::item {
                padding: 3px 0;
            }
            QTreeWidget::item:hover {
                background-color: #F3E5F5;
            }
            QTreeWidget::item:selected {
                background-color: #CE93D8;
                color: #4A148C;
            }
        """)
        splitter.addWidget(self.tree)

        # 下部：原始值序列和提取数据
        self.data_view = QTextEdit()
        self.data_view.setReadOnly(True)
        self.data_view.setStyleSheet("""
            QTextEdit {
                border: none;
                border-top: 1px solid #E0E0E0;
                background-color: #1E1E1E;
                color: #D4D4D4;
                font-family: "Consolas", "Courier New", monospace;
                font-size: 11px;
                padding: 8px;
            }
        """)
        splitter.addWidget(self.data_view)

        splitter.setSizes([250, 250])
        layout.addWidget(splitter)

    def setContent(self, finding: ProtocolFinding):
        """设置协议分析发现内容"""
        # 禁用更新
        self.tree.setUpdatesEnabled(False)
        self.data_view.setUpdatesEnabled(False)
        try:
            self._buildContent(finding)
        finally:
            self.tree.setUpdatesEnabled(True)
            self.data_view.setUpdatesEnabled(True)

    def _buildContent(self, finding: ProtocolFinding):
        """实际构建协议分析视图内容"""
        self.tree.clear()
        self.data_view.clear()

        # 更新标题
        title_suffix = f" - {finding.title}" if finding.title else ""
        self.title_label.setText(f"协议分析 - {finding.protocol}{title_suffix}")

        # 协议信息
        proto_item = QTreeWidgetItem(self.tree, [f"Protocol: {finding.protocol}"])
        proto_item.setForeground(0, QColor("#7B1FA2"))
        QTreeWidgetItem(proto_item, [f"  发现类型: {finding.finding_type}"])
        QTreeWidgetItem(proto_item, [f"  置信度: {finding.confidence_display} ({finding.confidence:.0%})"])

        # 发现详情
        detail_item = QTreeWidgetItem(self.tree, [f"Finding: {finding.title or finding.finding_type}"])
        if finding.is_flag:
            detail_item.setForeground(0, QColor("#D32F2F"))
        else:
            detail_item.setForeground(0, QColor("#E65100"))
        QTreeWidgetItem(detail_item, [f"  {finding.description}"])

        # FLAG标记
        if finding.is_flag:
            flag_item = QTreeWidgetItem(self.tree, ["!! FLAG Detected !!"])
            flag_item.setForeground(0, QColor("#D32F2F"))
            if finding.data:
                QTreeWidgetItem(flag_item, [f"  {finding.data}"])

        # 提取数据
        if finding.data:
            data_item = QTreeWidgetItem(self.tree, ["Extracted Data (原始)"])
            data_item.setForeground(0, QColor("#388E3C"))
            # 分行展示长数据
            if len(finding.data) > 80:
                for i in range(0, len(finding.data), 80):
                    QTreeWidgetItem(data_item, [f"  {finding.data[i:i+80]}"])
            else:
                QTreeWidgetItem(data_item, [f"  {finding.data}"])

        # 解码后数据 (自动解码引擎处理后的结果)
        if finding.decoded_data:
            decoded_item = QTreeWidgetItem(self.tree, ["Decoded Data (解码后)"])
            decoded_item.setForeground(0, QColor("#1565C0"))  # 蓝色
            # 显示解码链
            if finding.decode_chain:
                QTreeWidgetItem(decoded_item, [f"  解码链: {finding.decode_chain}"])
            # 显示解码结果
            if len(finding.decoded_data) > 80:
                for i in range(0, len(finding.decoded_data), 80):
                    QTreeWidgetItem(decoded_item, [f"  {finding.decoded_data[i:i+80]}"])
            else:
                QTreeWidgetItem(decoded_item, [f"  {finding.decoded_data}"])

        self._add_cs_evidence_tree(finding)

        # 只展开前两级，不 expandAll()
        for i in range(self.tree.topLevelItemCount()):
            self.tree.topLevelItem(i).setExpanded(True)

        # 下部：解码结果和原始值序列
        lines = []

        # 优先显示解码后的数据
        if finding.decoded_data:
            lines.append(f"=== 解码结果 ===")
            if finding.decode_chain:
                lines.append(f"解码链: {finding.decode_chain}")
            lines.append(finding.decoded_data)
            lines.append("")

        if finding.data:
            lines.append(f"=== 提取数据 (原始) ===")
            lines.append(finding.data)
            lines.append("")

        if finding.raw_values:
            lines.extend(format_protocol_raw_values(finding.raw_values))

        self.data_view.setPlainText("\n".join(lines))

    @staticmethod
    def _short_tree_text(value, limit: int = 180) -> str:
        text = str(value or "")
        if len(text) <= limit:
            return text
        return text[:limit] + "... (截断)"

    def _add_cs_evidence_tree(self, finding: ProtocolFinding):
        """在树视图里展示 CS 加密载荷证据，避免用户只看到摘要。"""
        records = [
            item for item in (finding.raw_values or [])
            if isinstance(item, dict) and item.get("kind") == "encrypted_http_body"
        ]
        if not records:
            return

        root = QTreeWidgetItem(self.tree, [f"Cobalt Strike 加密 HTTP Body ({len(records)})"])
        root.setForeground(0, QColor("#C62828"))
        QTreeWidgetItem(root, ["  明文命令需要 Beacon AES/HMAC 会话密钥；下方展示密文帧、密文预览与 HMAC 取证证据"])

        for idx, record in enumerate(records[:20]):
            item = QTreeWidgetItem(root, [
                (
                    f"  [{idx:04d}] frame={record.get('frame_number', '?')} "
                    f"stream={record.get('tcp_stream', '?')} "
                    f"{record.get('method', '')} {record.get('uri', '')} "
                    f"declared={record.get('declared_length', '?')} "
                    f"encrypted={record.get('encrypted_length', '?')} "
                    f"hmac={record.get('hmac_length', '?')} "
                    f"entropy={float(record.get('entropy', 0.0)):.2f}"
                )
            ])
            QTreeWidgetItem(item, [f"    length_prefix_hex: {record.get('length_prefix_hex', '')}"])
            QTreeWidgetItem(item, [f"    hmac_hex: {record.get('hmac_hex', '')}"])
            if record.get("artifact_json_path"):
                QTreeWidgetItem(item, [
                    "    full_export_json: "
                    + self._short_tree_text(record.get("artifact_json_path"), 240)
                ])
            if record.get("artifact_bin_path"):
                QTreeWidgetItem(item, [
                    "    full_export_bin: "
                    + self._short_tree_text(record.get("artifact_bin_path"), 240)
                ])
            if record.get("encrypted_hex_preview"):
                QTreeWidgetItem(item, [
                    "    encrypted_hex_preview: "
                    + self._short_tree_text(record.get("encrypted_hex_preview"))
                ])
            if record.get("frame_hex_preview"):
                suffix = ""
                if record.get("frame_hex_truncated"):
                    suffix = (
                        f" ... (截断, 原始 {record.get('frame_length', '?')} bytes, "
                        f"显示前 {record.get('frame_hex_preview_bytes', '?')} bytes)"
                    )
                QTreeWidgetItem(item, [
                    "    frame_hex_preview: "
                    + self._short_tree_text(record.get("frame_hex_preview"), 220)
                    + suffix
                ])

        if len(records) > 20:
            QTreeWidgetItem(root, [f"  ... 剩余 {len(records) - 20} 个加密 Body 已省略，完整摘要见下方文本区"])

    def clear(self):
        self.tree.clear()
        self.data_view.clear()
        self.title_label.setText("协议分析")


class DecodingResultViewer(QFrame):
    """自动解码结果查看器 - 展示解码链和FLAG发现"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._setupUI()

    def _setupUI(self):
        self.setStyleSheet("""
            DecodingResultViewer {
                background-color: white;
                border: 1px solid #E0E0E0;
                border-radius: 4px;
            }
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # 标题栏
        title_bar = QWidget()
        title_bar.setStyleSheet("background-color: #E3F2FD; border-bottom: 1px solid #90CAF9;")
        title_layout = QHBoxLayout(title_bar)
        title_layout.setContentsMargins(10, 5, 10, 5)
        self.title_label = QLabel("自动解码")
        self.title_label.setStyleSheet("font-size: 12px; font-weight: bold; color: #1565C0;")
        title_layout.addWidget(self.title_label)
        title_layout.addStretch()
        layout.addWidget(title_bar)

        # 使用 QSplitter 分隔上下两部分
        splitter = QSplitter(Qt.Vertical)

        # 上部：解码链信息树
        self.tree = QTreeWidget()
        self.tree.setHeaderHidden(True)
        self.tree.setIndentation(20)
        self.tree.setAnimated(False)
        self.tree.setAlternatingRowColors(True)
        self.tree.setStyleSheet("""
            QTreeWidget {
                border: none;
                background-color: #FAFAFA;
                font-family: "Consolas", "Courier New", monospace;
                font-size: 11px;
            }
            QTreeWidget::item {
                padding: 3px 0;
            }
            QTreeWidget::item:hover {
                background-color: #E3F2FD;
            }
            QTreeWidget::item:selected {
                background-color: #90CAF9;
                color: #0D47A1;
            }
        """)
        splitter.addWidget(self.tree)

        # 下部：解码数据展示
        self.data_view = QTextEdit()
        self.data_view.setReadOnly(True)
        self.data_view.setStyleSheet("""
            QTextEdit {
                border: none;
                border-top: 1px solid #E0E0E0;
                background-color: #1E1E1E;
                color: #D4D4D4;
                font-family: "Consolas", "Courier New", monospace;
                font-size: 11px;
                padding: 8px;
            }
        """)
        splitter.addWidget(self.data_view)

        splitter.setSizes([250, 250])
        layout.addWidget(splitter)

    def setContent(self, result: AutoDecodingResult):
        """设置自动解码结果内容"""
        # 禁用更新
        self.tree.setUpdatesEnabled(False)
        self.data_view.setUpdatesEnabled(False)
        try:
            self._buildContent(result)
        finally:
            self.tree.setUpdatesEnabled(True)
            self.data_view.setUpdatesEnabled(True)

    def _buildContent(self, result: AutoDecodingResult):
        """实际构建解码结果视图内容"""
        self.tree.clear()
        self.data_view.clear()

        # 更新标题
        flag_mark = " [FLAG!]" if result.flags_found else ""
        self.title_label.setText(f"自动解码{flag_mark}")

        # 解码链信息
        chain_item = QTreeWidgetItem(self.tree, [f"Decode Chain: {result.decode_chain}"])
        chain_item.setForeground(0, QColor("#1565C0"))
        QTreeWidgetItem(chain_item, [f"  解码层数: {result.total_layers}"])
        QTreeWidgetItem(chain_item, [f"  来源: {result.source}"])
        QTreeWidgetItem(chain_item, [f"  置信度: {result.confidence:.0%}"])
        QTreeWidgetItem(chain_item, [f"  有意义: {'是' if result.is_meaningful else '否'}"])

        # 内容类型
        if result.detected_type:
            type_item = QTreeWidgetItem(self.tree, [f"Content Type: {result.detected_type}"])
            type_item.setForeground(0, QColor("#388E3C"))

        # FLAG发现
        if result.flags_found:
            flag_item = QTreeWidgetItem(self.tree, [f"!! FLAGS Found: {len(result.flags_found)} !!"])
            flag_item.setForeground(0, QColor("#D32F2F"))
            for flag in result.flags_found:
                f_item = QTreeWidgetItem(flag_item, [f"  {flag}"])
                f_item.setForeground(0, QColor("#D32F2F"))

        # 只展开前两级，不 expandAll()
        for i in range(self.tree.topLevelItemCount()):
            self.tree.topLevelItem(i).setExpanded(True)

        # 下部：显示解码数据
        lines = []
        if result.flags_found:
            lines.append("=== FLAGS ===")
            for flag in result.flags_found:
                lines.append(flag)
            lines.append("")

        lines.append("=== 解码结果 ===")
        if result.final_data:
            lines.append(result.final_data[:2000])
            if len(result.final_data) > 2000:
                lines.append("... (截断)")
        lines.append("")

        lines.append("=== 原始数据 ===")
        if result.original_data:
            lines.append(result.original_data[:500])
            if len(result.original_data) > 500:
                lines.append("... (截断)")

        self.data_view.setPlainText("\n".join(lines))

    def clear(self):
        self.tree.clear()
        self.data_view.clear()
        self.title_label.setText("自动解码")


class FileRecoveryViewer(QFrame):
    """文件还原结果查看器 - 展示Magic Number检测到的文件"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._setupUI()

    def _setupUI(self):
        self.setStyleSheet("""
            FileRecoveryViewer {
                background-color: white;
                border: 1px solid #E0E0E0;
                border-radius: 4px;
            }
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # 标题栏
        title_bar = QWidget()
        title_bar.setStyleSheet("background-color: #E8F5E9; border-bottom: 1px solid #A5D6A7;")
        title_layout = QHBoxLayout(title_bar)
        title_layout.setContentsMargins(10, 5, 10, 5)
        self.title_label = QLabel("文件还原")
        self.title_label.setStyleSheet("font-size: 12px; font-weight: bold; color: #2E7D32;")
        title_layout.addWidget(self.title_label)
        title_layout.addStretch()
        layout.addWidget(title_bar)

        # 使用 QSplitter 分隔上下两部分
        splitter = QSplitter(Qt.Vertical)

        # 上部：文件信息树
        self.tree = QTreeWidget()
        self.tree.setHeaderHidden(True)
        self.tree.setIndentation(20)
        self.tree.setAnimated(False)
        self.tree.setAlternatingRowColors(True)
        self.tree.setStyleSheet("""
            QTreeWidget {
                border: none;
                background-color: #FAFAFA;
                font-family: "Consolas", "Courier New", monospace;
                font-size: 11px;
            }
            QTreeWidget::item {
                padding: 3px 0;
            }
            QTreeWidget::item:hover {
                background-color: #E8F5E9;
            }
            QTreeWidget::item:selected {
                background-color: #A5D6A7;
                color: #1B5E20;
            }
        """)
        splitter.addWidget(self.tree)

        # 下部：十六进制预览
        self.hex_view = QTextEdit()
        self.hex_view.setReadOnly(True)
        self.hex_view.setStyleSheet("""
            QTextEdit {
                border: none;
                border-top: 1px solid #E0E0E0;
                background-color: #263238;
                color: #AABBC3;
                font-family: "Consolas", "Courier New", monospace;
                font-size: 10px;
                padding: 8px;
            }
        """)
        splitter.addWidget(self.hex_view)

        splitter.setSizes([200, 300])
        layout.addWidget(splitter)

    def setContent(self, recovery: FileRecoveryResult):
        """设置文件还原结果内容"""
        # 禁用更新
        self.tree.setUpdatesEnabled(False)
        self.hex_view.setUpdatesEnabled(False)
        try:
            self._buildContent(recovery)
        finally:
            self.tree.setUpdatesEnabled(True)
            self.hex_view.setUpdatesEnabled(True)

    def _buildContent(self, recovery: FileRecoveryResult):
        """实际构建文件还原视图内容"""
        self.tree.clear()
        self.hex_view.clear()

        # 更新标题
        self.title_label.setText(f"文件还原 - {recovery.extension.upper()}")

        # 文件信息
        file_item = QTreeWidgetItem(self.tree, [f"File: {recovery.description}"])
        file_item.setForeground(0, QColor("#2E7D32"))
        QTreeWidgetItem(file_item, [f"  扩展名: .{recovery.extension}"])
        QTreeWidgetItem(file_item, [f"  MIME: {recovery.mime_type}"])
        QTreeWidgetItem(file_item, [f"  类别: {recovery.category}"])
        QTreeWidgetItem(file_item, [f"  大小: {self._format_size(recovery.size)}"])
        QTreeWidgetItem(file_item, [f"  置信度: {recovery.confidence:.0%}"])

        # 位置信息
        if recovery.offset > 0 or recovery.source_packet > 0:
            loc_item = QTreeWidgetItem(self.tree, ["Location"])
            loc_item.setForeground(0, QColor("#E65100"))
            if recovery.offset > 0:
                QTreeWidgetItem(loc_item, [f"  偏移: 0x{recovery.offset:08X} ({recovery.offset})"])
            if recovery.source_packet > 0:
                QTreeWidgetItem(loc_item, [f"  数据包: #{recovery.source_packet}"])

        # 保存路径
        if recovery.saved_path:
            path_item = QTreeWidgetItem(self.tree, ["Saved"])
            path_item.setForeground(0, QColor("#1565C0"))
            QTreeWidgetItem(path_item, [f"  {recovery.saved_path}"])

        # 可执行文件警告
        if recovery.category == "executable":
            warn_item = QTreeWidgetItem(self.tree, ["!! WARNING: Executable File !!"])
            warn_item.setForeground(0, QColor("#D32F2F"))

        # 只展开前两级，不 expandAll()
        for i in range(self.tree.topLevelItemCount()):
            self.tree.topLevelItem(i).setExpanded(True)

        # 下部：十六进制预览
        if recovery.data_preview:
            self.hex_view.setPlainText(recovery.data_preview)
        else:
            self.hex_view.setPlainText("无数据预览")

    def _format_size(self, size: int) -> str:
        """格式化文件大小"""
        if size < 1024:
            return f"{size} B"
        elif size < 1024 * 1024:
            return f"{size / 1024:.1f} KB"
        else:
            return f"{size / (1024 * 1024):.2f} MB"

    def clear(self):
        self.tree.clear()
        self.hex_view.clear()
        self.title_label.setText("文件还原")


class _RTPExportWorker(QThread):
    """RTP 导出工作线程，支持单条/批量"""

    progress = Signal(int, int, str)
    done = Signal(int, int, str)
    error = Signal(str)

    def __init__(self, streams, out_dir, tshark_path):
        super().__init__()
        self.streams = streams
        self.out_dir = out_dir
        self.tshark_path = tshark_path
        self._cancel = False

    def cancel(self):
        self._cancel = True

    def run(self):
        try:
            self._do_export()
        except Exception as e:
            self.error.emit(str(e))

    def _do_export(self):
        from core.rtp_analyzer import export_rtp_stream, export_rtp_streams_batch
        total = len(self.streams)

        if total > 1:
            self._do_batch_export(export_rtp_streams_batch, total)
        else:
            self._do_single_export(export_rtp_stream, total)

    def _do_batch_export(self, batch_fn, total):
        pcap_path = self.streams[0].pcap_path
        try:
            results = batch_fn(
                pcap_path, self.tshark_path, self.streams, self.out_dir,
                progress_cb=lambda cur, tot, label: self.progress.emit(cur, tot, label),
                cancel_check=lambda: self._cancel
            )
            self.done.emit(len(results), total, self.out_dir)
        except Exception as e:
            self.error.emit(str(e))

    def _do_single_export(self, export_fn, total):
        exported = 0
        for i, stream in enumerate(self.streams):
            if self._cancel:
                break
            label = f"rtp_{stream.ssrc}_{stream.codec_name}"
            self.progress.emit(i + 1, total, label)
            try:
                export_fn(
                    stream.pcap_path, self.tshark_path, stream, self.out_dir
                )
                exported += 1
            except Exception as e:
                if total == 1:
                    self.error.emit(str(e))
                    return
                logger.debug(f"导出跳过 {label}: {e}")

        self.done.emit(exported, total, self.out_dir)


class RTPStreamViewer(QFrame):
    """RTP 音视频流查看器"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._current_stream: Optional[RTPStreamInfo] = None
        self._all_streams: list = []
        self._worker: Optional[_RTPExportWorker] = None
        self._setupUI()

    def _setupUI(self):
        self.setStyleSheet("""
            RTPStreamViewer {
                background-color: white;
                border: 1px solid #E0E0E0;
                border-radius: 4px;
            }
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        title_bar = QWidget()
        title_bar.setStyleSheet("background-color: #E3F2FD; border-bottom: 1px solid #90CAF9;")
        title_layout = QHBoxLayout(title_bar)
        title_layout.setContentsMargins(10, 5, 10, 5)
        self.title_label = QLabel("音视频流")
        self.title_label.setStyleSheet("font-size: 12px; font-weight: bold; color: #1565C0;")
        title_layout.addWidget(self.title_label)
        title_layout.addStretch()
        layout.addWidget(title_bar)

        self.tree = QTreeWidget()
        self.tree.setHeaderHidden(True)
        self.tree.setIndentation(20)
        self.tree.setAnimated(False)
        self.tree.setAlternatingRowColors(True)
        self.tree.setStyleSheet("""
            QTreeWidget {
                border: none;
                background-color: #FAFAFA;
                font-family: "Consolas", "Courier New", monospace;
                font-size: 11px;
            }
            QTreeWidget::item { padding: 3px 0; }
            QTreeWidget::item:hover { background-color: #E3F2FD; }
            QTreeWidget::item:selected { background-color: #90CAF9; color: #0D47A1; }
        """)
        layout.addWidget(self.tree, 1)

        bottom = QFrame()
        bottom.setStyleSheet("QFrame { border-top: 1px solid #E0E0E0; }")
        bottom_layout = QVBoxLayout(bottom)
        bottom_layout.setContentsMargins(10, 8, 10, 8)
        bottom_layout.setSpacing(6)

        btn_row = QHBoxLayout()
        btn_row.setSpacing(8)

        self.export_btn = QPushButton("导出当前流")
        self.export_btn.setStyleSheet("""
            QPushButton {
                background-color: #1976D2; color: white; border: none;
                border-radius: 4px; padding: 8px 16px; font-size: 12px; font-weight: bold;
            }
            QPushButton:hover { background-color: #1565C0; }
            QPushButton:pressed { background-color: #0D47A1; }
            QPushButton:disabled { background-color: #BDBDBD; }
        """)
        self.export_btn.clicked.connect(self._onExportSingle)
        btn_row.addWidget(self.export_btn)

        self.batch_btn = QPushButton("导出全部")
        self.batch_btn.setStyleSheet("""
            QPushButton {
                background-color: #388E3C; color: white; border: none;
                border-radius: 4px; padding: 8px 16px; font-size: 12px; font-weight: bold;
            }
            QPushButton:hover { background-color: #2E7D32; }
            QPushButton:pressed { background-color: #1B5E20; }
            QPushButton:disabled { background-color: #BDBDBD; }
        """)
        self.batch_btn.clicked.connect(self._onExportBatch)
        btn_row.addWidget(self.batch_btn)

        self.cancel_btn = QPushButton("取消")
        self.cancel_btn.setStyleSheet("""
            QPushButton {
                background-color: #D32F2F; color: white; border: none;
                border-radius: 4px; padding: 8px 16px; font-size: 12px; font-weight: bold;
            }
            QPushButton:hover { background-color: #C62828; }
        """)
        self.cancel_btn.clicked.connect(self._onCancel)
        self.cancel_btn.hide()
        btn_row.addWidget(self.cancel_btn)

        btn_row.addStretch()
        bottom_layout.addLayout(btn_row)

        self.progress_bar = QProgressBar()
        self.progress_bar.setFixedHeight(20)
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setRange(0, 1)
        self.progress_bar.setValue(0)
        self.progress_bar.setFormat("")
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: 1px solid #E0E0E0; border-radius: 4px;
                background-color: #F5F5F5;
                text-align: center; font-size: 11px; color: #333;
            }
            QProgressBar::chunk {
                background-color: #42A5F5; border-radius: 3px;
            }
        """)
        bottom_layout.addWidget(self.progress_bar)

        self.status_label = QLabel("")
        self.status_label.setStyleSheet("color: #666; font-size: 11px;")
        self.status_label.setWordWrap(True)
        bottom_layout.addWidget(self.status_label)

        layout.addWidget(bottom)

    def setContent(self, stream: RTPStreamInfo, all_streams: list = None):
        self.tree.setUpdatesEnabled(False)
        try:
            self._buildContent(stream)
        finally:
            self.tree.setUpdatesEnabled(True)
        self._current_stream = stream
        if all_streams is not None:
            self._all_streams = all_streams
        total = len(self._all_streams)
        self.batch_btn.setText(f"导出全部 ({total})" if total > 1 else "导出全部")
        self.batch_btn.setVisible(total > 1)

    def _buildContent(self, stream: RTPStreamInfo):
        self.tree.clear()
        self.status_label.clear()

        media_icon = "Audio" if stream.media_type == "audio" else "Video"
        self.title_label.setText(f"RTP {media_icon} Stream - {stream.codec_name}")

        info_item = QTreeWidgetItem(self.tree, [f"Stream: {stream.codec_name}"])
        info_item.setForeground(0, QColor("#1565C0"))
        QTreeWidgetItem(info_item, [f"  SSRC: {stream.ssrc}"])
        QTreeWidgetItem(info_item, [f"  媒体类型: {stream.media_type}"])
        QTreeWidgetItem(info_item, [f"  采样率: {stream.sample_rate} Hz"])

        addr_item = QTreeWidgetItem(self.tree, ["Address"])
        addr_item.setForeground(0, QColor("#E65100"))
        QTreeWidgetItem(addr_item, [f"  源: {stream.src_addr}"])
        QTreeWidgetItem(addr_item, [f"  目的: {stream.dst_addr}"])

        stat_item = QTreeWidgetItem(self.tree, ["Statistics"])
        stat_item.setForeground(0, QColor("#2E7D32"))
        QTreeWidgetItem(stat_item, [f"  数据包: {stream.packets}"])
        QTreeWidgetItem(stat_item, [f"  丢包: {stream.lost}"])
        if stream.packets > 0:
            loss_pct = stream.lost / stream.packets * 100
            QTreeWidgetItem(stat_item, [f"  丢包率: {loss_pct:.1f}%"])
        QTreeWidgetItem(stat_item, [f"  最大抖动: {stream.max_jitter:.2f} ms"])
        if stream.duration_sec > 0:
            QTreeWidgetItem(stat_item, [f"  估计时长: {stream.duration_sec:.1f}s"])

        import shutil as _shutil
        tools = []
        if _shutil.which("sox"):
            tools.append("sox")
        if _shutil.which("ffmpeg"):
            tools.append("ffmpeg")
        tool_text = ", ".join(tools) if tools else "未检测到（将保存为 raw）"

        tool_item = QTreeWidgetItem(self.tree, ["Export"])
        tool_item.setForeground(0, QColor("#6A1B9A"))
        QTreeWidgetItem(tool_item, [f"  可用工具: {tool_text}"])

        for i in range(self.tree.topLevelItemCount()):
            self.tree.topLevelItem(i).setExpanded(True)

    def _get_output_dir(self) -> str:
        import pathlib
        return str(pathlib.Path(__file__).resolve().parent.parent.parent / "output" / "rtp")

    def _find_tshark(self) -> str:
        tshark = find_tshark()
        if tshark:
            return tshark
        raise FileNotFoundError("未找到 tshark，请安装 Wireshark")

    def _start_export(self, streams: list):
        try:
            out_dir = self._get_output_dir()
            tshark = self._find_tshark()
        except Exception as e:
            self.status_label.setText(f"导出失败: {e}")
            self.status_label.setStyleSheet("color: #D32F2F; font-size: 11px;")
            return

        self._worker = _RTPExportWorker(streams, out_dir, tshark)
        self._worker.progress.connect(self._onProgress)
        self._worker.done.connect(self._onDone)
        self._worker.error.connect(self._onError)

        total = len(streams)
        self.progress_bar.setRange(0, total)
        self.progress_bar.setValue(0)
        self.progress_bar.setFormat(f"0 / {total}")

        self.export_btn.setEnabled(False)
        self.batch_btn.setEnabled(False)
        self.cancel_btn.show()
        self.status_label.setText(f"准备导出到 {out_dir}")
        self.status_label.setStyleSheet("color: #666; font-size: 11px;")

        self._worker.start()

    def _onExportSingle(self):
        if not self._current_stream:
            return
        self._start_export([self._current_stream])

    def _onExportBatch(self):
        if not self._all_streams:
            return
        self._start_export(self._all_streams)

    def _onCancel(self):
        if self._worker:
            self._worker.cancel()
            self.status_label.setText("正在取消...")

    def _onProgress(self, current: int, total: int, label: str):
        self.progress_bar.setValue(current)
        self.progress_bar.setFormat(f"{current} / {total}")
        if label:
            self.status_label.setText(f"正在导出 ({current}/{total}): {label}")

    def _onDone(self, exported: int, total: int, out_dir: str):
        self._reset_ui()
        self.progress_bar.setValue(self.progress_bar.maximum())
        self.progress_bar.setFormat(f"{exported} / {total} 完成")
        if exported == total:
            self.status_label.setText(f"导出完成: {exported} 个文件 → {out_dir}")
            self.status_label.setStyleSheet("color: #2E7D32; font-size: 11px;")
        else:
            failed = total - exported
            self.status_label.setText(f"导出完成: {exported} 成功, {failed} 失败 → {out_dir}")
            self.status_label.setStyleSheet("color: #E65100; font-size: 11px;")

    def _onError(self, err: str):
        self._reset_ui()
        self.status_label.setText(f"导出失败: {err}")
        self.status_label.setStyleSheet("color: #D32F2F; font-size: 11px;")

    def _reset_ui(self):
        self.export_btn.setEnabled(True)
        self.batch_btn.setEnabled(True)
        self.cancel_btn.hide()
        self._worker = None

    def clear(self):
        self.tree.clear()
        self.status_label.clear()
        self.progress_bar.setValue(0)
        self.progress_bar.setFormat("")
        self.cancel_btn.hide()
        self.title_label.setText("音视频流")
        self._current_stream = None
        self._all_streams = []


class ScoreBreakdownPanel(QFrame):
    """得分拆解面板，展示各检测维度的得分"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._setupUI()

    def _setupUI(self):
        self.setStyleSheet("""
            ScoreBreakdownPanel {
                background-color: #FFF8E1;
                border: 1px solid #FFE082;
                border-radius: 6px;
            }
        """)
        # 少了"判定"那一行，高度跟着收一档，免得留一块空白
        self.setMinimumHeight(80)
        self.setMaximumHeight(125)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 8, 10, 8)
        layout.setSpacing(4)

        # 标题行
        header = QHBoxLayout()
        title = QLabel("Score Breakdown (得分拆解)")
        title.setStyleSheet("font-size: 11px; font-weight: bold; color: #F57C00;")
        header.addWidget(title)
        header.addStretch()
        layout.addLayout(header)

        # 这里原来还有一个"灵敏度: N"。它取的是 breakdown['sensitivity']，
        # 而那个值就是 fast_filter 预筛分(_calculate_combined_verdict 的
        # risk_score) —— 和刚摘掉的"判定"行同源，只是换了个名字。一条高危攻击
        # 旁边挂"灵敏度: 5"，读起来仍然像系统在给它打低分。名字里的"灵敏度"
        # 另有所指(_sensitivity_profile 那个 0-100 旋钮)，同名不同物，更绕。

        # 分隔线
        line = QFrame()
        line.setFrameShape(QFrame.HLine)
        line.setStyleSheet("background-color: #FFE082;")
        layout.addWidget(line)

        # 得分网格
        grid = QGridLayout()
        grid.setSpacing(8)

        # 熵值
        self.entropy_label = QLabel("熵值: --")
        self.entropy_indicator = QLabel("●")
        self.entropy_indicator.setStyleSheet("color: #9E9E9E;")
        grid.addWidget(self.entropy_indicator, 0, 0)
        grid.addWidget(self.entropy_label, 0, 1)

        # 格式
        self.structure_label = QLabel("格式: --")
        self.structure_indicator = QLabel("●")
        self.structure_indicator.setStyleSheet("color: #9E9E9E;")
        grid.addWidget(self.structure_indicator, 0, 2)
        grid.addWidget(self.structure_label, 0, 3)

        # 字符频率
        self.char_label = QLabel("字符: --")
        self.char_indicator = QLabel("●")
        self.char_indicator.setStyleSheet("color: #9E9E9E;")
        grid.addWidget(self.char_indicator, 1, 0)
        grid.addWidget(self.char_label, 1, 1)

        # 载荷长度
        self.length_label = QLabel("长度: --")
        self.length_indicator = QLabel("●")
        self.length_indicator.setStyleSheet("color: #9E9E9E;")
        grid.addWidget(self.length_indicator, 1, 2)
        grid.addWidget(self.length_label, 1, 3)

        layout.addLayout(grid)

        # 这里原来还有一行"判定: skip/notice/review/audit"。
        #
        # 那个值来自 core.fast_filter，回答的是"这段载荷值不值得再花 CPU 跑一遍
        # AST"，**不是**"这是不是攻击"。把它摆在一条已经确认的攻击载荷下面、还写成
        # "判定: skip (正常流量)"，读起来就成了系统在给这条攻击盖"正常"的章 ——
        # 和左边的威胁等级、和"研判"列(core.success_adjudicator，那个才是"攻击有没有
        # 打下")互相打架。三套判定挤在一个界面里，只有这一套是纯内部调度信号，
        # 不该露给人看。

    def setScoreBreakdown(self, breakdown: dict):
        """设置得分拆解数据"""
        if not breakdown:
            self.clear()
            return

        # 熵值
        entropy = breakdown.get('entropy', {})
        self.entropy_label.setText(entropy.get('display', '熵值: --'))
        self._setIndicator(self.entropy_indicator, entropy.get('hit', False))

        # 结构
        structure = breakdown.get('structure', {})
        self.structure_label.setText(structure.get('display', '格式: --'))
        self._setIndicator(self.structure_indicator, structure.get('hit', False))

        # 字符频率
        char_freq = breakdown.get('char_frequency', {})
        self.char_label.setText(char_freq.get('display', '字符: --'))
        self._setIndicator(self.char_indicator, char_freq.get('hit', False))

        # 载荷长度
        length = breakdown.get('payload_length', {})
        self.length_label.setText(length.get('display', '长度: --'))
        self._setIndicator(self.length_indicator, length.get('hit', False))

    def _setIndicator(self, indicator: QLabel, hit: bool):
        """设置指示器颜色"""
        if hit:
            indicator.setStyleSheet("color: #F44336; font-size: 12px;")  # 红色 = 命中
        else:
            indicator.setStyleSheet("color: #4CAF50; font-size: 12px;")  # 绿色 = 正常

    def clear(self):
        """清空显示"""
        self.entropy_label.setText("熵值: --")
        self.structure_label.setText("格式: --")
        self.char_label.setText("字符: --")
        self.length_label.setText("长度: --")
        self.entropy_indicator.setStyleSheet("color: #9E9E9E;")
        self.structure_indicator.setStyleSheet("color: #9E9E9E;")
        self.char_indicator.setStyleSheet("color: #9E9E9E;")
        self.length_indicator.setStyleSheet("color: #9E9E9E;")


class AttackDetectionViewer(QWidget):
    """攻击检测结果展示"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._setupUI()

    def _setupUI(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # 标题栏
        title_bar = QWidget()
        title_bar.setStyleSheet("background-color: #FFEBEE; border-bottom: 1px solid #EF9A9A;")
        title_layout = QHBoxLayout(title_bar)
        title_layout.setContentsMargins(10, 5, 10, 5)
        self.title_label = QLabel("攻击检测")
        self.title_label.setStyleSheet("font-size: 12px; font-weight: bold; color: #C62828;")
        title_layout.addWidget(self.title_label)
        title_layout.addStretch()

        # 风险等级标签
        self.risk_badge = QLabel()
        self.risk_badge.setStyleSheet("""
            padding: 2px 8px;
            border-radius: 3px;
            font-size: 10px;
            font-weight: bold;
        """)
        title_layout.addWidget(self.risk_badge)

        layout.addWidget(title_bar)

        # 使用 QSplitter 分隔上下两部分
        splitter = QSplitter(Qt.Vertical)

        # 上部：攻击信息树
        self.tree = QTreeWidget()
        self.tree.setHeaderHidden(True)
        self.tree.setIndentation(20)
        self.tree.setAnimated(False)
        self.tree.setAlternatingRowColors(True)
        self.tree.setStyleSheet("""
            QTreeWidget {
                border: none;
                background-color: #FAFAFA;
                font-family: "Consolas", "Courier New", monospace;
                font-size: 11px;
            }
            QTreeWidget::item {
                padding: 3px 0;
            }
            QTreeWidget::item:hover {
                background-color: #FFEBEE;
            }
            QTreeWidget::item:selected {
                background-color: #EF9A9A;
                color: #B71C1C;
            }
        """)
        splitter.addWidget(self.tree)

        # 下部：上下文/匹配文本详情
        self.context_view = QTextEdit()
        self.context_view.setReadOnly(True)
        self.context_view.setStyleSheet("""
            QTextEdit {
                border: none;
                border-top: 1px solid #E0E0E0;
                background-color: #263238;
                color: #ECEFF1;
                font-family: "Consolas", "Courier New", monospace;
                font-size: 10px;
                padding: 8px;
            }
        """)
        splitter.addWidget(self.context_view)

        splitter.setSizes([250, 250])
        layout.addWidget(splitter)

    def setContent(self, attack: AttackDetectionInfo):
        """设置攻击检测结果内容"""
        # 禁用更新，避免每个 QTreeWidgetItem 创建都触发布局重算
        self.tree.setUpdatesEnabled(False)
        self.context_view.setUpdatesEnabled(False)
        try:
            self._buildContent(attack)
        finally:
            self.tree.setUpdatesEnabled(True)
            self.context_view.setUpdatesEnabled(True)

    def _buildContent(self, attack: AttackDetectionInfo):
        """实际构建攻击检测视图内容"""
        self.tree.clear()
        self.context_view.clear()

        # 更新标题
        self.title_label.setText(f"攻击检测 - {attack.attack_type}")

        # 更新风险等级标签
        risk_colors = {
            "critical": ("#9C27B0", "#FFFFFF"),
            "high": ("#F44336", "#FFFFFF"),
            "medium": ("#FF9800", "#000000"),
            "low": ("#4CAF50", "#FFFFFF"),
            "info": ("#2196F3", "#FFFFFF"),
        }
        bg_color, fg_color = risk_colors.get(attack.risk_level, ("#757575", "#FFFFFF"))
        self.risk_badge.setText(attack.risk_level_display)
        self.risk_badge.setStyleSheet(f"""
            padding: 2px 8px;
            border-radius: 3px;
            font-size: 10px;
            font-weight: bold;
            background-color: {bg_color};
            color: {fg_color};
        """)

        # 基本信息
        info_item = QTreeWidgetItem(self.tree, [f"Attack: {attack.attack_type}"])
        info_item.setForeground(0, QColor("#C62828"))
        QTreeWidgetItem(info_item, [f"  风险等级: {attack.risk_level_display}"])
        QTreeWidgetItem(info_item, [f"  置信度: {attack.confidence}"])
        QTreeWidgetItem(info_item, [f"  总权重: {attack.total_weight}"])

        # 来源信息
        if attack.source_uri or attack.method:
            source_item = QTreeWidgetItem(self.tree, ["Source"])
            source_item.setForeground(0, QColor("#1565C0"))
            if attack.method:
                QTreeWidgetItem(source_item, [f"  方法: {attack.method}"])
            if attack.source_uri:
                uri_display = attack.source_uri[:60] + "..." if len(attack.source_uri) > 60 else attack.source_uri
                QTreeWidgetItem(source_item, [f"  URI: {uri_display}"])
            if attack.source_ip:
                QTreeWidgetItem(source_item, [f"  源IP: {attack.source_ip}"])
            if attack.dest_ip:
                QTreeWidgetItem(source_item, [f"  目标IP: {attack.dest_ip}"])
            if attack.source_packet > 0:
                QTreeWidgetItem(source_item, [f"  数据包: #{attack.source_packet}"])
            if attack.timestamp:
                QTreeWidgetItem(source_item, [f"  时间: {attack.timestamp}"])

        # 匹配的签名
        if attack.matched_signatures:
            sig_item = QTreeWidgetItem(self.tree, [f"Matched Signatures ({len(attack.matched_signatures)})"])
            sig_item.setForeground(0, QColor("#E65100"))
            for sig_name in attack.matched_signatures:
                QTreeWidgetItem(sig_item, [f"  - {sig_name}"])

        # 原始匹配详情
        if attack.raw_matches:
            match_item = QTreeWidgetItem(self.tree, [f"Match Details ({len(attack.raw_matches)})"])
            match_item.setForeground(0, QColor("#6A1B9A"))
            for match in attack.raw_matches:
                name = match.get('name', 'Unknown')
                weight = match.get('weight', 0)
                matched_text = match.get('matched_text', '')[:50]
                m = QTreeWidgetItem(match_item, [f"  {name} (w={weight})"])
                if matched_text:
                    QTreeWidgetItem(m, [f"    matched: {matched_text}"])
                desc = match.get('description', '')
                if desc:
                    QTreeWidgetItem(m, [f"    desc: {desc[:80]}"])

        # 只展开前两级，不 expandAll()
        for i in range(self.tree.topLevelItemCount()):
            self.tree.topLevelItem(i).setExpanded(True)

        # 设置上下文/匹配文本
        context_html = []
        context_html.append('<div style="font-family: Consolas, monospace;">')

        if attack.matched_text:
            context_html.append('<h4 style="color: #FF5722; margin: 5px 0;">Matched Text:</h4>')
            # 截断过长的匹配文本，避免 HTML 渲染卡死
            display_text = attack.matched_text[:2000]
            if len(attack.matched_text) > 2000:
                display_text += "\n... (截断)"
            escaped_text = display_text.replace('<', '&lt;').replace('>', '&gt;')
            # 高亮显示匹配的文本
            context_html.append(f'<pre style="color: #FF9800; background: #37474F; padding: 8px; border-radius: 4px; white-space: pre-wrap;">{escaped_text}</pre>')

        if attack.context:
            context_html.append('<h4 style="color: #4CAF50; margin: 10px 0 5px 0;">Context:</h4>')
            # 截断过长的上下文，避免 HTML 渲染卡死
            display_context = attack.context[:3000]
            if len(attack.context) > 3000:
                display_context += "\n... (截断)"
            escaped_context = display_context.replace('<', '&lt;').replace('>', '&gt;')
            # 尝试高亮匹配的签名
            for sig in attack.matched_signatures[:3]:
                if sig.lower() in escaped_context.lower():
                    # 简单高亮
                    idx = escaped_context.lower().find(sig.lower())
                    if idx >= 0:
                        end = idx + len(sig)
                        escaped_context = (
                            escaped_context[:idx] +
                            '<span style="background: #FFEB3B; color: #000;">' +
                            escaped_context[idx:end] +
                            '</span>' +
                            escaped_context[end:]
                        )
            context_html.append(f'<pre style="color: #B0BEC5; background: #37474F; padding: 8px; border-radius: 4px; white-space: pre-wrap; word-wrap: break-word;">{escaped_context}</pre>')

        context_html.append('</div>')
        self.context_view.setHtml(''.join(context_html))

    def clear(self):
        self.tree.clear()
        self.context_view.clear()
        self.title_label.setText("攻击检测")
        self.risk_badge.setText("")
        self.risk_badge.setStyleSheet("")


class PayloadViewer(QWidget):
    """载荷查看器 - 根据内容类型切换显示方式，支持Wireshark/Burp切换"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._current_detection: Optional[DetectionResult] = None
        self._current_extracted_file: Optional[ExtractedFile] = None
        self._current_protocol_finding: Optional[ProtocolFinding] = None
        self._current_decoding_result: Optional[AutoDecodingResult] = None
        self._current_file_recovery: Optional[FileRecoveryResult] = None
        self._current_attack_detection: Optional[AttackDetectionInfo] = None
        self._current_rtp_stream: Optional[RTPStreamInfo] = None

        # 得分拆解缓存
        self._score_cache: dict = {}
        self._score_cache_max = 50

        # 延迟渲染标记
        self._burp_dirty = False
        self._wireshark_dirty = False
        self._pending_score_detection = None  # 延迟 score breakdown

        self._setupUI()

    def _setupUI(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # 标题栏 + 切换按钮
        title_bar = QWidget()
        title_bar.setStyleSheet("background-color: #F5F5F5; border-bottom: 1px solid #E0E0E0;")
        title_layout = QHBoxLayout(title_bar)
        title_layout.setContentsMargins(10, 6, 10, 6)

        self.title_label = QLabel("载荷详情")
        self.title_label.setStyleSheet("font-size: 14px; font-weight: bold; color: #333;")
        title_layout.addWidget(self.title_label)

        title_layout.addStretch()

        # Wireshark/Burp 切换按钮
        self.view_btn_group = QWidget()
        btn_layout = QHBoxLayout(self.view_btn_group)
        btn_layout.setContentsMargins(0, 0, 0, 0)
        btn_layout.setSpacing(0)

        self.wireshark_btn = QPushButton("Wireshark")
        self.wireshark_btn.setCheckable(True)
        self.wireshark_btn.setChecked(True)
        self.wireshark_btn.clicked.connect(lambda: self._switchView("wireshark"))

        self.burp_btn = QPushButton("Burp Suite")
        self.burp_btn.setCheckable(True)
        self.burp_btn.clicked.connect(lambda: self._switchView("burp"))

        toggle_style = """
            QPushButton {
                background-color: #E0E0E0;
                color: #666;
                border: 1px solid #BDBDBD;
                padding: 5px 14px;
                font-size: 11px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #D0D0D0;
            }
            QPushButton:checked {
                background-color: #1976D2;
                color: white;
                border-color: #1565C0;
            }
        """
        self.wireshark_btn.setStyleSheet(toggle_style + """
            QPushButton {
                border-top-left-radius: 4px;
                border-bottom-left-radius: 4px;
                border-right: none;
            }
            QPushButton:checked {
                border-top-left-radius: 4px;
                border-bottom-left-radius: 4px;
            }
        """)
        self.burp_btn.setStyleSheet(toggle_style + """
            QPushButton {
                border-top-right-radius: 4px;
                border-bottom-right-radius: 4px;
            }
            QPushButton:checked {
                border-top-right-radius: 4px;
                border-bottom-right-radius: 4px;
            }
        """)

        btn_layout.addWidget(self.wireshark_btn)
        btn_layout.addWidget(self.burp_btn)

        self.view_btn_group.hide()  # 默认隐藏，HTTP内容时显示
        title_layout.addWidget(self.view_btn_group)

        # 工具按钮（带下拉菜单）
        self.tools_btn = QPushButton("🔧 工具")
        self.tools_btn.setStyleSheet("""
            QPushButton {
                background-color: #FF9800;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 5px 14px;
                font-size: 11px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #F57C00;
            }
            QPushButton::menu-indicator {
                subcontrol-position: right center;
                subcontrol-origin: padding;
                right: 5px;
            }
        """)

        # 工具菜单
        tools_menu = QMenu(self)
        tools_menu.setStyleSheet("""
            QMenu {
                background-color: white;
                border: 1px solid #E0E0E0;
                border-radius: 4px;
                padding: 5px;
            }
            QMenu::item {
                padding: 8px 20px;
                border-radius: 3px;
            }
            QMenu::item:selected {
                background-color: #E3F2FD;
            }
        """)

        # 解码工具
        decode_menu = tools_menu.addMenu("解码工具")
        decode_menu.addAction("Base64 解码", lambda: self._openDecodeDialog("base64"))
        decode_menu.addAction("URL 解码", lambda: self._openDecodeDialog("url"))
        decode_menu.addAction("Hex 解码", lambda: self._openDecodeDialog("hex"))
        decode_menu.addAction("Unicode 解码", lambda: self._openDecodeDialog("unicode"))

        # 编码工具
        encode_menu = tools_menu.addMenu("编码工具")
        encode_menu.addAction("Base64 编码", lambda: self._openEncodeDialog("base64"))
        encode_menu.addAction("URL 编码", lambda: self._openEncodeDialog("url"))
        encode_menu.addAction("Hex 编码", lambda: self._openEncodeDialog("hex"))

        # 分析工具
        tools_menu.addSeparator()
        tools_menu.addAction("提取所有参数", self._extractAllParams)
        tools_menu.addAction("查看原始JSON", self._showRawJson)

        self.tools_btn.setMenu(tools_menu)
        title_layout.addWidget(self.tools_btn)

        # 导出按钮（用于提取文件）
        self.export_btn = QPushButton("导出文件")
        self.export_btn.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 5px 14px;
                font-size: 11px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #388E3C;
            }
        """)
        self.export_btn.clicked.connect(self._exportFile)
        self.export_btn.hide()  # 默认隐藏
        title_layout.addWidget(self.export_btn)

        layout.addWidget(title_bar)

        # 内容区域使用 QStackedWidget 切换不同视图
        self.stack = QStackedWidget()

        # 视图0: HTTP - Wireshark/Burp切换
        self.http_stack = QStackedWidget()
        self.wireshark_viewer = WiresharkStyleViewer()
        self.http_stack.addWidget(self.wireshark_viewer)   # index 0
        self.burp_viewer = BurpStyleViewer()
        self.http_stack.addWidget(self.burp_viewer)        # index 1
        self.stack.addWidget(self.http_stack)

        # 视图1: 图片
        self.image_viewer = ImageViewer()
        self.stack.addWidget(self.image_viewer)

        # 视图2: 原始数据（非HTTP）
        self.raw_viewer = RawDataViewer()
        self.stack.addWidget(self.raw_viewer)

        # 视图3: 空状态
        empty_widget = QWidget()
        empty_layout = QVBoxLayout(empty_widget)
        empty_label = QLabel("选择左侧的检测结果\n查看详细信息")
        empty_label.setAlignment(Qt.AlignCenter)
        empty_label.setStyleSheet("color: #999; font-size: 14px;")
        empty_layout.addWidget(empty_label)
        self.stack.addWidget(empty_widget)

        # 视图4: 提取文件的流量包查看器
        self.packet_hex_viewer = PacketHexViewer()
        self.stack.addWidget(self.packet_hex_viewer)

        # 视图5: 协议分析发现查看器
        self.protocol_finding_viewer = ProtocolFindingViewer()
        self.stack.addWidget(self.protocol_finding_viewer)

        # 视图6: 自动解码结果查看器
        self.decoding_result_viewer = DecodingResultViewer()
        self.stack.addWidget(self.decoding_result_viewer)

        # 视图7: 文件还原结果查看器
        self.file_recovery_viewer = FileRecoveryViewer()
        self.stack.addWidget(self.file_recovery_viewer)

        # 视图8: 攻击检测结果查看器
        self.attack_detection_viewer = AttackDetectionViewer()
        self.stack.addWidget(self.attack_detection_viewer)

        # 视图9: RTP 音视频流查看器
        self.rtp_stream_viewer = RTPStreamViewer()
        self.stack.addWidget(self.rtp_stream_viewer)

        # 默认显示空状态
        self.stack.setCurrentIndex(3)

        layout.addWidget(self.stack)

        # 得分拆解面板
        self.score_breakdown_panel = ScoreBreakdownPanel()
        self.score_breakdown_panel.hide()  # 默认隐藏
        layout.addWidget(self.score_breakdown_panel)

    def _switchView(self, view_name: str):
        """切换Wireshark/Burp视图"""
        if view_name == "wireshark":
            self.wireshark_btn.setChecked(True)
            self.burp_btn.setChecked(False)
            # 延迟渲染：切换时才填充内容
            if getattr(self, '_wireshark_dirty', False) and self._current_detection:
                self.wireshark_viewer.setContent(self._current_detection)
                self._wireshark_dirty = False
            self.http_stack.setCurrentIndex(0)
        else:
            self.wireshark_btn.setChecked(False)
            self.burp_btn.setChecked(True)
            # 延迟渲染：切换时才填充内容
            if getattr(self, '_burp_dirty', False) and self._current_detection:
                self.burp_viewer.setContent(self._current_detection)
                self._burp_dirty = False
            self.http_stack.setCurrentIndex(1)

    def showPayload(self, detection: DetectionResult):
        """显示检测结果的载荷详情"""
        # 同一个 detection 已经在显示就跳过
        if detection is self._current_detection:
            return

        self._current_detection = detection

        # 更新标题
        self.title_label.setText(f"载荷详情 - {detection.detection_type.display_name}")

        # score breakdown 延迟到下一事件循环执行
        # get_score_breakdown 做 AST+熵值+结构分析，同步调用会阻塞主线程
        # QTimer.singleShot(0) 让渲染先完成
        self._pending_score_detection = detection
        QTimer.singleShot(0, self._deferredScoreBreakdown)

        # 判断内容类型并切换视图
        if detection.method in ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]:
            # HTTP流量 - 显示切换按钮
            self.view_btn_group.show()
            self.export_btn.hide()

            # 只渲染当前可见的视图，另一个延迟渲染
            self._pending_burp_detection = detection
            current_http_view = self.http_stack.currentIndex()
            if current_http_view == 0:
                self.wireshark_viewer.setContent(detection)
                self._burp_dirty = True
            else:
                self.burp_viewer.setContent(detection)
                self._wireshark_dirty = True
            self.stack.setCurrentIndex(0)
        else:
            # 非HTTP流量 - 隐藏切换按钮
            self.view_btn_group.hide()
            self.export_btn.hide()
            self.raw_viewer.setContent(detection.raw_result or detection.payload or "无数据")
            self.stack.setCurrentIndex(2)

    def _deferredScoreBreakdown(self):
        """延迟执行 score breakdown，避免阻塞渲染"""
        detection = self._pending_score_detection
        # 检查是否仍然是当前显示的 detection（用户可能已切换到其他项）
        if detection is not self._current_detection:
            return
        self._updateScoreBreakdown(detection)

    @staticmethod
    def _extractContentType(detection: DetectionResult) -> str:
        """从 stream_worker 拼好的请求头里取 Content-Type，取不到返回空串"""
        raw = detection.raw_result if isinstance(detection.raw_result, dict) else None
        if not raw:
            return ''
        headers = raw.get('raw_request_headers') or ''
        if not isinstance(headers, str):
            return ''
        for line in headers.splitlines():
            name, sep, value = line.partition(':')
            if sep and name.strip().lower() == 'content-type':
                return value.strip()
        return ''

    def _updateScoreBreakdown(self, detection: DetectionResult):
        """更新得分拆解面板（带缓存）"""
        try:
            # 缓存命中检查 — 避免重复计算
            cache_key = id(detection)
            if cache_key in self._score_cache:
                cached = self._score_cache[cache_key]
                if cached is not None:
                    self.score_breakdown_panel.setScoreBreakdown(cached)
                    self.score_breakdown_panel.show()
                else:
                    self.score_breakdown_panel.hide()
                return

            # 延迟导入，避免循环导入
            from core.fast_filter import get_score_breakdown

            # 提取载荷数据
            payload_data = b''
            http_method = detection.method or ''
            uri = detection.uri or ''

            if detection.raw_result and isinstance(detection.raw_result, dict):
                raw_body = detection.raw_result.get('raw_request_body', '')
                if raw_body:
                    if isinstance(raw_body, bytes):
                        payload_data = raw_body
                    else:
                        # 限制分析长度，避免大载荷卡死
                        payload_data = str(raw_body)[:5000].encode('utf-8', errors='ignore')

            # content_type 原来是个赋空之后再没被写过的死变量，一路传到
            # fast_filter 里，Content-Type 相关的降权逻辑等于从来没生效过。
            # 真值在 stream_worker 拼好的请求头里(stream_worker.py:1175)。
            content_type = self._extractContentType(detection)

            if not payload_data and detection.payload:
                if isinstance(detection.payload, dict):
                    import json
                    payload_data = json.dumps(detection.payload).encode('utf-8')
                else:
                    payload_data = str(detection.payload)[:5000].encode('utf-8', errors='ignore')

            # body 可能是空的(GET 的目录穿越整个攻击都在 URI 里)，
            # 这种情况下只要有 URI 就仍然值得分析
            if payload_data or uri:
                breakdown = get_score_breakdown(
                    payload_data, content_type, http_method, uri)
                # 存入缓存
                if len(self._score_cache) >= self._score_cache_max:
                    # LRU: 清掉一半
                    keys = list(self._score_cache.keys())
                    for k in keys[:len(keys) // 2]:
                        del self._score_cache[k]
                self._score_cache[cache_key] = breakdown

                if breakdown:
                    self.score_breakdown_panel.setScoreBreakdown(breakdown)
                    self.score_breakdown_panel.show()
                else:
                    self.score_breakdown_panel.hide()
            else:
                self._score_cache[cache_key] = None
                self.score_breakdown_panel.hide()
        except ImportError:
            self.score_breakdown_panel.hide()
        except Exception as e:
            logger.debug(f"Score breakdown error: {e}")
            self.score_breakdown_panel.hide()

    def showImage(self, image_data: bytes = None, file_path: str = None):
        """显示图片"""
        self.title_label.setText("图片查看")
        self.view_btn_group.hide()
        self.export_btn.hide()
        self.score_breakdown_panel.hide()
        self.image_viewer.setImage(image_data, file_path)
        self.stack.setCurrentIndex(1)

    def showExtractedFile(self, ef: ExtractedFile):
        """显示提取文件的流量包"""
        self._current_extracted_file = ef
        self._current_detection = None
        self._current_protocol_finding = None

        self.title_label.setText(f"流量包详情 - {ef.file_name}")
        self.view_btn_group.hide()
        self.export_btn.setText("导出文件")
        self.export_btn.show()  # 显示导出按钮
        self.score_breakdown_panel.hide()

        # 设置内容到 PacketHexViewer
        self.packet_hex_viewer.setContent(ef)
        self.stack.setCurrentIndex(4)  # 切换到 PacketHexViewer

    def showProtocolFinding(self, finding: ProtocolFinding):
        """显示协议分析发现"""
        self._current_protocol_finding = finding
        self._current_detection = None
        self._current_extracted_file = None

        flag_mark = " [FLAG]" if finding.is_flag else ""
        self.title_label.setText(f"协议分析 - {finding.protocol} - {finding.title}{flag_mark}")
        self.view_btn_group.hide()
        if self._has_exportable_protocol_payload(finding):
            self.export_btn.setText("导出Payload")
            self.export_btn.show()
        else:
            self.export_btn.hide()
        self.score_breakdown_panel.hide()

        # 设置内容到 ProtocolFindingViewer
        self.protocol_finding_viewer.setContent(finding)
        self.stack.setCurrentIndex(5)  # 切换到 ProtocolFindingViewer

    def showDecodingResult(self, result: AutoDecodingResult):
        """显示自动解码结果"""
        self._current_decoding_result = result
        self._current_detection = None
        self._current_extracted_file = None
        self._current_protocol_finding = None
        self._current_file_recovery = None

        flag_mark = " [FLAG!]" if result.flags_found else ""
        self.title_label.setText(f"自动解码 - {result.decode_chain}{flag_mark}")
        self.view_btn_group.hide()
        self.export_btn.hide()
        self.score_breakdown_panel.hide()

        # 设置内容到 DecodingResultViewer
        self.decoding_result_viewer.setContent(result)
        self.stack.setCurrentIndex(6)  # 切换到 DecodingResultViewer

    def showFileRecovery(self, recovery: FileRecoveryResult):
        """显示文件还原结果"""
        self._current_file_recovery = recovery
        self._current_detection = None
        self._current_extracted_file = None
        self._current_protocol_finding = None
        self._current_decoding_result = None
        self._current_attack_detection = None

        self.title_label.setText(f"文件还原 - {recovery.description}")
        self.view_btn_group.hide()
        self.export_btn.setText("导出文件")
        self.export_btn.show() if recovery.saved_path else self.export_btn.hide()
        self.score_breakdown_panel.hide()

        # 设置内容到 FileRecoveryViewer
        self.file_recovery_viewer.setContent(recovery)
        self.stack.setCurrentIndex(7)  # 切换到 FileRecoveryViewer

    def showAttackDetection(self, attack: AttackDetectionInfo):
        """显示攻击检测结果"""
        self._current_attack_detection = attack
        self._current_detection = None
        self._current_extracted_file = None
        self._current_protocol_finding = None
        self._current_decoding_result = None
        self._current_file_recovery = None

        self.title_label.setText(f"攻击检测 - {attack.attack_type}")
        self.view_btn_group.hide()
        self.export_btn.hide()
        self.score_breakdown_panel.hide()

        # 设置内容到 AttackDetectionViewer
        self.attack_detection_viewer.setContent(attack)
        self.stack.setCurrentIndex(8)

    def showRTPStream(self, stream: RTPStreamInfo, all_streams: list = None):
        """显示 RTP 音视频流信息"""
        self._current_rtp_stream = stream
        self._current_detection = None
        self._current_extracted_file = None
        self._current_protocol_finding = None
        self._current_decoding_result = None
        self._current_file_recovery = None
        self._current_attack_detection = None

        media_label = "音频" if stream.media_type == "audio" else "视频"
        self.title_label.setText(f"RTP {media_label}流 - {stream.codec_name}")
        self.view_btn_group.hide()
        self.export_btn.hide()
        self.score_breakdown_panel.hide()

        self.rtp_stream_viewer.setContent(stream, all_streams)
        self.stack.setCurrentIndex(9)

    def _exportFile(self):
        """导出提取的文件或协议载荷证据。"""
        if self._current_protocol_finding and self._has_exportable_protocol_payload(self._current_protocol_finding):
            self._exportProtocolPayload()
            return

        if not self._current_extracted_file:
            return

        ef = self._current_extracted_file

        # 检查文件是否存在
        import os
        if not os.path.exists(ef.file_path):
            QMessageBox.warning(self, "导出失败", f"文件不存在:\n{ef.file_path}")
            return

        # 打开保存对话框
        save_path, _ = QFileDialog.getSaveFileName(
            self,
            "导出文件",
            ef.file_name,
            "All Files (*)"
        )

        if save_path:
            try:
                shutil.copy(ef.file_path, save_path)
                QMessageBox.information(self, "导出成功", f"文件已保存到:\n{save_path}")
            except Exception as e:
                QMessageBox.critical(self, "导出失败", f"保存文件时出错:\n{str(e)}")

    @staticmethod
    def _has_exportable_protocol_payload(finding: ProtocolFinding) -> bool:
        return any(
            isinstance(value, dict) and value.get("kind") == "encrypted_http_body"
            for value in (finding.raw_values or [])
        )

    def _exportProtocolPayload(self):
        finding = self._current_protocol_finding
        if not finding:
            return

        default_name = "cs_payload_evidence.html"
        save_path, selected_filter = QFileDialog.getSaveFileName(
            self,
            "导出 Cobalt Strike Payload",
            default_name,
            "HTML Report (*.html);;JSON Report (*.json)"
        )
        if not save_path:
            return

        lower_path = save_path.lower()
        if "." not in os.path.basename(save_path):
            save_path += ".json" if "json" in selected_filter.lower() else ".html"
        elif "json" in selected_filter.lower() and not lower_path.endswith(".json"):
            save_path += ".json"
        elif "html" in selected_filter.lower() and not lower_path.endswith((".html", ".htm")):
            save_path += ".html"

        try:
            from core.cs_payload_export import export_cs_payload_report

            count = export_cs_payload_report(finding.raw_values, save_path)
            QMessageBox.information(
                self,
                "导出成功",
                f"已导出 {count} 条 Cobalt Strike 加密 Payload 证据:\n{save_path}"
            )
        except Exception as e:
            QMessageBox.critical(self, "导出失败", f"导出 Payload 证据时出错:\n{str(e)}")

    def shutdown(self):
        """退出前收掉所有后台线程。

        QThread 还在跑的时候被析构会直接崩，所以窗口关闭必须走这一步。
        """
        self.packet_hex_viewer.shutdown()
        # Burp 视图的证据回取也是 QThread，漏掉同样会崩
        self.burp_viewer.shutdownWorkers()

    def clear(self):
        """清空显示"""
        self._current_detection = None
        self._current_extracted_file = None
        self._current_protocol_finding = None
        self._current_decoding_result = None
        self._current_file_recovery = None
        self._current_attack_detection = None
        self._current_rtp_stream = None
        self.title_label.setText("载荷详情")
        self.view_btn_group.hide()
        self.export_btn.hide()
        self.score_breakdown_panel.hide()
        self.score_breakdown_panel.clear()
        self.wireshark_viewer.clear()
        self.burp_viewer.clear()
        self.image_viewer.clear()
        self.raw_viewer.clear()
        self.packet_hex_viewer.clear()
        self.protocol_finding_viewer.clear()
        self.decoding_result_viewer.clear()
        self.file_recovery_viewer.clear()
        self.attack_detection_viewer.clear()
        self.rtp_stream_viewer.clear()
        self.stack.setCurrentIndex(3)


    def _openDecodeDialog(self, decode_type: str):
        """打开解码工具对话框"""
        dialog = DecodeToolDialog(decode_type, "decode", self)
        # 如果有当前检测结果，预填充载荷数据
        if self._current_detection:
            prefill = self._get_prefill_data()
            if prefill:
                dialog.setInputText(prefill)
        dialog.exec()

    def _openEncodeDialog(self, encode_type: str):
        """打开编码工具对话框"""
        dialog = DecodeToolDialog(encode_type, "encode", self)
        dialog.exec()

    def _get_prefill_data(self) -> str:
        """从当前检测结果中获取预填充数据"""
        det = self._current_detection
        if not det:
            return ""

        # 优先使用 payload
        if det.payload:
            if isinstance(det.payload, dict):
                return json.dumps(det.payload, ensure_ascii=False)
            return str(det.payload)[:2000]

        # 其次 raw_result 中的请求体
        if det.raw_result and isinstance(det.raw_result, dict):
            body = det.raw_result.get('raw_request_body', '')
            if body:
                return str(body)[:2000]

        return ""

    def _extractAllParams(self):
        """提取当前检测结果的所有参数"""
        det = self._current_detection
        if not det:
            QMessageBox.information(self, "提取参数", "没有当前检测结果")
            return

        lines = []
        lines.append(f"=== 参数提取: {det.detection_type.display_name} ===\n")

        # payload 参数
        if det.payload and isinstance(det.payload, dict):
            lines.append("[Payload Parameters]")
            for k, v in det.payload.items():
                if isinstance(v, dict):
                    decoded = v.get('decoded', v.get('decoded_content', ''))
                    lines.append(f"  {k} = {str(decoded)[:200]}")
                else:
                    lines.append(f"  {k} = {str(v)[:200]}")

        # 新格式 payloads
        if hasattr(det, 'payloads') and det.payloads:
            lines.append("\n[Decoded Payloads]")
            for p in det.payloads:
                lines.append(f"  {p.param_name}:")
                lines.append(f"    Type: {p.payload_type}")
                lines.append(f"    Decode Method: {p.decode_method}")
                if p.decoded_content:
                    lines.append(f"    Content: {p.decoded_content[:300]}")

        # raw_result 中的参数
        if det.raw_result and isinstance(det.raw_result, dict):
            raw_payloads = det.raw_result.get('payloads', {})
            if isinstance(raw_payloads, dict) and raw_payloads:
                lines.append("\n[Raw Payloads]")
                for k, v in raw_payloads.items():
                    lines.append(f"  {k}: {str(v)[:200]}")

        dialog = QDialog(self)
        dialog.setWindowTitle("参数提取结果")
        dialog.resize(600, 400)
        dlg_layout = QVBoxLayout(dialog)
        text_edit = QPlainTextEdit()
        text_edit.setReadOnly(True)
        text_edit.setFont(QFont("Consolas", 10))
        text_edit.setPlainText('\n'.join(lines))
        dlg_layout.addWidget(text_edit)

        btn_box = QDialogButtonBox(QDialogButtonBox.Close)
        btn_box.rejected.connect(dialog.close)
        dlg_layout.addWidget(btn_box)
        dialog.exec()

    def _showRawJson(self):
        """显示当前检测结果的原始JSON"""
        det = self._current_detection
        if not det:
            QMessageBox.information(self, "原始JSON", "没有当前检测结果")
            return

        data = {
            "detection_type": det.detection_type.value,
            "threat_level": det.threat_level.value,
            "method": det.method,
            "uri": det.uri,
            "indicator": det.indicator,
            "source_ip": det.source_ip,
            "dest_ip": det.dest_ip,
            "tags": det.tags,
            "raw_result": det.raw_result,
        }

        dialog = QDialog(self)
        dialog.setWindowTitle("原始检测结果 JSON")
        dialog.resize(700, 500)
        dlg_layout = QVBoxLayout(dialog)
        text_edit = QPlainTextEdit()
        text_edit.setReadOnly(True)
        text_edit.setFont(QFont("Consolas", 10))
        text_edit.setStyleSheet("background-color: #1E1E1E; color: #D4D4D4;")
        text_edit.setPlainText(json.dumps(data, ensure_ascii=False, indent=2, default=str))
        dlg_layout.addWidget(text_edit)

        btn_box = QDialogButtonBox(QDialogButtonBox.Close)
        btn_box.rejected.connect(dialog.close)
        dlg_layout.addWidget(btn_box)
        dialog.exec()


class DecodeToolDialog(QDialog):
    """解码/编码工具对话框"""

    CODEC_NAMES = {
        "base64": "Base64",
        "url": "URL",
        "hex": "Hex",
        "unicode": "Unicode",
    }

    def __init__(self, codec_type: str, mode: str = "decode", parent=None):
        # codec_type: base64/url/hex/unicode, mode: decode/encode
        super().__init__(parent)
        self._codec_type = codec_type
        self._mode = mode

        mode_label = "解码" if mode == "decode" else "编码"
        codec_name = self.CODEC_NAMES.get(codec_type, codec_type)
        self.setWindowTitle(f"{codec_name} {mode_label}")
        self.resize(700, 500)
        self._setupUI()

    def _setupUI(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(10)

        mode_label = "解码" if self._mode == "decode" else "编码"

        # 输入区
        input_label = QLabel(f"输入 ({mode_label}前):")
        input_label.setStyleSheet("font-weight: bold; font-size: 12px;")
        layout.addWidget(input_label)

        self.input_edit = QPlainTextEdit()
        self.input_edit.setFont(QFont("Consolas", 10))
        self.input_edit.setPlaceholderText(f"粘贴要{mode_label}的内容...")
        layout.addWidget(self.input_edit)

        # 按钮行
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()

        run_btn = QPushButton(f"执行{mode_label}")
        run_btn.setStyleSheet("""
            QPushButton {
                background-color: #1976D2;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 8px 24px;
                font-size: 12px;
                font-weight: bold;
            }
            QPushButton:hover { background-color: #1565C0; }
        """)
        run_btn.clicked.connect(self._execute)
        btn_layout.addWidget(run_btn)

        clear_btn = QPushButton("清空")
        clear_btn.setStyleSheet("""
            QPushButton {
                background-color: #757575;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 8px 16px;
                font-size: 12px;
            }
            QPushButton:hover { background-color: #616161; }
        """)
        clear_btn.clicked.connect(self._clearAll)
        btn_layout.addWidget(clear_btn)

        btn_layout.addStretch()
        layout.addLayout(btn_layout)

        # 输出区
        output_label = QLabel(f"输出 ({mode_label}后):")
        output_label.setStyleSheet("font-weight: bold; font-size: 12px;")
        layout.addWidget(output_label)

        self.output_edit = QPlainTextEdit()
        self.output_edit.setReadOnly(True)
        self.output_edit.setFont(QFont("Consolas", 10))
        self.output_edit.setStyleSheet("background-color: #F5F5F5;")
        layout.addWidget(self.output_edit)

        # 底部按钮
        bottom_layout = QHBoxLayout()

        copy_btn = QPushButton("复制结果")
        copy_btn.setStyleSheet("""
            QPushButton {
                background-color: #FF9800;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 6px 16px;
                font-size: 11px;
            }
            QPushButton:hover { background-color: #F57C00; }
        """)
        copy_btn.clicked.connect(self._copyResult)
        bottom_layout.addWidget(copy_btn)

        bottom_layout.addStretch()

        close_btn = QPushButton("关闭")
        close_btn.clicked.connect(self.close)
        bottom_layout.addWidget(close_btn)

        layout.addLayout(bottom_layout)

    def setInputText(self, text: str):
        """预设输入文本"""
        self.input_edit.setPlainText(text)

    def _execute(self):
        """执行解码/编码"""
        input_text = self.input_edit.toPlainText().strip()
        if not input_text:
            self.output_edit.setPlainText("[无输入]")
            return

        try:
            if self._mode == "decode":
                result = self._decode(input_text)
            else:
                result = self._encode(input_text)
            self.output_edit.setPlainText(result)
        except Exception as e:
            self.output_edit.setPlainText(f"[错误] {str(e)}")

    def _decode(self, text: str) -> str:
        """执行解码"""
        if self._codec_type == "base64":
            # 尝试多次base64解码
            try:
                decoded = base64.b64decode(text)
                try:
                    return decoded.decode('utf-8')
                except UnicodeDecodeError:
                    return format_binary_as_hex(decoded.decode('latin-1'))
            except Exception:
                # 去除空白后再试
                cleaned = text.replace('\n', '').replace('\r', '').replace(' ', '')
                decoded = base64.b64decode(cleaned)
                try:
                    return decoded.decode('utf-8')
                except UnicodeDecodeError:
                    return format_binary_as_hex(decoded.decode('latin-1'))

        elif self._codec_type == "url":
            result = text
            # 循环解码直到不再变化
            for _ in range(5):
                decoded = unquote(result)
                if decoded == result:
                    break
                result = decoded
            return result

        elif self._codec_type == "hex":
            # 去除常见前缀和分隔符
            cleaned = text.replace('0x', '').replace('\\x', '')
            cleaned = cleaned.replace(' ', '').replace('\n', '').replace('-', '')
            decoded = bytes.fromhex(cleaned)
            try:
                return decoded.decode('utf-8')
            except UnicodeDecodeError:
                return format_binary_as_hex(decoded.decode('latin-1'))

        elif self._codec_type == "unicode":
            result = text
            result = result.encode().decode('unicode_escape')
            return result

        return f"[不支持的解码类型: {self._codec_type}]"

    def _encode(self, text: str) -> str:
        """执行编码"""
        if self._codec_type == "base64":
            return base64.b64encode(text.encode('utf-8')).decode('ascii')

        elif self._codec_type == "url":
            from urllib.parse import quote
            return quote(text, safe='')

        elif self._codec_type == "hex":
            hex_str = text.encode('utf-8').hex()
            # 格式化为每2字符一组
            return ' '.join(hex_str[i:i+2] for i in range(0, len(hex_str), 2))

        return f"[不支持的编码类型: {self._codec_type}]"

    def _clearAll(self):
        """清空输入和输出"""
        self.input_edit.clear()
        self.output_edit.clear()

    def _copyResult(self):
        """复制输出结果"""
        from PySide6.QtWidgets import QApplication
        text = self.output_edit.toPlainText()
        if text:
            QApplication.clipboard().setText(text)
            QMessageBox.information(self, "复制成功", "结果已复制到剪贴板")
