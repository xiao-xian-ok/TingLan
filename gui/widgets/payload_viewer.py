# payload_viewer.py
# 数据包详情查看，支持hex/文本/格式化等多种视图

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
    QDialogButtonBox, QComboBox, QGridLayout
)
from PySide6.QtCore import Qt, QByteArray, Signal, QTimer
from PySide6.QtGui import QFont, QColor, QPixmap, QImage, QAction

from models.detection_result import (
    DetectionResult, ExtractedFile, ProtocolFinding,
    AutoDecodingResult, FileRecoveryResult, AttackDetectionInfo
)


def is_binary_data(data: str, threshold: float = 0.3) -> bool:
    """检查是否为二进制数据"""
    if not data:
        return False

    # 检查前1000个字符
    sample = data[:1000]
    non_printable = sum(1 for c in sample if ord(c) < 32 and c not in '\n\r\t')
    ratio = non_printable / len(sample) if sample else 0

    return ratio > threshold


def format_binary_as_hex(data: str, max_bytes: int = 512) -> str:
    """Wireshark风格hex dump"""
    try:
        # 尝试将字符串编码为字节
        if isinstance(data, str):
            raw_bytes = data.encode('latin-1', errors='replace')[:max_bytes]
        else:
            raw_bytes = bytes(data)[:max_bytes]

        lines = []
        for i in range(0, len(raw_bytes), 16):
            chunk = raw_bytes[i:i+16]
            offset = f"{i:04x}"

            # 十六进制部分
            hex_left = " ".join(f"{b:02x}" for b in chunk[:8])
            hex_right = " ".join(f"{b:02x}" for b in chunk[8:])
            hex_part = f"{hex_left:<23}  {hex_right:<23}"

            # ASCII部分
            ascii_part = "".join(chr(b) if 32 <= b < 127 else '.' for b in chunk)

            lines.append(f"{offset}   {hex_part}  |{ascii_part}|")

        if len(raw_bytes) == max_bytes:
            lines.append(f"\n... (仅显示前 {max_bytes} 字节)")

        return '\n'.join(lines)
    except Exception as e:
        return f"[无法格式化二进制数据: {e}]"


def safe_display_text(data, max_length: int = 1000) -> str:
    """安全显示文本，二进制自动转hex"""
    if data is None:
        return ""

    text = str(data)

    if is_binary_data(text):
        return format_binary_as_hex(text)

    if len(text) > max_length:
        return text[:max_length] + "\n... (截断)"

    return text


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
                for line in payload_str.split('\n')[:20]:
                    QTreeWidgetItem(payload_item, [f"  {line[:200]}"])

        # 解码后的载荷（新格式）
        if hasattr(detection, 'payloads') and detection.payloads:
            decoded_item = QTreeWidgetItem(self.tree, [f"Decoded Payloads ({len(detection.payloads)})"])
            decoded_item.setForeground(0, QColor("#00796B"))
            for payload in detection.payloads:
                param_item = QTreeWidgetItem(decoded_item, [f"  {payload.param_name} ({payload.payload_type})"])
                if payload.decoded_content:
                    content_preview = payload.decoded_content[:150]
                    if len(payload.decoded_content) > 150:
                        content_preview += "..."
                    QTreeWidgetItem(param_item, [f"    {content_preview}"])

        # Response层
        if detection.response_data:
            resp_item = QTreeWidgetItem(self.tree, ["Response Data"])
            resp_item.setForeground(0, QColor("#C2185B"))
            resp_str = str(detection.response_data)
            if is_binary_data(resp_str):
                QTreeWidgetItem(resp_item, ["  [Binary Data - Hex Dump]"])
                hex_dump = format_binary_as_hex(resp_str, max_bytes=256)
                for line in hex_dump.split('\n')[:20]:
                    QTreeWidgetItem(resp_item, [f"  {line}"])
            else:
                for line in resp_str.split('\n')[:15]:
                    QTreeWidgetItem(resp_item, [f"  {line[:200]}"])

        # response_sample（新版检测结果）
        if hasattr(detection, 'response_sample') and detection.response_sample:
            sample_item = QTreeWidgetItem(self.tree, ["Response Sample"])
            sample_item.setForeground(0, QColor("#C2185B"))
            sample_str = str(detection.response_sample)
            if is_binary_data(sample_str):
                QTreeWidgetItem(sample_item, ["  [Binary Data - Hex Dump]"])
                hex_dump = format_binary_as_hex(sample_str, max_bytes=256)
                for line in hex_dump.split('\n')[:20]:
                    QTreeWidgetItem(sample_item, [f"  {line}"])
            else:
                for line in sample_str.split('\n')[:15]:
                    QTreeWidgetItem(sample_item, [f"  {line[:200]}"])

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
        if len(raw_text) > 500:
            raw_text = raw_text[:500] + "\n... (截断)"
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
        'raw_request_body', 'raw_http_request', 'raw_request_headers',
        'raw_response_body', 'raw_http_response'
    }

    def _add_dict_items_safe(self, parent: QTreeWidgetItem, data: dict, depth: int = 0):
        """
        安全版递归添加字典项 — 跳过大块原始数据，限制总节点数

        与 _add_dict_items 的区别：
        - 跳过 raw_request_body 等大块字段（只显示摘要）
        - 限制总子节点数量不超过 50
        - 字符串值截断到 150 字符
        """
        if depth > 2:
            return
        node_count = 0
        max_nodes = 50
        for key, value in data.items():
            if node_count >= max_nodes:
                QTreeWidgetItem(parent, [f"  ... 剩余 {len(data) - node_count} 项已省略"])
                break
            # 跳过大块原始数据，只显示长度摘要
            if key in self._RAW_SKIP_KEYS:
                val_len = len(str(value)) if value else 0
                QTreeWidgetItem(parent, [f"  {key}: [{val_len} chars] (展开查看Burp视图)"])
                node_count += 1
                continue
            if isinstance(value, dict):
                sub_item = QTreeWidgetItem(parent, [f"  {key}:"])
                self._add_dict_items_safe(sub_item, value, depth + 1)
                node_count += 1
            elif isinstance(value, list):
                sub_item = QTreeWidgetItem(parent, [f"  {key}: [{len(value)} items]"])
                for i, v in enumerate(value[:5]):
                    v_str = str(v)[:150]
                    QTreeWidgetItem(sub_item, [f"    [{i}]: {v_str}"])
                if len(value) > 5:
                    QTreeWidgetItem(sub_item, [f"    ... 剩余 {len(value) - 5} 项"])
                node_count += 1
            else:
                val_str = str(value)
                if len(val_str) > 150:
                    val_str = val_str[:150] + "..."
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


class BurpStyleViewer(QFrame):
    """Burp风格的HTTP请求查看器"""

    def __init__(self, parent=None):
        super().__init__(parent)
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
        lines = []

        # 优先使用真实的 HTTP 请求数据
        raw_http = None
        if detection.raw_result and isinstance(detection.raw_result, dict):
            raw_http = detection.raw_result.get('raw_http_request', '')

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
            # 显示完整原始请求体
            lines.append(raw_body[:2000])
            if len(raw_body) > 2000:
                lines.append("... (truncated)")
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
                if len(payload_str) > 2000:
                    payload_str = payload_str[:2000] + "\n... (截断)"
                lines.append(payload_str)

        # 解密内容（冰蝎/哥斯拉）
        if detection.payloads:
            lines.append("")
            lines.append("# " + "=" * 50)
            lines.append("# Decoded Payloads")
            lines.append("# " + "=" * 50)
            for payload in detection.payloads:
                lines.append(f"#")
                lines.append(f"# [{payload.param_name}]")
                lines.append(f"#   Type: {payload.payload_type}")
                lines.append(f"#   Method: {payload.decode_method}")
                if payload.decoded_content:
                    lines.append(f"#   Content:")
                    for dc_line in payload.decoded_content[:500].split('\n')[:15]:
                        lines.append(f"#     {dc_line}")

        # 响应数据
        if detection.response_data:
            lines.append("")
            lines.append("=" * 50)
            lines.append("=== Response ===")
            lines.append("=" * 50)
            resp_str = str(detection.response_data)
            if is_binary_data(resp_str):
                lines.append("[Binary Data - Hex Dump]")
                lines.append(format_binary_as_hex(resp_str, max_bytes=512))
            else:
                if len(resp_str) > 1000:
                    resp_str = resp_str[:1000] + "\n... (截断)"
                lines.append(resp_str)

        # response_sample（新版检测结果）
        if hasattr(detection, 'response_sample') and detection.response_sample:
            lines.append("")
            lines.append("=" * 50)
            lines.append("=== Response Sample ===")
            lines.append("=" * 50)
            sample_str = str(detection.response_sample)
            if is_binary_data(sample_str):
                lines.append("[Binary Data - Hex Dump]")
                lines.append(format_binary_as_hex(sample_str, max_bytes=512))
            else:
                if len(sample_str) > 500:
                    sample_str = sample_str[:500] + "\n... (截断)"
                lines.append(sample_str)

        self.text_edit.setPlainText('\n'.join(lines))

    def clear(self):
        self.text_edit.clear()

    def _copyToClipboard(self):
        from PySide6.QtWidgets import QApplication
        clipboard = QApplication.clipboard()
        clipboard.setText(self.text_edit.toPlainText())


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


class PacketHexViewer(QFrame):
    """提取文件的hex查看器"""

    def __init__(self, parent=None):
        super().__init__(parent)
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
        """设置提取文件的内容"""
        # 禁用更新
        self.tree.setUpdatesEnabled(False)
        self.hex_view.setUpdatesEnabled(False)
        try:
            self.tree.clear()
            self.hex_view.clear()

            # 如果还没有加载 hex_dump，进行懒加载
            if not ef.hex_dump and ef.file_path:
                self._loadFileHexContent(ef)

            # 显示协议分层
            self._displayProtocolLayers(ef)

            # 显示十六进制 dump
            if ef.hex_dump:
                self.hex_view.setPlainText(ef.hex_dump)
            else:
                self.hex_view.setPlainText("无法获取十六进制数据")
        finally:
            self.tree.setUpdatesEnabled(True)
            self.hex_view.setUpdatesEnabled(True)

    def _loadFileHexContent(self, ef: ExtractedFile):
        """懒加载文件的十六进制内容"""
        from controllers.analysis_controller import get_file_hex_content, get_packet_hex_dump

        # 获取文件内容的十六进制
        ef.hex_dump = get_file_hex_content(ef.file_path, max_bytes=4096)

        # 如果有关联的包序号，尝试获取协议层信息
        if ef.source_packet > 0 and ef.pcap_path:
            _, protocol_layers = get_packet_hex_dump(ef.pcap_path, ef.source_packet)
            ef.protocol_layers = protocol_layers

    def _displayProtocolLayers(self, ef: ExtractedFile):
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
        self.title_label.setText(f"协议分析 - {finding.protocol}")

        # 协议信息
        proto_item = QTreeWidgetItem(self.tree, [f"Protocol: {finding.protocol}"])
        proto_item.setForeground(0, QColor("#7B1FA2"))
        QTreeWidgetItem(proto_item, [f"  发现类型: {finding.finding_type}"])
        QTreeWidgetItem(proto_item, [f"  置信度: {finding.confidence_display} ({finding.confidence:.0%})"])

        # 发现详情
        detail_item = QTreeWidgetItem(self.tree, [f"Finding: {finding.title}"])
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
            # 检测是否为二进制序列（全是0和1）
            is_binary = all(v in (0, 1) for v in finding.raw_values)

            if is_binary:
                lines.append(f"=== 二进制位序列 ({len(finding.raw_values)} bits) ===")
                # 每行显示32位（4字节）
                for i in range(0, len(finding.raw_values), 32):
                    chunk = finding.raw_values[i:i+32]
                    # 分组显示（每8位一组）
                    groups = []
                    for j in range(0, len(chunk), 8):
                        group = chunk[j:j+8]
                        groups.append("".join(str(b) for b in group))
                    lines.append(f"  [{i:04d}]  {' '.join(groups)}")

                lines.append("")
                lines.append("=== 二进制转文本 ===")
                # 将二进制位转换为字节再转ASCII
                usable_bits = (len(finding.raw_values) // 8) * 8
                text_result = []
                for i in range(0, usable_bits, 8):
                    byte_bits = finding.raw_values[i:i+8]
                    byte_val = 0
                    for bit in byte_bits:
                        byte_val = (byte_val << 1) | bit
                    if 32 <= byte_val <= 126:
                        text_result.append(chr(byte_val))
                    elif byte_val == 0:
                        text_result.append('\\0')
                    else:
                        text_result.append('.')
                lines.append("  " + "".join(text_result))
            else:
                lines.append(f"=== 原始值序列 ({len(finding.raw_values)} 值) ===")
                # 每行显示16个值
                for i in range(0, len(finding.raw_values), 16):
                    chunk = finding.raw_values[i:i+16]
                    # 数值行
                    num_str = " ".join(f"{v:>3}" for v in chunk)
                    lines.append(f"  [{i:04d}]  {num_str}")

                lines.append("")
                lines.append("=== ASCII转换 ===")
                ascii_result = []
                for v in finding.raw_values:
                    if isinstance(v, int) and 32 <= v <= 126:
                        ascii_result.append(chr(v))
                    else:
                        ascii_result.append(".")
                lines.append("  " + "".join(ascii_result))

        self.data_view.setPlainText("\n".join(lines))

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
        self.setMinimumHeight(100)
        self.setMaximumHeight(150)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 8, 10, 8)
        layout.setSpacing(4)

        # 标题行
        header = QHBoxLayout()
        title = QLabel("Score Breakdown (得分拆解)")
        title.setStyleSheet("font-size: 11px; font-weight: bold; color: #F57C00;")
        header.addWidget(title)
        header.addStretch()

        # 灵敏度显示
        self.sensitivity_label = QLabel("灵敏度: 50")
        self.sensitivity_label.setStyleSheet("font-size: 10px; color: #FF8F00;")
        header.addWidget(self.sensitivity_label)
        layout.addLayout(header)

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

        # 综合判定
        self.verdict_label = QLabel("综合判定: --")
        self.verdict_label.setStyleSheet("font-size: 11px; font-weight: bold; color: #333;")
        layout.addWidget(self.verdict_label)

    def setScoreBreakdown(self, breakdown: dict):
        """设置得分拆解数据"""
        if not breakdown:
            self.clear()
            return

        # 灵敏度
        sensitivity = breakdown.get('sensitivity', 50)
        self.sensitivity_label.setText(f"灵敏度: {sensitivity}")

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

        # 综合判定
        combined = breakdown.get('combined', {})
        verdict = combined.get('verdict', 'unknown')
        reason = combined.get('reason', '')
        force_audit = combined.get('force_audit', False)

        verdict_text = f"判定: {verdict}"
        if force_audit:
            verdict_text += " [强制审计]"
        if reason:
            verdict_text += f" ({reason[:50]})"
        self.verdict_label.setText(verdict_text)

        # 根据判定结果设置颜色
        if verdict == 'skip':
            self.verdict_label.setStyleSheet("font-size: 11px; font-weight: bold; color: #4CAF50;")
        elif verdict == 'audit' or force_audit:
            self.verdict_label.setStyleSheet("font-size: 11px; font-weight: bold; color: #F44336;")
        else:
            self.verdict_label.setStyleSheet("font-size: 11px; font-weight: bold; color: #FF9800;")

    def _setIndicator(self, indicator: QLabel, hit: bool):
        """设置指示器颜色"""
        if hit:
            indicator.setStyleSheet("color: #F44336; font-size: 12px;")  # 红色 = 命中
        else:
            indicator.setStyleSheet("color: #4CAF50; font-size: 12px;")  # 绿色 = 正常

    def clear(self):
        """清空显示"""
        self.sensitivity_label.setText("灵敏度: --")
        self.entropy_label.setText("熵值: --")
        self.structure_label.setText("格式: --")
        self.char_label.setText("字符: --")
        self.length_label.setText("长度: --")
        self.verdict_label.setText("综合判定: --")
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
            content_type = ''
            http_method = detection.method or ''

            if detection.raw_result and isinstance(detection.raw_result, dict):
                raw_body = detection.raw_result.get('raw_request_body', '')
                if raw_body:
                    if isinstance(raw_body, bytes):
                        payload_data = raw_body
                    else:
                        # 限制分析长度，避免大载荷卡死
                        payload_data = str(raw_body)[:5000].encode('utf-8', errors='ignore')

            if not payload_data and detection.payload:
                if isinstance(detection.payload, dict):
                    import json
                    payload_data = json.dumps(detection.payload).encode('utf-8')
                else:
                    payload_data = str(detection.payload)[:5000].encode('utf-8', errors='ignore')

            if payload_data and len(payload_data) > 0:
                breakdown = get_score_breakdown(payload_data, content_type, http_method)
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
        self.stack.setCurrentIndex(8)  # 切换到 AttackDetectionViewer

    def _exportFile(self):
        """导出提取的文件"""
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

    def clear(self):
        """清空显示"""
        self._current_detection = None
        self._current_extracted_file = None
        self._current_protocol_finding = None
        self._current_decoding_result = None
        self._current_file_recovery = None
        self._current_attack_detection = None
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
