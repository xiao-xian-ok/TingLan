# main_window.py - 主窗口
# 整个GUI的入口，管理所有面板和信号连接

import os
import time
import logging
from typing import Optional, List, Dict

from PySide6.QtWidgets import (
    QMainWindow, QWidget, QHBoxLayout, QVBoxLayout,
    QSplitter, QFileDialog, QMessageBox, QApplication,
    QStackedWidget, QPushButton, QLabel, QFrame,
    QListWidget, QListWidgetItem, QProgressBar,
    QMenu, QDialog, QLineEdit, QPlainTextEdit,
    QDialogButtonBox, QFormLayout, QSpinBox, QComboBox
)
from PySide6.QtCore import Qt, QSize, QSettings, Signal, QTimer
from PySide6.QtGui import QAction, QKeySequence, QFont

from gui.widgets.tree_panel import TreePanel
from gui.widgets.detail_table import DetailTable
from gui.widgets.payload_viewer import PayloadViewer
from gui.widgets.status_bar import StatusBar
from gui.widgets.pie_chart import ProtocolStatsWidget

try:  # 优先使用流式分析控制器
    from core.stream_worker import StreamAnalysisController as AnalysisController
    USE_STREAM_CONTROLLER = True
except ImportError:
    from controllers.analysis_controller import AnalysisController
    USE_STREAM_CONTROLLER = False

from controllers.export_controller import ExportController

from models.detection_result import (
    AnalysisSummary, DetectionResult, ExtractedFile, ProtocolFinding,
    AutoDecodingResult, FileRecoveryResult, AttackDetectionInfo
)
from models.tree_model import TreeNode

from services.interfaces import IAnalysisService

logger = logging.getLogger(__name__)


class UILimits:
    """UI显示限制"""
    MAX_DISPLAY_ROWS = 5000          # 详情表格最大显示行数
    MAX_TREE_ITEMS = 3000            # 树视图最大项目数
    PROGRESS_SMOOTH_INTERVAL = 50    # 进度平滑更新间隔 (毫秒)
    BATCH_UI_UPDATE_THRESHOLD = 10   # 超过此数量使用批量更新
    UI_FREEZE_TIMEOUT_MS = 100       # UI 冻结最长时间


def _get_engine_setting() -> str:
    from PySide6.QtCore import QSettings
    settings = QSettings("TingLan", "TrafficAnalyzer")
    engine_index = settings.value("engine", 0, int)
    return "tshark" if engine_index == 1 else "pyshark"


class FileListItem(QFrame):
    """单个文件卡片"""

    analyzeClicked = Signal(str)
    itemClicked = Signal(str)  # 点击后切换饼图

    def __init__(self, file_path: str, parent=None):
        super().__init__(parent)
        self.file_path = file_path
        self.file_name = os.path.basename(file_path)
        self._selected = False
        self._setupUI()

    def _setupUI(self):
        self.setFrameStyle(QFrame.StyledPanel | QFrame.Raised)
        self.setCursor(Qt.PointingHandCursor)  # 鼠标指针变为手型
        self._updateStyle()

        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)

        # 文件名
        name_label = QLabel(f"📄 {self.file_name}")
        name_label.setFont(QFont("Microsoft YaHei", 11, QFont.Bold))
        name_label.setStyleSheet("color: #333;")
        layout.addWidget(name_label)

        # 文件路径
        path_label = QLabel(self.file_path)
        path_label.setStyleSheet("color: #666; font-size: 10px;")
        path_label.setWordWrap(True)
        layout.addWidget(path_label)

        # 进度条（默认隐藏）
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: 1px solid #E0E0E0;
                border-radius: 4px;
                text-align: center;
                height: 20px;
            }
            QProgressBar::chunk {
                background-color: #1976D2;
                border-radius: 3px;
            }
        """)
        self.progress_bar.hide()
        layout.addWidget(self.progress_bar)

        # 状态标签
        self.status_label = QLabel("等待分析")
        self.status_label.setStyleSheet("color: #999; font-size: 11px;")
        layout.addWidget(self.status_label)

        # 分析按钮
        self.analyze_btn = QPushButton("▶ 开始分析")
        self.analyze_btn.setStyleSheet("""
            QPushButton {
                background-color: #1976D2;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 8px 16px;
                font-size: 12px;
            }
            QPushButton:hover {
                background-color: #1565C0;
            }
            QPushButton:pressed {
                background-color: #0D47A1;
            }
            QPushButton:disabled {
                background-color: #BDBDBD;
            }
        """)
        self.analyze_btn.clicked.connect(lambda: self.analyzeClicked.emit(self.file_path))
        layout.addWidget(self.analyze_btn)

    def _updateStyle(self):
        if self._selected:
            self.setStyleSheet("""
                FileListItem {
                    background-color: #E3F2FD;
                    border: 2px solid #1976D2;
                    border-radius: 8px;
                    margin: 4px;
                }
            """)
        else:
            self.setStyleSheet("""
                FileListItem {
                    background-color: white;
                    border: 1px solid #E0E0E0;
                    border-radius: 8px;
                    margin: 4px;
                }
                FileListItem:hover {
                    border-color: #1976D2;
                }
            """)

    def setSelected(self, selected: bool):
        self._selected = selected
        self._updateStyle()

    def isSelected(self) -> bool:
        return self._selected

    def mousePressEvent(self, event):
        super().mousePressEvent(event)
        self.itemClicked.emit(self.file_path)

    def setAnalyzing(self, analyzing: bool):
        if analyzing:
            self.progress_bar.show()
            self.progress_bar.setValue(0)
            self.analyze_btn.setEnabled(False)
            self.analyze_btn.setText("分析中...")
            self.status_label.setText("正在分析...")
            self.status_label.setStyleSheet("color: #1976D2; font-size: 11px;")
        else:
            self.analyze_btn.setEnabled(True)
            self.analyze_btn.setText("▶ 重新分析")

    def setProgress(self, percent: int, message: str):
        self.progress_bar.setValue(percent)
        self.status_label.setText(message)

    def setCompleted(self, success: bool, message: str = ""):
        self.progress_bar.hide()
        self.analyze_btn.setEnabled(True)
        self.analyze_btn.setText("▶ 重新分析")
        if success:
            self.status_label.setText(f"✓ {message}" if message else "✓ 分析完成")
            self.status_label.setStyleSheet("color: #4CAF50; font-size: 11px;")
        else:
            self.status_label.setText(f"✗ {message}" if message else "✗ 分析失败")
            self.status_label.setStyleSheet("color: #F44336; font-size: 11px;")


class FunctionBar(QFrame):
    """顶部功能栏"""

    functionChanged = Signal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._current = "file"
        self._setupUI()

    def _setupUI(self):
        self.setFixedHeight(50)
        self.setStyleSheet("""
            FunctionBar {
                background-color: #1976D2;
                border: none;
            }
        """)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(10, 0, 10, 0)
        layout.setSpacing(0)

        # 标题
        title = QLabel("TingLan 听澜")
        title.setStyleSheet("color: white; font-size: 16px; font-weight: bold; margin-right: 30px;")
        layout.addWidget(title)

        # 文件按钮
        self.file_btn = QPushButton("📁 文件")
        self.file_btn.setCheckable(True)
        self.file_btn.setChecked(True)
        self.file_btn.clicked.connect(lambda: self._onButtonClicked("file"))
        layout.addWidget(self.file_btn)

        # 分析按钮
        self.analysis_btn = QPushButton("📊 分析")
        self.analysis_btn.setCheckable(True)
        self.analysis_btn.clicked.connect(lambda: self._onButtonClicked("analysis"))
        layout.addWidget(self.analysis_btn)

        # 密钥管理按钮
        self.keys_btn = QPushButton("🔑 密钥管理")
        self.keys_btn.setCheckable(True)
        self.keys_btn.clicked.connect(lambda: self._onButtonClicked("keys"))
        layout.addWidget(self.keys_btn)

        # 解码工具按钮
        self.decode_btn = QPushButton("🔓 解码工具")
        self.decode_btn.setCheckable(True)
        self.decode_btn.clicked.connect(lambda: self._onButtonClicked("decode"))
        layout.addWidget(self.decode_btn)

        # 按钮样式
        btn_style = """
            QPushButton {
                background-color: transparent;
                color: rgba(255, 255, 255, 0.7);
                border: none;
                padding: 12px 24px;
                font-size: 14px;
                border-bottom: 3px solid transparent;
            }
            QPushButton:hover {
                color: white;
                background-color: rgba(255, 255, 255, 0.1);
            }
            QPushButton:checked {
                color: white;
                border-bottom: 3px solid white;
            }
        """
        self.file_btn.setStyleSheet(btn_style)
        self.analysis_btn.setStyleSheet(btn_style)
        self.keys_btn.setStyleSheet(btn_style)
        self.decode_btn.setStyleSheet(btn_style)

        layout.addStretch()

    def _onButtonClicked(self, name: str):
        self._current = name
        self.file_btn.setChecked(name == "file")
        self.analysis_btn.setChecked(name == "analysis")
        self.keys_btn.setChecked(name == "keys")
        self.decode_btn.setChecked(name == "decode")
        self.functionChanged.emit(name)

    def currentFunction(self) -> str:
        return self._current


class KeyManagementPanel(QWidget):
    """密钥管理面板"""

    resultReady = Signal(str, str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._custom_keys: Dict[str, str] = {}
        self._loadKeys()
        self._setupUI()

    def _setupUI(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 15, 20, 15)
        layout.setSpacing(12)

        # 标题
        title = QLabel("🔑 密钥管理与解密")
        title.setStyleSheet("font-size: 18px; font-weight: bold; color: #1976D2;")
        layout.addWidget(title)

        # 密钥类型选择行
        type_layout = QHBoxLayout()
        type_layout.addWidget(QLabel("密钥类型:"))
        self.key_type_combo = QComboBox()
        self.key_type_combo.addItems(["冰蝎 (Behinder)", "哥斯拉 (Godzilla)", "AES 通用"])
        self.key_type_combo.setStyleSheet("""
            QComboBox {
                padding: 8px 12px;
                border: 1px solid #E0E0E0;
                border-radius: 4px;
                min-width: 180px;
            }
        """)
        self.key_type_combo.currentIndexChanged.connect(self._onKeyTypeChanged)
        type_layout.addWidget(self.key_type_combo)

        # 使用默认密钥按钮
        self.default_btn = QPushButton("使用默认密钥")
        self.default_btn.setStyleSheet("""
            QPushButton {
                background-color: #FF9800;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 8px 16px;
            }
            QPushButton:hover { background-color: #F57C00; }
        """)
        self.default_btn.clicked.connect(self._useDefaultKey)
        type_layout.addWidget(self.default_btn)
        type_layout.addStretch()
        layout.addLayout(type_layout)

        # 提示信息
        self.info_label = QLabel("冰蝎默认密钥: e45e329feb5d925b (rebeyond)\n支持格式: 16字节HEX或明文密码")
        self.info_label.setStyleSheet("""
            color: #666; padding: 8px;
            background-color: #FFF3E0;
            border-radius: 4px;
            border-left: 4px solid #FF9800;
        """)
        self.info_label.setWordWrap(True)
        layout.addWidget(self.info_label)

        # 密钥输入区
        key_frame = QFrame()
        key_frame.setStyleSheet("QFrame { background-color: #FAFAFA; border-radius: 8px; }")
        key_layout = QVBoxLayout(key_frame)
        key_layout.setContentsMargins(12, 10, 12, 10)

        key_header = QHBoxLayout()
        key_header.addWidget(QLabel("密钥 (Key):"))
        self.pass_input = QLineEdit()
        self.pass_input.setPlaceholderText("或输入密码生成MD5密钥...")
        self.pass_input.setStyleSheet("padding: 6px; border: 1px solid #E0E0E0; border-radius: 4px;")
        self.pass_input.setMaximumWidth(200)
        key_header.addWidget(self.pass_input)

        gen_btn = QPushButton("生成")
        gen_btn.setStyleSheet("background-color: #4CAF50; color: white; padding: 6px 12px; border-radius: 4px;")
        gen_btn.clicked.connect(self._generateKeyFromPassword)
        key_header.addWidget(gen_btn)
        key_header.addStretch()
        key_layout.addLayout(key_header)

        self.key_input = QPlainTextEdit()
        self.key_input.setPlaceholderText("输入密钥（HEX格式，如: e45e329feb5d925b）...")
        self.key_input.setMaximumHeight(50)
        self.key_input.setStyleSheet("background-color: white; border: 1px solid #E0E0E0; border-radius: 4px;")
        key_layout.addWidget(self.key_input)
        layout.addWidget(key_frame)

        # 密文输入区 - 占用更多空间
        cipher_label = QLabel("密文 (Ciphertext):")
        layout.addWidget(cipher_label)

        self.cipher_input = QPlainTextEdit()
        self.cipher_input.setPlaceholderText("输入要解密的密文（Base64编码的AES密文）...\n\n支持多行输入，可以直接粘贴从流量中提取的加密数据...")
        self.cipher_input.setStyleSheet("""
            background-color: white;
            border: 1px solid #E0E0E0;
            border-radius: 4px;
            font-family: Consolas, Monaco, monospace;
            font-size: 13px;
        """)
        self.cipher_input.setMinimumHeight(200)
        layout.addWidget(self.cipher_input, stretch=1)  # 让密文区域占用剩余空间

        # 按钮行
        btn_layout = QHBoxLayout()
        decrypt_btn = QPushButton("🔓 解密")
        decrypt_btn.setStyleSheet("""
            QPushButton {
                background-color: #1976D2;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 12px 40px;
                font-size: 14px;
                font-weight: bold;
            }
            QPushButton:hover { background-color: #1565C0; }
        """)
        decrypt_btn.clicked.connect(self._doDecrypt)
        btn_layout.addWidget(decrypt_btn)

        save_key_btn = QPushButton("💾 保存密钥")
        save_key_btn.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 12px 24px;
            }
            QPushButton:hover { background-color: #43A047; }
        """)
        save_key_btn.clicked.connect(self._saveCurrentKey)
        btn_layout.addWidget(save_key_btn)

        clear_btn = QPushButton("清空")
        clear_btn.setStyleSheet("""
            QPushButton {
                background-color: #9E9E9E;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 12px 24px;
            }
            QPushButton:hover { background-color: #757575; }
        """)
        clear_btn.clicked.connect(self._clearAll)
        btn_layout.addWidget(clear_btn)
        btn_layout.addStretch()
        layout.addLayout(btn_layout)

    def _onKeyTypeChanged(self, index: int):
        infos = [
            "冰蝎默认密钥: e45e329feb5d925b (rebeyond)\n支持格式: 16字节HEX或明文密码",
            "哥斯拉默认密钥: 3c6e0b8a9c15224a (key)\n支持格式: 16字节HEX或明文密码",
            "输入AES密钥 (16/24/32字节)\n支持AES-128/192/256"
        ]
        self.info_label.setText(infos[index])
        key_types = ["behinder", "godzilla", "aes"]
        saved_key = self._custom_keys.get(key_types[index], "")
        if saved_key:
            self.key_input.setPlainText(saved_key)

    def _useDefaultKey(self):
        defaults = ["e45e329feb5d925b", "3c6e0b8a9c15224a", ""]
        self.key_input.setPlainText(defaults[self.key_type_combo.currentIndex()])

    def _generateKeyFromPassword(self):
        password = self.pass_input.text().strip()
        if password:
            import hashlib
            key = hashlib.md5(password.encode()).hexdigest()[:16]
            self.key_input.setPlainText(key)

    def _doDecrypt(self):
        key = self.key_input.toPlainText().strip()
        ciphertext = self.cipher_input.toPlainText().strip()

        if not key:
            self.resultReady.emit("错误", "请输入密钥")
            return
        if not ciphertext:
            self.resultReady.emit("错误", "请输入密文")
            return

        try:
            import base64
            try:
                from Crypto.Cipher import AES
                from Crypto.Util.Padding import unpad
            except ImportError:
                try:
                    from Cryptodome.Cipher import AES
                    from Cryptodome.Util.Padding import unpad
                except ImportError:
                    self.resultReady.emit("错误", "未安装加密库\n\n请安装 pycryptodome:\npip install pycryptodome")
                    return

            # 处理密钥
            if len(key) == 32:
                key_bytes = bytes.fromhex(key)
            elif len(key) == 16:
                try:
                    key_bytes = bytes.fromhex(key)
                except ValueError:
                    key_bytes = key.encode('utf-8')
            else:
                key_bytes = key.encode('utf-8')

            if len(key_bytes) < 16:
                key_bytes = key_bytes.ljust(16, b'\x00')
            elif len(key_bytes) > 16 and len(key_bytes) < 24:
                key_bytes = key_bytes[:16]
            elif len(key_bytes) > 24 and len(key_bytes) < 32:
                key_bytes = key_bytes[:24]
            elif len(key_bytes) > 32:
                key_bytes = key_bytes[:32]

            cipher_bytes = base64.b64decode(ciphertext)
            cipher = AES.new(key_bytes, AES.MODE_ECB)
            decrypted = unpad(cipher.decrypt(cipher_bytes), AES.block_size)

            try:
                result = decrypted.decode('utf-8')
            except:
                result = decrypted.decode('latin-1')

            self.resultReady.emit("解密结果", result)

        except Exception as e:
            self.resultReady.emit("解密失败", f"{str(e)}\n\n可能原因:\n1. 密钥不正确\n2. 密文格式错误\n3. 加密模式不匹配")

    def _saveCurrentKey(self):
        key = self.key_input.toPlainText().strip()
        if not key:
            return
        key_types = ["behinder", "godzilla", "aes"]
        key_type = key_types[self.key_type_combo.currentIndex()]
        self._custom_keys[key_type] = key
        self._saveKeys()
        self.resultReady.emit("保存成功", f"密钥已保存: {key_type}")

    def _clearAll(self):
        self.key_input.clear()
        self.cipher_input.clear()
        self.pass_input.clear()

    def _loadKeys(self):
        settings = QSettings("TingLan", "TrafficAnalyzer")
        keys_json = settings.value("custom_keys", "{}")
        try:
            import json
            self._custom_keys = json.loads(keys_json)
        except:
            self._custom_keys = {}

    def _saveKeys(self):
        import json
        settings = QSettings("TingLan", "TrafficAnalyzer")
        settings.setValue("custom_keys", json.dumps(self._custom_keys))

    def getCustomKeys(self) -> Dict[str, str]:
        return self._custom_keys.copy()


class DecodeToolPanel(QWidget):
    """解码工具面板"""

    resultReady = Signal(str, str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._setupUI()

    def _setupUI(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 15, 20, 15)
        layout.setSpacing(12)

        # 标题
        title = QLabel("🔓 解码工具")
        title.setStyleSheet("font-size: 18px; font-weight: bold; color: #1976D2;")
        layout.addWidget(title)

        # 编码类型选择
        type_layout = QHBoxLayout()
        type_layout.addWidget(QLabel("编码类型:"))

        self.encode_type_combo = QComboBox()
        self.encode_type_combo.addItems([
            "Base64",
            "URL编码",
            "Hex (十六进制)",
            "ROT13/凯撒密码",
            "HTML实体",
            "Unicode转义"
        ])
        self.encode_type_combo.setStyleSheet("""
            QComboBox {
                padding: 8px 12px;
                border: 1px solid #E0E0E0;
                border-radius: 4px;
                min-width: 180px;
            }
        """)
        self.encode_type_combo.currentIndexChanged.connect(self._onTypeChanged)
        type_layout.addWidget(self.encode_type_combo)

        # ROT偏移量
        self.offset_label = QLabel("偏移量:")
        self.offset_label.hide()
        type_layout.addWidget(self.offset_label)

        self.offset_spin = QSpinBox()
        self.offset_spin.setRange(1, 25)
        self.offset_spin.setValue(13)
        self.offset_spin.setStyleSheet("padding: 6px;")
        self.offset_spin.hide()
        type_layout.addWidget(self.offset_spin)

        type_layout.addStretch()
        layout.addLayout(type_layout)

        # 输入区 - 占用大部分空间
        input_label = QLabel("输入内容:")
        layout.addWidget(input_label)

        self.input_edit = QPlainTextEdit()
        self.input_edit.setPlaceholderText("输入要解码/编码的文本...\n\n支持多行输入，可以直接粘贴需要处理的数据...")
        self.input_edit.setStyleSheet("""
            background-color: white;
            border: 1px solid #E0E0E0;
            border-radius: 4px;
            font-family: Consolas, Monaco, monospace;
            font-size: 13px;
        """)
        self.input_edit.setMinimumHeight(250)
        layout.addWidget(self.input_edit, stretch=1)

        # 按钮行
        btn_layout = QHBoxLayout()

        decode_btn = QPushButton("⬇ 解码")
        decode_btn.setStyleSheet("""
            QPushButton {
                background-color: #1976D2;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 12px 40px;
                font-size: 14px;
                font-weight: bold;
            }
            QPushButton:hover { background-color: #1565C0; }
        """)
        decode_btn.clicked.connect(self._doDecode)
        btn_layout.addWidget(decode_btn)

        encode_btn = QPushButton("⬆ 编码")
        encode_btn.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 12px 40px;
                font-size: 14px;
                font-weight: bold;
            }
            QPushButton:hover { background-color: #43A047; }
        """)
        encode_btn.clicked.connect(self._doEncode)
        btn_layout.addWidget(encode_btn)

        clear_btn = QPushButton("清空")
        clear_btn.setStyleSheet("""
            QPushButton {
                background-color: #9E9E9E;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 12px 24px;
            }
            QPushButton:hover { background-color: #757575; }
        """)
        clear_btn.clicked.connect(self._clearAll)
        btn_layout.addWidget(clear_btn)

        btn_layout.addStretch()
        layout.addLayout(btn_layout)

    def _onTypeChanged(self, index: int):
        is_rot = index == 3
        self.offset_label.setVisible(is_rot)
        self.offset_spin.setVisible(is_rot)

    def _doDecode(self):
        import base64
        import urllib.parse
        import binascii
        import html

        text = self.input_edit.toPlainText()
        if not text:
            self.resultReady.emit("提示", "请输入要解码的内容")
            return

        encode_type = self.encode_type_combo.currentIndex()
        type_names = ["Base64", "URL", "Hex", "ROT", "HTML实体", "Unicode"]

        try:
            if encode_type == 0:
                result = base64.b64decode(text).decode('utf-8', errors='replace')
            elif encode_type == 1:
                result = urllib.parse.unquote(text)
            elif encode_type == 2:
                clean_text = text.replace(" ", "").replace("\n", "")
                result = binascii.unhexlify(clean_text).decode('utf-8', errors='replace')
            elif encode_type == 3:
                offset = self.offset_spin.value()
                result = self._rot_decode(text, offset)
            elif encode_type == 4:
                result = html.unescape(text)
            elif encode_type == 5:
                result = text.encode().decode('unicode_escape')
            else:
                result = text

            self.resultReady.emit(f"{type_names[encode_type]} 解码结果", result)
        except Exception as e:
            self.resultReady.emit("解码失败", str(e))

    def _doEncode(self):
        import base64
        import urllib.parse
        import binascii
        import html

        text = self.input_edit.toPlainText()
        if not text:
            self.resultReady.emit("提示", "请输入要编码的内容")
            return

        encode_type = self.encode_type_combo.currentIndex()
        type_names = ["Base64", "URL", "Hex", "ROT", "HTML实体", "Unicode"]

        try:
            if encode_type == 0:
                result = base64.b64encode(text.encode()).decode()
            elif encode_type == 1:
                result = urllib.parse.quote(text)
            elif encode_type == 2:
                result = binascii.hexlify(text.encode()).decode()
            elif encode_type == 3:
                offset = self.offset_spin.value()
                result = self._rot_decode(text, offset)
            elif encode_type == 4:
                result = html.escape(text)
            elif encode_type == 5:
                result = text.encode('unicode_escape').decode()
            else:
                result = text

            self.resultReady.emit(f"{type_names[encode_type]} 编码结果", result)
        except Exception as e:
            self.resultReady.emit("编码失败", str(e))

    def _rot_decode(self, text: str, offset: int) -> str:
        result = []
        for c in text:
            if 'a' <= c <= 'z':
                result.append(chr((ord(c) - ord('a') + offset) % 26 + ord('a')))
            elif 'A' <= c <= 'Z':
                result.append(chr((ord(c) - ord('A') + offset) % 26 + ord('A')))
            else:
                result.append(c)
        return ''.join(result)

    def _clearAll(self):
        self.input_edit.clear()


class ToolResultPanel(QWidget):
    """工具结果面板"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._setupUI()

    def _setupUI(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)

        # 标题
        self.title_label = QLabel("📋 结果输出")
        self.title_label.setStyleSheet("font-size: 18px; font-weight: bold; color: #1976D2;")
        layout.addWidget(self.title_label)

        # 结果类型标签
        self.type_label = QLabel("等待操作...")
        self.type_label.setStyleSheet("""
            color: #666;
            padding: 8px 12px;
            background-color: #F5F5F5;
            border-radius: 4px;
            font-size: 13px;
        """)
        layout.addWidget(self.type_label)

        # 结果内容
        self.result_edit = QPlainTextEdit()
        self.result_edit.setReadOnly(True)
        self.result_edit.setPlaceholderText("解密/解码结果将显示在这里...")
        self.result_edit.setStyleSheet("""
            background-color: #FAFAFA;
            border: 1px solid #E0E0E0;
            border-radius: 4px;
            font-family: Consolas, Monaco, monospace;
            font-size: 13px;
            padding: 10px;
        """)
        layout.addWidget(self.result_edit, stretch=1)

        # 底部按钮
        btn_layout = QHBoxLayout()

        copy_btn = QPushButton("📋 复制结果")
        copy_btn.setStyleSheet("""
            QPushButton {
                background-color: #1976D2;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 10px 24px;
            }
            QPushButton:hover { background-color: #1565C0; }
        """)
        copy_btn.clicked.connect(self._copyResult)
        btn_layout.addWidget(copy_btn)

        clear_btn = QPushButton("清空")
        clear_btn.setStyleSheet("""
            QPushButton {
                background-color: #9E9E9E;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 10px 24px;
            }
            QPushButton:hover { background-color: #757575; }
        """)
        clear_btn.clicked.connect(self._clearResult)
        btn_layout.addWidget(clear_btn)

        btn_layout.addStretch()
        layout.addLayout(btn_layout)

    def setResult(self, title: str, content: str):
        self.type_label.setText(title)

        # 根据标题设置不同样式
        if "失败" in title or "错误" in title:
            self.type_label.setStyleSheet("""
                color: #D32F2F;
                padding: 8px 12px;
                background-color: #FFEBEE;
                border-radius: 4px;
                border-left: 4px solid #D32F2F;
                font-size: 13px;
            """)
            self.result_edit.setStyleSheet("""
                background-color: #FFF8F8;
                border: 1px solid #FFCDD2;
                border-radius: 4px;
                font-family: Consolas, Monaco, monospace;
                font-size: 13px;
                padding: 10px;
            """)
        elif "成功" in title:
            self.type_label.setStyleSheet("""
                color: #388E3C;
                padding: 8px 12px;
                background-color: #E8F5E9;
                border-radius: 4px;
                border-left: 4px solid #388E3C;
                font-size: 13px;
            """)
            self.result_edit.setStyleSheet("""
                background-color: #F1F8E9;
                border: 1px solid #C8E6C9;
                border-radius: 4px;
                font-family: Consolas, Monaco, monospace;
                font-size: 13px;
                padding: 10px;
            """)
        else:
            self.type_label.setStyleSheet("""
                color: #1976D2;
                padding: 8px 12px;
                background-color: #E3F2FD;
                border-radius: 4px;
                border-left: 4px solid #1976D2;
                font-size: 13px;
            """)
            self.result_edit.setStyleSheet("""
                background-color: #FAFAFA;
                border: 1px solid #E0E0E0;
                border-radius: 4px;
                font-family: Consolas, Monaco, monospace;
                font-size: 13px;
                padding: 10px;
            """)

        self.result_edit.setPlainText(content)

    def _copyResult(self):
        text = self.result_edit.toPlainText()
        if text:
            QApplication.clipboard().setText(text)
            self.type_label.setText("已复制到剪贴板!")

    def _clearResult(self):
        self.result_edit.clear()
        self.type_label.setText("等待操作...")
        self.type_label.setStyleSheet("""
            color: #666;
            padding: 8px 12px;
            background-color: #F5F5F5;
            border-radius: 4px;
            font-size: 13px;
        """)


class FilePanelWidget(QWidget):
    """文件面板"""

    fileAdded = Signal(str)
    analyzeRequested = Signal(str)
    fileSelected = Signal(str)  # 文件被选中时发出信号

    def __init__(self, parent=None):
        super().__init__(parent)
        self._file_items: dict = {}  # file_path -> FileListItem
        self._selected_file: str = ""  # 当前选中的文件
        self._setupUI()

    def _setupUI(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)

        # 标题栏
        header = QHBoxLayout()
        title = QLabel("文件列表")
        title.setStyleSheet("font-size: 14px; font-weight: bold; color: #333;")
        header.addWidget(title)
        header.addStretch()

        # 导入按钮
        import_btn = QPushButton("+ 导入文件")
        import_btn.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 8px 16px;
                font-size: 12px;
            }
            QPushButton:hover {
                background-color: #43A047;
            }
        """)
        import_btn.clicked.connect(self._onImportFile)
        header.addWidget(import_btn)

        layout.addLayout(header)

        # 文件列表容器
        self.file_list_widget = QWidget()
        self.file_list_layout = QVBoxLayout(self.file_list_widget)
        self.file_list_layout.setContentsMargins(0, 0, 0, 0)
        self.file_list_layout.setSpacing(8)
        self.file_list_layout.addStretch()

        # 空状态提示
        self.empty_label = QLabel("暂无文件\n\n点击「导入文件」按钮添加PCAP文件")
        self.empty_label.setAlignment(Qt.AlignCenter)
        self.empty_label.setStyleSheet("color: #999; font-size: 13px;")
        self.file_list_layout.insertWidget(0, self.empty_label)

        from PySide6.QtWidgets import QScrollArea
        scroll = QScrollArea()
        scroll.setWidget(self.file_list_widget)
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("""
            QScrollArea {
                border: 1px solid #E0E0E0;
                border-radius: 8px;
                background-color: #FAFAFA;
            }
        """)
        layout.addWidget(scroll)

    def _onImportFile(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "打开PCAP文件", "",
            "PCAP文件 (*.pcap *.pcapng);;所有文件 (*.*)"
        )
        if file_path:
            self.addFile(file_path)
            self.fileAdded.emit(file_path)

    def addFile(self, file_path: str):
        if file_path in self._file_items:
            # 已存在，选中该文件
            self._selectFile(file_path)
            return

        # 隐藏空状态提示
        self.empty_label.hide()

        # 创建文件项
        item = FileListItem(file_path)
        item.analyzeClicked.connect(self.analyzeRequested.emit)
        item.itemClicked.connect(self._onFileItemClicked)

        # 插入到列表（在stretch之前）
        self.file_list_layout.insertWidget(self.file_list_layout.count() - 1, item)
        self._file_items[file_path] = item

        # 自动选中新添加的文件
        self._selectFile(file_path)

    def _onFileItemClicked(self, file_path: str):
        self._selectFile(file_path)

    def _selectFile(self, file_path: str):
        if self._selected_file and self._selected_file in self._file_items:
            self._file_items[self._selected_file].setSelected(False)

        # 设置新的选中状态
        self._selected_file = file_path
        if file_path in self._file_items:
            self._file_items[file_path].setSelected(True)

        # 发出信号
        self.fileSelected.emit(file_path)

    def getSelectedFile(self) -> str:
        return self._selected_file

    def getFileItem(self, file_path: str) -> Optional[FileListItem]:
        return self._file_items.get(file_path)


class AnalysisPanelWidget(QWidget):
    """分析面板，结果树 + 文件标签页"""

    itemSelected = Signal(object)
    fileTabChanged = Signal(str)
    fileTabClosed = Signal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._summaries: Dict[str, AnalysisSummary] = {}  # 存储所有分析结果
        self._setupUI()

    def _setupUI(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(5, 5, 5, 5)
        layout.setSpacing(5)

        # 文件标签栏
        from PySide6.QtWidgets import QTabBar
        self.file_tabs = QTabBar()
        self.file_tabs.setTabsClosable(True)
        self.file_tabs.setMovable(True)
        self.file_tabs.setExpanding(False)
        self.file_tabs.setStyleSheet("""
            QTabBar::tab {
                background-color: #F5F5F5;
                border: 1px solid #E0E0E0;
                border-bottom: none;
                padding: 8px 16px;
                margin-right: 2px;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
            }
            QTabBar::tab:selected {
                background-color: white;
                border-bottom: 2px solid #1976D2;
            }
            QTabBar::tab:hover {
                background-color: #E3F2FD;
            }
            QTabBar::close-button {
                image: url(none);
                subcontrol-position: right;
            }
            QTabBar::close-button:hover {
                background-color: #FFCDD2;
                border-radius: 2px;
            }
        """)
        self.file_tabs.currentChanged.connect(self._onTabChanged)
        self.file_tabs.tabCloseRequested.connect(self._onTabClose)
        self.file_tabs.hide()  # 初始隐藏，有多个文件时显示
        layout.addWidget(self.file_tabs)

        # 使用现有的TreePanel
        self.tree_panel = TreePanel()
        self.tree_panel.itemSelected.connect(self.itemSelected.emit)
        layout.addWidget(self.tree_panel)

    def addOrUpdateFile(self, file_path: str, summary: AnalysisSummary):
        file_name = os.path.basename(file_path)

        # 存储分析结果
        self._summaries[file_path] = summary

        # 查找是否已有此文件的标签
        tab_index = -1
        for i in range(self.file_tabs.count()):
            if self.file_tabs.tabData(i) == file_path:
                tab_index = i
                break

        if tab_index == -1:
            # 添加新标签
            tab_index = self.file_tabs.addTab(f"📄 {file_name}")
            self.file_tabs.setTabData(tab_index, file_path)
            self.file_tabs.setTabToolTip(tab_index, file_path)

        # 显示标签栏（至少有一个文件）
        if self.file_tabs.count() > 0:
            self.file_tabs.show()

        # 切换到此标签
        self.file_tabs.setCurrentIndex(tab_index)
        self.tree_panel.buildTree(summary)

    def _onTabChanged(self, index: int):
        if index < 0:
            return
        file_path = self.file_tabs.tabData(index)
        if file_path and file_path in self._summaries:
            self.tree_panel.buildTree(self._summaries[file_path])
        # 无论是否在 _summaries 中，都发出信号让 MainWindow 处理
        if file_path:
            self.fileTabChanged.emit(file_path)

    def _onTabClose(self, index: int):
        file_path = self.file_tabs.tabData(index)
        if file_path and file_path in self._summaries:
            del self._summaries[file_path]
            self.fileTabClosed.emit(file_path)  # 通知 MainWindow 同步删除
        self.file_tabs.removeTab(index)

        # 如果没有标签了，隐藏标签栏并清空树
        if self.file_tabs.count() == 0:
            self.file_tabs.hide()
            self.tree_panel.clear()

    def getCurrentFilePath(self) -> Optional[str]:
        index = self.file_tabs.currentIndex()
        if index >= 0:
            return self.file_tabs.tabData(index)
        return None

    def getCurrentSummary(self) -> Optional[AnalysisSummary]:
        file_path = self.getCurrentFilePath()
        if file_path:
            return self._summaries.get(file_path)
        return None

    def clear(self):
        self.tree_panel.clear()

    def addDetection(self, detection: DetectionResult):
        self.tree_panel.addDetection(detection)

    def addProtocolFinding(self, finding: ProtocolFinding):
        self.tree_panel.addProtocolFinding(finding)

    def addDecodingResult(self, result: AutoDecodingResult):
        self.tree_panel.addDecodingResult(result)

    def addFileRecovery(self, recovery: FileRecoveryResult):
        self.tree_panel.addFileRecovery(recovery)

    def addAttackDetection(self, attack: AttackDetectionInfo):
        self.tree_panel.addAttackDetection(attack)

    def buildTree(self, summary: AnalysisSummary):
        self.tree_panel.buildTree(summary)


class MainWindow(QMainWindow):

    def __init__(self, service: IAnalysisService = None):
        super().__init__()

        self.setWindowTitle("TingLan 听澜 - 流量分析工具")
        self.setMinimumSize(1200, 800)

        # 控制器（优先使用流式控制器）
        if USE_STREAM_CONTROLLER:
            self.analysis_controller = AnalysisController(self)
            logger.info("使用 StreamAnalysisController (流式分析)")
        else:
            self.analysis_controller = AnalysisController(self, service=service)
            logger.info("使用传统 AnalysisController")

        self.export_controller = ExportController(self)

        # 当前数据
        self._current_file: str = ""
        self._current_summary: Optional[AnalysisSummary] = None
        self._summaries: Dict[str, AnalysisSummary] = {}  # 多文件分析结果

        # 显示计数器 - 防止 UI 过载
        self._display_count = 0
        self._batch_update_pending = False

        # 进度平滑
        self._last_progress_percent = 0
        self._last_progress_time = 0.0
        self._progress_timer: Optional[QTimer] = None

        # 初始化UI
        self._setupUI()
        self._setupMenuBar()
        self._connectSignals()
        self._loadSettings()

        # 抑制表格反馈信号，防止双重调用 showPayload
        self._suppress_table_feedback = False

        # 树选择防抖定时器
        # 根因：快速点击不同检测项时，每次都同步执行 get_score_breakdown（100-500ms）
        # + WiresharkViewer重建（50-100ms），6次连续点击累计阻塞主线程3-5秒。
        # 防抖确保只处理最后一次点击，将6次昂贵操作降为1次。
        from PySide6.QtCore import QTimer as _QTimer
        self._tree_select_timer = _QTimer()
        self._tree_select_timer.setSingleShot(True)
        self._tree_select_timer.setInterval(80)  # 80ms 防抖，用户感知不到延迟
        self._tree_select_timer.timeout.connect(self._processTreeSelection)
        self._pending_tree_node = None

        # 初始化进度平滑定时器
        self._setup_progress_timer()

    def _setupUI(self):
        """设置主界面布局"""
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # 顶部功能栏
        self.function_bar = FunctionBar()
        main_layout.addWidget(self.function_bar)

        # 内容区域
        content_widget = QWidget()
        content_layout = QHBoxLayout(content_widget)
        content_layout.setContentsMargins(10, 10, 10, 10)
        content_layout.setSpacing(10)

        # 水平分割器
        splitter = QSplitter(Qt.Horizontal)

        # 展示区（左侧）
        self.blue_stack = QStackedWidget()
        self.blue_stack.setStyleSheet("""
            QStackedWidget {
                background-color: white;
                border: 1px solid #E0E0E0;
                border-radius: 8px;
            }
        """)

        # 文件面板 (index 0)
        self.file_panel = FilePanelWidget()
        self.blue_stack.addWidget(self.file_panel)

        # 分析面板 (index 1)
        self.analysis_panel = AnalysisPanelWidget()
        self.blue_stack.addWidget(self.analysis_panel)

        # 密钥管理面板 (index 2)
        self.keys_panel = KeyManagementPanel()
        self.blue_stack.addWidget(self.keys_panel)

        # 解码工具面板 (index 3)
        self.decode_panel = DecodeToolPanel()
        self.blue_stack.addWidget(self.decode_panel)

        splitter.addWidget(self.blue_stack)

        # 结果区（右侧）
        self.yellow_stack = QStackedWidget()
        self.yellow_stack.setStyleSheet("""
            QStackedWidget {
                background-color: white;
                border: 1px solid #E0E0E0;
                border-radius: 8px;
            }
        """)

        # 文件结果面板（饼图）
        self.protocol_stats_widget = ProtocolStatsWidget()
        self.yellow_stack.addWidget(self.protocol_stats_widget)

        # 分析结果面板（详情+载荷）
        self.analysis_result_panel = QWidget()
        analysis_result_layout = QVBoxLayout(self.analysis_result_panel)
        analysis_result_layout.setContentsMargins(0, 0, 0, 0)

        # 垂直分割器
        result_splitter = QSplitter(Qt.Vertical)

        # 上半：详情表格
        self.detail_table = DetailTable()
        result_splitter.addWidget(self.detail_table)

        # 下半：载荷查看器
        self.payload_viewer = PayloadViewer()
        result_splitter.addWidget(self.payload_viewer)

        result_splitter.setSizes([300, 300])
        analysis_result_layout.addWidget(result_splitter)

        self.yellow_stack.addWidget(self.analysis_result_panel)

        # 工具结果面板 (index 2) - 用于密钥管理和解码工具的输出
        self.tool_result_panel = ToolResultPanel()
        self.yellow_stack.addWidget(self.tool_result_panel)

        splitter.addWidget(self.yellow_stack)

        # 设置分割比例 4:6
        splitter.setSizes([400, 600])

        content_layout.addWidget(splitter)
        main_layout.addWidget(content_widget, stretch=1)

        # 状态栏
        self.status_bar = StatusBar()
        main_layout.addWidget(self.status_bar)

        # 设置整体样式
        self.setStyleSheet("""
            QMainWindow {
                background-color: #F5F5F5;
            }
            QSplitter::handle {
                background-color: #E0E0E0;
            }
            QSplitter::handle:horizontal {
                width: 2px;
            }
            QSplitter::handle:vertical {
                height: 2px;
            }
        """)

    def _setupMenuBar(self):
        """设置菜单栏"""
        menubar = self.menuBar()
        menubar.setStyleSheet("""
            QMenuBar {
                background-color: white;
                border-bottom: 1px solid #E0E0E0;
                padding: 2px;
            }
            QMenuBar::item {
                padding: 5px 10px;
                border-radius: 4px;
            }
            QMenuBar::item:selected {
                background-color: #E3F2FD;
            }
            QMenu {
                background-color: white;
                border: 1px solid #E0E0E0;
                border-radius: 4px;
                padding: 5px;
            }
            QMenu::item {
                padding: 8px 30px;
                border-radius: 4px;
            }
            QMenu::item:selected {
                background-color: #E3F2FD;
            }
        """)

        # 文件菜单
        file_menu = menubar.addMenu("文件(&F)")

        open_action = QAction("打开(&O)", self)
        open_action.setShortcut(QKeySequence.Open)
        open_action.triggered.connect(self._onOpenFile)
        file_menu.addAction(open_action)

        file_menu.addSeparator()

        self.export_action = QAction("导出(&E)", self)
        self.export_action.setShortcut("Ctrl+E")
        self.export_action.triggered.connect(self._onExport)
        self.export_action.setEnabled(False)
        file_menu.addAction(self.export_action)

        file_menu.addSeparator()

        exit_action = QAction("退出(&X)", self)
        exit_action.setShortcut(QKeySequence.Quit)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        # 帮助菜单
        help_menu = menubar.addMenu("帮助(&H)")
        about_action = QAction("关于(&A)", self)
        about_action.triggered.connect(self._showAbout)
        help_menu.addAction(about_action)

    def _connectSignals(self):
        """连接信号槽"""
        # 功能栏切换
        self.function_bar.functionChanged.connect(self._onFunctionChanged)

        # 文件面板
        self.file_panel.fileAdded.connect(self._onFileAdded)
        self.file_panel.analyzeRequested.connect(self._onAnalyzeRequested)
        self.file_panel.fileSelected.connect(self._onFileSelected)

        # 分析面板
        self.analysis_panel.itemSelected.connect(self._onTreeItemSelected)
        self.analysis_panel.fileTabChanged.connect(self._onFileTabChanged)
        self.analysis_panel.fileTabClosed.connect(self._onFileTabClosed)

        # 表格选择
        self.detail_table.itemSelected.connect(self._onTableItemSelected)

        # 密钥管理和解码工具 - 结果显示到右侧
        self.keys_panel.resultReady.connect(self.tool_result_panel.setResult)
        self.decode_panel.resultReady.connect(self.tool_result_panel.setResult)

        # 分析控制器信号
        self.analysis_controller.analysisStarted.connect(self._onAnalysisStarted)
        self.analysis_controller.analysisProgress.connect(self._onAnalysisProgress)

        # 检测结果信号：优先使用批量信号
        if hasattr(self.analysis_controller, 'batchDetectionsFound'):
            # 流式控制器：只连接批量信号
            self.analysis_controller.batchDetectionsFound.connect(self._onBatchResultsFound)
            logger.info("使用批量信号模式 (batchDetectionsFound)")
        else:
            # 传统控制器：使用单个信号
            self.analysis_controller.detectionFound.connect(self._onDetectionFound)
            logger.info("使用单个信号模式 (detectionFound)")

        self.analysis_controller.protocolFindingFound.connect(self._onProtocolFindingFound)
        self.analysis_controller.decodingResultFound.connect(self._onDecodingResultFound)
        self.analysis_controller.fileRecovered.connect(self._onFileRecovered)
        self.analysis_controller.analysisFinished.connect(self._onAnalysisFinished)
        self.analysis_controller.analysisError.connect(self._onAnalysisError)
        self.analysis_controller.analysisCancelled.connect(self._onAnalysisCancelled)

        # 导出控制器信号
        self.export_controller.exportFinished.connect(self._onExportFinished)
        self.export_controller.exportError.connect(self._onExportError)

    def _setup_progress_timer(self):
        """初始化进度平滑定时器"""
        self._progress_timer = QTimer(self)
        self._progress_timer.setInterval(UILimits.PROGRESS_SMOOTH_INTERVAL)
        self._progress_timer.timeout.connect(self._smooth_progress_update)

    def _smooth_progress_update(self):
        """进度平滑更新回调"""
        # 此定时器用于平滑进度条更新，避免跳跃
        pass  # 当前实现中进度由信号直接控制

    def _loadSettings(self):
        """加载设置"""
        settings = QSettings("TingLan", "TrafficAnalyzer")
        geometry = settings.value("geometry")
        if geometry:
            self.restoreGeometry(geometry)

    def _saveSettings(self):
        """保存设置"""
        settings = QSettings("TingLan", "TrafficAnalyzer")
        settings.setValue("geometry", self.saveGeometry())

    def closeEvent(self, event):
        """关闭时确保资源释放"""
        self._saveSettings()

        if self.analysis_controller.is_running:
            reply = QMessageBox.question(
                self, "确认退出",
                "分析正在进行中，确定要退出吗？",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No
            )
            if reply == QMessageBox.No:
                event.ignore()
                return
            self.analysis_controller.stopAnalysis()

        # 停止进度定时器
        if self._progress_timer:
            self._progress_timer.stop()

        event.accept()

    def _onFunctionChanged(self, function_name: str):
        """功能栏切换"""
        if function_name == "file":
            self.blue_stack.setCurrentIndex(0)
            self.yellow_stack.setCurrentIndex(0)
            self.status_bar.setStatus("当前功能: 文件")
        elif function_name == "analysis":
            self.blue_stack.setCurrentIndex(1)
            self.yellow_stack.setCurrentIndex(1)
            self.status_bar.setStatus("当前功能: 分析")
        elif function_name == "keys":
            self.blue_stack.setCurrentIndex(2)
            self.yellow_stack.setCurrentIndex(2)  # 显示工具结果面板
            self.status_bar.setStatus("当前功能: 密钥管理")
        elif function_name == "decode":
            self.blue_stack.setCurrentIndex(3)
            self.yellow_stack.setCurrentIndex(2)  # 显示工具结果面板
            self.status_bar.setStatus("当前功能: 解码工具")

    def _onFileTabChanged(self, file_path: str):
        """文件标签切换 - 更新饼图和详情表格"""
        logger.debug(f"_onFileTabChanged: file_path={file_path}")
        self._current_file = file_path

        # 优先从 MainWindow._summaries 获取
        summary = self._summaries.get(file_path)

        # 如果没有，尝试从 analysis_panel._summaries 获取
        if not summary:
            summary = self.analysis_panel._summaries.get(file_path)
            if summary:
                # 同步数据到 MainWindow._summaries
                self._summaries[file_path] = summary
                logger.debug(f"从 analysis_panel 同步 summary: {file_path}")

        if summary:
            self._current_summary = summary
            # 更新饼图（即使在"分析"功能下不可见，也要更新数据）
            total_attacks = len(summary.detections) + len(summary.attack_detections)
            summary_data = [
                ("攻击行为检测", total_attacks),
                ("协议分类", len(summary.protocol_stats)),
                ("协议分析", len(summary.protocol_findings)),
                ("自动解码", len(summary.decoding_results)),
                ("文件还原", len(summary.recovered_files)),
                ("文件提取", len(summary.extracted_files)),
            ]
            self.protocol_stats_widget.setData(summary_data)
            logger.debug(f"饼图已更新: {summary_data}")

            # 更新详情表格
            self.detail_table.showFromSummary(summary)
            # 更新载荷查看器（清空以避免显示旧数据）
            self.payload_viewer.clear()
            # 更新状态栏
            self.status_bar.setFileInfo(file_path)
            self.status_bar.setPacketCount(summary.total_packets)
            self.status_bar.setThreatCount(total_attacks)
        else:
            logger.warning(f"未找到 summary: {file_path}")

    def _onFileTabClosed(self, file_path: str):
        """文件标签关闭"""
        # 同步删除 MainWindow._summaries 中的数据
        if file_path in self._summaries:
            del self._summaries[file_path]

        # 如果关闭的是当前文件，清空相关显示
        if file_path == self._current_file:
            self._current_file = ""
            self._current_summary = None
            self.detail_table.clear()
            self.payload_viewer.clear()
            self.protocol_stats_widget.clear()

    def _onFileSelected(self, file_path: str):
        """文件被选中，更新饼图"""
        logger.debug(f"_onFileSelected: {file_path}")

        # 更新当前文件
        self._current_file = file_path

        # 获取该文件的分析结果
        summary = self._summaries.get(file_path)

        if summary:
            self._current_summary = summary

            # 更新饼图数据
            total_attacks = len(summary.detections) + len(summary.attack_detections)
            summary_data = [
                ("攻击行为检测", total_attacks),
                ("协议分类", len(summary.protocol_stats)),
                ("协议分析", len(summary.protocol_findings)),
                ("自动解码", len(summary.decoding_results)),
                ("文件还原", len(summary.recovered_files)),
                ("文件提取", len(summary.extracted_files)),
            ]
            self.protocol_stats_widget.setData(summary_data)

            # 更新状态栏
            self.status_bar.setFileInfo(file_path)
            self.status_bar.setPacketCount(summary.total_packets)
            self.status_bar.setThreatCount(total_attacks)

            logger.debug(f"饼图已更新为文件: {file_path}, 攻击数: {total_attacks}")
        else:
            # 文件尚未分析，显示空数据或提示
            self.protocol_stats_widget.clear()
            self.status_bar.setFileInfo(file_path)
            self.status_bar.setPacketCount(0)
            self.status_bar.setThreatCount(0)
            logger.debug(f"文件尚未分析: {file_path}")

    def _onOpenFile(self):
        """菜单-打开文件"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "打开PCAP文件", "",
            "PCAP文件 (*.pcap *.pcapng);;所有文件 (*.*)"
        )
        if file_path:
            self.file_panel.addFile(file_path)
            self._onFileAdded(file_path)

    def _onFileAdded(self, file_path: str):
        """文件添加后"""
        self._current_file = file_path
        filename = os.path.basename(file_path)
        self.setWindowTitle(f"TingLan 听澜 - {filename}")
        self.status_bar.setFileInfo(file_path)
        self.status_bar.setStatus(f"已添加文件: {filename}")

    def _onAnalyzeRequested(self, file_path: str):
        """请求分析文件"""
        self._current_file = file_path

        # 获取分析选项（包括引擎选择）
        engine = _get_engine_setting()
        options = {
            "engine": engine,
            "detect_webshell": True,
            "extract_images": True,
            "protocol_stats": True
        }

        self.status_bar.setStatus(f"使用 {engine} 引擎分析...")
        self.analysis_controller.startAnalysis(file_path, options)

    def _onAnalysisStarted(self):
        """分析开始，重置UI状态"""
        logger.debug("_onAnalysisStarted 被调用")

        # 重置显示计数器
        self._display_count = 0
        self._batch_update_pending = False
        self._last_progress_percent = 0
        self._last_progress_time = time.time()

        # 分析期间收集的结果，完成后一次性显示
        self._pending_detections: List[DetectionResult] = []

        item = self.file_panel.getFileItem(self._current_file)
        if item:
            item.setAnalyzing(True)

        self.analysis_panel.clear()
        self.detail_table.clear()
        self.payload_viewer.clear()
        self.status_bar.showProgress(True)

        logger.debug("_onAnalysisStarted 完成")

    def _onAnalysisProgress(self, percent: int, message: str):
        """进度更新，带平滑处理"""
        logger.debug(f"_onAnalysisProgress: {percent}% - {message}")

        current_time = time.time()

        # 进度平滑：避免进度条跳跃
        # 只有在进度增加或间隔超过阈值时才更新
        should_update = (
            percent >= 100 or
            percent > self._last_progress_percent or
            (current_time - self._last_progress_time) * 1000 >= UILimits.PROGRESS_SMOOTH_INTERVAL
        )

        if should_update:
            self._last_progress_percent = percent
            self._last_progress_time = current_time

            item = self.file_panel.getFileItem(self._current_file)
            if item:
                item.setProgress(percent, message)
            self.status_bar.setProgress(percent, message)

    def _onDetectionFound(self, detection: DetectionResult):
        """检测结果到达，检查显示上限"""
        # 检查显示上限
        if self._display_count >= UILimits.MAX_DISPLAY_ROWS:
            # 超过上限，只记录不显示
            if self._display_count == UILimits.MAX_DISPLAY_ROWS:
                self.status_bar.setStatus(f"显示上限 {UILimits.MAX_DISPLAY_ROWS} 条，后续结果仅记录")
            self._display_count += 1
            return

        self._display_count += 1
        self.analysis_panel.addDetection(detection)
        self.detail_table.addDetection(detection)

    def _onBatchResultsFound(self, results: List[DetectionResult]):
        """批量结果先收集，分析完后再统一更新UI"""
        logger.debug(f"_onBatchResultsFound: results={len(results)}")

        if not results:
            return

        # 分析期间只收集结果，不更新UI
        # UI更新会在 _onAnalysisFinished 中一次性完成
        if not hasattr(self, '_pending_detections'):
            self._pending_detections = []

        self._pending_detections.extend(results)
        self._display_count = len(self._pending_detections)

        # 只更新状态栏显示进度
        if self._display_count % 20 == 0:
            self.status_bar.setStatus(f"已检测到 {self._display_count} 个攻击行为...")

    def _batch_update_ui(self, detections: List[DetectionResult]):
        """
        已废弃 - 分析期间不再调用此方法
        UI更新在 _onAnalysisFinished 中一次性完成
        """
        pass

    def _onProtocolFindingFound(self, finding: ProtocolFinding):
        """发现协议分析结果"""
        self.analysis_panel.addProtocolFinding(finding)

    def _onDecodingResultFound(self, result: AutoDecodingResult):
        """发现自动解码结果"""
        self.analysis_panel.addDecodingResult(result)

    def _onFileRecovered(self, recovery: FileRecoveryResult):
        """发现文件还原结果"""
        self.analysis_panel.addFileRecovery(recovery)

    def _onAnalysisFinished(self, summary: AnalysisSummary):
        """分析完成，更新所有UI面板"""
        logger.debug(f"_onAnalysisFinished: detections={len(summary.detections)}")

        # 恢复 UI 状态
        self._restore_ui_state()

        self._current_summary = summary
        self._summaries[self._current_file] = summary

        item = self.file_panel.getFileItem(self._current_file)
        if item:
            # 显示置信度统计
            high_count = summary.high_confidence_count
            medium_count = summary.medium_confidence_count
            low_count = summary.low_confidence_count

            total_detections = len(summary.detections) + len(summary.attack_detections)
            display_note = ""
            if total_detections > UILimits.MAX_DISPLAY_ROWS:
                display_note = f" (显示 {UILimits.MAX_DISPLAY_ROWS})"

            item.setCompleted(
                True,
                f"检测到 {total_detections} 个攻击行为{display_note} (高:{high_count} 中:{medium_count} 低:{low_count})"
            )

        self.export_action.setEnabled(True)
        self.status_bar.showProgress(False)

        # 更新饼图 - 显示三大类汇总
        total_attacks = len(summary.detections) + len(summary.attack_detections)
        summary_data = [
            ("攻击行为检测", total_attacks),
            ("协议分类", len(summary.protocol_stats)),
            ("协议分析", len(summary.protocol_findings)),
            ("自动解码", len(summary.decoding_results)),
            ("文件还原", len(summary.recovered_files)),
            ("文件提取", len(summary.extracted_files)),
        ]
        self.protocol_stats_widget.setData(summary_data)

        # 更新分析面板（标签页管理）
        self.analysis_panel.addOrUpdateFile(self._current_file, summary)

        self.detail_table.showFromSummary(summary)

        # 更新状态栏
        self.status_bar.setStatus("分析完成")
        self.status_bar.setPacketCount(summary.total_packets)
        self.status_bar.setThreatCount(total_attacks)

        # 自动切换到分析视图
        self.function_bar._onButtonClicked("analysis")

        # 提示框显示置信度统计
        protocol_findings_text = ""
        if summary.protocol_findings:
            flag_count = sum(1 for f in summary.protocol_findings if f.is_flag)
            protocol_findings_text = (
                f"\n协议分析发现: {len(summary.protocol_findings)} 条"
                f"\n  - 疑似FLAG: {flag_count}"
            )

        decoding_text = ""
        if summary.decoding_results:
            flag_count = sum(1 for r in summary.decoding_results if r.flags_found)
            decoding_text = (
                f"\n自动解码结果: {len(summary.decoding_results)} 条"
                f"\n  - 发现FLAG: {flag_count}"
            )

        recovery_text = ""
        if summary.recovered_files:
            recovery_text = f"\n文件还原: {len(summary.recovered_files)} 个"

        extracted_text = ""
        if summary.extracted_files:
            extracted_text = f"\n文件提取: {len(summary.extracted_files)} 个"

        total_attacks = len(summary.detections) + len(summary.attack_detections)
        QMessageBox.information(
            self, "分析完成",
            f"分析完成!\n\n"
            f"总数据包: {summary.total_packets}\n"
            f"检测到攻击行为: {total_attacks} 条\n"
            f"  - 高置信度: {summary.high_confidence_count}\n"
            f"  - 中置信度: {summary.medium_confidence_count}\n"
            f"  - 低置信度: {summary.low_confidence_count}"
            f"{protocol_findings_text}"
            f"{decoding_text}"
            f"{recovery_text}"
            f"{extracted_text}\n"
            f"耗时: {summary.analysis_time:.2f} 秒"
        )

    def _onAnalysisError(self, error_msg: str):
        """分析出错，恢复UI并给出提示"""
        # 恢复 UI 状态
        self._restore_ui_state()

        item = self.file_panel.getFileItem(self._current_file)
        if item:
            item.setCompleted(False, "分析失败")

        self.status_bar.showProgress(False)
        self.status_bar.setStatus("分析失败")

        # 分析错误类型，给出详细提示
        detailed_msg = self._format_error_message(error_msg)

        QMessageBox.critical(self, "分析错误", detailed_msg)

    def _format_error_message(self, error_msg: str) -> str:
        """根据错误类型给出解决方案"""
        msg_lower = error_msg.lower()

        # TShark 未找到
        if "tshark" in msg_lower and ("未找到" in error_msg or "not found" in msg_lower):
            return (
                f"{error_msg}\n\n"
                "【解决方案】\n"
                "1. 安装 Wireshark: https://www.wireshark.org/download.html\n"
                "2. 确保安装时勾选 TShark 组件\n"
                "3. 或设置环境变量 WIRESHARK_PATH\n\n"
                "常见安装路径:\n"
                "• C:\\Program Files\\Wireshark\\\n"
                "• E:\\internet_safe\\wireshark\\"
            )

        # 权限不足
        if "权限" in error_msg or "permission" in msg_lower:
            return (
                f"{error_msg}\n\n"
                "【解决方案】\n"
                "1. 以管理员身份运行程序\n"
                "2. 检查 PCAP 文件是否被其他程序占用\n"
                "3. 确保有读取该文件的权限"
            )

        # 内存不足
        if "内存" in error_msg or "memory" in msg_lower:
            return (
                f"{error_msg}\n\n"
                "【解决方案】\n"
                "1. 关闭其他占用内存的程序\n"
                "2. 尝试分析较小的 PCAP 文件\n"
                "3. 增加系统虚拟内存"
            )

        # 文件格式错误
        if "capture file" in msg_lower or "not a valid" in msg_lower:
            return (
                f"{error_msg}\n\n"
                "【解决方案】\n"
                "1. 确认文件是有效的 PCAP/PCAPNG 格式\n"
                "2. 文件可能已损坏，尝试用 Wireshark 打开验证\n"
                "3. 检查文件是否完整传输"
            )

        # 默认
        return error_msg

    def _onAnalysisCancelled(self):
        """分析取消，恢复UI"""
        # 恢复 UI 状态
        self._restore_ui_state()

        item = self.file_panel.getFileItem(self._current_file)
        if item:
            item.setCompleted(False, "已取消")

        self.status_bar.showProgress(False)
        self.status_bar.setStatus("分析已取消")

    def _restore_ui_state(self):
        """确保错误或取消后UI回到可用状态"""
        try:
            # 确保 UI 更新已启用
            self.analysis_panel.setUpdatesEnabled(True)
            self.detail_table.setUpdatesEnabled(True)

            # 重置显示计数
            self._display_count = 0
            self._batch_update_pending = False

        except Exception as e:
            logger.warning(f"UI 状态恢复异常: {e}")

    def _onExport(self):
        """导出报告"""
        if not self._current_summary:
            QMessageBox.warning(self, "提示", "没有可导出的分析结果")
            return

        file_path, selected_filter = QFileDialog.getSaveFileName(
            self, "导出报告", "",
            "HTML报告 (*.html);;JSON数据 (*.json)"
        )
        if file_path:
            if "html" in selected_filter.lower():
                if not file_path.endswith(".html"):
                    file_path += ".html"
                self.export_controller.exportToHtml(self._current_summary, file_path)
            else:
                if not file_path.endswith(".json"):
                    file_path += ".json"
                self.export_controller.exportToJson(self._current_summary, file_path)

    def _onExportFinished(self, file_path: str):
        """导出完成"""
        reply = QMessageBox.information(
            self, "导出成功",
            f"报告已导出到:\n{file_path}\n\n是否打开文件?",
            QMessageBox.Yes | QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            import subprocess
            import platform
            if platform.system() == "Windows":
                os.startfile(file_path)
            elif platform.system() == "Darwin":
                subprocess.call(["open", file_path])
            else:
                subprocess.call(["xdg-open", file_path])

    def _onExportError(self, error_msg: str):
        """导出错误"""
        QMessageBox.critical(self, "导出失败", error_msg)

    def _onTreeItemSelected(self, node: TreeNode):
        """树节点选择变化 — 防抖处理，避免快速点击累积阻塞主线程"""
        self._pending_tree_node = node
        self._tree_select_timer.start()  # (重新)启动80ms定时器

    def _processTreeSelection(self):
        """防抖后实际处理树节点选择"""
        node = self._pending_tree_node
        if node is None:
            return
        self._pending_tree_node = None

        if node.payload:
            if isinstance(node.payload, DetectionResult):
                self._suppress_table_feedback = True
                self.detail_table.showDetection(node.payload)
                self._suppress_table_feedback = False
                self.payload_viewer.showPayload(node.payload)
            elif isinstance(node.payload, ExtractedFile):
                self.payload_viewer.showExtractedFile(node.payload)
            elif isinstance(node.payload, ProtocolFinding):
                self.payload_viewer.showProtocolFinding(node.payload)
            elif isinstance(node.payload, AutoDecodingResult):
                self.payload_viewer.showDecodingResult(node.payload)
            elif isinstance(node.payload, FileRecoveryResult):
                self.payload_viewer.showFileRecovery(node.payload)
            elif isinstance(node.payload, AttackDetectionInfo):
                self.payload_viewer.showAttackDetection(node.payload)

    def _onTableItemSelected(self, detection: DetectionResult):
        """表格行选择变化"""
        # 如果由 _onTreeItemSelected 触发的 showDetection → selectRow 引起，跳过
        if self._suppress_table_feedback:
            return
        self.payload_viewer.showPayload(detection)

    def _showAbout(self):
        """显示关于对话框"""
        stream_mode = "流式处理" if USE_STREAM_CONTROLLER else "传统模式"
        QMessageBox.about(
            self, "关于 TingLan 听澜",
            "<h3>TingLan 听澜</h3>"
            f"<p>版本: v1.0 ({stream_mode})</p>"
            "<p>CTF场景下的蓝队流量分析工具</p>"
            "<p><b>功能特性:</b></p>"
            "<ul>"
            "<li>Webshell流量检测 (蚁剑/菜刀/冰蝎/哥斯拉)</li>"
            "<li>OWASP攻击检测 (SQLi/XSS/RCE等)</li>"
            "<li>ICMP隐写分析</li>"
            "<li>自动解码与文件还原</li>"
            "<li>流式分析架构</li>"
            "</ul>"
            "<p><b>技术栈:</b></p>"
            "<ul>"
            "<li>PySide6 GUI框架</li>"
            "<li>TShark流式处理</li>"
            "<li>权重评分检测引擎</li>"
            "</ul>"
            "<p>C404_TL</p>"
        )
