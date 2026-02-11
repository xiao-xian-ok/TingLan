# 设置对话框

from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QCheckBox, QGroupBox, QComboBox, QSpinBox, QTabWidget, QWidget
)
from PySide6.QtCore import Qt, QSettings


class SettingsDialog(QDialog):
    """设置对话框"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("设置")
        self.setFixedSize(500, 400)
        self.setModal(True)

        self._setupUI()
        self._loadSettings()

    def _setupUI(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(15)
        layout.setContentsMargins(20, 20, 20, 20)

        # 标签页
        tab_widget = QTabWidget()

        # 分析设置
        analysis_tab = self._createAnalysisTab()
        tab_widget.addTab(analysis_tab, "分析")

        # 显示设置
        display_tab = self._createDisplayTab()
        tab_widget.addTab(display_tab, "显示")

        layout.addWidget(tab_widget)

        # 按钮
        button_layout = QHBoxLayout()
        button_layout.addStretch()

        cancel_btn = QPushButton("取消")
        cancel_btn.setProperty("secondary", True)
        cancel_btn.setFixedWidth(80)
        cancel_btn.clicked.connect(self.reject)
        button_layout.addWidget(cancel_btn)

        save_btn = QPushButton("保存")
        save_btn.setFixedWidth(80)
        save_btn.clicked.connect(self._saveSettings)
        button_layout.addWidget(save_btn)

        layout.addLayout(button_layout)

        # 样式
        self.setStyleSheet("""
            QDialog {
                background-color: #FFFFFF;
            }
            QTabWidget::pane {
                border: 1px solid #E0E0E0;
                border-radius: 6px;
                background-color: #FFFFFF;
            }
            QTabBar::tab {
                padding: 10px 20px;
                background-color: #F5F5F5;
                border: none;
            }
            QTabBar::tab:selected {
                background-color: #FFFFFF;
                border-bottom: 2px solid #1976D2;
            }
            QGroupBox {
                font-weight: bold;
                border: 1px solid #E0E0E0;
                border-radius: 6px;
                margin-top: 10px;
                padding-top: 10px;
            }
            QCheckBox {
                padding: 5px;
            }
            QComboBox, QSpinBox {
                padding: 6px;
                border: 1px solid #E0E0E0;
                border-radius: 4px;
            }
            QPushButton {
                padding: 8px 16px;
                border: none;
                border-radius: 4px;
                background-color: #1976D2;
                color: white;
            }
            QPushButton:hover {
                background-color: #1565C0;
            }
            QPushButton[secondary="true"] {
                background-color: transparent;
                color: #1976D2;
                border: 1px solid #1976D2;
            }
        """)

    def _createAnalysisTab(self) -> QWidget:
        """创建分析设置标签页"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setSpacing(15)

        # 分析引擎选择（新增）
        engine_group = QGroupBox("分析引擎")
        engine_layout = QVBoxLayout(engine_group)

        engine_row = QHBoxLayout()
        engine_row.addWidget(QLabel("分析引擎:"))
        self.engine_combo = QComboBox()
        self.engine_combo.addItems(["pyshark (功能完整)", "tshark (高性能)"])
        self.engine_combo.setToolTip(
            "pyshark: 功能完整，支持更多协议细节分析\n"
            "tshark: 高性能流式处理，适合大文件，速度更快"
        )
        engine_row.addWidget(self.engine_combo)
        engine_row.addStretch()
        engine_layout.addLayout(engine_row)

        engine_note = QLabel("提示：tshark 模式处理速度可提升 50-100 倍")
        engine_note.setStyleSheet("color: #666; font-size: 11px; font-style: italic;")
        engine_layout.addWidget(engine_note)

        layout.addWidget(engine_group)

        # 检测选项
        detect_group = QGroupBox("检测选项")
        detect_layout = QVBoxLayout(detect_group)

        self.detect_antsword = QCheckBox("检测蚁剑 (AntSword)")
        self.detect_antsword.setChecked(True)
        detect_layout.addWidget(self.detect_antsword)

        self.detect_caidao = QCheckBox("检测菜刀 (Caidao)")
        self.detect_caidao.setChecked(True)
        detect_layout.addWidget(self.detect_caidao)

        self.extract_images = QCheckBox("提取HTTP传输的图片")
        self.extract_images.setChecked(True)
        detect_layout.addWidget(self.extract_images)

        layout.addWidget(detect_group)

        # 性能选项
        perf_group = QGroupBox("性能")
        perf_layout = QHBoxLayout(perf_group)

        perf_layout.addWidget(QLabel("最大数据包数:"))
        self.max_packets = QSpinBox()
        self.max_packets.setRange(0, 1000000)
        self.max_packets.setValue(0)
        self.max_packets.setSpecialValueText("无限制")
        perf_layout.addWidget(self.max_packets)

        perf_layout.addStretch()

        layout.addWidget(perf_group)

        layout.addStretch()

        return widget

    def _createDisplayTab(self) -> QWidget:
        """创建显示设置标签页"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setSpacing(15)

        # 主题
        theme_group = QGroupBox("主题")
        theme_layout = QHBoxLayout(theme_group)

        theme_layout.addWidget(QLabel("界面主题:"))
        self.theme_combo = QComboBox()
        self.theme_combo.addItems(["浅色", "深色", "跟随系统"])
        theme_layout.addWidget(self.theme_combo)

        theme_layout.addStretch()

        layout.addWidget(theme_group)

        # 显示选项
        display_group = QGroupBox("显示选项")
        display_layout = QVBoxLayout(display_group)

        self.show_packet_count = QCheckBox("状态栏显示数据包计数")
        self.show_packet_count.setChecked(True)
        display_layout.addWidget(self.show_packet_count)

        self.auto_expand_tree = QCheckBox("自动展开分析结果树")
        self.auto_expand_tree.setChecked(True)
        display_layout.addWidget(self.auto_expand_tree)

        layout.addWidget(display_group)

        layout.addStretch()

        return widget

    def _loadSettings(self):
        """加载设置"""
        settings = QSettings("TingLan", "TrafficAnalyzer")

        # 引擎选择
        engine_index = settings.value("engine", 0, int)
        self.engine_combo.setCurrentIndex(engine_index)

        self.detect_antsword.setChecked(settings.value("detect_antsword", True, bool))
        self.detect_caidao.setChecked(settings.value("detect_caidao", True, bool))
        self.extract_images.setChecked(settings.value("extract_images", True, bool))
        self.max_packets.setValue(settings.value("max_packets", 0, int))

        self.theme_combo.setCurrentIndex(settings.value("theme", 0, int))
        self.show_packet_count.setChecked(settings.value("show_packet_count", True, bool))
        self.auto_expand_tree.setChecked(settings.value("auto_expand_tree", True, bool))

    def _saveSettings(self):
        """保存设置"""
        settings = QSettings("TingLan", "TrafficAnalyzer")

        # 引擎选择
        settings.setValue("engine", self.engine_combo.currentIndex())

        settings.setValue("detect_antsword", self.detect_antsword.isChecked())
        settings.setValue("detect_caidao", self.detect_caidao.isChecked())
        settings.setValue("extract_images", self.extract_images.isChecked())
        settings.setValue("max_packets", self.max_packets.value())

        settings.setValue("theme", self.theme_combo.currentIndex())
        settings.setValue("show_packet_count", self.show_packet_count.isChecked())
        settings.setValue("auto_expand_tree", self.auto_expand_tree.isChecked())

        self.accept()

    def getEngine(self) -> str:
        """获取选择的引擎"""
        return "tshark" if self.engine_combo.currentIndex() == 1 else "pyshark"
