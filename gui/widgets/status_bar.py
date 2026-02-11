# 状态栏

import time

from PySide6.QtWidgets import (
    QWidget, QHBoxLayout, QLabel, QProgressBar, QFrame
)
from PySide6.QtCore import Qt


class StatusBar(QWidget):
    """自定义状态栏"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedHeight(30)

        # 进度更新节流（防止频繁刷新UI）
        self._last_update_time = 0
        self._update_interval = 0.05  # 50ms 最小间隔
        self._last_progress_value = -1

        self._setupUI()

    def _setupUI(self):
        layout = QHBoxLayout(self)
        layout.setContentsMargins(10, 0, 10, 0)
        layout.setSpacing(15)

        # 状态消息
        self.status_label = QLabel("就绪")
        self.status_label.setStyleSheet("color: #666; font-size: 12px;")
        layout.addWidget(self.status_label)

        # 分隔符
        layout.addWidget(self._createSeparator())

        # 文件信息
        self.file_label = QLabel("")
        self.file_label.setStyleSheet("color: #666; font-size: 12px;")
        layout.addWidget(self.file_label)

        # 分隔符
        layout.addWidget(self._createSeparator())

        # 数据包计数
        self.packet_label = QLabel("")
        self.packet_label.setStyleSheet("color: #666; font-size: 12px;")
        layout.addWidget(self.packet_label)

        # 分隔符
        layout.addWidget(self._createSeparator())

        # 威胁计数
        self.threat_label = QLabel("")
        self.threat_label.setStyleSheet("color: #F44336; font-size: 12px; font-weight: bold;")
        layout.addWidget(self.threat_label)

        layout.addStretch()

        # 进度条
        self.progress_bar = QProgressBar()
        self.progress_bar.setFixedWidth(150)
        self.progress_bar.setFixedHeight(16)
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: 1px solid #E0E0E0;
                border-radius: 4px;
                background-color: #F5F5F5;
                text-align: center;
                font-size: 10px;
                color: #666;
            }
            QProgressBar::chunk {
                background-color: #1976D2;
                border-radius: 3px;
            }
        """)
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)

        # 整体样式
        self.setStyleSheet("""
            StatusBar {
                background-color: #FAFAFA;
                border-top: 1px solid #E0E0E0;
            }
        """)

    def _createSeparator(self) -> QFrame:
        """创建分隔符"""
        sep = QFrame()
        sep.setFrameShape(QFrame.VLine)
        sep.setStyleSheet("background-color: #E0E0E0;")
        sep.setFixedWidth(1)
        sep.setFixedHeight(16)
        return sep

    def setStatus(self, message: str):
        """设置状态消息"""
        self.status_label.setText(message)

    def setFileInfo(self, file_path: str):
        """设置文件信息"""
        import os
        if file_path:
            filename = os.path.basename(file_path)
            self.file_label.setText(f"文件: {filename}")
        else:
            self.file_label.setText("")

    def setPacketCount(self, count: int):
        """设置数据包计数"""
        if count > 0:
            self.packet_label.setText(f"数据包: {count:,}")
        else:
            self.packet_label.setText("")

    def setThreatCount(self, count: int):
        """设置攻击行为计数"""
        if count > 0:
            self.threat_label.setText(f"攻击: {count}")
        else:
            self.threat_label.setText("")

    def showProgress(self, visible: bool = True):
        """显示/隐藏进度条"""
        self.progress_bar.setVisible(visible)

    def setProgress(self, value: int, message: str = ""):
        """设置进度（带节流，防止频繁刷新UI）"""
        current_time = time.time()

        # 跳过过于频繁的更新（除非是关键节点：0%、100%、值变化≥5%）
        is_key_value = value == 0 or value == 100 or abs(value - self._last_progress_value) >= 5
        if not is_key_value and (current_time - self._last_update_time) < self._update_interval:
            return

        self._last_update_time = current_time
        self._last_progress_value = value
        self.progress_bar.setValue(value)
        if message:
            self.setStatus(message)

    def reset(self):
        """重置状态栏"""
        self.status_label.setText("就绪")
        self.file_label.setText("")
        self.packet_label.setText("")
        self.threat_label.setText("")
        self.progress_bar.setValue(0)
        self.progress_bar.setVisible(False)
        # 重置节流状态
        self._last_update_time = 0
        self._last_progress_value = -1
