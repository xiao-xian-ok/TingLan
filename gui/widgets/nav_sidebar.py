# 侧边导航栏

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QPushButton, QButtonGroup, QLabel, QFrame
)
from PySide6.QtCore import Signal, Qt, QSize
from PySide6.QtGui import QIcon, QFont


class NavButton(QPushButton):
    """导航按钮"""

    def __init__(self, text: str, icon_text: str = "", parent=None):
        super().__init__(parent)
        self.setText(text)
        self.setCheckable(True)
        self.setFixedHeight(60)
        self.setMinimumWidth(70)

        # 设置图标文字(使用emoji作为临时图标)
        self._icon_text = icon_text
        self._text = text

        # 样式
        self.setStyleSheet("""
            QPushButton {
                background-color: transparent;
                border: none;
                border-radius: 8px;
                padding: 8px;
                color: #666;
                font-size: 11px;
                text-align: center;
            }
            QPushButton:hover {
                background-color: #E3F2FD;
                color: #1976D2;
            }
            QPushButton:checked {
                background-color: #1976D2;
                color: white;
            }
        """)

    def paintEvent(self, event):
        from PySide6.QtGui import QPainter, QColor
        from PySide6.QtCore import QRect

        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)

        # 背景
        if self.isChecked():
            painter.fillRect(self.rect(), QColor("#1976D2"))
        elif self.underMouse():
            painter.fillRect(self.rect(), QColor("#E3F2FD"))

        # 图标文字
        icon_font = QFont("Segoe UI Emoji", 20)
        painter.setFont(icon_font)
        if self.isChecked():
            painter.setPen(QColor("white"))
        else:
            painter.setPen(QColor("#666"))

        icon_rect = QRect(0, 8, self.width(), 30)
        painter.drawText(icon_rect, Qt.AlignCenter, self._icon_text)

        # 文字标签
        text_font = QFont("Microsoft YaHei", 9)
        painter.setFont(text_font)
        text_rect = QRect(0, 38, self.width(), 20)
        painter.drawText(text_rect, Qt.AlignCenter, self._text)

        painter.end()


class NavSidebar(QWidget):
    """左侧导航侧边栏"""

    moduleChanged = Signal(str)  # 模块切换信号

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("navSidebar")
        self.setFixedWidth(80)

        self._setupUI()

    def _setupUI(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(5, 10, 5, 10)
        layout.setSpacing(5)

        # Logo区域
        logo_label = QLabel("听澜")
        logo_label.setAlignment(Qt.AlignCenter)
        logo_label.setStyleSheet("""
            QLabel {
                font-size: 16px;
                font-weight: bold;
                color: #1976D2;
                padding: 10px 0;
            }
        """)
        layout.addWidget(logo_label)

        # 分隔线
        line = QFrame()
        line.setFrameShape(QFrame.HLine)
        line.setStyleSheet("background-color: #E0E0E0;")
        layout.addWidget(line)

        layout.addSpacing(10)

        # 按钮组
        self.button_group = QButtonGroup(self)
        self.button_group.setExclusive(True)

        # 导航项 (图标使用emoji临时替代)
        nav_items = [
            ("分析", "🛡️", "analysis"),
            ("协议", "📊", "protocol"),
            ("提取", "📁", "extract"),
            ("统计", "📈", "statistics"),
            ("导出", "📤", "export"),
        ]

        self.buttons = {}
        for text, icon, name in nav_items:
            btn = NavButton(text, icon)
            btn.setProperty("moduleName", name)
            btn.clicked.connect(lambda checked, n=name: self._onButtonClicked(n))
            self.button_group.addButton(btn)
            self.buttons[name] = btn
            layout.addWidget(btn)

        layout.addStretch()

        # 设置按钮
        settings_btn = NavButton("设置", "⚙️")
        settings_btn.setProperty("moduleName", "settings")
        settings_btn.clicked.connect(lambda checked, n="settings": self._onButtonClicked(n))
        layout.addWidget(settings_btn)

        # 默认选中分析模块
        self.buttons["analysis"].setChecked(True)

        # 整体样式
        self.setStyleSheet("""
            #navSidebar {
                background-color: #FAFAFA;
                border-right: 1px solid #E0E0E0;
            }
        """)

    def _onButtonClicked(self, module_name: str):
        self.moduleChanged.emit(module_name)

    def setCurrentModule(self, module_name: str):
        """设置当前选中的模块"""
        if module_name in self.buttons:
            self.buttons[module_name].setChecked(True)
