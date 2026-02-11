# 导出对话框

from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QRadioButton, QButtonGroup, QLineEdit, QFileDialog, QGroupBox
)
from PySide6.QtCore import Qt


class ExportDialog(QDialog):
    """导出对话框"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("导出报告")
        self.setFixedSize(450, 280)
        self.setModal(True)

        self._output_path = ""
        self._export_format = "html"

        self._setupUI()

    def _setupUI(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(15)
        layout.setContentsMargins(20, 20, 20, 20)

        # 格式选择
        format_group = QGroupBox("导出格式")
        format_layout = QVBoxLayout(format_group)

        self.format_button_group = QButtonGroup(self)

        self.html_radio = QRadioButton("HTML报告 - 可在浏览器中查看，包含样式")
        self.html_radio.setChecked(True)
        self.format_button_group.addButton(self.html_radio)
        format_layout.addWidget(self.html_radio)

        self.json_radio = QRadioButton("JSON数据 - 结构化数据，便于程序处理")
        self.format_button_group.addButton(self.json_radio)
        format_layout.addWidget(self.json_radio)

        layout.addWidget(format_group)

        # 输出路径
        path_group = QGroupBox("输出位置")
        path_layout = QHBoxLayout(path_group)

        self.path_input = QLineEdit()
        self.path_input.setPlaceholderText("选择保存位置...")
        self.path_input.setReadOnly(True)
        path_layout.addWidget(self.path_input)

        browse_btn = QPushButton("浏览...")
        browse_btn.setFixedWidth(80)
        browse_btn.clicked.connect(self._browsePath)
        path_layout.addWidget(browse_btn)

        layout.addWidget(path_group)

        layout.addStretch()

        # 按钮
        button_layout = QHBoxLayout()
        button_layout.addStretch()

        cancel_btn = QPushButton("取消")
        cancel_btn.setProperty("secondary", True)
        cancel_btn.setFixedWidth(80)
        cancel_btn.clicked.connect(self.reject)
        button_layout.addWidget(cancel_btn)

        self.export_btn = QPushButton("导出")
        self.export_btn.setFixedWidth(80)
        self.export_btn.clicked.connect(self.accept)
        self.export_btn.setEnabled(False)
        button_layout.addWidget(self.export_btn)

        layout.addLayout(button_layout)

        # 样式
        self.setStyleSheet("""
            QDialog {
                background-color: #FFFFFF;
            }
            QGroupBox {
                font-weight: bold;
                border: 1px solid #E0E0E0;
                border-radius: 6px;
                margin-top: 10px;
                padding-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                subcontrol-position: top left;
                padding: 0 5px;
            }
            QRadioButton {
                padding: 5px;
            }
            QLineEdit {
                padding: 8px;
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
            QPushButton[secondary="true"]:hover {
                background-color: #E3F2FD;
            }
            QPushButton:disabled {
                background-color: #BDBDBD;
            }
        """)

    def _browsePath(self):
        """浏览保存路径"""
        if self.html_radio.isChecked():
            filter_str = "HTML文件 (*.html)"
            default_ext = ".html"
        else:
            filter_str = "JSON文件 (*.json)"
            default_ext = ".json"

        file_path, _ = QFileDialog.getSaveFileName(
            self, "选择保存位置", "", filter_str
        )

        if file_path:
            if not file_path.endswith(default_ext):
                file_path += default_ext
            self._output_path = file_path
            self.path_input.setText(file_path)
            self.export_btn.setEnabled(True)

    @property
    def output_path(self) -> str:
        return self._output_path

    @property
    def export_format(self) -> str:
        return "html" if self.html_radio.isChecked() else "json"
