# detail_table.py - 详情表格

from typing import List, Optional
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTableView, QLineEdit,
    QLabel, QPushButton, QComboBox, QHeaderView, QAbstractItemView
)
from PySide6.QtCore import Signal, Qt, QSortFilterProxyModel

from models.table_model import DetectionTableModel, DetectionFilterProxyModel
from models.detection_result import DetectionResult, AnalysisSummary


class DetailTable(QWidget):
    """详情表格"""

    itemSelected = Signal(object)  # 选中行变化信号，传递DetectionResult

    def __init__(self, parent=None):
        super().__init__(parent)
        self._setupUI()
        self._setupModel()

    def _setupUI(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)

        # 工具栏
        toolbar = QHBoxLayout()
        toolbar.setContentsMargins(10, 10, 10, 5)

        # 标题
        title = QLabel("检测详情")
        title.setStyleSheet("""
            QLabel {
                font-size: 14px;
                font-weight: bold;
                color: #333;
            }
        """)
        toolbar.addWidget(title)

        toolbar.addStretch()

        # 过滤输入框
        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("过滤...")
        self.filter_input.setFixedWidth(180)
        self.filter_input.setClearButtonEnabled(True)
        self.filter_input.setStyleSheet("""
            QLineEdit {
                padding: 6px 10px;
                border: 1px solid #E0E0E0;
                border-radius: 4px;
                background-color: white;
            }
            QLineEdit:focus {
                border-color: #1976D2;
            }
        """)
        self.filter_input.textChanged.connect(self._onFilterTextChanged)
        toolbar.addWidget(self.filter_input)

        # 类型过滤下拉框
        self.type_filter = QComboBox()
        self.type_filter.addItems([
            "全部类型", "蚁剑", "菜刀", "冰蝎", "哥斯拉",
            "── OWASP ──",
            "文件上传", "SQL注入", "XSS", "RCE", "XXE", "SSRF", "目录穿越", "命令注入", "反序列化"
        ])
        self.type_filter.setStyleSheet("""
            QComboBox {
                padding: 6px 10px;
                border: 1px solid #E0E0E0;
                border-radius: 4px;
                background-color: white;
                min-width: 90px;
            }
            QComboBox:focus {
                border-color: #1976D2;
            }
            QComboBox::drop-down {
                border: none;
                width: 20px;
            }
        """)
        self.type_filter.currentIndexChanged.connect(self._onTypeFilterChanged)
        toolbar.addWidget(self.type_filter)

        # 置信度过滤下拉框
        self.confidence_filter = QComboBox()
        self.confidence_filter.addItems(["全部置信度", "高置信度", "中置信度", "低置信度"])
        self.confidence_filter.setStyleSheet("""
            QComboBox {
                padding: 6px 10px;
                border: 1px solid #E0E0E0;
                border-radius: 4px;
                background-color: white;
                min-width: 100px;
            }
            QComboBox:focus {
                border-color: #1976D2;
            }
            QComboBox::drop-down {
                border: none;
                width: 20px;
            }
        """)
        self.confidence_filter.currentIndexChanged.connect(self._onConfidenceFilterChanged)
        toolbar.addWidget(self.confidence_filter)

        layout.addLayout(toolbar)

        # 表格视图
        self.table_view = QTableView()
        self.table_view.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table_view.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table_view.setAlternatingRowColors(True)
        self.table_view.setSortingEnabled(True)
        self.table_view.setShowGrid(False)
        self.table_view.verticalHeader().setVisible(False)

        # 设置列宽
        header = self.table_view.horizontalHeader()
        header.setStretchLastSection(True)
        header.setSectionResizeMode(QHeaderView.Interactive)
        header.setDefaultSectionSize(120)

        self.table_view.setStyleSheet("""
            QTableView {
                background-color: white;
                border: 1px solid #E0E0E0;
                border-radius: 6px;
                outline: none;
                gridline-color: transparent;
            }
            QTableView::item {
                padding: 8px;
                border-bottom: 1px solid #F0F0F0;
            }
            QTableView::item:hover {
                background-color: #E3F2FD;
            }
            QTableView::item:selected {
                background-color: #1976D2;
                color: white;
            }
            QHeaderView::section {
                background-color: #F5F5F5;
                padding: 10px;
                border: none;
                border-bottom: 2px solid #1976D2;
                font-weight: bold;
                color: #333;
            }
        """)

        layout.addWidget(self.table_view)

        # 底部状态
        bottom_layout = QHBoxLayout()
        bottom_layout.setContentsMargins(10, 5, 10, 10)

        self.count_label = QLabel("共 0 条记录")
        self.count_label.setStyleSheet("color: #666; font-size: 12px;")
        bottom_layout.addWidget(self.count_label)

        # 置信度统计标签
        self.stats_label = QLabel("")
        self.stats_label.setStyleSheet("color: #666; font-size: 12px;")
        bottom_layout.addWidget(self.stats_label)

        bottom_layout.addStretch()

        layout.addLayout(bottom_layout)

    def _setupModel(self):
        self.source_model = DetectionTableModel(self)
        self.proxy_model = DetectionFilterProxyModel(self)
        self.proxy_model.setSourceModel(self.source_model)
        self.table_view.setModel(self.proxy_model)

        # 连接选择变化信号
        self.table_view.selectionModel().currentRowChanged.connect(self._onSelectionChanged)

    def setDetections(self, detections: List[DetectionResult]):
        """
        设置检测结果列表

        参数:
            detections: DetectionResult对象列表
        """
        self.source_model.setDetections(detections)
        self._updateCount()
        self._updateStats(detections)

    def showDetection(self, detection: DetectionResult):
        """显示单条检测结果（高亮选中）"""
        # 临时阻塞选择信号，避免 selectRow 触发 _onSelectionChanged
        selection_model = self.table_view.selectionModel()
        selection_model.blockSignals(True)
        try:
            for row in range(self.source_model.rowCount()):
                if self.source_model.getDetection(row) is detection:
                    proxy_index = self.proxy_model.mapFromSource(
                        self.source_model.index(row, 0)
                    )
                    if proxy_index.isValid():
                        self.table_view.selectRow(proxy_index.row())
                    break
        finally:
            selection_model.blockSignals(False)

    def showFromSummary(self, summary: AnalysisSummary):
        """从分析摘要显示检测结果"""
        self.setDetections(summary.detections)

        # 更新置信度统计
        self.stats_label.setText(
            f"高: {summary.high_confidence_count} | "
            f"中: {summary.medium_confidence_count} | "
            f"低: {summary.low_confidence_count}"
        )

    def addDetection(self, detection: DetectionResult):
        """添加单条检测结果"""
        self.source_model.addDetection(detection)
        # 改为批量更新后再 _updateCount

    def addDetectionBatch(self, detections: list):
        """批量添加，只触发一次UI更新"""
        if hasattr(self.source_model, 'addDetectionBatch'):
            self.source_model.addDetectionBatch(detections)
        else:
            for detection in detections:
                self.source_model.addDetection(detection)
        self._updateCount()

    def clear(self):
        """清空表格"""
        self.source_model.clear()
        self._updateCount()
        self.stats_label.setText("")

    def _onFilterTextChanged(self, text: str):
        """过滤文本变化"""
        self.proxy_model.setFilterText(text)
        self._updateCount()

    def _onTypeFilterChanged(self, index: int):
        """类型过滤变化"""
        type_map = {
            0: [],  # 全部
            1: ["antsword"],
            2: ["caidao"],
            3: ["behinder"],
            4: ["godzilla"],
            5: [],  # 分隔符 (不过滤)
            6: ["file_upload"],
            7: ["sqli"],
            8: ["xss"],
            9: ["rce"],
            10: ["xxe"],
            11: ["ssrf"],
            12: ["path_traversal"],
            13: ["command_injection"],
            14: ["deserialization"]
        }
        self.proxy_model.setFilterTypes(type_map.get(index, []))
        self._updateCount()

    def _onConfidenceFilterChanged(self, index: int):
        """
        置信度过滤变化

        参数:
            index: 下拉框选中索引
                0 - 全部
                1 - 高置信度
                2 - 中置信度
                3 - 低置信度
        """
        level_map = {
            0: [],  # 全部
            1: ["high"],
            2: ["medium"],
            3: ["low"]
        }
        self.proxy_model.setFilterLevels(level_map.get(index, []))
        self._updateCount()

    def _onSelectionChanged(self, current, previous):
        """选择变化处理"""
        if current.isValid():
            source_index = self.proxy_model.mapToSource(current)
            detection = self.source_model.getDetection(source_index.row())
            if detection:
                self.itemSelected.emit(detection)

    def _updateCount(self):
        """更新计数标签"""
        total = self.source_model.rowCount()
        filtered = self.proxy_model.rowCount()
        if total == filtered:
            self.count_label.setText(f"共 {total} 条记录")
        else:
            self.count_label.setText(f"显示 {filtered}/{total} 条记录")

    def _updateStats(self, detections: List[DetectionResult]):
        """
        更新置信度统计

        参数:
            detections: 检测结果列表
        """
        high_count = sum(1 for d in detections if d.confidence == "high")
        medium_count = sum(1 for d in detections if d.confidence == "medium")
        low_count = sum(1 for d in detections if d.confidence == "low")
        self.stats_label.setText(
            f"高: {high_count} | 中: {medium_count} | 低: {low_count}"
        )
