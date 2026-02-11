# tree_panel.py - 检测结果树

from typing import Optional
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QTreeView, QLineEdit, QLabel, QHBoxLayout, QHeaderView
)
from PySide6.QtCore import Signal, Qt, QModelIndex, QSortFilterProxyModel, QTimer
from PySide6.QtGui import QFont

from models.tree_model import AnalysisTreeModel, TreeNode
from models.detection_result import (
    AnalysisSummary, DetectionResult, ProtocolFinding,
    AutoDecodingResult, FileRecoveryResult, AttackDetectionInfo
)


class TreeFilterProxyModel(QSortFilterProxyModel):
    """树形视图过滤代理模型 - 递归过滤"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._filter_text = ""
        # Qt C++ 层自动递归检查子节点，无需 Python 手动递归
        self.setRecursiveFilteringEnabled(True)

    def setFilterText(self, text: str):  # 设置过滤文本
        self._filter_text = text.lower().strip()
        self.invalidateFilter()

    def filterAcceptsRow(self, source_row: int, source_parent: QModelIndex) -> bool:  # 判断行是否应该显示
        if not self._filter_text:
            return True

        source_model = self.sourceModel()
        if not source_model:
            return True

        index = source_model.index(source_row, 0, source_parent)
        if not index.isValid():
            return True

        node = index.internalPointer()
        if not node:
            return True

        # 只检查当前节点名称，Qt 的 setRecursiveFilteringEnabled(True)
        # 会自动递归检查子节点，无需手动递归（手动递归会导致指数级重复遍历）
        return self._filter_text in node.name.lower()


class TreePanel(QWidget):
    """树形面板"""

    itemSelected = Signal(object)  # 选中项变化信号，传递TreeNode

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumWidth(250)

        # 搜索防抖定时器（300ms）
        self._search_timer = QTimer(self)
        self._search_timer.setSingleShot(True)
        self._search_timer.setInterval(300)
        self._search_timer.timeout.connect(self._applySearchFilter)
        self._pending_search_text = ""

        self._setupUI()
        self._setupModel()

    def _setupUI(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(8)

        # 标题
        title_layout = QHBoxLayout()
        title = QLabel("分析结果")
        title.setStyleSheet("""
            QLabel {
                font-size: 14px;
                font-weight: bold;
                color: #333;
            }
        """)
        title_layout.addWidget(title)
        title_layout.addStretch()
        layout.addLayout(title_layout)

        # 搜索框
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("搜索...")
        self.search_input.setClearButtonEnabled(True)
        self.search_input.setStyleSheet("""
            QLineEdit {
                padding: 8px 12px;
                border: 1px solid #E0E0E0;
                border-radius: 6px;
                background-color: white;
                font-size: 13px;
            }
            QLineEdit:focus {
                border-color: #1976D2;
            }
        """)
        self.search_input.textChanged.connect(self._onSearchTextChanged)
        layout.addWidget(self.search_input)

        # 树形视图
        self.tree_view = QTreeView()
        self.tree_view.setHeaderHidden(True)  # 先隐藏header，避免问题
        self.tree_view.setAnimated(False)  # 禁用动画，避免大量节点展开时的布局重算
        self.tree_view.setIndentation(20)
        self.tree_view.setUniformRowHeights(True)
        self.tree_view.setAlternatingRowColors(True)
        self.tree_view.setSelectionMode(QTreeView.SingleSelection)
        self.tree_view.setExpandsOnDoubleClick(True)

        self.tree_view.setStyleSheet("""
            QTreeView {
                background-color: white;
                border: 1px solid #E0E0E0;
                border-radius: 6px;
                outline: none;
            }
            QTreeView::item {
                padding: 6px;
                border-radius: 4px;
            }
            QTreeView::item:hover {
                background-color: #E3F2FD;
            }
            QTreeView::item:selected {
                background-color: #1976D2;
                color: white;
            }
        """)

        layout.addWidget(self.tree_view)

        # 状态标签
        self.status_label = QLabel("等待加载数据...")
        self.status_label.setStyleSheet("""
            QLabel {
                color: #999;
                font-size: 12px;
                padding: 4px;
            }
        """)
        layout.addWidget(self.status_label)

    def _setupModel(self):
        # 源模型
        self.source_model = AnalysisTreeModel(self)

        # 过滤代理模型
        self.proxy_model = TreeFilterProxyModel(self)
        self.proxy_model.setSourceModel(self.source_model)

        # 设置视图使用代理模型
        self.tree_view.setModel(self.proxy_model)

        # 模型设置后再配置header
        self.tree_view.setHeaderHidden(False)
        header = self.tree_view.header()
        header.setStretchLastSection(True)

        self.tree_view.selectionModel().currentChanged.connect(self._onSelectionChanged)

    @property
    def model(self):
        """兼容旧代码，返回源模型"""
        return self.source_model

    def buildTree(self, summary: AnalysisSummary):
        """从分析结果构建树"""
        self.source_model.buildFromSummary(summary)

        # 只展开第一级分类节点，避免大量子节点导致 UI 卡死
        self.tree_view.setUpdatesEnabled(False)
        for i in range(self.proxy_model.rowCount(QModelIndex())):
            idx = self.proxy_model.index(i, 0, QModelIndex())
            self.tree_view.expand(idx)
        self.tree_view.setUpdatesEnabled(True)

        self._updateStatus(summary)

    def addDetection(self, detection: DetectionResult):
        """动态添加检测结果"""
        self.source_model.addDetection(detection)

    def addDetectionBatch(self, detections: list):
        """批量添加检测结果"""
        if hasattr(self.source_model, 'addDetectionBatch'):
            self.source_model.addDetectionBatch(detections)
        else:
            for detection in detections:
                self.source_model.addDetection(detection)

    def addProtocolFinding(self, finding: ProtocolFinding):
        """动态添加协议分析发现"""
        self.source_model.addProtocolFinding(finding)

    def addDecodingResult(self, result: AutoDecodingResult):
        """动态添加自动解码结果"""
        self.source_model.addDecodingResult(result)

    def addFileRecovery(self, recovery: FileRecoveryResult):
        """动态添加文件还原结果"""
        self.source_model.addFileRecovery(recovery)

    def addAttackDetection(self, attack: AttackDetectionInfo):
        """动态添加攻击检测结果"""
        self.source_model.addAttackDetection(attack)

    def clear(self):
        """清空树"""
        self.source_model.beginResetModel()
        self.source_model.root = TreeNode("Root")
        self.source_model.endResetModel()
        self.status_label.setText("等待加载数据...")
        self.search_input.clear()

    def _onSelectionChanged(self, current: QModelIndex, previous: QModelIndex):
        """选择变化处理"""
        if current.isValid():
            # 从代理模型映射到源模型
            source_index = self.proxy_model.mapToSource(current)
            if source_index.isValid():
                node = source_index.internalPointer()
                if node:
                    self.itemSelected.emit(node)

    def _onSearchTextChanged(self, text: str):
        """搜索文本变化 - 防抖处理"""
        self._pending_search_text = text
        self._search_timer.start()

    def _applySearchFilter(self):
        """实际执行搜索过滤（防抖后触发）"""
        text = self._pending_search_text
        self.proxy_model.setFilterText(text)

        # 搜索时只展开第一级分类节点，避免大量节点卡死
        if text:
            self.tree_view.setUpdatesEnabled(False)
            for i in range(self.proxy_model.rowCount(QModelIndex())):
                idx = self.proxy_model.index(i, 0, QModelIndex())
                self.tree_view.expand(idx)
            self.tree_view.setUpdatesEnabled(True)

        # 更新状态标签（只统计第一级子节点数量，避免深度递归）
        if text:
            visible_count = self._countTopLevelItems()
            self.status_label.setText(f"搜索结果: {visible_count} 项匹配")
        else:
            self.status_label.setText("等待加载数据...")

    def _countTopLevelItems(self) -> int:
        """统计可见的顶级分类下的直接子项数量（轻量级，不递归）"""
        count = 0
        for i in range(self.proxy_model.rowCount(QModelIndex())):
            parent_idx = self.proxy_model.index(i, 0, QModelIndex())
            count += self.proxy_model.rowCount(parent_idx)
        return count

    def _updateStatus(self, summary: AnalysisSummary):
        """更新状态标签"""
        threat_count = len(summary.detections)
        protocol_count = len(summary.protocol_stats)
        file_count = len(summary.extracted_files)
        finding_count = len(summary.protocol_findings)
        decoding_count = len(summary.decoding_results)
        recovery_count = len(summary.recovered_files)
        attack_count = len(summary.attack_detections)

        # 合并威胁和攻击为"攻击行为"
        total_attack_count = threat_count + attack_count
        status_parts = [f"检测到 {total_attack_count} 个攻击行为"]
        if finding_count > 0:
            status_parts.append(f"{finding_count} 个协议发现")
        if decoding_count > 0:
            status_parts.append(f"{decoding_count} 个解码")
        if recovery_count > 0:
            status_parts.append(f"{recovery_count} 个还原文件")
        status_parts.extend([f"{protocol_count} 种协议", f"{file_count} 个文件"])

        self.status_label.setText(" | ".join(status_parts))
