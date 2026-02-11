# 表格数据模型

from typing import List, Any, Optional
from PySide6.QtCore import Qt, QAbstractTableModel, QModelIndex, QSortFilterProxyModel
from PySide6.QtGui import QColor

from models.detection_result import DetectionResult


class DetectionTableModel(QAbstractTableModel):

    def __init__(self, parent=None):
        super().__init__(parent)
        self._data: List[DetectionResult] = []
        self._headers = DetectionResult.table_headers()

    def setDetections(self, detections: List[DetectionResult]):
        self.beginResetModel()
        self._data = detections
        self.endResetModel()

    def addDetection(self, detection: DetectionResult):
        row = len(self._data)
        self.beginInsertRows(QModelIndex(), row, row)
        self._data.append(detection)
        self.endInsertRows()

    def addDetectionBatch(self, detections: List[DetectionResult]):
        """批量添加，一次性通知UI"""
        if not detections:
            return

        start_row = len(self._data)
        end_row = start_row + len(detections) - 1

        self.beginInsertRows(QModelIndex(), start_row, end_row)
        self._data.extend(detections)
        self.endInsertRows()

    def clear(self):
        self.beginResetModel()
        self._data = []
        self.endResetModel()

    def getDetection(self, row: int) -> Optional[DetectionResult]:
        if 0 <= row < len(self._data):
            return self._data[row]
        return None

    # QAbstractTableModel 必要方法

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return len(self._data)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return len(self._headers)

    def data(self, index: QModelIndex, role: int = Qt.DisplayRole) -> Any:
        if not index.isValid():
            return None

        row = index.row()
        col = index.column()

        if row >= len(self._data):
            return None

        detection = self._data[row]

        if role == Qt.DisplayRole:
            row_data = detection.to_table_row()
            if col < len(row_data):
                return row_data[col]

        elif role == Qt.ForegroundRole:
            if col == 0:  # 威胁等级列
                return QColor(detection.threat_level.color)

        elif role == Qt.BackgroundRole:
            if row % 2 == 0:
                return QColor("#FAFAFA")
            return QColor("#FFFFFF")

        elif role == Qt.UserRole:
            return detection

        elif role == Qt.TextAlignmentRole:
            if col in [0, 1, 2]:  # 威胁等级、类型、方法列居中
                return Qt.AlignCenter
            elif col == 6:  # 权重列居中
                return Qt.AlignCenter
            return Qt.AlignLeft | Qt.AlignVCenter

        return None

    def headerData(self, section: int, orientation: Qt.Orientation, role: int = Qt.DisplayRole) -> Any:
        if orientation == Qt.Horizontal and role == Qt.DisplayRole:
            if section < len(self._headers):
                return self._headers[section]
        return None

    def flags(self, index: QModelIndex) -> Qt.ItemFlags:
        if not index.isValid():
            return Qt.NoItemFlags
        return Qt.ItemIsEnabled | Qt.ItemIsSelectable


class DetectionFilterProxyModel(QSortFilterProxyModel):
    """检测结果过滤代理"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._filter_text = ""
        self._filter_types = []      # 检测类型过滤
        self._filter_levels = []     # 置信度过滤 (high/medium/low)

    def setFilterText(self, text: str):
        self._filter_text = text.lower()
        self.invalidateFilter()

    def setFilterTypes(self, types: List[str]):
        self._filter_types = types
        self.invalidateFilter()

    def setFilterLevels(self, levels: List[str]):
        self._filter_levels = levels
        self.invalidateFilter()

    def filterAcceptsRow(self, source_row: int, source_parent: QModelIndex) -> bool:
        model = self.sourceModel()
        if not isinstance(model, DetectionTableModel):
            return True

        detection = model.getDetection(source_row)
        if not detection:
            return False

        # 文本过滤
        if self._filter_text:
            # 搜索 URI、指标、方法、标签
            tags_str = " ".join(detection.tags).lower() if detection.tags else ""
            text_match = (
                self._filter_text in detection.uri.lower() or
                self._filter_text in detection.indicator.lower() or
                self._filter_text in detection.method.lower() or
                self._filter_text in tags_str
            )
            if not text_match:
                return False

        # 类型过滤
        if self._filter_types:
            if detection.detection_type.value not in self._filter_types:
                return False

        # 置信度过滤 (使用新的confidence字段)
        if self._filter_levels:
            if detection.confidence not in self._filter_levels:
                return False

        return True
