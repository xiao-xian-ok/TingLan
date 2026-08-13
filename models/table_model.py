# 表格数据模型

from typing import List, Any, Optional
from PySide6.QtCore import Qt, QAbstractTableModel, QModelIndex, QSortFilterProxyModel
from PySide6.QtGui import QColor

from models.detection_result import DetectionResult
from models.severity_policy import is_noise_level


# 研判列的配色：确认得手要一眼看见，未生效要能被视觉忽略
_OUTCOME_COLORS = {
    "confirmed": "#C62828",
    "suspected": "#EF6C00",
    "failed": "#9E9E9E",
    "unknown": "#757575",
}


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
            if col == 1:  # 研判列
                return QColor(_OUTCOME_COLORS.get(detection.success_outcome, "#757575"))

        elif role == Qt.ToolTipRole:
            if col == 1:
                reasons = detection.success_reasons
                if reasons:
                    return "\n".join(reasons[:5])

        elif role == Qt.BackgroundRole:
            if row % 2 == 0:
                return QColor("#FAFAFA")
            return QColor("#FFFFFF")

        elif role == Qt.UserRole:
            return detection

        elif role == Qt.TextAlignmentRole:
            # 威胁等级 / 研判 / 类型 / 方法 居中
            if col in (0, 1, 2, 3):
                return Qt.AlignCenter
            elif col == 7:  # 权重列居中
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
        self._filter_outcomes = []   # 研判结论过滤 (confirmed/suspected/...)
        self._suppress_noise = False  # 超量时收敛低危/信息级

    def setFilterText(self, text: str):
        self._filter_text = text.lower()
        self.invalidateFilter()

    def setFilterTypes(self, types: List[str]):
        self._filter_types = types
        self.invalidateFilter()

    def setFilterLevels(self, levels: List[str]):
        self._filter_levels = levels
        self.invalidateFilter()

    def setSuppressNoise(self, suppress: bool):
        """开关"隐藏低危/信息级"。

        命中量大到一定程度（见 severity_policy.ATTACK_OVERLOAD_THRESHOLD）
        时由界面自动打开：那个量级的结果基本是扫描器噪声，全铺开只会把真
        正的攻击淹掉。数据仍在 summary 里，导出不受影响。
        """
        if self._suppress_noise == suppress:
            return
        self._suppress_noise = suppress
        self.invalidateFilter()

    def isNoiseSuppressed(self) -> bool:
        return self._suppress_noise

    def setFilterOutcomes(self, outcomes: List[str]):
        """按 A/B/C 研判结论过滤

        真实取证现场里绝大多数命中来自扫描器噪声，"只看确认/疑似得手的"
        是把一屏红色收敛成几条的最快办法。空列表 = 不过滤。
        """
        self._filter_outcomes = outcomes
        self.invalidateFilter()

    def filterAcceptsRow(self, source_row: int, source_parent: QModelIndex) -> bool:
        model = self.sourceModel()
        if not isinstance(model, DetectionTableModel):
            return True

        detection = model.getDetection(source_row)
        if not detection:
            return False

        # 低危/信息级收敛。放在最前面：命中过万时这条能最快把候选砍掉，
        # 后面几个字符串比较就不用做了。
        if self._suppress_noise and is_noise_level(detection.threat_level):
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

        # 研判结论过滤
        if self._filter_outcomes:
            if detection.success_outcome not in self._filter_outcomes:
                return False

        return True
