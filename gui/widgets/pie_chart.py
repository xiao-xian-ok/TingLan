# 饼图组件

import math
from typing import List, Tuple, Optional

from PySide6.QtWidgets import QWidget, QVBoxLayout, QLabel, QScrollArea, QFrame, QHBoxLayout
from PySide6.QtCore import Qt, QRectF, QPointF, Signal
from PySide6.QtGui import QPainter, QColor, QPen, QBrush, QFont, QPainterPath, QFontMetrics


class PieChartWidget(QWidget):
    """饼图组件 - 展示协议占比"""

    # 预定义颜色列表
    COLORS = [
        "#1976D2",  # 蓝色
        "#388E3C",  # 绿色
        "#F57C00",  # 橙色
        "#7B1FA2",  # 紫色
        "#C2185B",  # 粉色
        "#00796B",  # 青色
        "#5D4037",  # 棕色
        "#455A64",  # 灰蓝
        "#D32F2F",  # 红色
        "#1565C0",  # 深蓝
    ]

    hovered = Signal(str, int, float)  # (协议名, 数量, 百分比)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._data: List[Tuple[str, int]] = []  # [(协议名, 数量), ...]
        self._total = 0
        self._hover_index = -1
        self._angles: List[Tuple[float, float]] = []  # [(起始角度, 跨度), ...]

        self.setMinimumSize(300, 300)
        self.setMouseTracking(True)

    def setData(self, data: List[Tuple[str, int]]):
        """设置数据 [(协议名, 数量), ...]"""
        self._data = sorted(data, key=lambda x: -x[1])  # 按数量降序
        self._total = sum(count for _, count in self._data)
        self._calculateAngles()
        self.update()

    def _calculateAngles(self):
        """计算每个扇形的角度"""
        self._angles = []
        if self._total == 0:
            return

        start_angle = 90 * 16  # Qt使用1/16度为单位，从12点方向开始
        for name, count in self._data:
            span = int((count / self._total) * 360 * 16)
            self._angles.append((start_angle, span))
            start_angle += span

    def paintEvent(self, event):
        """绘制饼图"""
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)

        # 计算绘制区域
        width = self.width()
        height = self.height()
        size = min(width, height) - 40
        x = (width - size) // 2
        y = (height - size) // 2
        rect = QRectF(x, y, size, size)

        if not self._data or self._total == 0:
            # 无数据时显示提示
            painter.setPen(QColor("#999999"))
            painter.setFont(QFont("Microsoft YaHei", 12))
            painter.drawText(self.rect(), Qt.AlignCenter, "暂无协议统计数据\n\n请先分析PCAP文件")
            return

        # 绘制每个扇形
        for i, ((name, count), (start, span)) in enumerate(zip(self._data, self._angles)):
            color = QColor(self.COLORS[i % len(self.COLORS)])

            # 悬浮时突出显示
            draw_rect = rect
            if i == self._hover_index:
                # 扇形向外偏移
                mid_angle = (start + span / 2) / 16 * math.pi / 180
                offset = 10
                offset_x = -offset * math.cos(mid_angle)
                offset_y = offset * math.sin(mid_angle)
                draw_rect = QRectF(rect.x() + offset_x, rect.y() + offset_y, rect.width(), rect.height())
                color = color.lighter(110)

            painter.setPen(QPen(Qt.white, 2))
            painter.setBrush(QBrush(color))
            painter.drawPie(draw_rect, start, span)

        # 绘制中心圆（环形图效果）
        center_size = size * 0.5
        center_rect = QRectF(
            x + (size - center_size) / 2,
            y + (size - center_size) / 2,
            center_size,
            center_size
        )
        painter.setPen(Qt.NoPen)
        painter.setBrush(QBrush(QColor("#FFFFFF")))
        painter.drawEllipse(center_rect)

        # 中心显示总数
        painter.setPen(QColor("#333333"))
        painter.setFont(QFont("Microsoft YaHei", 14, QFont.Bold))
        painter.drawText(center_rect, Qt.AlignCenter, f"总计\n{self._total}")

    def mouseMoveEvent(self, event):
        """鼠标移动 - 检测悬浮"""
        if not self._data or self._total == 0:
            return

        # 计算鼠标相对于圆心的角度
        width = self.width()
        height = self.height()
        size = min(width, height) - 40
        center_x = width / 2
        center_y = height / 2
        radius = size / 2

        dx = event.position().x() - center_x
        dy = center_y - event.position().y()  # Y轴翻转
        distance = math.sqrt(dx * dx + dy * dy)

        # 检查是否在环形区域内
        inner_radius = radius * 0.25
        if distance < inner_radius or distance > radius:
            if self._hover_index != -1:
                self._hover_index = -1
                self.update()
            return

        # 计算角度（从12点方向顺时针）
        angle = math.atan2(dx, dy) * 180 / math.pi
        if angle < 0:
            angle += 360
        angle_16 = (90 - angle) * 16
        if angle_16 < 0:
            angle_16 += 360 * 16

        # 找到对应的扇形
        new_hover = -1
        for i, (start, span) in enumerate(self._angles):
            # 标准化角度到 [0, 360*16)
            norm_start = start % (360 * 16)
            norm_angle = angle_16 % (360 * 16)

            # 检查角度是否在扇形范围内
            if span > 0:
                end = (norm_start + span) % (360 * 16)
                if norm_start <= end:
                    if norm_start <= norm_angle < end:
                        new_hover = i
                        break
                else:  # 跨越0度
                    if norm_angle >= norm_start or norm_angle < end:
                        new_hover = i
                        break

        if new_hover != self._hover_index:
            self._hover_index = new_hover
            self.update()

            if new_hover >= 0:
                name, count = self._data[new_hover]
                percent = (count / self._total) * 100
                self.hovered.emit(name, count, percent)

    def leaveEvent(self, event):
        """鼠标离开"""
        if self._hover_index != -1:
            self._hover_index = -1
            self.update()


class ProtocolLegend(QFrame):
    """协议图例"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._setupUI()

    def _setupUI(self):
        self.setStyleSheet("""
            ProtocolLegend {
                background-color: white;
                border: 1px solid #E0E0E0;
                border-radius: 8px;
            }
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(5)

        # 标题
        title = QLabel("分析汇总")
        title.setStyleSheet("font-size: 13px; font-weight: bold; color: #333;")
        layout.addWidget(title)

        # 图例容器
        self.legend_layout = QVBoxLayout()
        self.legend_layout.setSpacing(4)
        layout.addLayout(self.legend_layout)

        layout.addStretch()

    def setData(self, data: List[Tuple[str, int]], total: int):
        """设置数据"""
        # 清空现有图例
        while self.legend_layout.count():
            item = self.legend_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        if total == 0:
            return

        colors = PieChartWidget.COLORS
        for i, (name, count) in enumerate(data):
            percent = (count / total) * 100
            item = self._createLegendItem(name, count, percent, colors[i % len(colors)])
            self.legend_layout.addWidget(item)

    def _createLegendItem(self, name: str, count: int, percent: float, color: str) -> QWidget:
        """创建单个图例项"""
        widget = QWidget()
        layout = QHBoxLayout(widget)
        layout.setContentsMargins(0, 2, 0, 2)
        layout.setSpacing(8)

        # 颜色方块
        color_box = QLabel()
        color_box.setFixedSize(12, 12)
        color_box.setStyleSheet(f"background-color: {color}; border-radius: 2px;")
        layout.addWidget(color_box)

        # 协议名
        name_label = QLabel(name)
        name_label.setStyleSheet("color: #333; font-size: 12px;")
        layout.addWidget(name_label)

        layout.addStretch()

        # 数量和百分比
        value_label = QLabel(f"{count} ({percent:.1f}%)")
        value_label.setStyleSheet("color: #666; font-size: 11px;")
        layout.addWidget(value_label)

        return widget


class ProtocolStatsWidget(QWidget):
    """协议统计面板 - 包含饼图和图例"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._setupUI()

    def _setupUI(self):
        layout = QHBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(15)

        # 左侧：饼图
        self.pie_chart = PieChartWidget()
        layout.addWidget(self.pie_chart, stretch=2)

        # 右侧：图例
        self.legend = ProtocolLegend()
        self.legend.setFixedWidth(200)
        layout.addWidget(self.legend)

        # 悬浮提示
        self.pie_chart.hovered.connect(self._onHovered)

        # 提示标签
        self.tooltip_label = QLabel()
        self.tooltip_label.setStyleSheet("""
            QLabel {
                background-color: rgba(0, 0, 0, 0.8);
                color: white;
                padding: 8px 12px;
                border-radius: 4px;
                font-size: 12px;
            }
        """)
        self.tooltip_label.hide()
        self.tooltip_label.setParent(self)

    def setData(self, protocol_stats: List[Tuple[str, int]]):
        """设置协议统计数据 [(协议名, 数量), ...]"""
        total = sum(count for _, count in protocol_stats)
        self.pie_chart.setData(protocol_stats)
        self.legend.setData(protocol_stats, total)

    def _onHovered(self, name: str, count: int, percent: float):
        """悬浮显示详情"""
        self.tooltip_label.setText(f"{name}: {count} 个数据包 ({percent:.1f}%)")
        self.tooltip_label.adjustSize()
        # 显示在鼠标附近（简化处理，显示在固定位置）
        self.tooltip_label.move(20, 20)
        self.tooltip_label.show()

    def leaveEvent(self, event):
        self.tooltip_label.hide()

    def clear(self):
        """清空数据"""
        self.pie_chart.setData([])
        self.legend.setData([], 0)
