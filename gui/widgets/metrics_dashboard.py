# metrics_dashboard.py - 统计仪表盘

from typing import Dict, Optional
import time

from PySide6.QtWidgets import (
    QWidget, QHBoxLayout, QVBoxLayout, QLabel, QFrame,
    QProgressBar, QGroupBox, QSlider
)
from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtGui import QFont, QPainter, QColor

# 尝试导入观测中心
try:
    from core.observability import get_observability_hub
    HAS_OBSERVABILITY = True
except ImportError:
    HAS_OBSERVABILITY = False

# 尝试导入灵敏度控制 (延迟导入，避免启动时冲突)
HAS_SENSITIVITY_CONTROL = False

def _get_sensitivity_control():
    """延迟获取灵敏度控制函数"""
    global HAS_SENSITIVITY_CONTROL
    try:
        from core.fast_filter import get_sensitivity, set_sensitivity
        HAS_SENSITIVITY_CONTROL = True
        return get_sensitivity, set_sensitivity
    except ImportError:
        return None, None


class MetricCard(QFrame):
    """单个指标卡片"""

    def __init__(self, title: str, unit: str = "", parent=None):
        super().__init__(parent)
        self._title = title
        self._unit = unit
        self._value = 0.0
        self._setupUI()

    def _setupUI(self):
        self.setFrameStyle(QFrame.StyledPanel | QFrame.Raised)
        self.setStyleSheet("""
            MetricCard {
                background-color: white;
                border: 1px solid #E0E0E0;
                border-radius: 8px;
                padding: 8px;
            }
        """)
        self.setMinimumWidth(120)
        self.setMaximumHeight(70)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 4, 8, 4)
        layout.setSpacing(2)

        # 标题
        title_label = QLabel(self._title)
        title_label.setStyleSheet("color: #666; font-size: 10px;")
        title_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(title_label)

        # 值
        self.value_label = QLabel("0")
        self.value_label.setFont(QFont("Microsoft YaHei", 16, QFont.Bold))
        self.value_label.setStyleSheet("color: #1976D2;")
        self.value_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.value_label)

        # 单位
        if self._unit:
            unit_label = QLabel(self._unit)
            unit_label.setStyleSheet("color: #999; font-size: 9px;")
            unit_label.setAlignment(Qt.AlignCenter)
            layout.addWidget(unit_label)

    def setValue(self, value: float, color: str = None):
        """设置值"""
        self._value = value
        if isinstance(value, float):
            if value >= 1000:
                self.value_label.setText(f"{value/1000:.1f}K")
            elif value >= 100:
                self.value_label.setText(f"{value:.0f}")
            else:
                self.value_label.setText(f"{value:.1f}")
        else:
            self.value_label.setText(str(value))

        if color:
            self.value_label.setStyleSheet(f"color: {color};")


class DropRateBar(QFrame):
    """丢弃率进度条"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._rate = 0.0
        self._setupUI()

    def _setupUI(self):
        self.setFrameStyle(QFrame.StyledPanel)
        self.setStyleSheet("""
            DropRateBar {
                background-color: white;
                border: 1px solid #E0E0E0;
                border-radius: 8px;
            }
        """)
        self.setMinimumWidth(200)
        self.setMaximumHeight(70)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 4, 8, 4)
        layout.setSpacing(2)

        # 标题行
        header = QHBoxLayout()
        title = QLabel("丢弃率")
        title.setStyleSheet("color: #666; font-size: 10px;")
        header.addWidget(title)

        self.rate_label = QLabel("0.0%")
        self.rate_label.setStyleSheet("color: #4CAF50; font-size: 12px; font-weight: bold;")
        header.addWidget(self.rate_label)
        header.addStretch()
        layout.addLayout(header)

        # 进度条
        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.progress.setTextVisible(False)
        self.progress.setMaximumHeight(12)
        self.progress.setStyleSheet("""
            QProgressBar {
                border: none;
                border-radius: 6px;
                background-color: #E8F5E9;
            }
            QProgressBar::chunk {
                background-color: #4CAF50;
                border-radius: 6px;
            }
        """)
        layout.addWidget(self.progress)

    def setRate(self, rate: float):
        """设置丢弃率 (0.0 - 1.0)"""
        self._rate = rate
        percent = min(rate * 100, 100)
        self.progress.setValue(int(percent))
        self.rate_label.setText(f"{percent:.1f}%")

        # 根据丢弃率改变颜色
        if percent < 10:
            color = "#4CAF50"  # 绿色 - 正常
            bg_color = "#E8F5E9"
        elif percent < 30:
            color = "#FF9800"  # 橙色 - 警告
            bg_color = "#FFF3E0"
        else:
            color = "#F44336"  # 红色 - 危险
            bg_color = "#FFEBEE"

        self.rate_label.setStyleSheet(f"color: {color}; font-size: 12px; font-weight: bold;")
        self.progress.setStyleSheet(f"""
            QProgressBar {{
                border: none;
                border-radius: 6px;
                background-color: {bg_color};
            }}
            QProgressBar::chunk {{
                background-color: {color};
                border-radius: 6px;
            }}
        """)


class SensitivitySlider(QFrame):
    """灵敏度滑块: 0=极速 50=平衡 100=全量"""

    # 灵敏度变更信号
    sensitivityChanged = Signal(int)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._initialized = False  # 防止初始化时触发回调
        self._setupUI()
        self._initialized = True

    def _setupUI(self):
        self.setFrameStyle(QFrame.StyledPanel)
        self.setStyleSheet("""
            SensitivitySlider {
                background-color: white;
                border: 1px solid #E0E0E0;
                border-radius: 8px;
            }
        """)
        self.setMinimumWidth(250)
        self.setMaximumHeight(70)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 6, 10, 6)
        layout.setSpacing(4)

        # 标题行
        header = QHBoxLayout()

        title = QLabel("灵敏度")
        title.setStyleSheet("color: #666; font-size: 10px;")
        header.addWidget(title)

        self.mode_label = QLabel("平衡模式")
        self.mode_label.setStyleSheet("color: #1976D2; font-size: 11px; font-weight: bold;")
        header.addWidget(self.mode_label)

        header.addStretch()

        self.value_label = QLabel("50")
        self.value_label.setStyleSheet("color: #333; font-size: 12px; font-weight: bold;")
        header.addWidget(self.value_label)

        layout.addLayout(header)

        # 滑块
        self.slider = QSlider(Qt.Horizontal)
        self.slider.setRange(0, 100)
        self.slider.setTickPosition(QSlider.TicksBelow)
        self.slider.setTickInterval(25)
        self.slider.setStyleSheet("""
            QSlider::groove:horizontal {
                border: 1px solid #BDBDBD;
                height: 6px;
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #4CAF50, stop:0.5 #FF9800, stop:1 #F44336);
                margin: 2px 0;
                border-radius: 3px;
            }
            QSlider::handle:horizontal {
                background: white;
                border: 2px solid #1976D2;
                width: 16px;
                margin: -5px 0;
                border-radius: 8px;
            }
            QSlider::handle:horizontal:hover {
                background: #E3F2FD;
            }
        """)
        # 先连接信号，再设置值（设置值时 _initialized=False，不会触发回调）
        self.slider.valueChanged.connect(self._onValueChanged)
        self.slider.setValue(50)  # 此时 _initialized=False，不会触发实际操作
        layout.addWidget(self.slider)

        # 标签行
        labels_layout = QHBoxLayout()
        labels_layout.setContentsMargins(0, 0, 0, 0)

        left_label = QLabel("极速")
        left_label.setStyleSheet("color: #4CAF50; font-size: 9px;")
        labels_layout.addWidget(left_label)

        labels_layout.addStretch()

        right_label = QLabel("全量")
        right_label.setStyleSheet("color: #F44336; font-size: 9px;")
        labels_layout.addWidget(right_label)

        layout.addLayout(labels_layout)

    def _onValueChanged(self, value: int):
        """滑块值变更"""
        self.value_label.setText(str(value))

        # 更新模式标签
        if value < 30:
            mode = "极速模式"
            color = "#4CAF50"
        elif value < 70:
            mode = "平衡模式"
            color = "#FF9800"
        else:
            mode = "全量模式"
            color = "#F44336"

        self.mode_label.setText(mode)
        self.mode_label.setStyleSheet(f"color: {color}; font-size: 11px; font-weight: bold;")

        # 只在完全初始化后才应用到过滤器
        if not self._initialized:
            return

        # 应用到过滤器（延迟导入，避免初始化冲突）
        try:
            _, set_sensitivity = _get_sensitivity_control()
            if set_sensitivity:
                set_sensitivity(value)
        except Exception as e:
            print(f"[SensitivitySlider] 设置灵敏度失败: {e}")

        # 发出信号
        self.sensitivityChanged.emit(value)

    def getValue(self) -> int:
        """获取当前灵敏度值"""
        return self.slider.value()

    def setValue(self, value: int):
        """设置灵敏度值"""
        self.slider.setValue(value)


class MetricsDashboard(QWidget):
    """
    实时指标仪表盘

    功能：
        1. 接收 ObservabilityHub 的心跳数据
        2. 实时显示处理速率、丢弃率等指标
        3. 告警计数显示
    """

    # 信号：关键告警
    criticalAlert = Signal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._last_update = 0.0
        self._setupUI()
        self._setupTimer()

        # 注册观测中心回调
        if HAS_OBSERVABILITY:
            try:
                hub = get_observability_hub()
                hub.register_heartbeat_callback(self._onHeartbeat)
            except Exception as e:
                print(f"[MetricsDashboard] 注册观测中心失败: {e}")

    def _setupUI(self):
        self.setFixedHeight(80)
        self.setStyleSheet("background-color: #FAFAFA; border-radius: 8px;")

        layout = QHBoxLayout(self)
        layout.setContentsMargins(10, 5, 10, 5)
        layout.setSpacing(10)

        # 已扫描数
        self.scanned_card = MetricCard("已扫描", "包")
        layout.addWidget(self.scanned_card)

        # 命中数
        self.hits_card = MetricCard("命中", "攻击")
        layout.addWidget(self.hits_card)

        # 处理速率
        self.pps_card = MetricCard("处理速率", "pps")
        layout.addWidget(self.pps_card)

        # 丢弃率
        self.drop_rate_bar = DropRateBar()
        layout.addWidget(self.drop_rate_bar)

        # 采样命中率
        self.sample_card = MetricCard("采样命中", "%")
        layout.addWidget(self.sample_card)

        # 告警计数
        self.alert_card = MetricCard("告警数", "")
        layout.addWidget(self.alert_card)

        # 处理时间
        self.latency_card = MetricCard("平均延迟", "ms")
        layout.addWidget(self.latency_card)

        # 灵敏度滑块
        self.sensitivity_slider = SensitivitySlider()
        self.sensitivity_slider.sensitivityChanged.connect(self._onSensitivityChanged)
        layout.addWidget(self.sensitivity_slider)

        layout.addStretch()

        # 状态指示
        self.status_label = QLabel("就绪")
        self.status_label.setStyleSheet("""
            color: #4CAF50;
            font-size: 11px;
            padding: 4px 8px;
            background-color: #E8F5E9;
            border-radius: 4px;
        """)
        layout.addWidget(self.status_label)

    def _setupTimer(self):
        """设置刷新定时器"""
        self._timer = QTimer(self)
        self._timer.setInterval(1000)  # 1秒刷新
        self._timer.timeout.connect(self._refresh)

    def start(self):
        """开始监控"""
        self._timer.start()
        self.status_label.setText("运行中")
        self.status_label.setStyleSheet("""
            color: #1976D2;
            font-size: 11px;
            padding: 4px 8px;
            background-color: #E3F2FD;
            border-radius: 4px;
        """)

    def stop(self):
        """停止监控"""
        self._timer.stop()
        self.status_label.setText("已停止")
        self.status_label.setStyleSheet("""
            color: #666;
            font-size: 11px;
            padding: 4px 8px;
            background-color: #F5F5F5;
            border-radius: 4px;
        """)

    def _refresh(self):
        """定时刷新 (从 ObservabilityHub 获取数据)"""
        if not HAS_OBSERVABILITY:
            return

        try:
            hub = get_observability_hub()
            data = hub.get_dashboard_data()
            self._updateFromData(data)
        except Exception as e:
            print(f"[MetricsDashboard] 刷新异常: {e}")

    def _onHeartbeat(self, data: Dict):
        """
        接收心跳数据回调

        Args:
            data: ObservabilityHub.get_dashboard_data() 返回的数据
        """
        self._updateFromData(data)

    def _updateFromData(self, data: Dict):
        """
        从数据更新 UI

        Args:
            data: 仪表盘数据
        """
        try:
            self._last_update = time.time()

            # 处理速率
            rates = data.get("rates", {})
            pps = rates.get("packets_per_second", 0)
            self.pps_card.setValue(pps)

            # 丢弃率
            drop_rate = rates.get("drop_rate", 0)
            self.drop_rate_bar.setRate(drop_rate)

            # 采样命中率
            sampling = data.get("sampling", {})
            hit_rate_str = sampling.get("sample_hit_rate", "0%")
            try:
                hit_rate = float(hit_rate_str.replace("%", ""))
            except:
                hit_rate = 0
            self.sample_card.setValue(hit_rate)

            # 告警计数
            alerts = data.get("alerts", {})
            total_alerts = alerts.get("total_alerts", 0)
            critical_count = alerts.get("critical_count", 0)

            if critical_count > 0:
                self.alert_card.setValue(total_alerts, "#F44336")
            elif total_alerts > 0:
                self.alert_card.setValue(total_alerts, "#FF9800")
            else:
                self.alert_card.setValue(total_alerts)

            # 平均处理时间
            avg_time = rates.get("avg_process_time_ms", 0)
            if avg_time > 100:
                self.latency_card.setValue(avg_time, "#F44336")
            elif avg_time > 50:
                self.latency_card.setValue(avg_time, "#FF9800")
            else:
                self.latency_card.setValue(avg_time)

        except Exception as e:
            print(f"[MetricsDashboard] 更新异常: {e}")

    def updateManual(self, pps: float = 0, drop_rate: float = 0,
                     alerts: int = 0, latency_ms: float = 0):
        """
        手动更新指标 (不依赖 ObservabilityHub)

        Args:
            pps: 每秒处理包数
            drop_rate: 丢弃率 (0.0-1.0)
            alerts: 告警数
            latency_ms: 平均处理延迟 (毫秒)
        """
        self.pps_card.setValue(pps)
        self.drop_rate_bar.setRate(drop_rate)
        self.alert_card.setValue(alerts)
        self.latency_card.setValue(latency_ms)

    def update_hit_count(self, hits: int):
        """更新命中数显示"""
        # 命中卡片显示命中数
        if hits > 0:
            self.hits_card.setValue(hits, "#F44336")  # 红色高亮
        else:
            self.hits_card.setValue(hits)

    def update_stats(self, scanned: int, hits: int):
        """更新扫描统计"""
        # 已扫描
        self.scanned_card.setValue(scanned, "#1976D2")  # 蓝色

        # 命中数
        if hits > 0:
            self.hits_card.setValue(hits, "#F44336")  # 红色
        else:
            self.hits_card.setValue(hits)

    def _onSensitivityChanged(self, value: int):
        """灵敏度变更回调"""
        # 灵敏度变更会自动应用到过滤器
        # 此处可添加额外的 UI 更新或日志记录
        mode = "极速" if value < 30 else ("平衡" if value < 70 else "全量")
        print(f"[MetricsDashboard] 灵敏度调整为: {value} ({mode}模式)")

    def get_sensitivity(self) -> int:
        """获取当前灵敏度值"""
        return self.sensitivity_slider.getValue()

    def set_sensitivity(self, value: int):
        """设置灵敏度值"""
        self.sensitivity_slider.setValue(value)
