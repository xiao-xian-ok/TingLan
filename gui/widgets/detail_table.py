# detail_table.py - 详情表格

from typing import List, Optional
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTableView, QLineEdit,
    QLabel, QPushButton, QComboBox, QHeaderView, QAbstractItemView,
    QCheckBox
)
from PySide6.QtCore import Signal, Qt, QSortFilterProxyModel

from models.table_model import DetectionTableModel, DetectionFilterProxyModel
from models.detection_result import DetectionResult, AnalysisSummary
from models.severity_policy import (
    ATTACK_OVERLOAD_THRESHOLD,
    should_suppress_noise,
    sort_by_severity,
)


class DetailTable(QWidget):
    """详情表格"""

    itemSelected = Signal(object)  # 选中行变化信号，传递DetectionResult
    # "隐藏低危/信息"开关变化。左侧结果树要跟着一起变 —— 这个复选框是
    # 整个界面唯一的收敛开关，不能只管右边这半屏。
    noiseSuppressionChanged = Signal(bool)

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

        # 研判结论过滤。真实现场里绝大多数命中是扫描器噪声，
        # "只看得手的"是把一屏红色收敛成几条的最快办法。
        self.outcome_filter = QComboBox()
        self.outcome_filter.addItems([
            "全部研判", "确认得手", "疑似得手", "得手(确认+疑似)", "未生效", "未研判",
        ])
        self.outcome_filter.setStyleSheet(self.type_filter.styleSheet())
        self.outcome_filter.currentIndexChanged.connect(self._onOutcomeFilterChanged)
        toolbar.addWidget(self.outcome_filter)

        # 低危/信息级收敛开关。命中超过阈值时自动勾上（见 showFromSummary），
        # 但仍然让用户能手动取消 —— 取证工具不该单方面决定什么看不到。
        self.noise_filter = QCheckBox("隐藏低危/信息")
        self.noise_filter.setToolTip(
            f"检测到的攻击超过 {ATTACK_OVERLOAD_THRESHOLD} 条时自动开启。\n"
            "只影响界面显示，导出仍包含全部结果。"
        )
        self.noise_filter.setStyleSheet("QCheckBox { color: #666; font-size: 12px; }")
        self.noise_filter.toggled.connect(self._onNoiseFilterToggled)
        toolbar.addWidget(self.noise_filter)

        layout.addLayout(toolbar)

        # 攻击者聚合摘要条。
        #
        # 详情表是**逐条**平铺的，而攻击是**成链**发生的。实测一个 166MB
        # 的抓包：6747 条检测来自同一个来源 IP，真正得手的只有一条
        # `/images/article/a.php` 上的菜刀 WebShell。分析员要在 6747 行里
        # 把它找出来 —— 而"这个人试了 6747 次、成了 19 次"这个信息本身
        # 就淹没在那 6747 行里，反而看不出来。
        #
        # 这里先只加一条摘要（不改表格结构）：把结论摆到眼前，
        # 逐条列表仍然原样保留，需要细看时照旧。
        self.chain_summary = QLabel()
        self.chain_summary.setWordWrap(True)
        self.chain_summary.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.chain_summary.setVisible(False)
        self.chain_summary.setStyleSheet("""
            QLabel {
                padding: 8px 12px;
                margin: 0 10px;
                border-radius: 4px;
                border-left: 3px solid #D32F2F;
                background-color: #FFF3F3;
                color: #333;
                font-size: 12px;
            }
        """)
        layout.addWidget(self.chain_summary)

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

        统一按威胁等级降序装填：严重/高危/中危在最前，低危和信息垫底。
        表格自己带排序表头，用户点列头照样能改，这里只决定初始顺序。
        """
        self.source_model.setDetections(sort_by_severity(detections))
        self._updateCount()

    def showDetection(self, detection: DetectionResult):
        """显示单条检测结果（高亮并滚动到可见区）

        原来只 selectRow 不滚动。表里上万条时，从左侧结果树点一条，选中的行
        往往落在视口之外 —— 界面上看起来"右边没跟着动"，而实际上高亮就在
        几千行以外。必须 scrollTo 才算真的定位过去。

        另一半症状是被过滤掉的情况：勾了"隐藏低危/信息"或设了类型/研判过滤时，
        mapFromSource 返回无效索引，原来直接 return，**上一次的选中行还亮着**。
        用户点了新的一条，右边却还停在旧的那条上，看起来就是"对不上"。
        这种情况要把选中清掉，宁可空着也不要显示错的。
        """
        selection_model = self.table_view.selectionModel()
        # 临时阻塞选择信号，避免 selectRow 触发 _onSelectionChanged
        selection_model.blockSignals(True)
        try:
            proxy_index = None
            for row in range(self.source_model.rowCount()):
                if self.source_model.getDetection(row) is detection:
                    candidate = self.proxy_model.mapFromSource(
                        self.source_model.index(row, 0)
                    )
                    proxy_index = candidate if candidate.isValid() else None
                    break

            if proxy_index is None:
                # 当前过滤条件下这条看不见 —— 清掉旧高亮，别留着误导
                selection_model.clearSelection()
                selection_model.clearCurrentIndex()
                return

            self.table_view.selectRow(proxy_index.row())
            self.table_view.scrollTo(
                proxy_index, QAbstractItemView.PositionAtCenter)
        finally:
            selection_model.blockSignals(False)

    def showFromSummary(self, summary: AnalysisSummary):
        """从分析摘要显示检测结果

        攻击条数超阈值时自动收敛低危/信息级。算总数要把 attack_detections
        一起算上 —— 界面上"检测到 N 个攻击行为"就是这两个之和，只按
        detections 判会和用户看到的数字对不上。
        """
        total_attacks = len(summary.detections) + len(summary.attack_detections)
        self.setSuppressNoise(should_suppress_noise(total_attacks))
        self.setDetections(summary.detections)
        self._updateChainSummary(summary.detections)

    def _updateChainSummary(self, detections: List[DetectionResult]):
        """把检测聚成攻击者会话，把结论摆到表格上方。

        只读不写：worker 已经在 raw_result 里写过 chain_* 字段了，这里
        重算一遍纯粹是为了让控件自足（单独喂一批检测给它也能工作）。
        聚合是 O(n) 的字典分组，几千条检测的开销可以忽略。

        聚合失败绝不能影响表格本身 —— 它只是个摘要条。
        """
        try:
            from core.attack_chain import build_chains, build_sessions
        except ImportError:
            self.chain_summary.setVisible(False)
            return

        try:
            sessions = build_sessions(build_chains(detections or []))
        except Exception:
            self.chain_summary.setVisible(False)
            return

        landed = [s for s in sessions if s.landed_chains]
        if not landed:
            # 一条都没得手时不摆这个条 —— 它的价值在于"指出那几条"，
            # 没有可指的就别占地方，更不能显示成绿色的"安全"结论：
            # 研判没发现得手迹象 ≠ 没被打进来。
            self.chain_summary.setVisible(False)
            return

        lines = []
        tips = []
        for session in landed[:3]:
            hit = sum(chain.size for chain in session.landed_chains)
            lines.append(
                f"<b>{session.src_ip or '未知来源'}</b> → "
                f"{session.dst_ip or '未知目标'}　"
                f"尝试 <b>{session.attempts}</b> 次，"
                f"<b style='color:#D32F2F'>得手 {hit} 次</b>")
            for chain in session.landed_chains[:5]:
                lines.append(
                    f"　　★ <code>{chain.path}</code>　"
                    f"{chain.size} 条交互，研判 {chain.outcome}")
                tips.append(f"{session.src_ip} → {session.dst_ip}{chain.path}"
                            f"（{chain.size} 条，{chain.outcome}）")

        extra = len(landed) - 3
        if extra > 0:
            lines.append(f"　　…… 另有 {extra} 个来源存在得手迹象")

        self.chain_summary.setText("　攻击链聚合：<br>" + "<br>".join(lines))
        self.chain_summary.setToolTip(
            "已证实得手的攻击链：\n" + "\n".join(tips) if tips else "")
        self.chain_summary.setVisible(True)

    def setSuppressNoise(self, suppress: bool):
        """同步开关状态到复选框、代理模型和结果树。"""
        # 用 setChecked 触发 toggled，代理和树由 _onNoiseFilterToggled 统一
        # 更新，避免两处各写一份状态。blockSignals 会让它们收不到通知。
        if self.noise_filter.isChecked() != suppress:
            self.noise_filter.setChecked(suppress)
        else:
            self._applyNoiseSuppression(suppress)

    def _onNoiseFilterToggled(self, checked: bool):
        self._applyNoiseSuppression(checked)

    def _applyNoiseSuppression(self, suppress: bool):
        self.proxy_model.setSuppressNoise(suppress)
        self._updateCount()
        self.noiseSuppressionChanged.emit(suppress)

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

    def _onFilterTextChanged(self, text: str):
        """过滤文本变化"""
        self.proxy_model.setFilterText(text)
        self._updateCount()

    def _onOutcomeFilterChanged(self, index: int):
        """研判结论过滤变化"""
        outcome_map = {
            0: [],                              # 全部
            1: ["confirmed"],
            2: ["suspected"],
            3: ["confirmed", "suspected"],
            4: ["failed"],
            5: ["", "unknown"],                 # 没研判过 / 证据不足
        }
        self.proxy_model.setFilterOutcomes(outcome_map.get(index, []))
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
        elif self.proxy_model.isNoiseSuppressed():
            # 说清楚少掉的那些去哪了。只写"显示 N/M"会让人以为是漏检。
            self.count_label.setText(
                f"显示 {filtered}/{total} 条记录（已隐藏 {total - filtered} 条低危/信息）"
            )
        else:
            self.count_label.setText(f"显示 {filtered}/{total} 条记录")

