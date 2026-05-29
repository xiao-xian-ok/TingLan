from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QTextEdit,
    QVBoxLayout,
)

from models.detection_result import AnalysisSummary


class AnalysisCompleteDialog(QDialog):
    """分析完成摘要弹窗，保留导出入口并集中展示关键统计。"""

    exportRequested = Signal()

    def __init__(self, summary: AnalysisSummary, parent=None):
        super().__init__(parent)
        self._summary = summary
        self.setWindowTitle("分析完成")
        self.resize(520, 420)
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(10)

        title = QLabel("分析完成")
        title.setStyleSheet("font-size: 18px; font-weight: 600;")
        layout.addWidget(title)

        detail = QTextEdit(self)
        detail.setReadOnly(True)
        detail.setPlainText(self._summary_text())
        layout.addWidget(detail)

        buttons = QHBoxLayout()
        buttons.addStretch()

        export_btn = QPushButton("导出报告", self)
        export_btn.clicked.connect(self.exportRequested.emit)
        buttons.addWidget(export_btn)

        close_btn = QPushButton("关闭", self)
        close_btn.clicked.connect(self.accept)
        buttons.addWidget(close_btn)

        layout.addLayout(buttons)

    def _summary_text(self) -> str:
        summary = self._summary
        total_attacks = len(summary.detections) + len(summary.attack_detections)
        lines = [
            f"文件: {summary.file_path}",
            f"总数据包: {summary.total_packets}",
            f"检测到攻击行为: {total_attacks} 条",
            f"  - 高置信度: {summary.high_confidence_count}",
            f"  - 中置信度: {summary.medium_confidence_count}",
            f"  - 低置信度: {summary.low_confidence_count}",
        ]

        if summary.protocol_findings:
            flag_count = sum(1 for finding in summary.protocol_findings if finding.is_flag)
            lines.extend([
                f"协议分析发现: {len(summary.protocol_findings)} 条",
                f"  - 疑似FLAG: {flag_count}",
            ])

        if summary.decoding_results:
            flag_count = sum(1 for result in summary.decoding_results if result.flags_found)
            lines.extend([
                f"自动解码结果: {len(summary.decoding_results)} 条",
                f"  - 发现FLAG: {flag_count}",
            ])

        if summary.recovered_files:
            lines.append(f"文件还原: {len(summary.recovered_files)} 个")

        if summary.rtp_streams:
            audio_count = sum(1 for stream in summary.rtp_streams if stream.media_type == "audio")
            video_count = sum(1 for stream in summary.rtp_streams if stream.media_type == "video")
            lines.append(f"音视频流: {len(summary.rtp_streams)} 条")
            if audio_count:
                lines.append(f"  - 音频流: {audio_count}")
            if video_count:
                lines.append(f"  - 视频流: {video_count}")

        if summary.extracted_files:
            lines.append(f"文件提取: {len(summary.extracted_files)} 个")

        lines.append(f"耗时: {summary.analysis_time:.2f} 秒")
        return "\n".join(lines)
