# 导出控制器

import os
import json
from datetime import datetime
from typing import Optional

from PySide6.QtCore import QObject, Signal

from models.detection_result import AnalysisSummary, DetectionResult


class ExportController(QObject):

    exportStarted = Signal()
    exportProgress = Signal(int, str)
    exportFinished = Signal(str)  # 导出文件路径
    exportError = Signal(str)

    def __init__(self, parent=None):
        super().__init__(parent)

    def _protocol_stat_to_dict(self, stat):
        d = {"protocol": stat.protocol, "count": stat.count, "percentage": stat.percentage}
        if stat.children:
            d["children"] = [self._protocol_stat_to_dict(c) for c in stat.children]
        return d

    def _build_protocol_html(self, stats, depth):
        html = ""
        indent = "&nbsp;" * (depth * 4)
        for i, p in enumerate(stats):
            is_last = (i == len(stats) - 1)
            prefix = ("└─ " if is_last else "├─ ") if depth > 0 else ""
            html += f'<tr><td>{indent}{prefix}{p.protocol}</td><td>{p.count}</td><td>{p.percentage:.1f}%</td></tr>\n'
            if p.children:
                html += self._build_protocol_html(p.children, depth + 1)
        return html

    def exportToJson(self, summary: AnalysisSummary, output_path: str) -> bool:
        try:
            self.exportStarted.emit()
            self.exportProgress.emit(10, "准备导出数据...")

            data = {
                "export_time": datetime.now().isoformat(),
                "file_path": summary.file_path,
                "total_packets": summary.total_packets,
                "analysis_time": summary.analysis_time,
                "protocol_stats": [
                    self._protocol_stat_to_dict(s)
                    for s in summary.protocol_stats
                ],
                "detections": [
                    {
                        "id": d.id,
                        "type": d.detection_type.value,
                        "threat_level": d.threat_level.value,
                        "method": d.method,
                        "uri": d.uri,
                        "indicator": d.indicator,
                        "timestamp": d.timestamp,
                        "payload": d.payload,
                        "response_data": d.response_data[:500] if d.response_data else None
                    }
                    for d in summary.detections
                ],
                "extracted_files": [
                    {
                        "file_name": f.file_name,
                        "file_type": f.file_type,
                        "content_type": f.content_type
                    }
                    for f in summary.extracted_files
                ]
            }

            self.exportProgress.emit(50, "写入文件...")

            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)

            self.exportProgress.emit(100, "导出完成")
            self.exportFinished.emit(output_path)
            return True

        except Exception as e:
            self.exportError.emit(f"JSON导出失败: {str(e)}")
            return False

    def exportToHtml(self, summary: AnalysisSummary, output_path: str) -> bool:
        try:
            self.exportStarted.emit()
            self.exportProgress.emit(10, "生成HTML报告...")

            html_content = self._generateHtmlReport(summary)

            self.exportProgress.emit(80, "写入文件...")

            with open(output_path, "w", encoding="utf-8") as f:
                f.write(html_content)

            self.exportProgress.emit(100, "导出完成")
            self.exportFinished.emit(output_path)
            return True

        except Exception as e:
            self.exportError.emit(f"HTML导出失败: {str(e)}")
            return False

    def _generateHtmlReport(self, summary: AnalysisSummary) -> str:
        detections_html = ""
        for d in summary.detections:
            payload_str = ""
            if d.payload:
                if isinstance(d.payload, dict):
                    payload_str = json.dumps(d.payload, ensure_ascii=False, indent=2)[:500]
                else:
                    payload_str = str(d.payload)[:500]

            detections_html += f"""
            <tr>
                <td><span class="threat-{d.threat_level.value}">{d.threat_level.display_name}</span></td>
                <td>{d.detection_type.display_name}</td>
                <td>{d.method}</td>
                <td class="uri-cell" title="{d.uri}">{d.uri[:60]}{'...' if len(d.uri) > 60 else ''}</td>
                <td>{d.indicator}</td>
            </tr>
            """

        protocol_html = self._build_protocol_html(summary.protocol_stats, 0)

        html = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TingLan 听澜 - 分析报告</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: "Microsoft YaHei", sans-serif; background: #f5f5f5; color: #333; line-height: 1.6; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
        .header {{ background: linear-gradient(135deg, #1a237e 0%, #3949ab 100%); color: white; padding: 30px; border-radius: 8px; margin-bottom: 20px; }}
        .header h1 {{ font-size: 28px; margin-bottom: 10px; }}
        .header .meta {{ opacity: 0.9; font-size: 14px; }}
        .card {{ background: white; border-radius: 8px; padding: 20px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .card h2 {{ color: #1a237e; border-bottom: 2px solid #3949ab; padding-bottom: 10px; margin-bottom: 15px; }}
        .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; }}
        .summary-item {{ background: #f8f9fa; padding: 15px; border-radius: 6px; text-align: center; }}
        .summary-item .value {{ font-size: 28px; font-weight: bold; color: #1a237e; }}
        .summary-item .label {{ color: #666; font-size: 14px; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #eee; }}
        th {{ background: #f8f9fa; font-weight: 600; color: #1a237e; }}
        tr:hover {{ background: #f5f5f5; }}
        .uri-cell {{ max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
        .threat-critical {{ background: #9c27b0; color: white; padding: 2px 8px; border-radius: 4px; }}
        .threat-high {{ background: #f44336; color: white; padding: 2px 8px; border-radius: 4px; }}
        .threat-medium {{ background: #ff9800; color: white; padding: 2px 8px; border-radius: 4px; }}
        .threat-low {{ background: #4caf50; color: white; padding: 2px 8px; border-radius: 4px; }}
        .threat-info {{ background: #2196f3; color: white; padding: 2px 8px; border-radius: 4px; }}
        .footer {{ text-align: center; color: #999; padding: 20px; font-size: 12px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>TingLan 听澜 分析报告</h1>
            <div class="meta">
                <p>文件: {os.path.basename(summary.file_path)}</p>
                <p>生成时间: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
                <p>分析耗时: {summary.analysis_time:.2f}秒</p>
            </div>
        </div>

        <div class="card">
            <h2>摘要</h2>
            <div class="summary-grid">
                <div class="summary-item">
                    <div class="value">{summary.total_packets}</div>
                    <div class="label">总数据包</div>
                </div>
                <div class="summary-item">
                    <div class="value" style="color: #f44336;">{len(summary.detections)}</div>
                    <div class="label">检测到威胁</div>
                </div>
                <div class="summary-item">
                    <div class="value">{len(summary.protocol_stats)}</div>
                    <div class="label">协议类型</div>
                </div>
                <div class="summary-item">
                    <div class="value">{len(summary.extracted_files)}</div>
                    <div class="label">提取文件</div>
                </div>
            </div>
        </div>

        <div class="card">
            <h2>威胁检测 ({len(summary.detections)})</h2>
            {f'<table><thead><tr><th>威胁等级</th><th>类型</th><th>方法</th><th>URI</th><th>检测指标</th></tr></thead><tbody>{detections_html}</tbody></table>' if summary.detections else '<p style="color:#666;">未检测到威胁</p>'}
        </div>

        <div class="card">
            <h2>协议统计</h2>
            <table>
                <thead>
                    <tr><th>协议</th><th>数量</th><th>占比</th></tr>
                </thead>
                <tbody>
                    {protocol_html}
                </tbody>
            </table>
        </div>

        <div class="footer">
            <p>TingLan 听澜 - CTF流量分析工具</p>
        </div>
    </div>
</body>
</html>"""

        return html
