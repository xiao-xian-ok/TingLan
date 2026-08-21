# 导出控制器

import os
import json
import html
from datetime import datetime
from typing import Optional

from PySide6.QtCore import QObject, Signal

from models.detection_result import AnalysisSummary, DetectionResult


def _esc(value) -> str:
    """HTML 转义。**所有插值都必须过这里。**

    报告里的 URI、indicator、参数名、解码后的载荷片段全部是攻击者可控文本。
    不转义就等于把 payload 里的 `<script>` 原样写进报告 —— 分析员用浏览器
    打开报告的那一刻它就执行了，用取证工具给自己下毒。
    core/provenance_html.py 一开始就是这么做的，这里对齐。
    """
    return html.escape(str(value if value is not None else ""), quote=True)


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
        html_out = ""
        indent = "&nbsp;" * (depth * 4)
        for i, p in enumerate(stats):
            is_last = (i == len(stats) - 1)
            prefix = ("└─ " if is_last else "├─ ") if depth > 0 else ""
            html_out += (f'<tr><td>{indent}{prefix}{_esc(p.protocol)}</td>'
                         f'<td>{p.count}</td><td>{p.percentage:.1f}%</td></tr>\n')
            if p.children:
                html_out += self._build_protocol_html(p.children, depth + 1)
        return html_out

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
                        # 两个等级都留：threat_level 是规则判定的原始结论，
                        # effective_threat_level 叠加了"打成了没有"。降过档的
                        # 条目 downgrade_reason 非空，事后能复核也能回退。
                        "threat_level": d.threat_level.value,
                        "effective_threat_level": d.effective_threat_level.value,
                        "downgrade_reason": d.threat_downgrade_reason,
                        "success_outcome": d.success_outcome,
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

    def exportToProvenanceHtml(self, summary: AnalysisSummary, output_path: str) -> bool:
        """导出攻击溯源图（自包含 HTML）

        和 exportToHtml 的区别：那个是一张平铺的威胁表格，回答不了"谁打的、
        从哪进来、下一步做了什么"；这个把 summary 重组成有向图（攻击者 →
        目标 → 端点 → 落地物），边分 flow/causal/drop/temporal，并把 A/B/C
        成功研判的结论挂在节点上。

        建图是纯内存遍历（不读 pcap、不起 tshark），复杂度对检测条数线性，
        和现有的 exportToHtml 一样跑在 UI 线程上。
        """
        try:
            self.exportStarted.emit()
            self.exportProgress.emit(10, "构建攻击溯源图...")

            try:
                from core.provenance_html import export_provenance_html
            except ImportError as e:
                self.exportError.emit(f"溯源图模块不可用: {e}")
                return False

            self.exportProgress.emit(50, "渲染并写入文件...")
            graph = export_provenance_html(summary, output_path)

            stats = graph.stats or {}
            self.exportProgress.emit(
                100,
                f"溯源图完成: {stats.get('nodes', 0)} 个节点 / "
                f"{stats.get('edges', 0)} 条边",
            )
            self.exportFinished.emit(output_path)
            return True

        except Exception as e:
            self.exportError.emit(f"溯源图导出失败: {str(e)}")
            return False

    def _build_ast_html(self, summary: AnalysisSummary) -> str:
        """AST 语义分析段：解开的编码层 + 每层挖出来的危险调用

        这一段回答的是"eval 里到底装了什么"。数据来自
        webshell_detect._apply_ast_validation 写进 raw_result['ast_analysis']
        的结构，之前算完就躺在字典里没有任何出口。

        最有价值的是 nesting_depth > 0 的那些行 —— 它们是**解码之后才看见**
        的调用，原文里根本搜不到。报告要把这个"第几层"显式标出来，否则
        `system()` 和 `eval()` 在表格里长得一样，看不出谁套着谁。
        """
        rows = []
        chain_count = 0
        nested_count = 0
        notes_count = 0

        for det in summary.detections:
            raw = det.raw_result if isinstance(det.raw_result, dict) else {}
            analysis = raw.get("ast_analysis")
            if not isinstance(analysis, dict) or not analysis.get("results"):
                continue

            for item in analysis.get("results") or []:
                if not isinstance(item, dict):
                    continue

                chains = item.get("decode_chains") or []
                chain_text = "、".join(
                    " → ".join(str(c) for c in chain) for chain in chains
                ) or "—"
                if chains:
                    chain_count += 1

                calls = item.get("dangerous_calls") or []
                call_rows = []
                for call in calls:
                    if not isinstance(call, dict):
                        continue
                    depth = int(call.get("nesting_depth") or 0)
                    if depth > 0:
                        nested_count += 1
                    per_chain = " → ".join(
                        str(c) for c in (call.get("decode_chain") or [])) or "—"
                    taint = "是" if call.get("tainted") else "否"
                    # 解码后才看见的调用单独标色，这是整段的重点
                    cls = "nested" if depth > 0 else ""
                    label = f"第 {depth} 层" if depth > 0 else "原文可见"
                    call_rows.append(
                        f'<tr class="{cls}">'
                        f'<td><code>{_esc(call.get("func"))}()</code></td>'
                        f'<td>{int(call.get("severity") or 0)}</td>'
                        f'<td>{taint}</td>'
                        f'<td><b>{label}</b></td>'
                        f'<td><code>{_esc(per_chain)}</code></td>'
                        f'</tr>'
                    )

                flags = []
                if item.get("windowed"):
                    flags.append('<span class="warn">滑窗分段分析，'
                                 '跨窗口污点链可能不完整</span>')
                notes = item.get("decode_notes") or []
                if notes:
                    notes_count += 1
                    flags.append('<span class="warn">解码预算耗尽：'
                                 f'{_esc("、".join(str(n) for n in notes))} '
                                 '—— 部分编码内容未被展开</span>')
                if item.get("is_likely_webshell"):
                    flags.append('<span class="hit">语义判定为 WebShell</span>')

                obf = item.get("obfuscation_score")
                if isinstance(obf, (int, float)) and obf > 0:
                    flags.append(f'混淆评分 {obf:.0%}')

                direction = ("请求侧（攻击者投递）"
                             if item.get("direction") != "response"
                             else "响应侧（服务器回显）")

                rows.append(f"""
            <div class="ast-item">
                <div class="ast-head">
                    <code>{_esc(det.uri)}</code>
                    &nbsp;参数 <b>{_esc(item.get("param"))}</b>
                    &nbsp;<span class="tag">{direction}</span>
                </div>
                <div class="ast-chain">解码链：<code>{_esc(chain_text)}</code></div>
                {'<div class="ast-flags">' + ' · '.join(flags) + '</div>' if flags else ''}
                {'<table class="ast-calls"><thead><tr><th>危险函数</th><th>严重度</th>'
                 '<th>参数可控</th><th>发现位置</th><th>走到它的解码链</th></tr></thead>'
                 '<tbody>' + ''.join(call_rows) + '</tbody></table>' if call_rows else ''}
            </div>""")

        if not rows:
            return ""

        return f"""
        <div class="card">
            <h2>AST 语义分析 —— 编码载荷还原</h2>
            <p class="hint">
                共 {len(rows)} 个参数经过语法树分析，其中 {chain_count} 个存在编码层，
                <b>{nested_count} 个危险调用是解码之后才被发现的</b>（原文里搜不到）。
                {f'{notes_count} 个参数因解码预算耗尽未被完全展开。' if notes_count else ''}
            </p>
            {''.join(rows)}
        </div>"""

    def _build_coverage_html(self) -> str:
        """覆盖率审计段：有多少载荷没被完整分析

        取证工具里"我没看"和"我看了没问题"是两个结论，混成一个 SKIP 就等于
        把盲区伪装成阴性。这段把 core/fast_filter._CoverageAudit 攒的计数和
        采样倒出来 —— 那份数据一直在算，只是从来没有出口。
        """
        try:
            from core.fast_filter import get_coverage_audit
            stats = get_coverage_audit().get_stats()
        except Exception:
            return ""

        if not isinstance(stats, dict) or not stats.get("payloads_seen"):
            return ""

        seen = stats.get("payloads_seen", 0)
        incomplete = stats.get("incomplete_analysis", 0)
        rate = stats.get("incomplete_rate", "0.00%")

        if not incomplete:
            body = ('<p class="ok">本次进入过滤层的 '
                    f'{seen} 个载荷全部被完整扫描，无覆盖盲区。</p>')
        else:
            reason_rows = "".join(
                f"<tr><td>{_esc(k)}</td><td>{v}</td></tr>"
                for k, v in sorted((stats.get("by_reason") or {}).items(),
                                   key=lambda kv: -kv[1])
            )
            sample_rows = "".join(
                f"<tr><td>{_esc(s.get('reason'))}</td>"
                f"<td>{s.get('payload_len', 0)}</td>"
                f"<td>{s.get('scanned_len', 0)}</td>"
                f"<td><code>{_esc('、'.join(s.get('keywords') or []) or '—')}</code></td></tr>"
                for s in (stats.get("samples") or [])
            )
            body = f"""
            <p class="warn-block">
                进入过滤层的 {seen} 个载荷中，<b>{incomplete} 个（{_esc(rate)}）
                未被完整分析</b>。这些载荷的"未命中"不等于"安全"，建议人工复核。
            </p>
            <h3>按原因分布</h3>
            <table><thead><tr><th>原因</th><th>数量</th></tr></thead>
            <tbody>{reason_rows}</tbody></table>
            <h3>样本（最多 50 条）</h3>
            <table><thead><tr><th>原因</th><th>载荷长度</th><th>实际扫描</th>
            <th>已命中关键字</th></tr></thead>
            <tbody>{sample_rows}</tbody></table>"""

        return f"""
        <div class="card">
            <h2>分析覆盖率审计</h2>
            <p class="hint">
                统计口径为<b>本进程累计</b>：一次程序运行内分析过的所有文件都会计入，
                打开新文件不会重置。分母是"进入过滤层的载荷"，不是全部数据包 ——
                纯净流量在更早的阶段就被排除了，走不到这一层。
            </p>
            {body}
        </div>"""

    def _generateHtmlReport(self, summary: AnalysisSummary) -> str:
        detections_html = ""
        downgraded = 0
        for d in summary.detections:
            uri_short = d.uri[:60] + ('...' if len(d.uri) > 60 else '')

            # 等级列显示**有效**等级（叠加了"打成了没有"），降过档的把原判
            # 一并写出来。只写降后的会让人以为规则本来就只匹配到这一档，
            # 只写原判又会让一屏 404 扫描噪声全是红的 —— 两个都得在。
            level = d.effective_threat_level
            if d.threat_downgrade_steps:
                downgraded += 1
                badge = d.threat_downgrade_badge
                level_cell = (
                    f'<span class="threat-{_esc(level.value)}">{_esc(level.display_name)}</span>'
                    f'<span class="demoted" title="{_esc(d.threat_downgrade_note)}，'
                    f'已降 {d.threat_downgrade_steps} 档；原始权重 {d.total_weight} 未修改">'
                    f'原{_esc(d.threat_level.display_name)} · {_esc(badge)}</span>'
                )
            else:
                level_cell = (f'<span class="threat-{_esc(level.value)}">'
                              f'{_esc(level.display_name)}</span>')

            detections_html += f"""
            <tr>
                <td>{level_cell}</td>
                <td>{_esc(d.detection_type.display_name)}</td>
                <td>{_esc(d.method)}</td>
                <td class="uri-cell" title="{_esc(d.uri)}">{_esc(uri_short)}</td>
                <td>{_esc(d.indicator)}</td>
            </tr>
            """

        downgrade_note = (
            f'<p class="hint">其中 <b>{downgraded}</b> 条因服务器返回失败状态码'
            f'（400/401/403/404/405/406/410/501）且研判为未生效而降低了显示等级，'
            f'原始判定与权重未被修改，JSON 导出中两个等级都在。'
            f'有反弹连接、主机侧证据、AST 污点或带外特征的条目不参与降档。</p>'
        ) if downgraded else ""

        protocol_html = self._build_protocol_html(summary.protocol_stats, 0)
        ast_html = self._build_ast_html(summary)
        coverage_html = self._build_coverage_html()

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
        /* 降过档的条目：原判和状态码跟在有效等级后面，小字灰底，不抢视线 */
        .demoted {{ display: inline-block; margin-left: 6px; background: #eceff1;
                    color: #607d8b; padding: 1px 7px; border-radius: 4px;
                    font-size: 12px; white-space: nowrap; cursor: help; }}
        .footer {{ text-align: center; color: #999; padding: 20px; font-size: 12px; }}
        /* ---- AST 语义分析段 ---- */
        code {{ font-family: Consolas, "Courier New", monospace; background: #f3f4f6;
                padding: 1px 5px; border-radius: 3px; font-size: 13px; word-break: break-all; }}
        .hint {{ color: #666; font-size: 13px; margin-bottom: 14px; }}
        .ast-item {{ border: 1px solid #e0e0e0; border-left: 4px solid #3949ab;
                     border-radius: 6px; padding: 14px; margin-bottom: 14px; }}
        .ast-head {{ font-size: 14px; margin-bottom: 6px; }}
        .ast-chain {{ color: #444; font-size: 13px; margin-bottom: 6px; }}
        .ast-flags {{ font-size: 13px; color: #666; margin-bottom: 8px; }}
        .ast-calls {{ margin-top: 8px; }}
        .ast-calls th, .ast-calls td {{ padding: 7px 10px; font-size: 13px; }}
        /* 解码之后才看见的调用 —— 这是整段的重点，必须一眼能挑出来 */
        .ast-calls tr.nested {{ background: #fff5e6; }}
        .ast-calls tr.nested td {{ border-bottom: 1px solid #ffd699; }}
        .tag {{ background: #eef1f8; color: #3949ab; padding: 1px 8px;
                border-radius: 10px; font-size: 12px; }}
        .hit {{ color: #c62828; font-weight: 600; }}
        .warn {{ color: #e65100; }}
        .warn-block {{ background: #fff8e1; border-left: 4px solid #ff9800;
                       padding: 12px; border-radius: 4px; margin-bottom: 14px; }}
        .ok {{ background: #e8f5e9; border-left: 4px solid #4caf50;
               padding: 12px; border-radius: 4px; color: #2e7d32; }}
        h3 {{ color: #3949ab; font-size: 15px; margin: 16px 0 8px; }}
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
            {downgrade_note}
            {f'<table><thead><tr><th>威胁等级</th><th>类型</th><th>方法</th><th>URI</th><th>检测指标</th></tr></thead><tbody>{detections_html}</tbody></table>' if summary.detections else '<p style="color:#666;">未检测到威胁</p>'}
        </div>
{ast_html}
{coverage_html}

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
