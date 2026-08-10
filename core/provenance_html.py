# provenance_html.py - 溯源图 HTML 渲染
#
# 产出一个自包含的单文件 HTML：内联 SVG + 内联 CSS + 一小段原生 JS。
# 不引 CDN、不引模板引擎（requirements.txt 里虽然列了 jinja2，但全项目
# 没有一处 import，现有 export_controller 走的是 f-string，保持一致），
# 断网、拷到 U 盘、丢进比赛环境都能直接打开。
#
# 两个刻意的决定：
#   1. 布局在 Python 侧算死，SVG 直接吐出来。JS 只做平移缩放/过滤/看详情，
#      即使 JS 被禁用，图本身照样是完整可读的。
#   2. 所有插值一律 html.escape。URI、payload、indicator 全是攻击者可控文本，
#      一个分析工具的报告绝不能在分析师打开时执行攻击者塞进来的脚本。

import html
import json
import os
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from core.provenance import (
    KIND_META, STAGE_COLORS, STAGE_LABELS, STAGES,
    ProvenanceGraph, ProvenanceNode, build_provenance_graph,
)

# 画布几何
NODE_W = 200
NODE_H = 56
COL_GAP = 96
ROW_GAP = 26
PAD_X = 48
PAD_Y = 78          # 顶部给列标题留位置

THREAT_COLORS = {
    "critical": "#9C27B0",
    "high": "#F44336",
    "medium": "#FF9800",
    "low": "#4CAF50",
    "info": "#2196F3",
}

THREAT_LABELS = {
    "critical": "严重",
    "high": "高危",
    "medium": "中危",
    "low": "低危",
    "info": "信息",
}

EDGE_STYLES = {
    # kind: (颜色, 线宽, 虚线, 中文名)
    "flow":     ("#B0BEC5", 1.4, "",      "访问流量"),
    "drop":     ("#D81B60", 1.8, "",      "文件落地 / 数据带出"),
    "causal":   ("#7B1FA2", 2.6, "",      "因果关联"),
    "temporal": ("#90A4AE", 1.4, "5,4",   "同会话时序推进"),
}

_COL_ATTACKER = "__attacker"
_COL_TARGET = "__target"

COLUMN_TITLES = {
    _COL_ATTACKER: "攻击者",
    _COL_TARGET: "目标",
}
COLUMN_TITLES.update(STAGE_LABELS)

COLUMN_COLORS = {
    _COL_ATTACKER: KIND_META["attacker"][1],
    _COL_TARGET: KIND_META["target"][1],
}
COLUMN_COLORS.update(STAGE_COLORS)


# ---------------------------------------------------------------- 工具

def _e(value: Any) -> str:
    """所有进 HTML 的文本都过这里"""
    return html.escape(str(value if value is not None else ""), quote=True)


def _truncate(text: str, limit: int) -> str:
    text = str(text or "")
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _json_for_script(data: Any) -> str:
    """嵌进 <script> 的 JSON。必须切断 </script>，否则内容能提前闭合标签。"""
    blob = json.dumps(data, ensure_ascii=False)
    return blob.replace("</", "<\\/").replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")


# ---------------------------------------------------------------- 布局

def _column_of(node: ProvenanceNode) -> str:
    if node.kind == "attacker":
        return _COL_ATTACKER
    if node.kind == "target":
        return _COL_TARGET
    return node.stage or "exploit"


def _layout(graph: ProvenanceGraph) -> Tuple[Dict[str, Tuple[float, float]],
                                             List[Tuple[str, float]], float, float]:
    """把节点排进按阶段划分的列里

    返回 (节点 id -> (x, y), [(列 key, 列中心 x)], 画布宽, 画布高)
    空列直接跳过，免得图上出现大片留白。
    """
    order = [_COL_ATTACKER, _COL_TARGET] + [key for key, _, _ in STAGES]
    buckets: Dict[str, List[ProvenanceNode]] = {key: [] for key in order}
    for node in graph.nodes:
        buckets.setdefault(_column_of(node), []).append(node)

    used = [key for key in order if buckets.get(key)]
    if not used:
        return {}, [], 480.0, 240.0

    for key in used:
        # 列内按首次出现的帧号排，同帧按标签，保证输出确定
        buckets[key].sort(key=lambda n: (n.first_frame or 10 ** 9, n.label, n.id))

    tallest = max(len(buckets[key]) for key in used)
    canvas_h = PAD_Y + tallest * NODE_H + max(0, tallest - 1) * ROW_GAP + PAD_Y * 0.4
    canvas_w = PAD_X * 2 + len(used) * NODE_W + max(0, len(used) - 1) * COL_GAP

    positions: Dict[str, Tuple[float, float]] = {}
    headers: List[Tuple[str, float]] = []

    for col_index, key in enumerate(used):
        nodes = buckets[key]
        x = PAD_X + col_index * (NODE_W + COL_GAP)
        headers.append((key, x + NODE_W / 2))
        block_h = len(nodes) * NODE_H + max(0, len(nodes) - 1) * ROW_GAP
        top = PAD_Y + (canvas_h - PAD_Y - PAD_Y * 0.4 - block_h) / 2
        for row, node in enumerate(nodes):
            positions[node.id] = (x, top + row * (NODE_H + ROW_GAP))

    return positions, headers, canvas_w, canvas_h


def _edge_path(x1: float, y1: float, x2: float, y2: float) -> str:
    """节点右缘 -> 节点左缘的三次贝塞尔。回指的边绕远一点，避免压在节点上。"""
    if x2 > x1:
        dx = max(42.0, (x2 - x1) * 0.45)
        return f"M{x1:.1f},{y1:.1f} C{x1 + dx:.1f},{y1:.1f} {x2 - dx:.1f},{y2:.1f} {x2:.1f},{y2:.1f}"
    # 同列或回指：向外兜一个弧
    dx = 70.0
    lift = 46.0 if y2 >= y1 else -46.0
    return (f"M{x1:.1f},{y1:.1f} C{x1 + dx:.1f},{y1 + lift:.1f} "
            f"{x2 - dx:.1f},{y2 + lift:.1f} {x2:.1f},{y2:.1f}")


# ---------------------------------------------------------------- SVG

def _render_defs() -> str:
    markers = []
    for kind, (color, _, _, _) in EDGE_STYLES.items():
        markers.append(
            f'<marker id="arrow-{_e(kind)}" viewBox="0 0 10 10" refX="9" refY="5" '
            f'markerWidth="7" markerHeight="7" orient="auto-start-reverse">'
            f'<path d="M0,0 L10,5 L0,10 z" fill="{_e(color)}"/></marker>'
        )
    markers.append(
        '<filter id="nodeShadow" x="-20%" y="-20%" width="140%" height="140%">'
        '<feDropShadow dx="0" dy="1" stdDeviation="1.6" flood-color="#0f172a" '
        'flood-opacity="0.16"/></filter>'
    )
    return "<defs>" + "".join(markers) + "</defs>"


def _render_headers(headers: List[Tuple[str, float]], canvas_h: float) -> str:
    parts = []
    for key, cx in headers:
        title = COLUMN_TITLES.get(key, key)
        color = COLUMN_COLORS.get(key, "#607D8B")
        parts.append(
            f'<g class="col-head">'
            f'<line x1="{cx:.1f}" y1="52" x2="{cx:.1f}" y2="{canvas_h - 16:.1f}" '
            f'stroke="{_e(color)}" stroke-opacity="0.10" stroke-width="{NODE_W + 30}"/>'
            f'<text x="{cx:.1f}" y="34" text-anchor="middle" class="col-title" '
            f'fill="{_e(color)}">{_e(title)}</text>'
            f'</g>'
        )
    return "".join(parts)


def _render_edges(graph: ProvenanceGraph,
                  positions: Dict[str, Tuple[float, float]]) -> str:
    parts = []
    for edge in graph.edges:
        src = positions.get(edge.src)
        dst = positions.get(edge.dst)
        if not src or not dst:
            continue
        color, width, dash, _ = EDGE_STYLES.get(edge.kind, EDGE_STYLES["flow"])
        x1, y1 = src[0] + NODE_W, src[1] + NODE_H / 2
        x2, y2 = dst[0], dst[1] + NODE_H / 2
        dash_attr = f' stroke-dasharray="{dash}"' if dash else ""
        # count 越大线越粗，但设上限，免得一条边糊掉整张图
        stroke_w = min(width + (edge.count - 1) * 0.25, width + 2.2)
        title = f"{EDGE_STYLES.get(edge.kind, EDGE_STYLES['flow'])[3]}"
        if edge.label:
            title += f" · {edge.label}"
        if edge.count > 1:
            title += f" ×{edge.count}"
        parts.append(
            f'<g class="edge" data-kind="{_e(edge.kind)}" '
            f'data-src="{_e(edge.src)}" data-dst="{_e(edge.dst)}">'
            f'<path d="{_edge_path(x1, y1, x2, y2)}" fill="none" '
            f'stroke="{_e(color)}" stroke-width="{stroke_w:.2f}"{dash_attr} '
            f'marker-end="url(#arrow-{_e(edge.kind)})" stroke-linecap="round">'
            f'<title>{_e(title)}</title></path></g>'
        )
    return "".join(parts)


def _render_nodes(graph: ProvenanceGraph,
                  positions: Dict[str, Tuple[float, float]]) -> str:
    parts = []
    for node in graph.nodes:
        pos = positions.get(node.id)
        if not pos:
            continue
        x, y = pos
        kind_label, kind_color = KIND_META.get(node.kind, ("节点", "#607D8B"))
        accent = THREAT_COLORS.get(node.threat, kind_color)
        badge = ""
        if node.events > 1:
            badge = (
                f'<circle cx="{x + NODE_W - 14:.1f}" cy="{y + 14:.1f}" r="10" '
                f'fill="{_e(accent)}"/>'
                f'<text x="{x + NODE_W - 14:.1f}" y="{y + 18:.1f}" '
                f'text-anchor="middle" class="node-badge">{_e(min(node.events, 99))}</text>'
            )
        parts.append(
            f'<g class="node" data-id="{_e(node.id)}" data-stage="{_e(node.stage)}" '
            f'data-kind="{_e(node.kind)}" tabindex="0">'
            f'<rect x="{x:.1f}" y="{y:.1f}" width="{NODE_W}" height="{NODE_H}" rx="9" '
            f'class="node-box" filter="url(#nodeShadow)"/>'
            f'<rect x="{x:.1f}" y="{y:.1f}" width="5" height="{NODE_H}" rx="2.5" '
            f'fill="{_e(accent)}"/>'
            f'<text x="{x + 16:.1f}" y="{y + 24:.1f}" class="node-label">'
            f'{_e(_truncate(node.label, 24))}</text>'
            f'<text x="{x + 16:.1f}" y="{y + 42:.1f}" class="node-sub">'
            f'{_e(_truncate(node.sublabel or kind_label, 28))}</text>'
            f'{badge}'
            f'<title>{_e(node.label)}</title>'
            f'</g>'
        )
    return "".join(parts)


# ---------------------------------------------------------------- 面板

def _render_summary_cards(graph: ProvenanceGraph) -> str:
    stats = graph.stats or {}
    attackers = stats.get("attackers") or []
    targets = stats.get("targets") or []
    outcomes = stats.get("outcome_counts") or {}

    # "打成了没有"才是应急现场第一个要回答的问题，放在检测条目前面。
    # 研判没跑过（outcome_counts 为空）时如实说"未研判"，不要显示成 0 ——
    # "没判过"和"判过但都没得手"是两个完全不同的结论。
    confirmed = int(outcomes.get("confirmed", 0))
    suspected = int(outcomes.get("suspected", 0))
    if outcomes:
        landed_value = str(confirmed)
        landed_sub = f"疑似 {suspected} · 未生效 {int(outcomes.get('failed', 0))}"
        landed_color = "#C62828" if confirmed else ("#EF6C00" if suspected else "#2E7D32")
    else:
        landed_value = "—"
        landed_sub = "本次未执行成功研判"
        landed_color = "#757575"

    cards = [
        ("确认得手", landed_value, landed_sub, landed_color),
        ("攻击者", str(len(attackers)), ", ".join(attackers[:3]) or "—", "#1976D2"),
        ("目标主机", str(len(targets)), ", ".join(targets[:3]) or "—", "#455A64"),
        ("检测条目", str(stats.get("detections", 0)), "命中的可疑请求", "#F44336"),
        ("因果关联", str(stats.get("causal_edges", 0)), "上传→执行等强关联", "#7B1FA2"),
        ("图规模", f'{stats.get("nodes", 0)} / {stats.get("edges", 0)}', "节点 / 边", "#00838F"),
    ]
    out = []
    for title, value, sub, color in cards:
        out.append(
            f'<div class="card"><div class="card-title">{_e(title)}</div>'
            f'<div class="card-value" style="color:{_e(color)}">{_e(value)}</div>'
            f'<div class="card-sub">{_e(sub)}</div></div>'
        )
    return "".join(out)


def _render_stage_filters(graph: ProvenanceGraph) -> str:
    counts = graph.stage_counts()
    out = []
    for key, label, color in STAGES:
        count = counts.get(key, 0)
        disabled = "" if count else " disabled"
        out.append(
            f'<label class="chip{" chip-off" if not count else ""}">'
            f'<input type="checkbox" data-stage="{_e(key)}" checked{disabled}>'
            f'<span class="dot" style="background:{_e(color)}"></span>'
            f'{_e(label)} <b>{_e(count)}</b></label>'
        )
    return "".join(out)


def _render_legend() -> str:
    out = ['<div class="legend-group"><span class="legend-head">节点</span>']
    for kind, (label, color) in KIND_META.items():
        out.append(f'<span class="legend-item"><i class="sw" '
                   f'style="background:{_e(color)}"></i>{_e(label)}</span>')
    out.append('</div><div class="legend-group"><span class="legend-head">连线</span>')
    for kind, (color, _, dash, label) in EDGE_STYLES.items():
        style = f"background:{color}"
        if dash:
            style = (f"background:repeating-linear-gradient(90deg,{color} 0 5px,"
                     f"transparent 5px 9px)")
        out.append(f'<span class="legend-item"><i class="ln" style="{_e(style)}"></i>'
                   f'{_e(label)}</span>')
    out.append("</div>")
    return "".join(out)


def _render_timeline(graph: ProvenanceGraph) -> str:
    if not graph.timeline:
        return '<p class="muted">没有可排序的事件。</p>'
    rows = []
    for event in graph.timeline[:400]:
        color = THREAT_COLORS.get(event.threat, "#607D8B")
        stage_label = STAGE_LABELS.get(event.stage, event.stage or "—")
        frame_text = f"#{event.frame}" if event.frame else "—"
        rows.append(
            f'<li class="tl-item" data-node="{_e(event.node)}" '
            f'data-stage="{_e(event.stage)}">'
            f'<span class="tl-frame">{_e(frame_text)}</span>'
            f'<span class="tl-stage" style="color:{_e(color)}">{_e(stage_label)}</span>'
            f'<span class="tl-label">{_e(_truncate(event.label, 64))}</span>'
            f'</li>'
        )
    more = ""
    if len(graph.timeline) > 400:
        more = (f'<li class="muted tl-more">另有 '
                f'{_e(len(graph.timeline) - 400)} 条事件未列出</li>')
    return f'<ol class="timeline">{"".join(rows)}{more}</ol>'


# ---------------------------------------------------------------- 主入口

def render_provenance_html(graph: ProvenanceGraph,
                           title: str = "TingLan 听澜 - 攻击溯源图") -> str:
    positions, headers, canvas_w, canvas_h = _layout(graph)

    node_payload = {n.id: n.to_dict() for n in graph.nodes}
    file_name = os.path.basename(graph.file_path) if graph.file_path else "未知文件"
    generated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    frame_range = (graph.stats or {}).get("frame_range") or [0, 0]

    if graph.is_empty:
        canvas_body = (
            f'<text x="{canvas_w / 2:.0f}" y="{canvas_h / 2:.0f}" text-anchor="middle" '
            f'class="empty-hint">没有可用于溯源的检测结果</text>'
        )
    else:
        canvas_body = (
            _render_headers(headers, canvas_h)
            + _render_edges(graph, positions)
            + _render_nodes(graph, positions)
        )

    return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{_e(title)}</title>
<style>
* {{ margin:0; padding:0; box-sizing:border-box; }}
body {{ font-family:"Microsoft YaHei","PingFang SC",sans-serif; background:#eef1f5;
       color:#1f2933; line-height:1.55; }}
.wrap {{ max-width:1560px; margin:0 auto; padding:20px; }}
header.hero {{ background:linear-gradient(135deg,#12213f 0%,#2f4b8f 100%); color:#fff;
       padding:24px 28px; border-radius:12px; margin-bottom:18px; }}
header.hero h1 {{ font-size:24px; margin-bottom:6px; }}
header.hero .meta {{ font-size:13px; opacity:.88; }}
header.hero .meta span {{ margin-right:18px; white-space:nowrap; }}
.cards {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(184px,1fr));
       gap:12px; margin-bottom:18px; }}
.card {{ background:#fff; border-radius:10px; padding:14px 16px;
       box-shadow:0 1px 3px rgba(15,23,42,.10); }}
.card-title {{ font-size:12px; color:#64748b; }}
.card-value {{ font-size:26px; font-weight:700; line-height:1.2; }}
.card-sub {{ font-size:11px; color:#94a3b8; overflow:hidden; text-overflow:ellipsis;
       white-space:nowrap; }}
.panel {{ background:#fff; border-radius:12px; box-shadow:0 1px 3px rgba(15,23,42,.10);
       margin-bottom:18px; }}
.panel-head {{ display:flex; flex-wrap:wrap; gap:12px; align-items:center;
       padding:12px 16px; border-bottom:1px solid #e8edf3; }}
.panel-head h2 {{ font-size:15px; color:#12213f; margin-right:4px; }}
.chip {{ display:inline-flex; align-items:center; gap:6px; font-size:12px;
       background:#f1f5f9; border-radius:999px; padding:4px 11px; cursor:pointer;
       user-select:none; }}
.chip.chip-off {{ opacity:.45; cursor:not-allowed; }}
.chip input {{ cursor:pointer; }}
.chip .dot {{ width:9px; height:9px; border-radius:50%; display:inline-block; }}
.tools {{ margin-left:auto; display:flex; gap:8px; align-items:center; }}
.tools input[type=search] {{ font:inherit; font-size:12px; padding:5px 10px;
       border:1px solid #d7dee8; border-radius:6px; width:190px; }}
.tools button {{ font:inherit; font-size:12px; padding:5px 12px; border:1px solid #d7dee8;
       background:#fff; border-radius:6px; cursor:pointer; }}
.tools button:hover {{ background:#f1f5f9; }}
.stage {{ display:flex; align-items:stretch; min-height:460px; }}
.canvas-wrap {{ flex:1; overflow:hidden; position:relative; background:
       linear-gradient(#f7f9fc 1px,transparent 1px) 0 0/100% 26px,
       linear-gradient(90deg,#f7f9fc 1px,transparent 1px) 0 0/26px 100%, #fff;
       border-radius:0 0 0 12px; cursor:grab; }}
.canvas-wrap.dragging {{ cursor:grabbing; }}
svg {{ display:block; width:100%; height:100%; min-height:460px; }}
.col-title {{ font-size:13px; font-weight:700; }}
.node {{ cursor:pointer; }}
.node .node-box {{ fill:#fff; stroke:#dbe2ec; stroke-width:1; }}
.node:hover .node-box {{ stroke:#2f4b8f; stroke-width:1.8; }}
.node.sel .node-box {{ stroke:#7B1FA2; stroke-width:2.4; }}
.node.dim, .edge.dim {{ opacity:.10; }}
.node.hidden, .edge.hidden {{ display:none; }}
.node-label {{ font-size:13px; font-weight:600; fill:#1f2933; }}
.node-sub {{ font-size:11px; fill:#8494a7; }}
.node-badge {{ font-size:10px; font-weight:700; fill:#fff; }}
.empty-hint {{ font-size:15px; fill:#94a3b8; }}
.side {{ width:330px; border-left:1px solid #e8edf3; padding:14px 16px; overflow-y:auto;
       max-height:640px; }}
.side h3 {{ font-size:14px; color:#12213f; margin-bottom:4px; }}
.side .kindtag {{ display:inline-block; font-size:11px; color:#fff; border-radius:4px;
       padding:1px 7px; margin-bottom:10px; }}
.kv {{ display:grid; grid-template-columns:80px 1fr; gap:4px 10px; font-size:12px;
       margin-bottom:12px; }}
.kv dt {{ color:#8494a7; }}
.kv dd {{ color:#1f2933; word-break:break-all; }}
.muted {{ color:#94a3b8; font-size:12px; }}
.legend {{ display:flex; flex-wrap:wrap; gap:18px; padding:10px 16px; font-size:11px;
       color:#64748b; border-top:1px solid #e8edf3; }}
.legend-group {{ display:flex; align-items:center; gap:10px; flex-wrap:wrap; }}
.legend-head {{ font-weight:700; color:#475569; }}
.legend-item {{ display:inline-flex; align-items:center; gap:5px; }}
.sw {{ width:10px; height:10px; border-radius:3px; display:inline-block; }}
.ln {{ width:22px; height:3px; border-radius:2px; display:inline-block; }}
.timeline {{ list-style:none; padding:6px 0; max-height:340px; overflow-y:auto; }}
.tl-item {{ display:grid; grid-template-columns:64px 52px 1fr; gap:10px; font-size:12px;
       padding:5px 16px; cursor:pointer; border-left:3px solid transparent; }}
.tl-item:hover {{ background:#f6f8fb; border-left-color:#2f4b8f; }}
.tl-item.hidden {{ display:none; }}
.tl-more {{ padding:6px 16px; }}
.tl-frame {{ color:#94a3b8; font-family:Consolas,monospace; }}
.tl-stage {{ font-weight:600; }}
.tl-label {{ color:#334155; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }}
footer {{ text-align:center; color:#94a3b8; font-size:12px; padding:14px; }}
@media print {{ .tools, .side {{ display:none; }} body {{ background:#fff; }} }}
</style>
</head>
<body>
<div class="wrap">

<header class="hero">
  <h1>攻击溯源图</h1>
  <div class="meta">
    <span>文件：{_e(file_name)}</span>
    <span>生成时间：{generated}</span>
    <span>总包数：{_e(graph.total_packets)}</span>
    <span>分析耗时：{graph.analysis_time:.2f}s</span>
    <span>帧范围：#{_e(frame_range[0])} – #{_e(frame_range[1])}</span>
  </div>
</header>

<div class="cards">{_render_summary_cards(graph)}</div>

<section class="panel">
  <div class="panel-head">
    <h2>攻击链路</h2>
    {_render_stage_filters(graph)}
    <div class="tools">
      <input type="search" id="q" placeholder="搜索节点 / 路径…" autocomplete="off">
      <button type="button" id="fit">适应窗口</button>
      <button type="button" id="reset">重置</button>
    </div>
  </div>
  <div class="stage">
    <div class="canvas-wrap" id="cw">
      <svg id="svg" viewBox="0 0 {canvas_w:.0f} {canvas_h:.0f}"
           preserveAspectRatio="xMidYMid meet">
        {_render_defs()}
        <g id="scene">{canvas_body}</g>
      </svg>
    </div>
    <aside class="side" id="side">
      <p class="muted">点击任意节点查看详情。滚轮缩放，按住拖动平移。</p>
    </aside>
  </div>
  <div class="legend">{_render_legend()}</div>
</section>

<section class="panel">
  <div class="panel-head"><h2>时间线</h2>
    <span class="muted">按帧号排序，点击可定位到图上的节点</span></div>
  {_render_timeline(graph)}
</section>

<footer>TingLan 听澜 · CTF 流量分析工具 · 本页面为离线自包含文件</footer>
</div>

<script>
(function () {{
  "use strict";
  var NODES = {_json_for_script(node_payload)};
  var VIEW = {{x: 0, y: 0, w: {canvas_w:.0f}, h: {canvas_h:.0f}}};
  var BASE = {{x: 0, y: 0, w: {canvas_w:.0f}, h: {canvas_h:.0f}}};
  var THREATS = {_json_for_script(THREAT_LABELS)};
  var STAGE_NAMES = {_json_for_script(STAGE_LABELS)};
  var KINDS = {_json_for_script({k: v[0] for k, v in KIND_META.items()})};
  var KIND_COLORS = {_json_for_script({k: v[1] for k, v in KIND_META.items()})};

  var svg = document.getElementById('svg');
  var wrap = document.getElementById('cw');
  var side = document.getElementById('side');
  var nodes = Array.prototype.slice.call(svg.querySelectorAll('.node'));
  var edges = Array.prototype.slice.call(svg.querySelectorAll('.edge'));
  var tlItems = Array.prototype.slice.call(document.querySelectorAll('.tl-item'));
  var selected = null;

  function applyView() {{
    svg.setAttribute('viewBox', VIEW.x + ' ' + VIEW.y + ' ' + VIEW.w + ' ' + VIEW.h);
  }}

  // ---- 缩放 / 平移 ----
  wrap.addEventListener('wheel', function (ev) {{
    ev.preventDefault();
    var rect = wrap.getBoundingClientRect();
    var fx = (ev.clientX - rect.left) / rect.width;
    var fy = (ev.clientY - rect.top) / rect.height;
    var k = ev.deltaY > 0 ? 1.12 : 1 / 1.12;
    var nw = Math.min(BASE.w * 6, Math.max(BASE.w * 0.15, VIEW.w * k));
    var nh = nw * (VIEW.h / VIEW.w);
    VIEW.x += (VIEW.w - nw) * fx;
    VIEW.y += (VIEW.h - nh) * fy;
    VIEW.w = nw; VIEW.h = nh;
    applyView();
  }}, {{passive: false}});

  var dragging = false, lastX = 0, lastY = 0;
  wrap.addEventListener('mousedown', function (ev) {{
    dragging = true; lastX = ev.clientX; lastY = ev.clientY;
    wrap.classList.add('dragging');
  }});
  window.addEventListener('mouseup', function () {{
    dragging = false; wrap.classList.remove('dragging');
  }});
  window.addEventListener('mousemove', function (ev) {{
    if (!dragging) return;
    var rect = wrap.getBoundingClientRect();
    VIEW.x -= (ev.clientX - lastX) * (VIEW.w / rect.width);
    VIEW.y -= (ev.clientY - lastY) * (VIEW.h / rect.height);
    lastX = ev.clientX; lastY = ev.clientY;
    applyView();
  }});

  document.getElementById('fit').addEventListener('click', function () {{
    VIEW = {{x: BASE.x, y: BASE.y, w: BASE.w, h: BASE.h}}; applyView();
  }});
  document.getElementById('reset').addEventListener('click', function () {{
    VIEW = {{x: BASE.x, y: BASE.y, w: BASE.w, h: BASE.h}}; applyView();
    document.getElementById('q').value = '';
    document.querySelectorAll('.chip input').forEach(function (c) {{
      if (!c.disabled) c.checked = true;
    }});
    clearSelection(); applyFilters(); applySearch('');
  }});

  // ---- 详情面板 ----
  function esc(s) {{
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {{
      return {{'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}}[c];
    }});
  }}

  function showDetail(id) {{
    var d = NODES[id];
    if (!d) return;
    var rows = '';
    rows += '<dt>类别</dt><dd>' + esc(KINDS[d.kind] || d.kind) + '</dd>';
    if (d.stage) rows += '<dt>阶段</dt><dd>' + esc(STAGE_NAMES[d.stage] || d.stage) + '</dd>';
    rows += '<dt>威胁</dt><dd>' + esc(THREATS[d.threat] || d.threat) + '</dd>';
    if (d.events) rows += '<dt>命中次数</dt><dd>' + esc(d.events) + '</dd>';
    if (d.weight) rows += '<dt>累计权重</dt><dd>' + esc(d.weight) + '</dd>';
    if (d.first_frame) {{
      rows += '<dt>帧范围</dt><dd>#' + esc(d.first_frame) +
              (d.last_frame && d.last_frame !== d.first_frame ? ' – #' + esc(d.last_frame) : '') +
              '</dd>';
    }}
    if (d.first_time) rows += '<dt>首次出现</dt><dd>' + esc(d.first_time) + '</dd>';
    (d.detail || []).forEach(function (kv) {{
      rows += '<dt>' + esc(kv[0]) + '</dt><dd>' + esc(kv[1]) + '</dd>';
    }});
    var frames = (d.frames || []).length
      ? '<div class="muted">关联帧：' + esc((d.frames || []).join(', ')) + '</div>' : '';
    side.innerHTML =
      '<h3>' + esc(d.label) + '</h3>' +
      '<span class="kindtag" style="background:' + esc(KIND_COLORS[d.kind] || '#607D8B') +
      '">' + esc(KINDS[d.kind] || d.kind) + '</span>' +
      '<dl class="kv">' + rows + '</dl>' + frames;
  }}

  function clearSelection() {{
    selected = null;
    nodes.forEach(function (n) {{ n.classList.remove('sel', 'dim'); }});
    edges.forEach(function (e) {{ e.classList.remove('dim'); }});
    side.innerHTML = '<p class="muted">点击任意节点查看详情。滚轮缩放，按住拖动平移。</p>';
  }}

  function select(id) {{
    if (selected === id) {{ clearSelection(); return; }}
    selected = id;
    // 高亮直接邻居，其余压暗 —— 一眼看清这个节点连着谁
    var neighbours = {{}};
    neighbours[id] = true;
    edges.forEach(function (e) {{
      var s = e.getAttribute('data-src'), t = e.getAttribute('data-dst');
      if (s === id) neighbours[t] = true;
      if (t === id) neighbours[s] = true;
    }});
    nodes.forEach(function (n) {{
      var nid = n.getAttribute('data-id');
      n.classList.toggle('sel', nid === id);
      n.classList.toggle('dim', !neighbours[nid]);
    }});
    edges.forEach(function (e) {{
      var touch = e.getAttribute('data-src') === id || e.getAttribute('data-dst') === id;
      e.classList.toggle('dim', !touch);
    }});
    showDetail(id);
  }}

  nodes.forEach(function (n) {{
    var id = n.getAttribute('data-id');
    n.addEventListener('click', function (ev) {{ ev.stopPropagation(); select(id); }});
    n.addEventListener('keydown', function (ev) {{
      if (ev.key === 'Enter' || ev.key === ' ') {{ ev.preventDefault(); select(id); }}
    }});
  }});

  // ---- 阶段过滤 ----
  function activeStages() {{
    var on = {{}};
    document.querySelectorAll('.chip input').forEach(function (c) {{
      on[c.getAttribute('data-stage')] = c.checked;
    }});
    return on;
  }}

  function applyFilters() {{
    var on = activeStages();
    var visible = {{}};
    nodes.forEach(function (n) {{
      var stage = n.getAttribute('data-stage');
      // 攻击者/目标没有阶段，永远显示，否则图会断头
      var show = !stage || on[stage] !== false;
      n.classList.toggle('hidden', !show);
      if (show) visible[n.getAttribute('data-id')] = true;
    }});
    edges.forEach(function (e) {{
      var ok = visible[e.getAttribute('data-src')] && visible[e.getAttribute('data-dst')];
      e.classList.toggle('hidden', !ok);
    }});
    tlItems.forEach(function (li) {{
      var stage = li.getAttribute('data-stage');
      li.classList.toggle('hidden', !!stage && on[stage] === false);
    }});
  }}

  document.querySelectorAll('.chip input').forEach(function (c) {{
    c.addEventListener('change', applyFilters);
  }});

  // ---- 搜索 ----
  function applySearch(term) {{
    term = (term || '').trim().toLowerCase();
    nodes.forEach(function (n) {{
      if (!term) {{ n.classList.remove('dim'); return; }}
      var d = NODES[n.getAttribute('data-id')] || {{}};
      var hay = ((d.label || '') + ' ' + (d.sublabel || '') + ' ' +
                 (d.detail || []).map(function (kv) {{ return kv[1]; }}).join(' ')).toLowerCase();
      n.classList.toggle('dim', hay.indexOf(term) === -1);
    }});
    if (term) edges.forEach(function (e) {{ e.classList.add('dim'); }});
    else edges.forEach(function (e) {{ e.classList.remove('dim'); }});
  }}

  document.getElementById('q').addEventListener('input', function (ev) {{
    selected = null;
    nodes.forEach(function (n) {{ n.classList.remove('sel'); }});
    applySearch(ev.target.value);
  }});

  // ---- 时间线联动 ----
  tlItems.forEach(function (li) {{
    li.addEventListener('click', function () {{
      var id = li.getAttribute('data-node');
      if (!id || !NODES[id]) return;
      select(id);
      var el = svg.querySelector('.node[data-id="' + id + '"]');
      if (el && el.scrollIntoView) {{
        wrap.scrollIntoView({{behavior: 'smooth', block: 'nearest'}});
      }}
    }});
  }});

  wrap.addEventListener('click', function (ev) {{
    if (ev.target === wrap || ev.target === svg) clearSelection();
  }});

  applyView();
}})();
</script>
</body>
</html>"""


def export_provenance_html(summary, output_path: str,
                           graph: Optional[ProvenanceGraph] = None) -> ProvenanceGraph:
    """建图 + 落盘。返回建好的图，方便调用方拿统计数据。"""
    graph = graph if graph is not None else build_provenance_graph(summary)
    content = render_provenance_html(graph)
    directory = os.path.dirname(os.path.abspath(output_path))
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(content)
    return graph
