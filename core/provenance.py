# provenance.py - 攻击溯源图建模
#
# 现有 HTML 报告是一张平铺的威胁表格，回答不了"谁打的、从哪进来、下一步做了什么"。
# 但这些关系其实已经被算出来了 —— core/session_tracker.py 里的
# upload_then_access / recon_then_exploit / beaconing 三条规则本身就是因果判定，
# 只是结果只拿去加分，没留下可视化的结构。这里把 AnalysisSummary 重新组织成
# 一张有向图：节点是实体（攻击者 / 目标 / 端点 / 落地物），边是行为和因果。
#
# 三条硬约束：
#   1. 纯数据。不 import Qt、不开线程、不读 pcap —— 只遍历内存里的 summary，可单测
#   2. 确定性。同样输入必须产出同样的图（节点 id、顺序都稳定），便于 diff 和回归
#   3. 拿不到的关系就不画。溯源图给错因果比不给更糟，宁可少一条边

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
import logging

logger = logging.getLogger(__name__)

try:
    from core.session_tracker import (
        SCRIPT_EXTENSIONS, SessionTracker, extract_uploaded_names,
    )
except ImportError:  # 允许在没有 session_tracker 的环境下退化运行
    SCRIPT_EXTENSIONS = (
        ".php", ".php3", ".php4", ".php5", ".phtml", ".phar", ".pht",
        ".jsp", ".jspx", ".asp", ".aspx", ".ashx", ".cer", ".cfm",
        ".pl", ".cgi", ".py", ".sh",
    )
    SessionTracker = None
    extract_uploaded_names = None


# ---------------------------------------------------------------- 阶段定义

STAGE_RECON = "recon"
STAGE_EXPLOIT = "exploit"
STAGE_IMPLANT = "implant"
STAGE_CONTROL = "control"
STAGE_EXFIL = "exfil"

# 顺序即列顺序，颜色同时用于图例和节点描边
STAGES: List[Tuple[str, str, str]] = [
    (STAGE_RECON, "侦察", "#607D8B"),
    (STAGE_EXPLOIT, "利用", "#FF9800"),
    (STAGE_IMPLANT, "植入", "#F44336"),
    (STAGE_CONTROL, "控制", "#9C27B0"),
    (STAGE_EXFIL, "渗出", "#00897B"),
]

STAGE_ORDER: Dict[str, int] = {key: i for i, (key, _, _) in enumerate(STAGES)}
STAGE_LABELS: Dict[str, str] = {key: label for key, label, _ in STAGES}
STAGE_COLORS: Dict[str, str] = {key: color for key, _, color in STAGES}

# 节点类型 -> (中文名, 颜色)
KIND_META: Dict[str, Tuple[str, str]] = {
    "attacker": ("攻击者", "#1976D2"),
    "target": ("目标主机", "#455A64"),
    "endpoint": ("访问端点", "#5E35B1"),
    "artifact": ("落地物", "#D81B60"),
    "finding": ("协议发现", "#00838F"),
}

# 检测类型 -> 阶段。这里只列有明确阶段归属的，其余走 STAGE_EXPLOIT 兜底
_RECON_TYPES = {"path_traversal", "lfi", "rfi"}
_EXPLOIT_TYPES = {
    "sqli", "xss", "rce", "xxe", "ssrf", "command_injection",
    "ssti", "deserialization", "ldap_injection", "attack",
}
_IMPLANT_TYPES = {"file_upload"}
_CONTROL_TYPES = {"antsword", "caidao", "behinder", "godzilla", "encrypted_http"}

# session_tracker 打的标签 -> 阶段。标签比类型更可信（它是跨请求推出来的）
_TAG_STAGES = {
    "session:upload_then_access": STAGE_CONTROL,
    "session:repeated_high_entropy_post": STAGE_CONTROL,
    "session:beaconing": STAGE_CONTROL,
}

# 探测类攻击在低权重时算侦察，高权重才算真利用
_RECON_WEIGHT_CEILING = 40


# ---------------------------------------------------------------- 数据结构

@dataclass
class ProvenanceNode:
    id: str = ""
    kind: str = "endpoint"          # attacker / target / endpoint / artifact / finding
    label: str = ""                 # 图上显示的短文本
    sublabel: str = ""              # 第二行小字
    stage: str = ""                 # 属于哪个阶段，攻击者/目标为空
    threat: str = "info"            # info / low / medium / high / critical
    # 成功研判结论：confirmed / suspected / failed / unknown / ""(没研判过)
    # 溯源图真正要回答的是"哪条打成了"，威胁等级只说"像不像攻击"，两者不能混。
    outcome: str = ""
    weight: int = 0                 # 累计权重，用于节点大小
    events: int = 0                 # 关联的检测条数
    first_frame: int = 0
    last_frame: int = 0
    first_time: str = ""
    detail: List[Tuple[str, str]] = field(default_factory=list)  # 详情面板的键值对
    frames: List[int] = field(default_factory=list)              # 关联帧号，最多留 50

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "label": self.label,
            "sublabel": self.sublabel,
            "stage": self.stage,
            "threat": self.threat,
            "outcome": self.outcome,
            "weight": self.weight,
            "events": self.events,
            "first_frame": self.first_frame,
            "last_frame": self.last_frame,
            "first_time": self.first_time,
            "detail": [list(kv) for kv in self.detail],
            "frames": self.frames[:50],
        }


@dataclass
class ProvenanceEdge:
    src: str = ""
    dst: str = ""
    kind: str = "flow"              # flow(行为) / causal(因果) / drop(落地) / temporal(时序)
    label: str = ""
    count: int = 1
    frames: List[int] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "src": self.src,
            "dst": self.dst,
            "kind": self.kind,
            "label": self.label,
            "count": self.count,
            "frames": self.frames[:20],
        }


@dataclass
class TimelineEvent:
    frame: int = 0
    time: str = ""
    stage: str = ""
    threat: str = "info"
    label: str = ""
    node: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "frame": self.frame,
            "time": self.time,
            "stage": self.stage,
            "threat": self.threat,
            "label": self.label,
            "node": self.node,
        }


@dataclass
class ProvenanceGraph:
    nodes: List[ProvenanceNode] = field(default_factory=list)
    edges: List[ProvenanceEdge] = field(default_factory=list)
    timeline: List[TimelineEvent] = field(default_factory=list)
    file_path: str = ""
    total_packets: int = 0
    analysis_time: float = 0.0
    stats: Dict[str, Any] = field(default_factory=dict)

    @property
    def is_empty(self) -> bool:
        return not self.nodes

    def stage_counts(self) -> Dict[str, int]:
        counts = {key: 0 for key, _, _ in STAGES}
        for node in self.nodes:
            if node.stage in counts:
                counts[node.stage] += 1
        return counts

    def to_dict(self) -> Dict[str, Any]:
        return {
            "nodes": [n.to_dict() for n in self.nodes],
            "edges": [e.to_dict() for e in self.edges],
            "timeline": [t.to_dict() for t in self.timeline],
            "file_path": self.file_path,
            "total_packets": self.total_packets,
            "analysis_time": self.analysis_time,
            "stats": self.stats,
        }


# ---------------------------------------------------------------- 小工具

def _norm_path(uri: str) -> str:
    """URI -> 不带查询串的路径。空值统一成 /"""
    if not uri:
        return "/"
    path = uri.split("#", 1)[0].split("?", 1)[0].strip()
    return path or "/"


def _basename(path: str) -> str:
    return path.rstrip("/").rsplit("/", 1)[-1]


def _is_script(name: str) -> bool:
    return bool(name) and name.lower().endswith(tuple(SCRIPT_EXTENSIONS))


def _threat_value(detection) -> str:
    level = getattr(detection, "threat_level", None)
    return getattr(level, "value", "info") or "info"


_THREAT_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# 研判结论的严重度。一个端点上可能有好几条检测，取最重的那个作为节点结论——
# "这个端点上有一条打成了"比"这里还有 20 条失败的探测"重要得多。
_OUTCOME_RANK = {"": 0, "unknown": 1, "failed": 2, "suspected": 3, "confirmed": 4}

_OUTCOME_LABELS = {
    "confirmed": "确认得手",
    "suspected": "疑似得手",
    "failed": "未生效",
    "unknown": "证据不足",
}


def _max_threat(a: str, b: str) -> str:
    return a if _THREAT_RANK.get(a, 0) >= _THREAT_RANK.get(b, 0) else b


def _max_outcome(a: str, b: str) -> str:
    return a if _OUTCOME_RANK.get(a, 0) >= _OUTCOME_RANK.get(b, 0) else b


def _verdict_of(detection) -> Optional[Dict[str, Any]]:
    """取 A/B/C 成功研判的结论。

    结论由 SuccessAdjudicator 写进 raw_result（见 success_adjudicator
    .adjudicate_all），这里直接读，不重算也不猜——研判跑没跑过是上游的事，
    没有就是没有，图上照实留空。
    """
    verdict = _raw(detection).get("success_verdict")
    return verdict if isinstance(verdict, dict) else None


def _raw(detection) -> Dict[str, Any]:
    raw = getattr(detection, "raw_result", None)
    return raw if isinstance(raw, dict) else {}


def _frame_of(detection) -> int:
    """帧号是唯一一定有值的排序键，时间戳在攻击类检测上经常是空的"""
    raw = _raw(detection)
    for candidate in (raw.get("frame_number"), getattr(detection, "packet_number", 0)):
        try:
            value = int(candidate or 0)
        except (TypeError, ValueError):
            continue
        if value > 0:
            return value
    return 0


def _upload_names_of(detection) -> List[str]:
    """从已保存的原始请求体里重新抠出上传的脚本名

    没有直接复用 stream_worker 里算好的结果，是因为那份 names 只喂给了
    SessionTracker，没写回 detection。从 raw_request_body_full 重抠一遍
    的好处是对历史 summary 也成立，不需要改采集侧。
    """
    if extract_uploaded_names is None:
        return []
    raw = _raw(detection)
    body = raw.get("raw_request_body_full") or raw.get("raw_request_body") or ""
    if not body:
        return []
    try:
        return extract_uploaded_names(
            body.encode("utf-8", errors="ignore"),
            raw.get("content_type", "") or "",
        )
    except Exception as e:
        logger.debug(f"上传文件名提取失败: {e}")
        return []


def _session_key(detection) -> str:
    """会话键。与 SessionTracker.make_key 保持一致，保证图上的会话切分
    和打分时用的是同一套口径。"""
    raw = _raw(detection)
    src = getattr(detection, "source_ip", "") or raw.get("src_ip", "") or ""
    dst = getattr(detection, "dest_ip", "") or raw.get("dst_ip", "") or ""
    host = raw.get("host", "") or raw.get("http_host", "") or ""
    if SessionTracker is not None:
        try:
            return SessionTracker.make_key(src, host, dst)
        except Exception:
            pass
    target = (host or dst or "").lower()
    if src and target:
        return f"{src}->{target}"
    return f"{src}->*" if src else "unknown"


def _classify_stage(detection) -> str:
    """给一条检测定阶段。标签优先于类型 —— 标签是跨请求推出来的，更可信。"""
    tags = [str(t) for t in (getattr(detection, "tags", None) or [])]
    for tag in tags:
        if tag in _TAG_STAGES:
            return _TAG_STAGES[tag]

    dtype = getattr(getattr(detection, "detection_type", None), "value", "") or ""
    dtype = dtype.lower()

    if dtype in _CONTROL_TYPES:
        return STAGE_CONTROL
    if dtype in _IMPLANT_TYPES:
        return STAGE_IMPLANT
    if dtype in _RECON_TYPES:
        # 目录穿越/文件包含在低权重时多半是扫描器在探路，高权重才是真读到了东西
        weight = int(getattr(detection, "total_weight", 0) or 0)
        return STAGE_RECON if weight < _RECON_WEIGHT_CEILING else STAGE_EXPLOIT
    if dtype in _EXPLOIT_TYPES:
        return STAGE_EXPLOIT
    return STAGE_EXPLOIT


def _finding_stage(finding) -> str:
    """协议侧发现的阶段。隐蔽信道算渗出，CS 心跳算控制。"""
    protocol = (getattr(finding, "protocol", "") or "").lower()
    ftype = (getattr(finding, "finding_type", "") or "").lower()
    title = (getattr(finding, "title", "") or "").lower()
    blob = f"{protocol} {ftype} {title}"

    if "cobalt" in blob or "beacon" in blob or "c2" in blob:
        return STAGE_CONTROL
    if any(k in blob for k in ("tunnel", "隧道", "hidden", "stego", "隐写",
                               "covert", "exfil", "flag")):
        return STAGE_EXFIL
    return STAGE_EXFIL


# ---------------------------------------------------------------- 建图

class _GraphBuilder:

    def __init__(self, summary):
        self.summary = summary
        self._nodes: Dict[str, ProvenanceNode] = {}     # 语义 key -> node
        self._edges: Dict[Tuple[str, str, str], ProvenanceEdge] = {}
        self._timeline: List[TimelineEvent] = []
        self._seq = 0
        # 研判结论分布，进 stats 给报告顶部的卡片用
        self._outcome_counts: Dict[str, int] = {}
        # 入点帧号（研判认为攻击链真正生效的那一包）
        self._entry_frames: List[int] = []

    # ---- 节点/边的增量维护 ----

    def _node(self, key: str, kind: str, label: str, **kw) -> ProvenanceNode:
        node = self._nodes.get(key)
        if node is None:
            node = ProvenanceNode(id=f"n{self._seq}", kind=kind, label=label)
            self._seq += 1
            self._nodes[key] = node
        for attr, value in kw.items():
            if value in (None, "", 0, []):
                continue
            if attr == "stage":
                # 一个端点可能既被探测又被当 webshell 用，取更靠后的阶段
                if STAGE_ORDER.get(value, -1) > STAGE_ORDER.get(node.stage, -1):
                    node.stage = value
            elif attr == "threat":
                node.threat = _max_threat(node.threat, value)
            elif attr == "outcome":
                node.outcome = _max_outcome(node.outcome, value)
            elif attr == "detail":
                known = {k for k, _ in node.detail}
                for k, v in value:
                    if k not in known and v:
                        node.detail.append((k, v))
                        known.add(k)
            else:
                setattr(node, attr, value)
        return node

    def _touch(self, node: ProvenanceNode, frame: int, weight: int = 0,
               time_str: str = "") -> None:
        node.events += 1
        node.weight += max(0, int(weight or 0))
        if frame > 0:
            node.frames.append(frame)
            if node.first_frame == 0 or frame < node.first_frame:
                node.first_frame = frame
                if time_str:
                    node.first_time = time_str
            node.last_frame = max(node.last_frame, frame)
        elif time_str and not node.first_time:
            node.first_time = time_str

    def _edge(self, src: ProvenanceNode, dst: ProvenanceNode, kind: str,
              label: str = "", frame: int = 0) -> None:
        if src is None or dst is None or src.id == dst.id:
            return
        key = (src.id, dst.id, kind)
        edge = self._edges.get(key)
        if edge is None:
            edge = ProvenanceEdge(src=src.id, dst=dst.id, kind=kind, label=label, count=0)
            self._edges[key] = edge
        edge.count += 1
        if label and not edge.label:
            edge.label = label
        if frame > 0 and len(edge.frames) < 20:
            edge.frames.append(frame)

    # ---- 主流程 ----

    def build(self) -> ProvenanceGraph:
        detections = list(getattr(self.summary, "detections", None) or [])
        detections.sort(key=lambda d: (_frame_of(d), getattr(d, "uri", "") or ""))

        endpoint_by_frame: Dict[int, ProvenanceNode] = {}
        # 会话 -> {上传的脚本名: (帧号, 上传端点节点)}
        uploads: Dict[str, Dict[str, Tuple[int, ProvenanceNode]]] = {}
        # 会话 -> 上一条检测的 (阶段, 节点)，用于画时序边
        last_in_session: Dict[str, Tuple[str, ProvenanceNode]] = {}

        for det in detections:
            self._add_detection(det, endpoint_by_frame, uploads, last_in_session)

        self._add_extracted_files(endpoint_by_frame)
        self._add_recovered_files(endpoint_by_frame)
        self._add_decoded_flags()
        self._add_protocol_findings()

        return self._finish()

    def _add_detection(self, det, endpoint_by_frame, uploads, last_in_session) -> None:
        raw = _raw(det)
        frame = _frame_of(det)
        stage = _classify_stage(det)
        threat = _threat_value(det)
        weight = int(getattr(det, "total_weight", 0) or 0)
        timestamp = getattr(det, "timestamp", "") or raw.get("timestamp", "") or ""

        src_ip = getattr(det, "source_ip", "") or raw.get("src_ip", "") or ""
        dst_ip = getattr(det, "dest_ip", "") or raw.get("dst_ip", "") or ""
        host = raw.get("host", "") or raw.get("http_host", "") or ""
        method = (getattr(det, "method", "") or "").upper()
        uri = getattr(det, "uri", "") or ""
        path = _norm_path(uri)
        dtype = getattr(det, "detection_type", None)
        type_label = getattr(dtype, "display_name", "") or getattr(dtype, "value", "") or "未知"

        # 成功研判结论。它回答的是"打成了没有"，和威胁等级是两个维度：
        # 一条 CRITICAL 的注入可能被 WAF 挡了（failed），一条 MEDIUM 的
        # 上传却真的落地了（confirmed）。溯源图要看的是后者。
        verdict = _verdict_of(det)
        outcome = str((verdict or {}).get("outcome") or "")
        if outcome:
            self._outcome_counts[outcome] = self._outcome_counts.get(outcome, 0) + 1
        entry_frame = int((verdict or {}).get("entry_frame") or 0)
        if outcome in ("confirmed", "suspected") and entry_frame > 0:
            self._entry_frames.append(entry_frame)

        verdict_detail: List[Tuple[str, str]] = []
        if outcome:
            verdict_detail.append(("研判结论", _OUTCOME_LABELS.get(outcome, outcome)))
            reasons = [str(r) for r in ((verdict or {}).get("reasons") or []) if r]
            if reasons:
                verdict_detail.append(("研判依据", " / ".join(reasons[:3])))
            dims = [str(d) for d in ((verdict or {}).get("dimensions") or []) if d]
            if dims:
                verdict_detail.append(("命中维度", "、".join(sorted(set(dims)))))
            followups = [str(f) for f in ((verdict or {}).get("followup_frames") or [])][:5]
            if followups:
                verdict_detail.append(("后续行为帧", ", ".join(followups)))

        # 攻击者
        attacker = None
        if src_ip:
            attacker = self._node(
                f"attacker:{src_ip}", "attacker", src_ip,
                sublabel="攻击源", threat=threat, outcome=outcome,
                detail=[("源 IP", src_ip)],
            )
            self._touch(attacker, frame, weight, timestamp)

        # 目标主机：优先用 Host 头，回落到目的 IP
        target = None
        target_name = host or dst_ip
        if target_name:
            target = self._node(
                f"target:{target_name}", "target", target_name,
                sublabel="目标", threat=threat, outcome=outcome,
                detail=[("Host", host), ("目的 IP", dst_ip)],
            )
            self._touch(target, frame, weight, timestamp)
            if attacker is not None:
                self._edge(attacker, target, "flow", "攻击流量", frame)

        # 端点
        endpoint = self._node(
            f"endpoint:{target_name}:{path}", "endpoint", path,
            sublabel=f"{method} · {type_label}" if method else type_label,
            stage=stage, threat=threat, outcome=outcome,
            detail=[
                ("路径", path),
                ("方法", method),
                ("检测类型", type_label),
                ("首个指标", getattr(det, "indicator", "") or ""),
            ] + verdict_detail,
        )
        self._touch(endpoint, frame, weight, timestamp)
        if frame > 0:
            endpoint_by_frame.setdefault(frame, endpoint)
        if target is not None:
            self._edge(target, endpoint, "flow", "", frame)
        elif attacker is not None:
            self._edge(attacker, endpoint, "flow", "", frame)

        # 会话上下文给出的解释，直接挂到端点详情里
        signals = raw.get("session_signals")
        if isinstance(signals, dict):
            reasons = [str(r) for r in (signals.get("reasons") or []) if r]
            if reasons:
                endpoint.detail.append(("会话线索", " / ".join(reasons[:3])))

        skey = _session_key(det)
        session_uploads = uploads.setdefault(skey, {})

        # --- 落地物：这一条请求上传了什么 ---
        dropped = set()
        for name in _upload_names_of(det):
            dropped.add(name.lower())
        # PUT 到脚本路径 = 直接往服务器写文件，这条算落地。
        # POST 不算：POST /upload.php 是"调用上传接口"，POST /uploads/shell.php
        # 是"用 webshell"，两者都不是把文件写到这个路径上 —— 按 POST 也认的话，
        # 每个上传接口和每次 webshell 交互都会凭空多出一个假的落地物节点。
        # POST 形式的上传由 _upload_names_of 从 multipart 的 filename= 里认。
        base = _basename(path)
        if method == "PUT" and _is_script(base):
            dropped.add(base.lower())

        for name in sorted(dropped):
            artifact = self._node(
                f"artifact:{skey}:{name}", "artifact", name,
                sublabel="落地脚本", stage=STAGE_IMPLANT, threat=threat,
                detail=[("文件名", name), ("上传路径", path), ("会话", skey)],
            )
            self._touch(artifact, frame, 0, timestamp)
            self._edge(endpoint, artifact, "drop", "上传落地", frame)
            session_uploads.setdefault(name, (frame, endpoint))

        # --- 因果：访问的正是本会话早前落地的脚本 ---
        tags = [str(t) for t in (getattr(det, "tags", None) or [])]
        base_lower = base.lower()
        prior = session_uploads.get(base_lower)
        if prior is not None and prior[0] != frame:
            upload_frame, upload_endpoint = prior
            artifact = self._nodes.get(f"artifact:{skey}:{base_lower}")
            if artifact is not None:
                self._edge(artifact, endpoint, "causal",
                           f"落地后被访问 (frame {upload_frame} → {frame})", frame)
            if upload_endpoint is not endpoint:
                self._edge(upload_endpoint, endpoint, "temporal", "", frame)
        elif "session:upload_then_access" in tags and _is_script(base_lower):
            # SessionTracker 判定过"先上传后访问"，但上传那一条请求本身
            # 没进 detections（权重不够被丢了）。此时仍然建落地物节点：
            # 关系是确定的，只是上传端点未知，不硬造。
            artifact = self._node(
                f"artifact:{skey}:{base_lower}", "artifact", base_lower,
                sublabel="落地脚本", stage=STAGE_IMPLANT, threat=threat,
                detail=[("文件名", base_lower), ("来源", "会话上下文判定"),
                        ("会话", skey)],
            )
            self._touch(artifact, frame, 0, timestamp)
            self._edge(artifact, endpoint, "causal", "落地后被访问", frame)
            session_uploads.setdefault(base_lower, (frame, endpoint))

        # --- 时序：同会话内相邻阶段的推进 ---
        prev = last_in_session.get(skey)
        if prev is not None:
            prev_stage, prev_node = prev
            if (prev_node is not endpoint
                    and STAGE_ORDER.get(stage, -1) > STAGE_ORDER.get(prev_stage, -1)):
                self._edge(prev_node, endpoint, "temporal",
                           f"{STAGE_LABELS.get(prev_stage, prev_stage)} → "
                           f"{STAGE_LABELS.get(stage, stage)}", frame)
        last_in_session[skey] = (stage, endpoint)

        self._timeline.append(TimelineEvent(
            frame=frame, time=timestamp, stage=stage, threat=threat,
            label=f"{method} {path} · {type_label}".strip(),
            node=endpoint.id,
        ))

    # ---- 渗出侧 ----

    def _attach_exfil(self, node: ProvenanceNode, source_packet: int,
                      endpoint_by_frame: Dict[int, ProvenanceNode]) -> None:
        """把渗出物挂回它来自的端点；挂不上就退到目标节点，再不行就悬空"""
        origin = endpoint_by_frame.get(source_packet) if source_packet else None
        if origin is None:
            origin = next((n for n in self._nodes.values() if n.kind == "target"), None)
        if origin is not None:
            self._edge(origin, node, "drop", "数据带出", source_packet)

    def _add_extracted_files(self, endpoint_by_frame) -> None:
        for f in (getattr(self.summary, "extracted_files", None) or []):
            name = getattr(f, "file_name", "") or "未命名文件"
            frame = int(getattr(f, "source_packet", 0) or 0)
            node = self._node(
                f"exfil:extracted:{name}", "artifact", name,
                sublabel="提取文件", stage=STAGE_EXFIL, threat="medium",
                detail=[("文件名", name),
                        ("类型", getattr(f, "file_type", "") or ""),
                        ("Content-Type", getattr(f, "content_type", "") or "")],
            )
            self._touch(node, frame)
            self._attach_exfil(node, frame, endpoint_by_frame)

    def _add_recovered_files(self, endpoint_by_frame) -> None:
        for f in (getattr(self.summary, "recovered_files", None) or []):
            if not getattr(f, "detected", False):
                continue
            desc = getattr(f, "description", "") or getattr(f, "extension", "") or "还原文件"
            frame = int(getattr(f, "source_packet", 0) or 0)
            node = self._node(
                f"exfil:recovered:{desc}:{frame}", "artifact", desc,
                sublabel="还原文件", stage=STAGE_EXFIL, threat="medium",
                detail=[("描述", desc),
                        ("扩展名", getattr(f, "extension", "") or ""),
                        ("大小", str(getattr(f, "size", 0)))],
            )
            self._touch(node, frame)
            self._attach_exfil(node, frame, endpoint_by_frame)

    def _add_decoded_flags(self) -> None:
        """只画解出 flag 的那些。普通解码结果太多，画进去就成噪声了。"""
        for r in (getattr(self.summary, "decoding_results", None) or []):
            flags = list(getattr(r, "flags_found", None) or [])
            if not flags:
                continue
            for flag in flags:
                node = self._node(
                    f"exfil:flag:{flag}", "artifact", str(flag)[:60],
                    sublabel="解出 FLAG", stage=STAGE_EXFIL, threat="critical",
                    detail=[("FLAG", str(flag)),
                            ("解码链", getattr(r, "decode_chain", "") or ""),
                            ("来源", getattr(r, "source", "") or "")],
                )
                self._touch(node, 0)
                origin = next((n for n in self._nodes.values() if n.kind == "target"), None)
                if origin is not None:
                    self._edge(origin, node, "drop", "解码得到", 0)

    def _add_protocol_findings(self) -> None:
        for f in (getattr(self.summary, "protocol_findings", None) or []):
            title = getattr(f, "title", "") or "协议发现"
            protocol = getattr(f, "protocol", "") or ""
            is_flag = bool(getattr(f, "is_flag", False))
            confidence = float(getattr(f, "confidence", 0.0) or 0.0)
            node = self._node(
                f"finding:{protocol}:{title}", "finding", title,
                sublabel=protocol, stage=_finding_stage(f),
                threat="critical" if is_flag else ("high" if confidence >= 0.8 else "medium"),
                detail=[("协议", protocol),
                        ("类型", getattr(f, "finding_type", "") or ""),
                        ("说明", (getattr(f, "description", "") or "")[:300]),
                        ("置信度", f"{confidence:.0%}"),
                        ("解码链", getattr(f, "decode_chain", "") or "")],
            )
            self._touch(node, 0)

    # ---- 收尾 ----

    def _finish(self) -> ProvenanceGraph:
        nodes = list(self._nodes.values())
        for node in nodes:
            node.frames = sorted(set(node.frames))[:50]
            node.detail = [(k, v) for k, v in node.detail if v]

        self._timeline.sort(key=lambda e: (e.frame, e.label))

        frames = [n.first_frame for n in nodes if n.first_frame > 0]
        attackers = sorted({n.label for n in nodes if n.kind == "attacker"})
        targets = sorted({n.label for n in nodes if n.kind == "target"})

        graph = ProvenanceGraph(
            nodes=nodes,
            edges=list(self._edges.values()),
            timeline=self._timeline,
            file_path=getattr(self.summary, "file_path", "") or "",
            total_packets=int(getattr(self.summary, "total_packets", 0) or 0),
            analysis_time=float(getattr(self.summary, "analysis_time", 0.0) or 0.0),
        )
        graph.stats = {
            "nodes": len(nodes),
            "edges": len(graph.edges),
            "detections": len(getattr(self.summary, "detections", None) or []),
            "attackers": attackers,
            "targets": targets,
            "stage_counts": graph.stage_counts(),
            "frame_range": [min(frames), max(frames)] if frames else [0, 0],
            "causal_edges": sum(1 for e in graph.edges if e.kind == "causal"),
            # A/B/C 研判结论分布 + 入点。空字典表示这次分析没跑研判，
            # 和"跑了但都没得手"是两回事，渲染侧要能区分。
            "outcome_counts": dict(self._outcome_counts),
            "entry_frames": sorted(set(self._entry_frames))[:20],
        }
        return graph


def build_provenance_graph(summary) -> ProvenanceGraph:
    """把一次分析的结果重组成攻击溯源图

    summary 为 None 或空分析时返回一张空图，不抛异常 —— 导出入口不该因为
    "这个包干干净净"而报错。
    """
    if summary is None:
        return ProvenanceGraph()
    try:
        return _GraphBuilder(summary).build()
    except Exception as e:
        logger.warning(f"溯源图构建失败: {e}", exc_info=True)
        return ProvenanceGraph(
            file_path=getattr(summary, "file_path", "") or "",
            total_packets=int(getattr(summary, "total_packets", 0) or 0),
        )
