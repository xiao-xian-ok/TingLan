# session_tracker.py - 会话上下文感知打分
#
# 现有 AttackDetector.detect() 是完全无状态的单包判定，同一个攻击者的
# "上传 shell.php -> 访问 shell.php -> 反复投喂高熵指令" 这条链在单包视角下
# 每一步都可能不过阈值。这里按会话把前序请求记下来，用序列行为补一个有界的置信度。
#
# 三条硬约束（防止上下文变成误报放大器）：
#   1. 加分有上限（MAX_BONUS），且永远只加不减，不去动规则引擎已有的判定
#   2. 每条规则都带 reason/tag，报告里能解释"为什么这次分高了"
#   3. 内存有界：会话数 LRU 封顶，每会话事件环形缓冲封顶

import re
import math
import threading
from collections import OrderedDict, deque
from dataclasses import dataclass, field
from typing import Deque, Dict, List, Optional, Tuple
import logging

logger = logging.getLogger(__name__)


# 落地后可被解释器执行的扩展名
SCRIPT_EXTENSIONS = (
    ".php", ".php3", ".php4", ".php5", ".php7", ".phtml", ".phar", ".pht",
    ".jsp", ".jspx", ".jspf", ".jsw", ".jsv",
    ".asp", ".aspx", ".asa", ".asax", ".ascx", ".ashx", ".cer",
    ".cfm", ".cfc", ".pl", ".cgi", ".py", ".sh",
)

_FILENAME_RE = re.compile(r'filename\s*=\s*["\']?([^"\';\r\n]+)', re.IGNORECASE)
_SCRIPT_MAGIC_RE = re.compile(
    rb'<\?php|<\?=|<%@\s*page|<%\s*@\s*language|<script\s+runat\s*=',
    re.IGNORECASE,
)


@dataclass
class RequestEvent:
    """一次请求的轻量快照。故意不存 body，只存长度和熵，避免会话表吃内存。"""
    frame_number: int = 0
    ts: float = 0.0                 # epoch 秒，0 表示未知
    src_ip: str = ""
    dst_ip: str = ""
    host: str = ""
    method: str = ""
    uri: str = ""
    content_type: str = ""
    body_len: int = 0
    entropy: float = 0.0
    rule_weight: int = 0
    detected: bool = False
    attack_type: str = ""
    uploaded_names: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)

    @property
    def path(self) -> str:
        return (self.uri or "/").split("?", 1)[0]

    @property
    def basename(self) -> str:
        return self.path.rstrip("/").rsplit("/", 1)[-1]


@dataclass
class SessionSignal:
    """会话上下文给出的增量，融合方只需要 bonus/reasons/tags"""
    bonus: int = 0
    reasons: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    session_key: str = ""
    session_events: int = 0

    @property
    def triggered(self) -> bool:
        return self.bonus > 0

    def to_dict(self) -> Dict[str, object]:
        return {
            "bonus": self.bonus,
            "reasons": list(self.reasons),
            "tags": list(self.tags),
            "session_key": self.session_key,
            "session_events": self.session_events,
        }


class _SessionState:
    """单个会话的滚动状态"""

    __slots__ = ("events", "uploads", "path_hits", "attack_types", "last_ts")

    MAX_EVENTS = 64
    MAX_UPLOADS = 32
    MAX_PATHS = 128

    def __init__(self) -> None:
        self.events: Deque[RequestEvent] = deque(maxlen=self.MAX_EVENTS)
        # basename -> (ts, path, frame_number)
        self.uploads: "OrderedDict[str, Tuple[float, str, int]]" = OrderedDict()
        # path -> [(ts, entropy, body_len, weight, method)]
        self.path_hits: "OrderedDict[str, List[Tuple[float, float, int, int, str]]]" = OrderedDict()
        self.attack_types: Dict[str, int] = {}
        self.last_ts: float = 0.0

    def remember_upload(self, name: str, ts: float, path: str, frame: int) -> None:
        key = name.lower()
        if key in self.uploads:
            self.uploads.move_to_end(key)
            return
        self.uploads[key] = (ts, path, frame)
        while len(self.uploads) > self.MAX_UPLOADS:
            self.uploads.popitem(last=False)

    def remember_path(self, event: RequestEvent) -> None:
        key = event.path.lower()
        bucket = self.path_hits.get(key)
        if bucket is None:
            bucket = []
            self.path_hits[key] = bucket
        else:
            self.path_hits.move_to_end(key)
        bucket.append((event.ts, event.entropy, event.body_len, event.rule_weight, event.method))
        if len(bucket) > 32:
            del bucket[:-32]
        while len(self.path_hits) > self.MAX_PATHS:
            self.path_hits.popitem(last=False)


class SessionTracker:
    """按会话聚合请求，输出序列行为置信度

    会话键：优先 src_ip -> host（跨 TCP 连接也能串起来，webshell 连接工具
    每次请求经常新开连接，用 tcp.stream 会把链断掉）。两者都缺时退回 tcp_stream。
    """

    MAX_SESSIONS = 2048
    MAX_BONUS = 80

    # 时间窗（秒）。时间戳缺失时退化成"只看次数不看时间"
    UPLOAD_WINDOW = 3600.0
    INTERACTION_WINDOW = 900.0
    RECON_WINDOW = 900.0

    def __init__(self, max_sessions: int = MAX_SESSIONS, max_bonus: int = MAX_BONUS):
        self._sessions: "OrderedDict[str, _SessionState]" = OrderedDict()
        self._max_sessions = max_sessions
        self._max_bonus = max_bonus
        self._lock = threading.RLock()
        self._rule_counts: Dict[str, int] = {}

    # ---------- 会话键 ----------

    @staticmethod
    def make_key(src_ip: str = "", host: str = "", dst_ip: str = "",
                 tcp_stream: int = -1) -> str:
        src = (src_ip or "").strip()
        target = (host or "").strip().lower() or (dst_ip or "").strip()
        if src and target:
            return f"{src}->{target}"
        if src:
            return f"{src}->*"
        if tcp_stream is not None and tcp_stream >= 0:
            return f"stream:{tcp_stream}"
        return "unknown"

    # ---------- 主入口 ----------

    def process(self, event: RequestEvent, session_key: str = "") -> SessionSignal:
        """先拿历史算增量，再把当前事件记进去。返回的 bonus 只反映"前序"行为。"""
        key = session_key or self.make_key(
            event.src_ip, event.host, event.dst_ip
        )

        with self._lock:
            state = self._sessions.get(key)
            if state is None:
                state = _SessionState()
                self._sessions[key] = state
                while len(self._sessions) > self._max_sessions:
                    self._sessions.popitem(last=False)
            else:
                self._sessions.move_to_end(key)

            signal = self._evaluate(state, event)
            signal.session_key = key
            signal.session_events = len(state.events)

            self._record(state, event)
            for tag in signal.tags:
                self._rule_counts[tag] = self._rule_counts.get(tag, 0) + 1

        return signal

    # ---------- 规则 ----------

    def _evaluate(self, state: _SessionState, event: RequestEvent) -> SessionSignal:
        signal = SessionSignal()
        if not state.events:
            return signal

        self._rule_upload_then_access(state, event, signal)
        self._rule_repeated_interaction(state, event, signal)
        self._rule_recon_escalation(state, event, signal)
        self._rule_persistent_attacker(state, event, signal)
        self._rule_beaconing(state, event, signal)

        signal.bonus = min(signal.bonus, self._max_bonus)
        return signal

    def _within(self, event_ts: float, prior_ts: float, window: float) -> bool:
        """时间戳缺失（任一为 0）时不做时间约束，只靠次数判定"""
        if event_ts <= 0 or prior_ts <= 0:
            return True
        return 0 <= (event_ts - prior_ts) <= window

    def _rule_upload_then_access(self, state: _SessionState, event: RequestEvent,
                                 signal: SessionSignal) -> None:
        """上传 + 执行：本会话先上传过某脚本，现在又来访问它"""
        basename = event.basename.lower()
        if not basename:
            return
        record = state.uploads.get(basename)
        if record is None:
            return
        ts, upload_path, upload_frame = record
        if upload_frame == event.frame_number:
            return  # 就是上传那一个包本身
        if not self._within(event.ts, ts, self.UPLOAD_WINDOW):
            return

        signal.bonus += 60
        signal.reasons.append(
            f"同会话先上传 {basename}(frame {upload_frame})，随后 {event.method} 访问该脚本"
        )
        signal.tags.append("session:upload_then_access")

    def _rule_repeated_interaction(self, state: _SessionState, event: RequestEvent,
                                   signal: SessionSignal) -> None:
        """同一路径反复投喂高熵大体积 POST —— webshell 交互 / C2 指令下发的典型形态"""
        if (event.method or "").upper() not in ("POST", "PUT", "PATCH"):
            return
        bucket = state.path_hits.get(event.path.lower())
        if not bucket:
            return

        hits = [
            h for h in bucket
            if h[1] >= 4.5 and h[2] >= 64
            and (h[4] or "").upper() in ("POST", "PUT", "PATCH")
            and self._within(event.ts, h[0], self.INTERACTION_WINDOW)
        ]
        if len(hits) < 3:
            return

        signal.bonus += 35
        signal.reasons.append(
            f"同一路径 {event.path} 已出现 {len(hits)} 次高熵大体积 {event.method}"
        )
        signal.tags.append("session:repeated_high_entropy_post")

    def _rule_recon_escalation(self, state: _SessionState, event: RequestEvent,
                               signal: SessionSignal) -> None:
        """先大面积探测再命中 —— 扫描器/人工渗透的典型节奏"""
        if not event.detected:
            return
        probes = {
            e.path for e in state.events
            if e.rule_weight > 0 and self._within(event.ts, e.ts, self.RECON_WINDOW)
        }
        if len(probes) < 5:
            return

        signal.bonus += 25
        signal.reasons.append(f"命中前已对 {len(probes)} 个不同路径发起过可疑请求")
        signal.tags.append("session:recon_then_exploit")

    def _rule_persistent_attacker(self, state: _SessionState, event: RequestEvent,
                                  signal: SessionSignal) -> None:
        """同一攻击类型在本会话反复出现，说明不是偶然的字符串巧合"""
        atype = (event.attack_type or "").strip().lower()
        if not atype or atype == "unknown":
            return
        prior = state.attack_types.get(atype, 0)
        if prior < 3:
            return

        signal.bonus += 20
        signal.reasons.append(f"本会话已累计 {prior} 次 {atype} 类攻击特征")
        signal.tags.append("session:persistent_attack_type")

    def _rule_beaconing(self, state: _SessionState, event: RequestEvent,
                        signal: SessionSignal) -> None:
        """请求间隔高度规律 —— 心跳式回连"""
        bucket = state.path_hits.get(event.path.lower())
        if not bucket or len(bucket) < 4:
            return
        stamps = [h[0] for h in bucket[-8:] if h[0] > 0]
        if len(stamps) < 4:
            return

        gaps = [b - a for a, b in zip(stamps, stamps[1:]) if b > a]
        if len(gaps) < 3:
            return
        mean = sum(gaps) / len(gaps)
        if mean <= 0.5:  # 太密集的多半是页面并发资源加载，不算 beacon
            return
        variance = sum((g - mean) ** 2 for g in gaps) / len(gaps)
        jitter = math.sqrt(variance) / mean
        if jitter > 0.25:
            return

        signal.bonus += 20
        signal.reasons.append(
            f"{event.path} 请求间隔规律(均值 {mean:.1f}s, 抖动 {jitter:.0%})，疑似心跳回连"
        )
        signal.tags.append("session:beaconing")

    # ---------- 记账 ----------

    def _record(self, state: _SessionState, event: RequestEvent) -> None:
        state.events.append(event)
        state.remember_path(event)
        if event.ts > 0:
            state.last_ts = event.ts

        atype = (event.attack_type or "").strip().lower()
        if atype and atype != "unknown" and event.rule_weight > 0:
            state.attack_types[atype] = state.attack_types.get(atype, 0) + 1

        for name in event.uploaded_names:
            base = name.rstrip("/").rsplit("/", 1)[-1]
            if base:
                state.remember_upload(base, event.ts, event.path, event.frame_number)

        # PUT/POST 直接打到脚本路径本身也算落地
        method = (event.method or "").upper()
        if method in ("PUT", "POST") and event.basename:
            lowered = event.basename.lower()
            if lowered.endswith(SCRIPT_EXTENSIONS):
                state.remember_upload(lowered, event.ts, event.path, event.frame_number)

    # ---------- 观测 ----------

    def get_stats(self) -> Dict[str, object]:
        with self._lock:
            return {
                "sessions": len(self._sessions),
                "max_sessions": self._max_sessions,
                "max_bonus": self._max_bonus,
                "rule_hits": dict(self._rule_counts),
            }

    def clear(self) -> None:
        with self._lock:
            self._sessions.clear()
            self._rule_counts.clear()


def extract_uploaded_names(body: bytes, content_type: str = "") -> List[str]:
    """从 multipart 体里抠出 filename=，只保留能被执行的脚本名

    也兼容一种常见情况：Content-Type 不是 multipart，但 body 里带了脚本魔数
    （比如直接 PUT 一段 <?php ...），这时用 URI 侧的文件名兜底由调用方负责。
    """
    if not body:
        return []

    names: List[str] = []
    head = body[:65536]
    try:
        text = head.decode("utf-8", errors="ignore")
    except Exception:
        return []

    # body 里带脚本魔数说明内容本身可执行，哪怕文件名被改成 .jpg 也要记
    has_magic = bool(_SCRIPT_MAGIC_RE.search(head))

    for raw in _FILENAME_RE.findall(text):
        name = raw.strip().strip('"').strip("'")
        if not name:
            continue
        base = name.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]
        if not base:
            continue
        if base.lower().endswith(SCRIPT_EXTENSIONS) or has_magic:
            names.append(base)

    return names[:8]


_tracker_lock = threading.Lock()
_session_tracker: Optional[SessionTracker] = None


def get_session_tracker() -> SessionTracker:
    global _session_tracker
    if _session_tracker is None:
        with _tracker_lock:
            if _session_tracker is None:
                _session_tracker = SessionTracker()
    return _session_tracker


def reset_session_tracker() -> None:
    """每次开始分析新的 pcap 时调用，避免跨文件串味"""
    tracker = get_session_tracker()
    tracker.clear()
