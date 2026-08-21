# attack_chain.py - 攻击链聚合与结论传播
#
# 解决的问题：研判是**逐条**下结论的，而攻击是**成链**发生的。
#
# 实测一个 166MB 的抓包：6793 条检测里 6747 条来自同一个来源 IP，
# 3954 个不同 URI 几乎全是 `/admin/login.php?rec=` 这一个参数的 payload
# 变体（LFI 字典 + sqlmap）。真正得手的只有 1 条：`POST /images/article/a.php`
# —— 那是个 WebShell。
#
# 但同一个 `/images/article/a.php` 在包里出现了 **19 次**，只有 1 条被判
# confirmed，其余 18 条是 unknown。它们其实是**同一个 webshell 的反复
# 使用**：同一个来源、同一条路径、紧挨着的时间。逐条研判看不见这层关系，
# 因为每一条单独看都只是"POST 了一个 php 文件，响应 200"。
#
# 这里做两件事：
#
#   1. 聚簇   按 (来源 IP, 目标 IP, 规范化路径) 把检测分组
#   2. 传播   簇内任意一条得手 → 整簇标记为"同一条得手的攻击链"
#
# 传播是**只增不减**的：它只会阻止降档，永远不会把一条已有结论的检测
# 压低。理由和 success_adjudicator 的铁律一致 —— 漏报的代价远高于多留
# 一条待核实的记录。
#
# 为什么用路径而不是只用 (来源, 目标)：一个攻击者扫了 3954 个 URI、
# 其中一个得手，不能因此把另外 3953 个全部"救"回高危 —— 那就从一种
# 误报换成了另一种。路径级才是对的粒度："这条路径上发生过成功的事"，
# 同路径的其他请求才有理由被当成同一次利用的组成部分。

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple

logger = logging.getLogger(__name__)

# 结论强弱，取簇内最好的那个
_RANK = {"": 0, "unknown": 1, "failed": 2, "suspected": 3, "confirmed": 4}

# 视为"得手"的结论
LANDED = frozenset({"confirmed", "suspected"})


def normalize_path(uri: str) -> str:
    """去掉查询串和锚点，只留路径。

    攻击链的身份是**打的哪个文件**，不是带了什么参数 —— 同一个 webshell
    每次访问的 cmd 参数都不同，按完整 URI 分组会把一条链拆成 19 条。
    """
    if not uri:
        return "/"
    path = str(uri).split("#", 1)[0].split("?", 1)[0].strip()
    return path or "/"


@dataclass
class AttackChain:
    """一条攻击链：同一来源打同一目标的同一条路径。"""

    chain_id: str
    src_ip: str
    dst_ip: str
    path: str
    indices: List[int] = field(default_factory=list)
    frames: List[int] = field(default_factory=list)
    landed_frames: List[int] = field(default_factory=list)
    outcome: str = ""
    # 落地物关联：这条链上传的文件被哪条链访问了 / 这条链访问的文件是谁传的。
    # 只做留痕，供界面和报告解释"为什么这两条被算成同一次利用"。
    linked_artifact: str = ""
    linked_upload: str = ""

    @property
    def size(self) -> int:
        return len(self.indices)

    @property
    def landed(self) -> bool:
        return self.outcome in LANDED

    def to_dict(self) -> Dict[str, Any]:
        return {
            "chain_id": self.chain_id,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "path": self.path,
            "size": self.size,
            "outcome": self.outcome,
            "landed_frames": list(self.landed_frames[:20]),
        }


@dataclass
class AttackerSession:
    """一个来源打一个目标的全部动作。给界面做"按攻击者聚合"用。"""

    src_ip: str
    dst_ip: str
    chains: List[AttackChain] = field(default_factory=list)

    @property
    def attempts(self) -> int:
        return sum(chain.size for chain in self.chains)

    @property
    def landed_chains(self) -> List[AttackChain]:
        return [chain for chain in self.chains if chain.landed]

    @property
    def outcome(self) -> str:
        """会话结论 = 最好的那条链。一次都没得手就是这一堆里最强的结论。"""
        if not self.chains:
            return ""
        return max((c.outcome for c in self.chains), key=lambda o: _RANK.get(o, 0))

    def to_dict(self) -> Dict[str, Any]:
        landed = self.landed_chains
        return {
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "attempts": self.attempts,
            "chains": len(self.chains),
            "landed_chains": len(landed),
            "outcome": self.outcome,
            "summary": (f"尝试 {self.attempts} 次，"
                        f"得手 {sum(c.size for c in landed)} 次"),
        }


def _raw(detection) -> Dict[str, Any]:
    raw = getattr(detection, "raw_result", None)
    return raw if isinstance(raw, dict) else {}


def _outcome_of(detection) -> str:
    """取这条检测的研判结论。没研判过返回空串。"""
    verdict = _raw(detection).get("success_verdict")
    if not isinstance(verdict, dict):
        return ""
    return str(verdict.get("outcome") or "")


def _identity(detection) -> Tuple[str, str, str]:
    raw = _raw(detection)
    src = str(getattr(detection, "source_ip", "") or raw.get("src_ip", "") or "")
    dst = str(getattr(detection, "dest_ip", "") or raw.get("dst_ip", "") or "")
    uri = str(getattr(detection, "uri", "") or raw.get("uri", "") or "")
    return src, dst, normalize_path(uri)


def _uploaded_names(detection) -> List[str]:
    """这条检测上传了哪些文件（小写文件名）。

    优先用采集侧算好的 `uploaded_names`；没有就从原始请求体里重抠一遍，
    这样对历史 summary 也成立。
    """
    raw = _raw(detection)
    names = raw.get("uploaded_names") or []
    if not names:
        body = raw.get("raw_request_body_full") or raw.get("raw_request_body") or ""
        if body:
            try:
                from core.session_tracker import extract_uploaded_names
            except ImportError:
                return []
            try:
                if isinstance(body, str):
                    body = body.encode("utf-8", errors="ignore")
                names = extract_uploaded_names(body, raw.get("content_type", "") or "")
            except Exception as error:      # 抠不出来就当没有，别连累聚簇
                logger.debug("上传文件名提取失败: %s", error)
                return []
    return [str(n).lower() for n in names if n]


def _basename(path: str) -> str:
    return path.rstrip("/").rsplit("/", 1)[-1].lower()


def _frame_of(detection) -> int:
    raw = _raw(detection)
    for candidate in (raw.get("frame_number"), getattr(detection, "packet_number", 0)):
        try:
            value = int(candidate or 0)
        except (TypeError, ValueError):
            continue
        if value > 0:
            return value
    return 0


def build_chains(detections: Iterable) -> List[AttackChain]:
    """把检测按 (来源, 目标, 路径) 聚成攻击链，再把"上传"和"访问落地物"接起来。

    不做任何写入，纯计算 —— 方便单测和复用。
    """
    detections = list(detections)
    buckets: Dict[Tuple[str, str, str], AttackChain] = {}
    # (来源, 目标, 文件名) -> 上传它的那条链，用来接"上传 → 访问"
    uploader_of: Dict[Tuple[str, str, str], AttackChain] = {}

    for index, detection in enumerate(detections):
        src, dst, path = _identity(detection)
        key = (src, dst, path)
        chain = buckets.get(key)
        if chain is None:
            chain = buckets[key] = AttackChain(
                chain_id=f"{src}->{dst}{path}",
                src_ip=src, dst_ip=dst, path=path,
            )
        chain.indices.append(index)
        frame = _frame_of(detection)
        if frame:
            chain.frames.append(frame)

        outcome = _outcome_of(detection)
        if _RANK.get(outcome, 0) > _RANK.get(chain.outcome, 0):
            chain.outcome = outcome
        if outcome in LANDED and frame:
            chain.landed_frames.append(frame)

        for name in _uploaded_names(detection):
            uploader_of.setdefault((src, dst, name), chain)

    chains = list(buckets.values())

    # ── 把"上传了 X"和"访问了 .../X"接成同一条链 ──
    #
    # 实测：DVWA 的攻击链是
    #     frame 68  POST /DVWA/vulnerabilities/upload/   ← 上传 ma.php
    #     frame 93  GET  /DVWA/hackable/uploads/ma.php   ← 访问它
    # 两者**路径不同**，纯按路径聚簇会分成两条链。于是上传那条被判
    # confirmed（维度 B 认出了"上传后回访"），而访问那条自己看不出名堂、
    # 研判 unknown、被降档到"信息"级 —— 攻击链上最关键的一步在界面上
    # 最不显眼。
    #
    # 落地物是它们之间**确定的**关系：同一来源、同一目标、上传的文件名
    # 正好是被访问路径的最后一段。把结论在两边之间传播即可。
    for chain in chains:
        uploader = uploader_of.get(
            (chain.src_ip, chain.dst_ip, _basename(chain.path)))
        if uploader is None or uploader is chain:
            continue
        best = max((uploader.outcome, chain.outcome),
                   key=lambda o: _RANK.get(o, 0))
        if _RANK.get(best, 0) > _RANK.get(chain.outcome, 0):
            chain.outcome = best
            chain.landed_frames.extend(uploader.landed_frames)
        if _RANK.get(best, 0) > _RANK.get(uploader.outcome, 0):
            uploader.outcome = best
            uploader.landed_frames.extend(chain.landed_frames)
        chain.linked_upload = uploader.chain_id
        uploader.linked_artifact = chain.chain_id

    return chains


def build_sessions(chains: Iterable[AttackChain]) -> List[AttackerSession]:
    """把攻击链按 (来源, 目标) 聚成攻击者会话，按尝试次数降序。"""
    buckets: Dict[Tuple[str, str], AttackerSession] = {}
    for chain in chains:
        key = (chain.src_ip, chain.dst_ip)
        session = buckets.get(key)
        if session is None:
            session = buckets[key] = AttackerSession(chain.src_ip, chain.dst_ip)
        session.chains.append(chain)
    return sorted(buckets.values(), key=lambda s: -s.attempts)


def annotate(detections: List) -> List[AttackChain]:
    """聚簇并把链信息写回每条检测的 raw_result，返回所有链。

    写入三个字段：
        chain_id        链的身份，界面按它分组
        chain_size      这条链上有多少条检测
        chain_outcome   链的结论（簇内最好的那个）

    `chain_outcome` 是**传播的载体**：DetectionResult._downgrade_exemption
    看到它是 confirmed/suspected 就不降档 —— 因为这条检测是一次已证实
    得手的攻击链的组成部分，哪怕它自己那一条看不出名堂。

    只增不减：本函数不会修改 success_verdict，逐条研判的结论原样保留，
    界面上"这一条自己判成什么"和"它所属的链判成什么"是两个可区分的值。
    """
    chains = build_chains(detections)
    for chain in chains:
        if chain.size <= 0:
            continue
        payload = {
            "chain_id": chain.chain_id,
            "chain_size": chain.size,
            "chain_outcome": chain.outcome,
        }
        for index in chain.indices:
            raw = _raw(detections[index])
            if raw is not None and isinstance(raw, dict):
                raw.update(payload)
    return chains


def summarize(detections: List) -> Dict[str, Any]:
    """聚合一次并给出会话级摘要，供报告/界面直接使用。"""
    chains = annotate(detections)
    sessions = build_sessions(chains)
    landed = [chain for chain in chains if chain.landed]
    return {
        "detections": len(detections),
        "chains": len(chains),
        "landed_chains": len(landed),
        "sessions": [session.to_dict() for session in sessions],
        "top_landed": [chain.to_dict() for chain in landed[:50]],
    }
