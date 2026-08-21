# success_adjudicator.py - 攻击成功研判引擎
#
# 这个模块回答的不是"有没有人打"，而是"打进来了没有"。
#
# 请求侧的规则匹配（AC 自动机 + 信息熵）解决的是召回：只要报文里出现
# `;cat /etc/passwd`、`union select`、`<?php eval(`，就先记一笔。代价是真实
# 取证现场里，这类命中绝大多数来自扫描器噪声 —— 报一屏红色，分析员依然
# 不知道该先看哪一条。而事后应急真正要回答的只有一句话：**哪一条打成了**。
#
# 三个维度，都不看"请求像不像攻击"，只看**客观后果**：
#
#   A 响应特征   服务器回了什么？回显里出现 uid=0(root) 就是命令真的执行过
#   B 后续行为   攻击者接着干了什么？回访自己刚传的 1.php 就是马真的落地了
#   C 反向连接   服务器主动往外连了吗？非 HTTP 的出站 TCP 是 RCE 的铁证
#   D 主机落地   EDR 侧有没有对应的进程/文件/连接？（可选，未接入时整个跳过）
#
# A/B/C 三者互相独立：A 靠回显，B 靠时序，C 靠连接方向。攻击者可以让回显为空
# （`> /dev/null`）来躲 A，但躲不掉 B 的回访，也躲不掉 C 的反弹 —— 因为
# 那两件事正是他攻击的目的本身，放弃了就等于没打成。
#
# D 和前三个的性质不同，它是**确证器不是发现器**：正常主机每分钟几百条
# 遥测事件，让它独立定案只会变成新的噪声源。所以 D 的每一条计分都要和
# A/B/C 之一在时空上对上 —— 这和 A2「敏感文件读取必须请求与响应成对」
# 是同一个论证形式。
#
# 判定只增不减：本模块永远不会把已有的检测降级或删除，只在上面附加一个
# 结论。漏报的代价远高于多留一条待核实的记录。这条对 D 同样成立 ——
# EDR 说"这台机器上什么都没发生"是有价值的信息，但只能写进 reasons 留痕
# 给人看（D0），不能用它把已有结论降级。

import re
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

logger = logging.getLogger(__name__)

try:
    from core.edr_bridge import (
        HostEventLedger, SHELL_IMAGES, WEB_SERVER_IMAGES,
        event_brief as _ev_brief, image_name as _image_name,
    )
except ImportError:                     # pragma: no cover - 允许脚本方式直接跑
    try:
        from edr_bridge import (
            HostEventLedger, SHELL_IMAGES, WEB_SERVER_IMAGES,
            event_brief as _ev_brief, image_name as _image_name,
        )
    except ImportError:
        HostEventLedger = None
        SHELL_IMAGES = frozenset()
        WEB_SERVER_IMAGES = frozenset()

        def _ev_brief(event):
            return {}

        def _image_name(path):
            return ""


# ---------------------------------------------------------------- 结论模型

class Outcome(str, Enum):
    """研判结论。继承 str 是为了能直接进 JSON / Qt 模型而不用再转换。"""

    CONFIRMED = "confirmed"     # 有客观后果证据，打成了
    SUSPECTED = "suspected"     # 有迹象但不足以确认，需人工复核
    FAILED = "failed"           # 有明确的失败证据（404/403 等）
    UNKNOWN = "unknown"         # 证据不足，不下结论


# 分数阈值。定得比较高是刻意的：这个引擎的价值在于"说成功就真的是成功"，
# 一旦 CONFIRMED 变得廉价，分析员就会退回到挨条看的老路上。
_CONFIRM_SCORE = 70
_SUSPECT_SCORE = 30

_OUTCOME_RANK = {
    Outcome.UNKNOWN: 0,
    Outcome.FAILED: 1,
    Outcome.SUSPECTED: 2,
    Outcome.CONFIRMED: 3,
}


@dataclass
class SuccessVerdict:
    """一条检测的研判结论。

    entry_frame 是"入点"：整条攻击链上第一个真正生效的包。溯源图以它为根，
    分析员从这一帧开始看就够了。
    """

    outcome: Outcome = Outcome.UNKNOWN
    score: int = 0
    dimensions: List[str] = field(default_factory=list)   # 命中的维度 A/B/C
    reasons: List[str] = field(default_factory=list)      # 人话解释，直接进报告
    evidence: Dict[str, Any] = field(default_factory=dict)
    entry_frame: int = 0                                  # 入点帧号
    followup_frames: List[int] = field(default_factory=list)   # 后续行为帧号

    @property
    def landed(self) -> bool:
        """打成了没有 —— AST 是否值得为这条花时间，就看这个。"""
        return self.outcome in (Outcome.CONFIRMED, Outcome.SUSPECTED)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "outcome": self.outcome.value,
            "score": self.score,
            "dimensions": list(self.dimensions),
            "reasons": list(self.reasons),
            "evidence": dict(self.evidence),
            "entry_frame": self.entry_frame,
            "followup_frames": list(self.followup_frames),
        }

    def merge(self, other: "SuccessVerdict") -> None:
        """多维度结论合并。分数累加，结论取更严重的那个。"""
        self.score += other.score
        for dim in other.dimensions:
            if dim not in self.dimensions:
                self.dimensions.append(dim)
        self.reasons.extend(other.reasons)
        self.evidence.update(other.evidence)
        if _OUTCOME_RANK[other.outcome] > _OUTCOME_RANK[self.outcome]:
            self.outcome = other.outcome
        if other.entry_frame and (not self.entry_frame
                                  or other.entry_frame < self.entry_frame):
            self.entry_frame = other.entry_frame
        for frame in other.followup_frames:
            if frame not in self.followup_frames:
                self.followup_frames.append(frame)


# ------------------------------------------------- 维度 A：响应特征指纹表

# 命令执行回显。这些字符串出现在 HTTP 响应体里，只有一种解释：目标机器上
# 真的跑过一条命令，并且输出被回传了。权重给满。
#
# 每项 = (正则, 人话说明, 权重)
_CMD_ECHO_FINGERPRINTS: List[Tuple[re.Pattern, str, int]] = [
    # ── WebShell 应答协议标志 ──
    #
    # 这一条是实测补的。166MB 的真实抓包里有 37 个中国菜刀应答，格式是
    #     ->|/var/www/html/images/article	Linux localhost... x86_64(apache)|<-
    # 而研判引擎一条都没认出来 —— 因为它只找"命令回显长什么样"，没找
    # "WebShell 应答长什么样"。
    #
    # 这个包装本身就是铁证，比任何回显内容都硬：`->|` 和 `|<-` 成对出现
    # 意味着服务器上确实有一个菜刀马在正常应答。正常业务不会产出这种成对
    # 定界符（要求两个都在，单独一个 `->|` 在正常文本里偶尔会有）。
    (re.compile(r"->\|[\s\S]{0,65536}?\|<-"),
     "中国菜刀 WebShell 应答包装 (->|…|<-)", 90),
    # id / whoami 回显。uid= 和 gid= 必须同现，单独一个 uid= 在正常 JSON 里也会有
    (re.compile(r"uid=\d{1,7}\([^)\r\n]{1,32}\)\s+gid=\d{1,7}\([^)\r\n]{1,32}\)"),
     "id 命令回显 (uid=/gid=)", 80),
    # Windows 命令回显
    (re.compile(r"Windows IP Configuration", re.I),
     "ipconfig 回显", 80),
    (re.compile(r"Microsoft Windows \[Version\s+[\d.]+\]", re.I),
     "Windows 版本横幅回显 (ver/systeminfo)", 80),
    (re.compile(r"Volume Serial Number is [0-9A-F]{4}-[0-9A-F]{4}", re.I),
     "dir 命令回显", 75),
    (re.compile(r"^\s*Directory of\s+[A-Za-z]:\\", re.M),
     "dir 命令目录列表回显", 75),
    (re.compile(r"\bnt authority\\system\b", re.I),
     "whoami 回显 SYSTEM 权限", 85),
    # Linux 目录/进程回显
    (re.compile(r"^total\s+\d+\s*$.{0,80}^[bcdlps-][rwxsStT-]{9}", re.M | re.S),
     "ls -l 命令回显", 70),
    (re.compile(r"\bPID\s+TTY\s+TIME\s+CMD\b"),
     "ps 命令回显", 70),
    (re.compile(r"Linux\s+\S{1,64}\s+\d+\.\d+\.\d+\S*\s+#\d+"),
     "uname -a 回显", 75),
    # 服务账户名。单独出现证据力弱得多 —— 正常页面里也可能提到，
    # 所以权重压到"疑似"档，必须配合别的信号才够 CONFIRMED
    (re.compile(r"\bwww-data\b|\bapache\b:\w*:\d+|\bhttpd\b:x:"),
     "响应中出现 Web 服务账户名", 35),
    # 源码泄露：响应体**开头**就是 PHP/JSP 源码。
    #
    # 同样是实测补的：菜刀的读文件命令
    #     $F=base64_decode($_POST["z1"]);echo(@fread($P,filesize($F)));
    # 把站点源码整个读回来了，4 个响应里是 DouPHP 的 PHP 源码。这明显
    # 是得手，但研判引擎没有对应指纹 —— A2 的 _FILE_READ_PROOFS 要求
    # **请求侧**出现 /etc/passwd 这类关键词，而这里的文件路径是 base64
    # 编码藏在 POST 体里的，对不上。
    #
    # 判据卡在"开头"：服务器把 PHP 源码当静态文件吐出来（而不是执行它）
    # 只有两种解释 —— 源码泄露漏洞，或者有人用 WebShell 在读文件。
    # 教程站点在页面**中间**贴代码示例是正常的，所以不看中间只看开头。
    (re.compile(r"\A(?:->\|)?\s*<\?php\s", re.I),
     "响应体直接返回 PHP 源码（源码泄露 / WebShell 读文件）", 70),
]

# 敏感文件读取。这里必须**请求侧目标**和**响应侧内容**成对匹配才算数：
# 单看响应里有 root:x:0:0 可能是一篇讲漏洞的文章，配上"这次请求正好在读
# /etc/passwd"才构成读取成功的闭环。
#
# 每项 = (请求路径/参数里的目标关键词, 响应必须命中的正则, 说明, 权重)
_FILE_READ_PROOFS: List[Tuple[Tuple[str, ...], re.Pattern, str, int]] = [
    (("/etc/passwd", "etc/passwd", "etc%2fpasswd"),
     re.compile(r"root:.{0,3}:0:0:"), "/etc/passwd 内容回显", 80),
    (("/etc/shadow", "etc/shadow"),
     re.compile(r"root:[*!$][^:\r\n]{0,120}:\d+:"), "/etc/shadow 内容回显", 85),
    (("/etc/hosts", "etc/hosts"),
     re.compile(r"^\s*127\.0\.0\.1\s+localhost", re.M), "/etc/hosts 内容回显", 60),
    (("/proc/self/environ", "proc/self/environ"),
     re.compile(r"PATH=[^\r\n]{4,}"), "/proc/self/environ 回显", 75),
    (("/proc/self/cmdline",),
     re.compile(r"\x00"), "/proc/self/cmdline 回显", 60),
    (("win.ini",),
     re.compile(r"\[fonts\]|\[extensions\]|\[mci extensions\]", re.I),
     "win.ini 内容回显", 75),
    (("boot.ini",),
     re.compile(r"\[boot loader\]", re.I), "boot.ini 内容回显", 75),
    (("system32\\drivers\\etc\\hosts", "drivers/etc/hosts"),
     re.compile(r"^\s*127\.0\.0\.1\s+localhost", re.M), "Windows hosts 回显", 60),
    # 配置文件外泄：读到源码里的数据库口令
    (("wp-config.php", "config.php", "database.yml", ".env"),
     re.compile(r"DB_PASSWORD|DB_USER|define\s*\(\s*['\"]DB_|password\s*[:=]", re.I),
     "应用配置/凭据文件内容回显", 70),
]

# 上传成功的响应形态。攻击者传完马，服务端通常只回一个极短的确认。
_UPLOAD_OK_JSON = re.compile(
    r'"(?:code|status|errno)"\s*:\s*(?:0|200|true)'
    r'|"(?:success|ok)"\s*:\s*true'
    r'|"(?:url|path|filename|filepath|savename)"\s*:\s*"[^"]{1,200}"',
    re.I,
)
# 响应体短于这个长度、且状态 200，就符合"上传确认"的形态。
# 800 字节是经验值：正常业务页面几乎不可能这么短，而上传接口的 JSON 回执
# 普遍在 100 字节以内。
_SHORT_BODY_LIMIT = 800

# 请求体里的脚本特征 —— 判断"这次 POST 是在传马"
_SCRIPT_MAGIC = re.compile(
    r"<\?php|<\?=|<%@\s*page|<%\s*@\s*language|<script\s+runat\s*=|<script\s+language\s*=\s*[\"']?php",
    re.I,
)

# 明确的失败状态码。500 不在内：注入打崩了应用同样返回 500，
# 那反而是"打中了"的迹象，不能当失败处理。
_FAILED_STATUS = {"400", "401", "403", "404", "405", "406", "410", "501"}

# 会把文件写到请求 URI 所指路径上的方法。
# GET/POST 不算：GET /x.php 是执行它，POST /upload.php 是调用上传接口
# （真实落地名从 multipart 的 filename= 里认），POST /uploads/x.php 是在用马。
# 口径与 core/provenance.py 建落地物节点时保持一致。
_WRITE_METHODS = {"PUT"}

# 可执行脚本扩展名，判断"回访的是不是自己传的马"
_SCRIPT_EXTS = (
    ".php", ".php3", ".php4", ".php5", ".php7", ".phtml", ".phar", ".pht",
    ".jsp", ".jspx", ".jspf", ".jsw", ".jsv",
    ".asp", ".aspx", ".asa", ".asax", ".ascx", ".ashx", ".cer",
    ".cfm", ".cfc", ".pl", ".cgi", ".py", ".sh",
)


# ------------------------------------------------- 维度 C：出站连接模型

# 正常 Web 服务器会主动连出去的端口（回源、API 调用、DNS、数据库…）。
# 反弹 shell 用这些端口也不是不可能，但那属于刻意规避，交给权重降级处理，
# 不能因为"端口眼熟"就直接放行。
_BENIGN_OUTBOUND_PORTS = {
    80, 443, 53, 123, 3306, 5432, 6379, 11211, 27017, 9200, 5672, 8080, 8443,
}

# 反弹 shell 的常见落点端口，命中额外加分
_CLASSIC_SHELL_PORTS = {4444, 4445, 1337, 31337, 6666, 7777, 8888, 9001, 9999, 1234, 2333}


# ---------------------------------------------------------- 维度 D 权重
#
# 定权原则：主机侧证据天然比网络侧推断更硬（网络侧看到的是"服务器连出去了"，
# 主机侧看到的是"是 bash 连出去的"），但 D 必须与 A/B/C 之一对上才计分 ——
# 单独的 EDR 事件不构成攻击成功的证据。
#
# 唯一的例外是 D2：Web 服务进程派生解释器这个形状本身就没有良性解释，
# 不需要网络侧先给出线索。

# 维度 C 的出站连接对上 netconn，且发起进程是 shell
_D_REVERSE_SHELL_CONFIRMED = 95
# 对上 netconn，但发起进程不是 shell（可能是应用自己的正常回源）
_D_REVERSE_CONN_CONFIRMED = 70
# Web 服务进程派生解释器
_D_WEB_SPAWNS_SHELL = 90
# 上传文件在磁盘上确认落地
_D_ARTIFACT_ON_DISK = 85
# 维度 A 的回显指纹对应命令在 cmdline 里出现
_D_COMMAND_MATCHED = 80

# 回显指纹 -> 该指纹只可能由哪些命令产生。D4 用它把"响应里有 uid=0"
# 和"主机上跑过 id"接起来。
#
# 键要和 _CMD_ECHO_FINGERPRINTS 里的 label 完全一致 —— 那边改文案这边
# 就会失配，所以下面 _cmd_keywords_for 用**子串匹配**而不是精确查表，
# 文案微调不至于让整条 D4 静默失效。
_FINGERPRINT_COMMANDS: List[Tuple[str, Tuple[str, ...]]] = [
    ("id 命令回显", ("id", "whoami")),
    ("whoami", ("whoami",)),
    ("ipconfig", ("ipconfig",)),
    ("Windows 版本横幅", ("ver", "systeminfo")),
    ("dir 命令", ("dir", "cmd")),
    ("ls -l", ("ls",)),
    ("ps 命令", ("ps",)),
    ("uname", ("uname",)),
    ("Web 服务账户名", ("id", "whoami")),
]


def _cmd_keywords_for(fingerprints: Iterable[str]) -> List[str]:
    """把维度 A 命中的回显指纹翻译成"主机侧该出现哪些命令"。

    子串匹配而不是精确查表：_CMD_ECHO_FINGERPRINTS 的 label 是给人看的
    文案，随时可能微调，精确匹配会让 D4 在某次无关的措辞修改后静默失效。
    """
    wanted: List[str] = []
    for label in fingerprints or []:
        text = str(label)
        for key, commands in _FINGERPRINT_COMMANDS:
            if key in text:
                for command in commands:
                    if command not in wanted:
                        wanted.append(command)
    return wanted


@dataclass
class OutboundConnection:
    """服务器主动发起的一次 TCP 连接（SYN 且非 SYN-ACK）。"""

    frame: int = 0
    ts: float = 0.0
    src_ip: str = ""        # 发起方 = 我们的服务器
    dst_ip: str = ""        # 落点 = 攻击者或第三方
    dst_port: int = 0

    @property
    def suspicious(self) -> bool:
        return self.dst_port not in _BENIGN_OUTBOUND_PORTS


# ------------------------------------------------- 维度 B：请求流水账

@dataclass
class RequestRecord:
    """一次 HTTP 请求的极简快照，只留维度 B 需要的字段。"""

    __slots__ = ("frame", "ts", "src_ip", "dst_ip", "path", "method", "status")

    frame: int
    ts: float
    src_ip: str
    dst_ip: str
    path: str
    method: str
    status: str


class RequestLedger:
    """全量 HTTP 请求的路径索引，供维度 B 做"回访"关联。

    只索引不存体：一条记录几十字节，20 万请求也就几 MB，比"漏掉回访"划算。

    每条路径的记录数有上限，但**保留的是最早的 N 条**而不是最新的 N 条。
    这个方向很关键：维度 B 要问的是"上传之后有没有人来访问"，最早的几次
    回访就足以证明，留最新的反而会被后续的大量正常访问冲掉。
    """

    MAX_PER_PATH = 64
    MAX_PATHS = 200_000

    def __init__(self) -> None:
        self._by_path: Dict[str, List[RequestRecord]] = {}
        self._dropped = 0

    def add(self, frame: int, ts: float, src_ip: str, dst_ip: str,
            uri: str, method: str = "", status: str = "") -> None:
        path = _norm_path(uri).lower()
        if not path:
            return
        bucket = self._by_path.get(path)
        if bucket is None:
            if len(self._by_path) >= self.MAX_PATHS:
                self._dropped += 1
                return
            bucket = []
            self._by_path[path] = bucket
        if len(bucket) >= self.MAX_PER_PATH:
            self._dropped += 1
            return
        bucket.append(RequestRecord(
            frame=int(frame or 0), ts=float(ts or 0.0),
            src_ip=src_ip or "", dst_ip=dst_ip or "",
            path=path, method=(method or "").upper(), status=str(status or ""),
        ))

    def accesses_after(self, path: str, after_frame: int,
                       src_ip: str = "") -> List[RequestRecord]:
        """某路径在指定帧之后被访问的记录。src_ip 非空时只算同一来源。"""
        bucket = self._by_path.get(_norm_path(path).lower())
        if not bucket:
            return []
        hits = []
        for rec in bucket:
            if rec.frame <= after_frame:
                continue
            if src_ip and rec.src_ip and rec.src_ip != src_ip:
                continue
            hits.append(rec)
        return hits

    def find_by_basename(self, name: str) -> List[str]:
        """按文件名反查完整路径 —— 上传时只知道 filename，不知道落地目录。"""
        if not name:
            return []
        needle = name.lower()
        return [p for p in self._by_path if p.rsplit("/", 1)[-1] == needle]

    @property
    def dropped(self) -> int:
        return self._dropped

    def __len__(self) -> int:
        return len(self._by_path)


# ---------------------------------------------------------------- 小工具

def _norm_path(uri: str) -> str:
    if not uri:
        return "/"
    path = uri.split("#", 1)[0].split("?", 1)[0].strip()
    return path or "/"


def _raw(detection) -> Dict[str, Any]:
    raw = getattr(detection, "raw_result", None)
    return raw if isinstance(raw, dict) else {}


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


def _ts_of(detection) -> float:
    raw = _raw(detection)
    for key in ("timestamp_epoch", "ts", "epoch"):
        try:
            value = float(raw.get(key) or 0.0)
        except (TypeError, ValueError):
            continue
        if value > 0:
            return value
    return 0.0


def _response_text(detection) -> str:
    """拿响应体样本。

    只有 2000 字节（见 stream_worker._attach_response_evidence），对指纹匹配
    够用：命令回显、passwd 内容都出现在响应最前面。真要看全文走帧号回捞。
    """
    raw = _raw(detection)
    for key in ("response_sample", "response_data"):
        text = raw.get(key) or getattr(detection, key, "") or ""
        if text:
            return str(text)
    return ""


def _response_status(detection) -> str:
    raw = _raw(detection)
    return str(raw.get("response_status") or getattr(detection, "response_status", "") or "")


def _request_text(detection) -> str:
    """请求侧的可搜索文本：URI + 原始体。用于判断攻击意图指向什么。"""
    raw = _raw(detection)
    parts = [
        str(getattr(detection, "uri", "") or raw.get("uri", "") or ""),
        str(raw.get("raw_request_body_full") or raw.get("raw_request_body") or ""),
    ]
    return "\n".join(p for p in parts if p)


def _is_script_name(name: str) -> bool:
    return bool(name) and name.lower().endswith(_SCRIPT_EXTS)


# ---------------------------------------------------------------- 研判引擎

class SuccessAdjudicator:
    """把"检测到攻击"升级成"判断攻击是否得手"。

    三个维度各自独立评分再合并，任一维度拿到铁证即可 CONFIRMED。
    引擎本身不做 I/O：请求流水账和出站连接由调用方喂进来，
    这样单元测试可以完全脱离 pcap 运行。
    """

    # 维度 B：上传到回访的时间窗。跨度给足 —— 攻击者传完马隔几小时再回来
    # 用是常态，窗口卡太死等于把最典型的场景排除掉。
    ACCESS_WINDOW = 6 * 3600.0
    # 维度 C：攻击包到反弹连接的时间窗。反弹 shell 是攻击的直接后果，
    # 通常在秒级内发生，给 120 秒足够覆盖带延迟的分阶段载荷。
    REVERSE_WINDOW = 120.0
    # 维度 D：攻击包到主机事件的时间窗。比 C 略宽 —— 落地文件、派生进程
    # 可能比反弹连接晚几十秒（编译、解压、落盘都要时间）。
    HOST_EVENT_WINDOW = 300.0

    def __init__(
        self,
        ledger: Optional[RequestLedger] = None,
        outbound: Optional[Sequence[OutboundConnection]] = None,
        host_events: Optional["HostEventLedger"] = None,
    ) -> None:
        self.ledger = ledger
        self._outbound = list(outbound or [])
        # 拿不到就是拿不到：host_events=None 时 _dimension_d 立刻返回 None，
        # 全部行为与未接入 EDR 时**逐字节一致**。和 outbound 为空同一处理。
        self.host_events = host_events
        # 按发起方 IP 分组，维度 C 查起来就不用每次全表扫
        self._outbound_by_src: Dict[str, List[OutboundConnection]] = {}
        for conn in self._outbound:
            self._outbound_by_src.setdefault(conn.src_ip, []).append(conn)
        for bucket in self._outbound_by_src.values():
            bucket.sort(key=lambda c: c.frame)

    # ---- 对外入口 ----

    def adjudicate(self, detection) -> SuccessVerdict:
        """研判单条检测。"""
        verdict = SuccessVerdict(entry_frame=_frame_of(detection))

        # D 排在最后：它要读 C 已经写进 verdict.evidence 的反弹连接、
        # 以及 A 写进去的回显指纹，才能做精确关联。
        #
        # 各维度签名统一成 (pending, detection)：D 要读前面维度的产出，
        # A/B/C 用不到但保持一致，免得循环里按维度分支。A/B/C 内部逻辑
        # 一行未动 —— 参数取名 pending 而不是 verdict，是因为 _dimension_a
        # 内部有个同名局部变量，撞名不会立刻出错但迟早咬人。
        for dimension in (self._dimension_a, self._dimension_b,
                          self._dimension_c, self._dimension_d):
            try:
                part = dimension(verdict, detection)
            except Exception as error:      # 单维度出错不能连累整体研判
                logger.debug("研判维度 %s 失败: %s", dimension.__name__, error)
                continue
            if part is not None:
                verdict.merge(part)

        self._finalize(verdict, detection)
        return verdict

    def adjudicate_all(self, detections: Iterable) -> Dict[int, SuccessVerdict]:
        """批量研判，返回 {检测在列表中的下标: 结论}。

        同时把结论写回 detection.raw_result['success_verdict']，
        这样 GUI / 报告 / 溯源图都不需要再单独持有一份映射。
        """
        verdicts: Dict[int, SuccessVerdict] = {}
        for index, detection in enumerate(detections):
            verdict = self.adjudicate(detection)
            verdicts[index] = verdict
            raw = _raw(detection)
            if raw is not None and isinstance(raw, dict):
                raw["success_verdict"] = verdict.to_dict()
        return verdicts

    # ---- 维度 A：响应特征 ----

    def _dimension_a(self, pending, detection) -> Optional[SuccessVerdict]:
        """响应里有没有"命令真的跑过 / 文件真的被读到"的痕迹。"""
        body = _response_text(detection)
        status = _response_status(detection)
        if not body and not status:
            return None

        verdict = SuccessVerdict()

        # A1 命令执行回显
        for pattern, label, weight in _CMD_ECHO_FINGERPRINTS:
            match = pattern.search(body)
            if not match:
                continue
            verdict.score += weight
            if "A" not in verdict.dimensions:
                verdict.dimensions.append("A")
            verdict.reasons.append(f"响应中出现{label}：{_snippet(match.group(0))}")
            verdict.evidence.setdefault("response_fingerprints", []).append(label)
            if weight >= 70:
                verdict.outcome = Outcome.CONFIRMED
            elif verdict.outcome is Outcome.UNKNOWN:
                verdict.outcome = Outcome.SUSPECTED
            break       # 一条回显足以定性，不必把所有指纹都列出来

        # A2 敏感文件读取 —— 请求目标与响应内容必须对得上
        request_text = _request_text(detection).lower()
        for targets, pattern, label, weight in _FILE_READ_PROOFS:
            if not any(t in request_text for t in targets):
                continue
            match = pattern.search(body)
            if not match:
                continue
            verdict.score += weight
            if "A" not in verdict.dimensions:
                verdict.dimensions.append("A")
            verdict.reasons.append(
                f"请求目标命中 {targets[0]}，且{label} —— 文件读取成功")
            verdict.evidence.setdefault("file_read", []).append(targets[0])
            verdict.outcome = Outcome.CONFIRMED
            break

        # A3 WebShell 上传成功（按用户口径只给"疑似成功"）
        upload = self._upload_confirmation(detection, body, status)
        if upload is not None:
            verdict.merge(upload)

        # A5 命令执行确认
        command = self._command_confirmation(detection, body, status)
        if command is not None:
            verdict.merge(command)

        # A4 明确失败的证据。只有在没有任何正面证据时才下这个结论 ——
        # 响应里既有 404 又有 uid=0 的情况下，显然是后者说了算。
        if verdict.score == 0 and status in _FAILED_STATUS:
            # "A" 可能在 A1 里已经加过了。重复 append 会让 _finalize 里
            # "两个独立维度同时指向成功 → 升级 CONFIRMED"的规则被**单个**
            # 维度触发，凭空虚增确认数。
            if "A" not in verdict.dimensions:
                verdict.dimensions.append("A")
            verdict.outcome = Outcome.FAILED
            verdict.reasons.append(f"服务器返回 {status}，该次攻击未生效")
            verdict.evidence["response_status"] = status

        return verdict if (verdict.score or verdict.reasons) else None

    def _upload_confirmation(self, detection, body: str,
                             status: str) -> Optional[SuccessVerdict]:
        """带 <?php 的 POST + 200 + 极短响应体/上传成功 JSON = 疑似上传成功。"""
        method = str(getattr(detection, "method", "")
                     or _raw(detection).get("method", "")).upper()
        if method not in ("POST", "PUT"):
            return None
        request_body = str(
            _raw(detection).get("raw_request_body_full")
            or _raw(detection).get("raw_request_body") or "")
        if not _SCRIPT_MAGIC.search(request_body):
            return None
        if status and not status.startswith("20"):
            return None

        json_ok = bool(_UPLOAD_OK_JSON.search(body))
        short_ok = bool(status.startswith("20")) and len(body.strip()) <= _SHORT_BODY_LIMIT
        if not (json_ok and body) and not short_ok:
            return None

        reason = (
            "上传接口返回成功回执 JSON" if json_ok
            else f"返回 {status or '2xx'} 且响应体仅 {len(body.strip())} 字节")
        return SuccessVerdict(
            outcome=Outcome.SUSPECTED,
            score=40,
            dimensions=["A"],
            reasons=[f"POST 请求体含脚本特征（<?php 等），{reason} —— 疑似上传成功"],
            evidence={"upload_response": reason},
        )

    # 响应里出现命令执行函数的调用痕迹。正常页面不会谈论 libc::system()，
    # 这类字样几乎只可能来自 WebShell 自己打的执行横幅。
    _EXEC_BANNER = re.compile(
        r"libc::system|\bshell_exec\s*\(|\bpassthru\s*\(|\bproc_open\s*\("
        r"|\bpopen\s*\(|\bos\.system\s*\(|Executing command",
        re.I,
    )

    # 请求侧"这是一次命令执行尝试"的判据。
    #
    # 必须带 re.M：_request_text 是把 URI 和请求体用换行拼起来的，
    # `cmd=whoami` 通常落在第二行开头。不加 MULTILINE 的话 `^` 只匹配
    # 整串开头，这条规则对最常见的 POST 形态直接失效。
    _CMD_REQUEST = re.compile(
        r"(?:^|[&?\s])(?:cmd|exec|command|shell|execute|system|cmdline)=",
        re.I | re.M)

    def _command_confirmation(self, detection, body: str,
                              status: str) -> Optional[SuccessVerdict]:
        """请求让它跑一条命令，响应看起来像是真跑了。

        ── 为什么需要这一条 ──

        实测：`POST /hackable/uploads/ffi_shell.php` 带 `cmd=whoami`，服务器
        回 200 + `[+] Executing command via FFI -> libc::system():`。这是命令
        执行的铁证，但维度 A 原来一条都对不上 —— A1 找的是**命令输出**长什么样
        （uid=/gid=、ipconfig 回显），而这里响应里是 WebShell 自己的执行横幅，
        不是输出本身。结果研判给 unknown，界面把它降到"信息"级，比同一个包里
        的正常登录请求还低。

        两档判据，强度不同：

          执行横幅   响应里出现 libc::system / shell_exec( / Executing command
                     这类字样 —— 正常页面不会谈论这些，直接给 CONFIRMED

          短回执     请求是命令执行形态 + 200 + 响应体短且非 HTML
                     —— 只给 SUSPECTED。短 200 也可能是别的东西，这里
                     和 A3 的上传确认是同一个推理形式和同一个保守口径。
        """
        request_text = _request_text(detection)
        if not self._CMD_REQUEST.search(request_text):
            # 请求侧不是命令执行形态就不谈 —— 单看响应里有 system( 可能只是
            # 一篇讲 PHP 的文章
            return None
        if status and not status.startswith("20"):
            return None

        match = self._EXEC_BANNER.search(body or "")
        if match:
            return SuccessVerdict(
                outcome=Outcome.CONFIRMED,
                score=85,
                dimensions=["A"],
                reasons=[f"请求要求执行命令，响应中出现执行痕迹："
                         f"{_snippet(match.group(0))} —— 命令执行成功"],
                evidence={"command_exec": match.group(0)},
            )

        stripped = (body or "").strip()
        if not stripped or len(stripped) > _SHORT_BODY_LIMIT:
            return None
        if re.search(r"<html|<!doctype|<body", stripped[:200], re.I):
            return None

        return SuccessVerdict(
            outcome=Outcome.SUSPECTED,
            score=40,
            dimensions=["A"],
            reasons=[f"请求要求执行命令，服务器返回 {status or '2xx'} 且响应体仅 "
                     f"{len(stripped)} 字节的非 HTML 文本 —— 疑似命令已执行"],
            evidence={"command_response": f"{len(stripped)}B"},
        )

    # ---- 维度 B：后续行为关联 ----
    def _dimension_b(self, pending, detection) -> Optional[SuccessVerdict]:
        """攻击者是不是回来用他刚种下的东西了。

        真正成功的上传后面一定跟着访问 —— 传上去不用，等于没传。这条时序
        关系比任何请求特征都硬，因为它是攻击目的本身，无法在保留攻击效果
        的前提下省略。
        """
        if self.ledger is None:
            return None

        # 请求本身就被服务器拒了（404/403…），它不可能"种下"任何东西 ——
        # 维度 B 的整个前提是"这条检测投放了 X，后来 X 被访问了"，前提不成立
        # 就不该产出结论。
        #
        # 这一条不是可有可无的加固：`merge` 取的是**更严重**的结论，B 一旦
        # 给出 CONFIRMED，就会把维度 A 依据 404 得出的 FAILED 直接盖掉。
        # 实测过一个 `GET /index.php?id=1 union select...` 返回 404 的注入探测，
        # 因为 /index.php 在抓包里被正常访问了 4 次，最终被判成"确认得手"。
        #
        # 维度 C 不受这条约束：注入把页面打成 404、同时触发反弹 shell 是完全
        # 可能的，出站连接是独立于 HTTP 响应的客观证据。
        if _response_status(detection) in _FAILED_STATUS:
            return None

        frame = _frame_of(detection)
        ts = _ts_of(detection)
        src_ip = str(getattr(detection, "source_ip", "")
                     or _raw(detection).get("src_ip", "") or "")

        candidates = self._implanted_paths(detection)
        if not candidates:
            return None

        for path, origin in candidates:
            hits = self.ledger.accesses_after(path, frame, src_ip=src_ip)
            same_source = True
            if not hits and src_ip:
                # 攻击者换出口 IP 回来用马是常态（挂代理、跳板、动态拨号）。
                # 原来只认同源回访，这类直接漏掉。改成降级认定：同源=确认，
                # 跨源=疑似，并在 reason 里写明来源不同，让人工能复核。
                hits = self.ledger.accesses_after(path, frame)
                same_source = False
            if ts:
                hits = [h for h in hits
                        if not h.ts or (h.ts - ts) <= self.ACCESS_WINDOW]
            if not hits:
                continue

            frames = [h.frame for h in hits[:10]]
            # 只回访一次 = 疑似（也可能是攻击者在探测有没有传上去）；
            # 多次回访 = 已经在当 webshell 用了，定性确认。
            repeated = len(hits) >= 2
            confirmed = repeated and same_source
            sources = sorted({h.src_ip for h in hits if h.src_ip})
            verdict = SuccessVerdict(
                outcome=Outcome.CONFIRMED if confirmed else Outcome.SUSPECTED,
                score=70 if confirmed else 45,
                dimensions=["B"],
                entry_frame=frame,
                followup_frames=frames,
                evidence={
                    "implanted_path": path,
                    "implant_origin": origin,
                    "access_count": len(hits),
                    "same_source": same_source,
                    "access_sources": sources[:5],
                },
            )
            source_note = "" if same_source else f"（回访来源 {', '.join(sources[:3])}，与投放者不同）"
            verdict.reasons.append(
                f"frame {frame} 投放 {path}（{origin}），随后"
                f"{'同一来源' if same_source else '其他来源'}"
                f"{'多次' if repeated else ''}访问该路径 {len(hits)} 次"
                f"（frame {', '.join(str(f) for f in frames[:5])}）{source_note}"
                f" —— {'确认落地并已被使用' if confirmed else '疑似落地'}"
            )
            return verdict

        return None

    def _implanted_paths(self, detection) -> List[Tuple[str, str]]:
        """这条检测可能"种"下了哪些可执行路径。

        两个来源：
          1. 上传表单里的 filename（要按文件名去流水账里反查真实落地目录）
          2. 请求**把文件写到**了自身 URI 指向的脚本路径

        第 2 条必须卡方法，这里踩过一个很贵的坑：原来只要 URI 以 .php/.jsp
        结尾就算"种下了"，于是 `GET /index.php?id=1 union select...` 被判成
        投放了 /index.php —— 而 /index.php 是站点主入口，抓包里被访问几十次，
        维度 B 一看"投放后同一来源多次回访"就给了 CONFIRMED。**一次注入探测
        加上正常浏览，就凭空变成"确认得手"。**

        判据应该是"这个动作会不会把文件写到这个路径上"：
          PUT /shell.php        会      —— 直接写文件
          GET /index.php        不会    —— 只是执行它
          POST /upload.php      不会    —— 调用上传接口，文件落在别处，
                                          真实落地名由上面第 1 条从 multipart
                                          的 filename= 里认
          POST /uploads/x.php   不会    —— 那是在**用**马，不是种马
        `core/provenance.py` 建落地物节点时用的就是这个口径，两边保持一致。
        """
        results: List[Tuple[str, str]] = []
        raw = _raw(detection)

        names = raw.get("uploaded_names") or []
        if not names:
            body = raw.get("raw_request_body_full") or raw.get("raw_request_body") or ""
            content_type = raw.get("content_type", "") or ""
            names = _extract_uploaded_names(body, content_type)

        for name in names:
            if not _is_script_name(name):
                continue
            found = []
            if self.ledger is not None:
                found = [(path, f"上传文件 {name}")
                         for path in self.ledger.find_by_basename(name)]
            # 流水账里查不到落地路径（回访发生在采集窗口之外、或压根没回访）
            # 时给个根目录猜测，让维度 B 至少有个 key 可查，不至于整条断掉。
            results.extend(found or [(f"/{name}", f"上传文件 {name}")])

        method = str(getattr(detection, "method", "")
                     or raw.get("method", "")).upper()
        if method in _WRITE_METHODS:
            uri_path = _norm_path(str(getattr(detection, "uri", "")
                                      or raw.get("uri", "") or ""))
            if _is_script_name(uri_path.rsplit("/", 1)[-1]):
                results.append((uri_path, f"{method} 直接写入该脚本路径"))

        return results

    # ---- 维度 C：反向连接 ----

    def _dimension_c(self, pending, detection) -> Optional[SuccessVerdict]:
        """被攻击的服务器有没有掉头主动连出去。

        Web 服务器的正常角色是"被连"。它在收到一个攻击包之后突然主动向外
        发起非 HTTP 的 TCP 连接，只有一种合理解释：攻击载荷在它上面执行了，
        并且拉起了一个反向 shell。这是三个维度里唯一的铁证级信号。
        """
        if not self._outbound_by_src:
            return None

        raw = _raw(detection)
        server_ip = str(getattr(detection, "dest_ip", "") or raw.get("dst_ip", "") or "")
        attacker_ip = str(getattr(detection, "source_ip", "") or raw.get("src_ip", "") or "")
        if not server_ip:
            return None

        frame = _frame_of(detection)
        ts = _ts_of(detection)
        conns = self._outbound_by_src.get(server_ip) or []

        for conn in conns:
            if conn.frame <= frame:
                continue
            if ts and conn.ts and (conn.ts - ts) > self.REVERSE_WINDOW:
                break       # 已按帧号排序，再往后只会更远
            if not conn.suspicious:
                continue

            back_to_attacker = bool(attacker_ip and conn.dst_ip == attacker_ip)
            score = 90 if back_to_attacker else 70
            if conn.dst_port in _CLASSIC_SHELL_PORTS:
                score += 10
            target = "攻击者本机" if back_to_attacker else "第三方地址"

            return SuccessVerdict(
                outcome=Outcome.CONFIRMED,
                score=min(score, 100),
                dimensions=["C"],
                entry_frame=frame,
                followup_frames=[conn.frame],
                reasons=[
                    f"攻击包 frame {frame} 之后，服务器 {server_ip} 主动向"
                    f"{target} {conn.dst_ip}:{conn.dst_port} 发起非 HTTP 出站连接"
                    f"（frame {conn.frame}）—— 反弹 shell，命令执行已确认成功"
                ],
                evidence={
                    "reverse_shell": {
                        "frame": conn.frame,
                        "dst_ip": conn.dst_ip,
                        "dst_port": conn.dst_port,
                        "back_to_attacker": back_to_attacker,
                    }
                },
            )

        return None

    # ---- 维度 D：主机侧落地证据（可选，未接入 EDR 时整个跳过） ----

    def _dimension_d(self, pending, detection) -> Optional[SuccessVerdict]:
        """主机侧遥测有没有把网络侧的推断坐实。

        D 是**确证器不是发现器**：每一条计分都要和 A/B/C 之一对上。单独的
        EDR 事件（正常主机每分钟几百条）不构成攻击成功的证据 —— 让它独立
        定案只会把它变成新的噪声源，那正是这个引擎要解决的问题本身。

        所以 D1 要 C 已经找到出站连接、D3 要 B 的落地路径、D4 要 A 的回显
        指纹。只有 D2（Web 服务派生解释器）是自足的，因为那个形状本身就
        没有良性解释。
        """
        if self.host_events is None:
            return None

        raw = _raw(detection)
        server_ip = str(getattr(detection, "dest_ip", "")
                        or raw.get("dst_ip", "") or "")
        if not server_ip:
            return None

        ts = _ts_of(detection)
        frame = _frame_of(detection)
        out = SuccessVerdict(entry_frame=frame)
        prior = (pending.evidence or {}) if pending is not None else {}

        # ---- D1：把维度 C 的出站连接坐实到具体进程 ----
        conn = prior.get("reverse_shell")
        if conn:
            hits = self.host_events.netconns(
                server_ip,
                dst_ip=conn.get("dst_ip", ""),
                dst_port=int(conn.get("dst_port", 0) or 0),
                around_ts=conn.get("ts") or ts)
            for event in hits:
                is_shell = _image_name(event.image) in SHELL_IMAGES
                out.score += (_D_REVERSE_SHELL_CONFIRMED if is_shell
                              else _D_REVERSE_CONN_CONFIRMED)
                out.outcome = Outcome.CONFIRMED
                out.reasons.append(
                    f"主机 {server_ip} 侧确认该出站连接由进程 {event.image}"
                    f"(pid {event.pid}, 父进程 {event.parent_image}) 发起"
                    + ("　—— 解释器直连外网，反弹 shell 实锤" if is_shell else ""))
                out.evidence.setdefault("host_netconn", []).append(_ev_brief(event))
                break

        # ---- D2：Web 服务派生解释器 ----
        # 这条不需要前置维度：httpd 派生 bash 没有良性解释。
        spawns = self.host_events.processes(
            server_ip, after_ts=ts, window=self.HOST_EVENT_WINDOW,
            parent_hint=WEB_SERVER_IMAGES, image_hint=SHELL_IMAGES)
        if spawns:
            event = spawns[0]
            out.score += _D_WEB_SPAWNS_SHELL
            out.outcome = Outcome.CONFIRMED
            gap = (event.ts - self.host_events.clock_skew) - ts if ts else 0.0
            out.reasons.append(
                f"攻击包之后 {gap:.1f}s，Web 服务进程 {event.parent_image} "
                f"派生出 {event.image}：{_snippet(event.cmdline, 160)}")
            out.evidence.setdefault("process_chain", []).append(_ev_brief(event))

        # ---- D3：落地物在磁盘上被确认 ----
        for path, _origin in self._implanted_paths(detection):
            basename = path.rsplit("/", 1)[-1]
            if not basename:
                continue
            files = self.host_events.files_created(
                server_ip, basename=basename, after_ts=ts,
                window=self.HOST_EVENT_WINDOW)
            if not files:
                continue
            event = files[0]
            out.score += _D_ARTIFACT_ON_DISK
            out.outcome = Outcome.CONFIRMED
            out.reasons.append(
                f"上传的 {basename} 在主机磁盘上确认落地：{event.file_path}"
                f"（创建者 {event.image}）")
            out.evidence.setdefault("artifact_on_disk", []).append(_ev_brief(event))
            break

        # ---- D4：回显指纹对应的命令出现在 cmdline 里 ----
        fingerprints = prior.get("response_fingerprints") or []
        wanted = _cmd_keywords_for(fingerprints)
        if wanted:
            for event in self.host_events.processes(
                    server_ip, after_ts=ts, window=self.HOST_EVENT_WINDOW):
                low = (event.cmdline or "").lower()
                if any(word in low for word in wanted):
                    out.score += _D_COMMAND_MATCHED
                    out.outcome = Outcome.CONFIRMED
                    out.reasons.append(
                        "响应里的回显指纹与主机侧命令对上："
                        f"{_snippet(event.cmdline, 160)}")
                    out.evidence.setdefault("command_matched", []).append(
                        _ev_brief(event))
                    break

        # ---- D0：EDR 覆盖了这台主机，但窗口内什么都没发生 ----
        # 不改结论（研判只增不减），只留痕。这类条目最值得人工看一眼：
        # 要么攻击确实没打成，要么 EDR 在这台机器上有盲区。
        if out.score == 0 and self.host_events.covers(server_ip):
            out.reasons.append(
                f"主机 {server_ip} 已接入 EDR，但攻击包前后 "
                f"{self.HOST_EVENT_WINDOW:.0f}s 内无相关进程/文件/连接事件")
            out.evidence["edr_silent"] = True

        if out.score:
            out.dimensions.append("D")
        return out if (out.score or out.reasons) else None

    # ---- 收尾 ----

    @staticmethod
    def _finalize(verdict: SuccessVerdict, detection) -> None:
        """按总分兜底定级，并保证 entry_frame 一定有值。"""
        if verdict.outcome is not Outcome.CONFIRMED:
            if verdict.score >= _CONFIRM_SCORE:
                verdict.outcome = Outcome.CONFIRMED
            elif verdict.score >= _SUSPECT_SCORE and verdict.outcome is not Outcome.FAILED:
                verdict.outcome = Outcome.SUSPECTED
        # 多维交叉本身就是强证据：两个独立维度同时指向成功，
        # 即使各自都不够阈值，合起来也该被人看见。
        #
        # 判据必须用 set：`dimensions` 是 list，而各分支往里 append 的路径
        # 有好几条（A1/A2/A3 的 merge/A4），只要哪天有一条重复写入，
        # `len(list) >= 2` 就会把**单维度**当成多维交叉，凭空虚增 CONFIRMED。
        # SuccessVerdict.merge 本来就是按去重语义合并的，这里和它对齐。
        if len(set(verdict.dimensions)) >= 2 and verdict.outcome is Outcome.SUSPECTED:
            if verdict.score >= _CONFIRM_SCORE - 10:
                verdict.outcome = Outcome.CONFIRMED
        if not verdict.entry_frame:
            verdict.entry_frame = _frame_of(detection)


def _snippet(text: str, limit: int = 120) -> str:
    """给报告用的短摘录，压掉换行避免撑破表格。"""
    flat = " ".join(str(text).split())
    return flat if len(flat) <= limit else flat[:limit] + "…"


def _extract_uploaded_names(body: Any, content_type: str) -> List[str]:
    """复用 session_tracker 的实现，拿不到就退化成空列表。"""
    try:
        from core.session_tracker import extract_uploaded_names
    except ImportError:
        return []
    if not body:
        return []
    if isinstance(body, str):
        body = body.encode("utf-8", errors="ignore")
    try:
        return extract_uploaded_names(body, content_type or "")
    except Exception:
        return []


# ---------------------------------------------------- 维度 C 的数据采集

# 出站 SYN 的采集上限。这里可以设上限而检测条数不行，因为反弹 shell 只需要
# 一次连接就能证明，攻击者没法靠"多发连接"把自己藏起来 —— 多发只会更显眼。
MAX_OUTBOUND_SYN = 200_000

_SYN_FIELDS = [
    "frame.number", "frame.time_epoch", "ip.src", "ip.dst", "tcp.dstport",
]


def collect_outbound_syn(
    pcap_path: str,
    tshark_path: str,
    server_ips: Optional[Iterable[str]] = None,
    is_cancelled=None,
) -> List[OutboundConnection]:
    """扫一遍 pcap，收集所有"主动发起"的 TCP 连接。

    display filter 用 `tcp.flags.syn==1 && tcp.flags.ack==0` —— 只有连接
    发起方会发这种包，响应方发的是 SYN-ACK。所以命中的每一条都明确带方向。

    这一趟只取 5 个标量字段（不解析 payload、不组流），是 tshark 最快的
    工作模式，几百 MB 的包也就几秒，比 AST 全量重扫便宜两个数量级。
    """
    if not pcap_path or not tshark_path:
        return []

    try:
        from core.tshark_stream import (
            OutputFormat, StreamConfig, TsharkProcessHandler,
        )
    except ImportError as error:
        logger.warning("反弹连接检测不可用（tshark_stream 导入失败）: %s", error)
        return []

    wanted = {ip for ip in (server_ips or []) if ip}
    connections: List[OutboundConnection] = []
    handler = None
    try:
        handler = TsharkProcessHandler(tshark_path)
        config = StreamConfig(
            pcap_path=pcap_path,
            display_filter="tcp.flags.syn==1 && tcp.flags.ack==0",
            output_format=OutputFormat.FIELDS,
            fields=list(_SYN_FIELDS),
            disable_name_resolution=True,
            line_buffered=True,
        )
        for packet in handler.stream_packets(config):
            if is_cancelled is not None and is_cancelled():
                break
            src = getattr(packet, "src_ip", "") or ""
            # 只关心"我们的服务器"发出去的。attacker->server 的 SYN 是正常访问，
            # 混进来只会稀释信号。server_ips 为空时不过滤，交给上层判断。
            if wanted and src not in wanted:
                continue
            connections.append(OutboundConnection(
                frame=int(getattr(packet, "frame_number", 0) or 0),
                ts=float(getattr(packet, "timestamp_epoch", 0.0) or 0.0),
                src_ip=src,
                dst_ip=getattr(packet, "dst_ip", "") or "",
                dst_port=int(getattr(packet, "dst_port", 0) or 0),
            ))
            if len(connections) >= MAX_OUTBOUND_SYN:
                logger.warning("出站 SYN 采集达到 %d 上限", MAX_OUTBOUND_SYN)
                break
    except Exception as error:
        logger.warning("出站连接采集失败，维度 C 跳过: %s", error)
        return []
    finally:
        if handler is not None:
            try:
                handler.stop()
            except Exception:
                pass

    connections.sort(key=lambda c: c.frame)
    return connections


def build_adjudicator(
    detections: Sequence,
    ledger: Optional[RequestLedger] = None,
    pcap_path: str = "",
    tshark_path: str = "",
    is_cancelled=None,
    edr_client=None,
) -> SuccessAdjudicator:
    """按检测结果里出现过的服务器 IP，采集出站连接并装配研判引擎。

    edr_client 给了才会去拉主机侧遥测（维度 D）。默认 None —— 具体 EDR
    尚未选定，此时 D 整个跳过，行为与接入前完全一致。选定之后照
    `core.edr_bridge.EDRClient` 实现一个 client 传进来即可，本函数
    和引擎侧都不用再改。
    """
    server_ips = set()
    for det in detections:
        ip = str(getattr(det, "dest_ip", "") or _raw(det).get("dst_ip", "") or "")
        if ip:
            server_ips.add(ip)

    outbound: List[OutboundConnection] = []
    if pcap_path and tshark_path and server_ips:
        outbound = collect_outbound_syn(
            pcap_path, tshark_path, server_ips, is_cancelled=is_cancelled)

    host_events = None
    if edr_client is not None and server_ips:
        host_events = _build_host_events(
            edr_client, server_ips, detections, outbound, is_cancelled)

    return SuccessAdjudicator(ledger=ledger, outbound=outbound,
                              host_events=host_events)


def _build_host_events(edr_client, server_ips, detections, outbound,
                       is_cancelled):
    """拉主机事件并建索引。任何失败都降级为 None（维度 D 跳过）。

    时间范围从 detections 的 min/max 时间戳推出，两端各留一个
    HOST_EVENT_WINDOW 的余量 —— 落地文件可能比攻击包晚几分钟。
    """
    try:
        from core.edr_bridge import build_host_ledger
    except ImportError:
        try:
            from edr_bridge import build_host_ledger
        except ImportError as error:
            logger.warning("维度 D 不可用（edr_bridge 导入失败）: %s", error)
            return None

    stamps = [t for t in (_ts_of(d) for d in detections) if t]
    if not stamps:
        return None

    margin = SuccessAdjudicator.HOST_EVENT_WINDOW
    try:
        return build_host_ledger(
            edr_client, sorted(server_ips),
            start_ts=min(stamps) - margin,
            end_ts=max(stamps) + margin,
            outbound=outbound,
            is_cancelled=is_cancelled,
        )
    except Exception as error:
        logger.warning("主机事件装配失败，维度 D 跳过: %s", error)
        return None
