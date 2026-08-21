# -*- coding: utf-8 -*-
"""edr_bridge.py - 主机侧遥测桥接层（维度 D 的数据面）
#
# ============ 这个模块的定位 ============
#
# 维度 D 是**确证器，不是发现器**。
#
# 理由和维度 A2「敏感文件读取必须请求与响应成对」是同一个论证形式：正常主机
# 每分钟产生几百条进程/网络事件，让 EDR 独立定案只会把它变成新的噪声源。
# 所以 D 的每一条计分都必须和 A/B/C 之一在时空上对上 —— 引擎侧的
# `SuccessAdjudicator._dimension_d` 严格执行这条。
#
# 本模块只负责**数据面**：归一化事件模型、按 (主机, 时间) 的索引、厂商适配
# 接口、以及时钟偏移估算。判定逻辑一概不在这里。
#
# ============ 为什么归一化字段这么少 ============
#
# 只归一化研判用得上的那几个字段，其余原样丢进 `raw`。归一化字段越多，
# 厂商适配层越脆 —— 每加一个字段，就要在每家 EDR 的 schema 里找到对应项，
# 而它们的字段名、时区、层级结构毫无共识。少即是稳。
#
# ============ 尚未实现的部分 ============
#
# 具体 EDR 未选定，所以本模块**不含任何厂商适配器**。`EDRClient` 是
# Protocol（结构化类型），选定之后照着实现 `query()` 即可，引擎侧零改动。
# `collect_host_events` 已经写好了调用编排、上限保护和异常兜底，
# 接上任意一个 client 就能跑。
"""

import logging
from bisect import bisect_left, bisect_right
from dataclasses import dataclass, field
from statistics import median
from typing import (
    Any, Dict, Iterable, List, Optional, Sequence, Tuple,
)

try:                                    # Python 3.8+ 才有 Protocol
    from typing import Protocol
except ImportError:                     # pragma: no cover
    Protocol = object

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------- 事件模型

# 事件类型。只归一化研判用得上的四类，其余原样丢进 raw。
KIND_PROCESS = "process_create"
KIND_NETCONN = "network_connect"
KIND_FILE = "file_create"
KIND_SCRIPT = "script_block"        # PowerShell / WMI 脚本块日志

ALL_KINDS = (KIND_PROCESS, KIND_NETCONN, KIND_FILE, KIND_SCRIPT)


@dataclass
class HostEvent:
    """一条主机侧遥测的极简快照，只留关联用得上的字段。

    ts 是关联主键，必须是 **epoch 秒**。厂商返回的时区/格式五花八门
    （ISO8601 带 Z、本地时间不带时区、毫秒时间戳……），归一化在适配层做完，
    引擎侧只认 float。
    """

    ts: float = 0.0
    kind: str = ""
    host_ip: str = ""            # 关联网络侧 dst_ip（被攻击的那台服务器）
    hostname: str = ""
    pid: int = 0
    ppid: int = 0
    image: str = ""              # 进程完整路径
    parent_image: str = ""       # 父进程，判"web 服务派生 shell"的关键
    cmdline: str = ""
    dst_ip: str = ""             # KIND_NETCONN
    dst_port: int = 0
    file_path: str = ""          # KIND_FILE
    file_hash: str = ""          # SHA256，小写
    source: str = ""             # "sysmon" / "wazuh" / "defender"
    raw: Dict[str, Any] = field(default_factory=dict)


def image_name(path: str) -> str:
    """从完整路径里取可执行文件名，小写。

    Windows 用 `\\`，Linux 用 `/`，EDR 里两种都可能出现（甚至混用），
    所以两个分隔符都切。
    """
    if not path:
        return ""
    tail = str(path).replace("\\", "/").rsplit("/", 1)[-1]
    return tail.strip().lower()


def event_brief(event: HostEvent) -> Dict[str, Any]:
    """给 evidence / 报告用的精简视图，不带 raw（那可能有几 KB）"""
    brief = {
        "ts": event.ts,
        "kind": event.kind,
        "host": event.host_ip or event.hostname,
        "source": event.source,
    }
    if event.image:
        brief["image"] = event.image
    if event.parent_image:
        brief["parent_image"] = event.parent_image
    if event.pid:
        brief["pid"] = event.pid
    if event.cmdline:
        brief["cmdline"] = event.cmdline[:200]
    if event.dst_ip:
        brief["dst"] = f"{event.dst_ip}:{event.dst_port}"
    if event.file_path:
        brief["file_path"] = event.file_path
    if event.file_hash:
        brief["file_hash"] = event.file_hash
    return brief


# ---------------------------------------------------------------- 进程语义表

# Web 服务进程。它们派生出解释器几乎只有一种解释。
WEB_SERVER_IMAGES = frozenset({
    "w3wp.exe", "httpd.exe", "httpd", "nginx.exe", "nginx",
    "php-fpm", "php-cgi.exe", "java.exe", "java", "tomcat",
    "apache2", "caddy", "node.exe", "node",
})

# 解释器 / shell / 下载器。作为子进程出现在 Web 服务下 = 强信号。
SHELL_IMAGES = frozenset({
    "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe",
    "sh", "bash", "dash", "zsh", "python", "python3", "perl", "ruby",
    "nc", "ncat", "netcat", "socat", "curl", "wget", "certutil.exe",
    "bitsadmin.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe",
})


def is_shell_image(path: str) -> bool:
    return image_name(path) in SHELL_IMAGES


def is_web_server_image(path: str) -> bool:
    return image_name(path) in WEB_SERVER_IMAGES


# ---------------------------------------------------------------- 索引容器

class HostEventLedger:
    """按 (主机, 时间) 索引的主机事件表，供维度 D 做时空关联。

    和 `RequestLedger` 一样只索引不存体。桶按主机 IP 分，桶内按 ts 排序，
    查询用二分 —— 一次研判要查上千次，线性扫会成为瓶颈。

    时钟偏移在**入库时**就归一化掉（`_norm` 列表），查询侧不用再关心；
    这样 skew 改变时只要重建一次索引，不会散落到每个查询点上。
    """

    # 时钟容差。抓包机和终端时钟不同源，±30s 是经验值：NTP 同步良好时
    # 实测偏移 <2s，但虚拟机/容器环境能漂到十几秒。
    MATCH_WINDOW_S = 30.0

    # 单主机事件上限。这个上限**允许存在**，理由和 MAX_OUTBOUND_SYN 一样：
    # 确证只需要一条匹配事件，攻击者多产生事件只会更容易被抓到，不会因为
    # "事件多"而把自己藏起来。注意这和检测侧那些「填充即绕过」的上限性质
    # 完全不同 —— 那些是攻击者能把自己**挤出视野**，这里不能。
    MAX_PER_HOST = 500_000

    def __init__(self, events: Optional[Iterable[HostEvent]] = None,
                 clock_skew_s: float = 0.0,
                 covered_hosts: Optional[Iterable[str]] = None) -> None:
        self._by_host: Dict[str, List[HostEvent]] = {}
        self._norm_by_host: Dict[str, List[float]] = {}
        self._skew = float(clock_skew_s or 0.0)
        self._dropped = 0
        self._sealed = False
        # 哪些主机在 EDR 覆盖范围内。这个要**显式**给：
        # "查不到事件"和"这台机器没装 agent"是两个完全不同的结论，
        # D0 留痕（网络侧疑似 + 主机侧无痕）只有在确知覆盖时才有意义。
        self._covered = {ip for ip in (covered_hosts or []) if ip}

        for event in (events or []):
            self.add(event)
        self.seal()

    # ---- 装载 ----

    def add(self, event: HostEvent) -> None:
        key = event.host_ip or event.hostname
        if not key:
            self._dropped += 1
            return
        bucket = self._by_host.setdefault(key, [])
        if len(bucket) >= self.MAX_PER_HOST:
            self._dropped += 1
            return
        bucket.append(event)
        self._sealed = False

    def seal(self) -> None:
        """全部灌完后调一次：按归一化时间排序并建二分索引。

        归一化 = 事件时间减去时钟偏移，换算到**抓包机时间轴**上。
        正的 skew 表示 EDR 时钟比抓包机快。
        """
        self._norm_by_host = {}
        for key, bucket in self._by_host.items():
            bucket.sort(key=lambda e: e.ts)
            self._norm_by_host[key] = [e.ts - self._skew for e in bucket]
        self._sealed = True

    @property
    def clock_skew(self) -> float:
        return self._skew

    def set_clock_skew(self, skew: float) -> None:
        self._skew = float(skew or 0.0)
        self.seal()

    @property
    def dropped(self) -> int:
        return self._dropped

    def covers(self, host_ip: str) -> bool:
        """这台主机在 EDR 覆盖范围内吗

        显式声明优先。没声明时退化为"有没有该主机的事件" —— 弱一些，
        但比一律返回 False 有用（至少接了 EDR 又有别的事件时能判 D0）。
        """
        if not host_ip:
            return False
        if self._covered:
            return host_ip in self._covered
        return bool(self._by_host.get(host_ip))

    def __len__(self) -> int:
        return sum(len(b) for b in self._by_host.values())

    # ---- 内部：时间窗切片 ----

    def _window(self, host_ip: str, center_ts: float,
                window: Optional[float],
                forward_only: bool) -> List[HostEvent]:
        """取某主机在时间窗内的事件切片（已按时间排序）

        forward_only=True 时只看 center_ts 之后的（进程派生、文件落地都在
        攻击**之后**），但仍留 MATCH_WINDOW_S 的向前容差给时钟误差。
        """
        if not self._sealed:
            self.seal()
        bucket = self._by_host.get(host_ip)
        if not bucket:
            return []

        norms = self._norm_by_host.get(host_ip) or []
        span = self.MATCH_WINDOW_S if window is None else float(window)

        if not center_ts:
            return list(bucket)          # 没有时间基准就不切窗，交给调用方过滤

        low = center_ts - (self.MATCH_WINDOW_S if forward_only else span)
        high = center_ts + span
        start = bisect_left(norms, low)
        end = bisect_right(norms, high)
        return bucket[start:end]

    # ---- 三种查询，对应 D 的三条计分路径 ----

    def netconns(self, host_ip: str, dst_ip: str = "", dst_port: int = 0,
                 around_ts: float = 0.0,
                 window: Optional[float] = None) -> List[HostEvent]:
        """某主机在时间窗内的出站连接。dst_ip/dst_port 非空时精确匹配。"""
        out = []
        for event in self._window(host_ip, around_ts, window, forward_only=False):
            if event.kind != KIND_NETCONN:
                continue
            if dst_ip and event.dst_ip != dst_ip:
                continue
            if dst_port and event.dst_port != int(dst_port):
                continue
            out.append(event)
        return out

    def files_created(self, host_ip: str, basename: str = "",
                      file_hash: str = "", after_ts: float = 0.0,
                      window: Optional[float] = None) -> List[HostEvent]:
        """按文件名或 hash 找创建事件。

        hash 优先 —— 文件名可能被改，内容不会。两个都给时，hash 命中即可，
        不要求文件名也一致（攻击者落地时改名是常规操作）。
        """
        wanted_hash = (file_hash or "").strip().lower()
        wanted_name = (basename or "").strip().lower()
        out = []
        for event in self._window(host_ip, after_ts, window, forward_only=True):
            if event.kind != KIND_FILE:
                continue
            if wanted_hash and (event.file_hash or "").lower() == wanted_hash:
                out.append(event)
                continue
            if wanted_name and image_name(event.file_path) == wanted_name:
                out.append(event)
                continue
            if not wanted_hash and not wanted_name:
                out.append(event)
        return out

    def processes(self, host_ip: str, after_ts: float = 0.0,
                  window: Optional[float] = None,
                  parent_hint: Sequence[str] = (),
                  image_hint: Sequence[str] = ()) -> List[HostEvent]:
        """时间窗内的进程创建。

        parent_hint / image_hint 是**可执行文件名集合**（不是子串），
        取自 WEB_SERVER_IMAGES / SHELL_IMAGES 这类语义表。给空则不过滤。
        """
        parents = {p.lower() for p in parent_hint}
        images = {i.lower() for i in image_hint}
        out = []
        for event in self._window(host_ip, after_ts, window, forward_only=True):
            if event.kind not in (KIND_PROCESS, KIND_SCRIPT):
                continue
            if parents and image_name(event.parent_image) not in parents:
                continue
            if images and image_name(event.image) not in images:
                continue
            out.append(event)
        return out

    def stats(self) -> Dict[str, Any]:
        return {
            "hosts": len(self._by_host),
            "events": len(self),
            "dropped": self._dropped,
            "clock_skew_s": self._skew,
            "covered_hosts": len(self._covered),
        }


# ---------------------------------------------------------------- 厂商适配

class EDRClient(Protocol):
    """厂商适配接口。归一化在实现里做完，引擎只认 HostEvent。

    实现要点（选定 EDR 之后照这个写）：
      * `ts` 必须换算成 epoch 秒（float）。这是关联主键，错了整个维度失效。
      * `host_ip` 要能和网络侧的 `dst_ip` 对上。多网卡/NAT 环境下
        EDR 报的可能是内网地址，需要在适配层做映射。
      * 拿不到的字段留空，不要塞占位符 —— 引擎按空值跳过，
        塞了 "unknown" 反而会误匹配。
      * 查询失败**抛异常**即可，`collect_host_events` 会兜住并降级为
        "没有主机数据"，维度 D 静默跳过。
    """

    def query(self, host_ips: Iterable[str], start_ts: float, end_ts: float,
              kinds: Iterable[str]) -> Iterable[HostEvent]:
        ...


# 兜底上限，理由同 MAX_OUTBOUND_SYN：确证只需要一条匹配事件，
# 攻击者没法靠"多产生事件"把自己藏起来。
MAX_HOST_EVENTS = 2_000_000


def collect_host_events(
    client: Optional["EDRClient"],
    server_ips: Iterable[str],
    start_ts: float,
    end_ts: float,
    kinds: Iterable[str] = ALL_KINDS,
    is_cancelled=None,
) -> List[HostEvent]:
    """按检测结果里出现过的服务器 IP + 时间范围拉主机事件。

    时间范围由调用方从 detections 的 min/max 时间戳推出，两端各留
    `SuccessAdjudicator.HOST_EVENT_WINDOW` 的余量 —— 落地文件可能比攻击包
    晚几分钟。

    client 为 None 或查询失败时返回空列表，维度 D 会因此静默跳过，
    全部行为与未接入 EDR 时一致。
    """
    if client is None:
        return []

    wanted = [ip for ip in (server_ips or []) if ip]
    if not wanted:
        return []

    events: List[HostEvent] = []
    try:
        for event in client.query(wanted, start_ts, end_ts, list(kinds)):
            if is_cancelled is not None and is_cancelled():
                break
            if not isinstance(event, HostEvent):
                continue
            events.append(event)
            if len(events) >= MAX_HOST_EVENTS:
                logger.warning("主机事件采集达到 %d 上限", MAX_HOST_EVENTS)
                break
    except Exception as error:
        logger.warning("主机事件采集失败，维度 D 跳过: %s", error)
        return []

    events.sort(key=lambda e: e.ts)
    return events


# ---------------------------------------------------------------- 时钟标定

# 配对所需的最少样本数。样本太少的估计还不如不估 —— 撞上一条不相关的
# 连接就会把整个时间轴推歪，而时间轴一歪，维度 D 会系统性失配。
MIN_SKEW_SAMPLES = 3

# 配对时允许的最大时间差。超过这个值的配对基本可以断定不是同一次连接，
# 纳入统计只会污染中位数。10 分钟对任何现实中的时钟漂移都够宽了。
MAX_SKEW_PAIR_GAP_S = 600.0


def estimate_clock_skew(
    outbound: Sequence,
    events: Sequence[HostEvent],
) -> Optional[float]:
    """用维度 C 的出站连接做锚点，自动估算 EDR 与抓包机的时钟偏移。

    原理：同一次 TCP 连接在两侧都有记录，(dst_ip, dst_port) 在短时间窗内
    足以唯一定位。把两侧都出现的配对找出来，取时间差的**中位数**即偏移。

    要中位数不要均值：少数配对可能撞上不相关的连接（同一个目标端口被访问
    多次），均值会被那几条离群值整个拽偏，中位数不会。

    返回正数表示 EDR 时钟比抓包机快。样本不足时返回 None ——
    这时应当退回 skew=0 并在报告里说明"未标定"，而不是硬估一个值。

    为什么这条值得单独做：时钟偏移是所有网络-主机关联方案的第一大坑，
    绝大多数实现让用户手填。这里复用维度 C 已有的输出自动标定，
    不需要用户知道两台机器的时钟差多少。
    """
    if not outbound or not events:
        return None

    # 主机侧出站连接按 (dst_ip, dst_port) 建桶
    host_conns: Dict[Tuple[str, int], List[float]] = {}
    for event in events:
        if event.kind != KIND_NETCONN or not event.dst_ip:
            continue
        host_conns.setdefault((event.dst_ip, int(event.dst_port or 0)), []).append(event.ts)
    if not host_conns:
        return None

    for times in host_conns.values():
        times.sort()

    deltas: List[float] = []
    for conn in outbound:
        net_ts = float(getattr(conn, "ts", 0.0) or 0.0)
        if not net_ts:
            continue
        key = (getattr(conn, "dst_ip", "") or "",
               int(getattr(conn, "dst_port", 0) or 0))
        candidates = host_conns.get(key)
        if not candidates:
            continue
        # 取时间上最接近的那条作为配对
        index = bisect_left(candidates, net_ts)
        for probe in (index - 1, index):
            if 0 <= probe < len(candidates):
                gap = candidates[probe] - net_ts
                if abs(gap) <= MAX_SKEW_PAIR_GAP_S:
                    deltas.append(gap)
                    break

    if len(deltas) < MIN_SKEW_SAMPLES:
        logger.debug("时钟偏移样本不足（%d < %d），不做标定",
                     len(deltas), MIN_SKEW_SAMPLES)
        return None

    skew = float(median(deltas))
    logger.info("EDR 时钟偏移标定完成：%.2fs（%d 个配对）", skew, len(deltas))
    return skew


def build_host_ledger(
    client: Optional["EDRClient"],
    server_ips: Iterable[str],
    start_ts: float,
    end_ts: float,
    outbound: Sequence = (),
    is_cancelled=None,
) -> Optional[HostEventLedger]:
    """采集 + 自动标定时钟 + 建索引，一步到位。

    返回 None 表示"没有主机侧数据"，维度 D 会整个跳过 —— 这是**没接 EDR**
    和**接了但查不到**的共同出口，两者对研判结论的影响完全一致（都不影响）。
    """
    events = collect_host_events(
        client, server_ips, start_ts, end_ts, is_cancelled=is_cancelled)
    if not events:
        return None

    skew = estimate_clock_skew(outbound, events) or 0.0
    return HostEventLedger(
        events, clock_skew_s=skew,
        covered_hosts=[ip for ip in server_ips if ip],
    )
