# stream_worker.py - 后台分析工作线程

import sys
import os
import gc
import re
import time
import shlex
import logging
import threading
import weakref
import hashlib
from types import SimpleNamespace
from typing import Optional, Dict, List, Tuple, Any, Set
from dataclasses import dataclass, field
from collections import deque

from PySide6.QtCore import QThread, Signal, QObject, QMutex, QMutexLocker

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CORE_PATH = os.path.join(PROJECT_ROOT, "core")
for path in [PROJECT_ROOT, CORE_PATH]:
    if path not in sys.path:
        sys.path.insert(0, path)

from core.tshark_stream import (
    TsharkProcessHandler,
    StreamConfig,
    OutputFormat,
    PacketData,
    PacketWrapper,
    TsharkError,
    TsharkNotFoundError,
    TsharkProcessError,
    TsharkPermissionError,
    HTTP_REQUEST_FIELDS,
    HTTP_RESPONSE_FIELDS,
    get_protocol_stats,
    build_hierarchy_stats
)
from core.tshark_locator import find_tshark

from models.detection_result import (
    DetectionResult,
    DetectionType,
    ThreatLevel,
    ProtocolStats,
    AnalysisSummary,
    ExtractedFile,
    ProtocolFinding,
    AutoDecodingResult,
    FileRecoveryResult,
    RTPStreamInfo
)
from core.display_safety import safe_display_text
from core.http_response_inspector import (
    HttpResponseInspector,
    content_disposition_from_response_lines,
)
from core.safe_paths import safe_unique_path

# 会话上下文追踪是可选依赖：拿不到就退化成"逐包独立判定"，不影响主流程
try:
    from core.session_tracker import (
        RequestEvent, SessionTracker, extract_uploaded_names,
    )
except ImportError:  # pragma: no cover - 缺模块时静默降级
    RequestEvent = None
    SessionTracker = None
    extract_uploaded_names = None

# 观测中心同样是可选依赖
try:
    from core.observability import get_observability_hub
except ImportError:  # pragma: no cover
    get_observability_hub = None

# 内存看护。psutil 缺失时 MemoryGuard 自己会降级成"永远 ok"
try:
    from core.memory_guard import (
        MemoryGuard, LEVEL_OK, LEVEL_WARN, LEVEL_CRITICAL,
    )
except ImportError:  # pragma: no cover
    MemoryGuard = None
    LEVEL_OK, LEVEL_WARN, LEVEL_CRITICAL = "ok", "warn", "critical"

# 成功研判引擎。拿不到就退化成"只报攻击不判成败"，主流程照常跑完。
try:
    from core.success_adjudicator import (
        Outcome, RequestLedger, build_adjudicator,
    )
except ImportError:  # pragma: no cover
    Outcome = None
    RequestLedger = None
    build_adjudicator = None

logger = logging.getLogger(__name__)

# payload_viewer 里"完整请求"的上限。见 _detect_packet 里的说明。
_FULL_BODY_LIMIT = 1_000_000

# IPv4 / IPv6 字面量。只用来给 display filter 做白名单校验。
_IP_LITERAL_RE = re.compile(r"^[0-9a-fA-F:.]{3,45}$")


class ResourceLimits:
    # 这里原来有一个 MAX_DETECTIONS = 5000。它已被彻底删除，不是调大。
    #
    # 任何"最多记 N 条检测"的设计都是可绕过的：攻击者先用扫描器灌满 N 条
    # 噪声（这甚至不需要刻意为之，一次 dirb 就够了），真正的攻击排在 N+1
    # 位就永远不会被记录。取证工具漏掉的那一条，往往正是唯一重要的那一条。
    #
    # 内存不靠"少检测"来控，靠"证据字段按需驻留"—— 见下面
    # FULL_EVIDENCE_DETECTIONS：条目全留，重的原始报文按阈值卸载。
    #
    # 保留**完整证据**（原始请求头/体、响应体样本）的检测条数上限。
    #
    # 注意这不是"检测上限"：超过之后检测照做、条目照留，只是不再把原始
    # 报文驻留在内存里 —— 那个字段才是内存大头，一条可能上百 KB。
    # 用户点开某条时按帧号回 pcap 重取即可（_fetch_request_evidence）。
    #
    # 之所以不能用"检测上限"来控内存：那是可绕过的。攻击者先用扫描器灌满
    # 名额，后面真正的攻击就永远不会被看到。丢证据顶多是点开时慢一点，
    # 丢检测是直接漏报。
    FULL_EVIDENCE_DETECTIONS = 2000
    MAX_MEMORY_MB = 1024
    # 内存看护阈值（进程 RSS，MB）。
    # 上面那个 MAX_MEMORY_MB 历史上声明了但从没被使用，真正生效的是这两个。
    # 越过 WARN 只告警不改行为；越过 CRITICAL 自动转降级模式（证据不再驻留、
    # WebShell 采集提前收口），检测本身始终全量，不会因为内存而漏报。
    MEMORY_WARN_MB = 1500
    MEMORY_CRITICAL_MB = 2500
    GC_INTERVAL = 100               # 每N个包触发一次GC
    BATCH_SIZE = 50
    FLUSH_INTERVAL_MS = 200
    MAX_QUEUE_SIZE = 1000
    # WebShell AST 分析收集的 **HTTP 包** 上限（不是原始包数）。
    # 千万别把它当 tshark 的 -c 用：-c 限制的是读取量，会让文件后半段
    # 完全不被检查。详见 _run_webshell_ast_detection 的 docstring。
    #
    # 这只是个兜底的条数上限，**真正起作用的是下面的内存预算**：
    # 这条路径用 EK 格式（WebShellDetector 需要 PyShark 风格的包对象），
    # 实测每包约 20KB 常驻内存，是 FIELDS 格式的 16.7 倍。单纯按条数卡
    # 20 万会吃掉 3.7GB —— 所以按字节卡才是对的。
    MAX_WEBSHELL_HTTP_PACKETS = 200_000
    # 累积包的内存预算。EK JSON 文本解析成 Python 对象后约膨胀 4.5 倍，
    # 所以按文本字节数 × 该系数估算常驻内存。
    WEBSHELL_MEMORY_BUDGET_BYTES = 1024 * 1024 * 1024
    EK_MEMORY_EXPANSION = 4.5
    PROGRESS_THROTTLE_MS = 100


@dataclass
class ThrottleConfig:
    batch_size: int = ResourceLimits.BATCH_SIZE
    flush_interval_ms: int = ResourceLimits.FLUSH_INTERVAL_MS
    max_queue_size: int = ResourceLimits.MAX_QUEUE_SIZE


class ResultBuffer:
    """线程安全的结果缓冲器，发送后立即清空，用deque限制大小"""

    def __init__(self, config: ThrottleConfig = None):
        self.config = config or ThrottleConfig()
        self._buffer: deque = deque(maxlen=self.config.max_queue_size)
        self._lock = threading.Lock()
        self._last_flush_time = time.time()
        self._total_flushed = 0

    def add(self, item: Any) -> Optional[List[Any]]:
        """添加项目，达到阈值时返回批次并清空"""
        with self._lock:
            self._buffer.append(item)

            current_time = time.time()
            elapsed_ms = (current_time - self._last_flush_time) * 1000
            should_flush = (
                len(self._buffer) >= self.config.batch_size or
                elapsed_ms >= self.config.flush_interval_ms
            )

            if should_flush:
                return self._flush_internal()

        return None

    def flush(self) -> List[Any]:
        with self._lock:
            return self._flush_internal()

    def _flush_internal(self) -> List[Any]:
        items = list(self._buffer)
        self._buffer.clear()
        self._last_flush_time = time.time()
        self._total_flushed += len(items)
        return items

    @property
    def size(self) -> int:
        with self._lock:
            return len(self._buffer)

    @property
    def total_flushed(self) -> int:
        return self._total_flushed

    def clear(self):
        with self._lock:
            self._buffer.clear()


class ProgressThrottler:
    """进度信号节流

    要同时满足两个互相拉扯的诉求，旧实现只顾了前一个：

    1. 进度条不能倒退。_run_analysis 里 AST 阶段发 44，紧接着响应扫描发 38，
       条子往回跳看着像出错。
    2. 消息文本必须能刷新。HTTP 阶段的百分比在大包里可能几十秒停在同一个整数
       上，但"已处理 N 请求, M 威胁"一直在变。

    旧实现的做法是"百分比没变大就整条丢弃"，于是第 2 点被牺牲得很彻底：
    HTTP 阶段几分钟里界面收不到任何信号，看上去就是死了。而且 38 < 44 那条
    以及它之后所有小于 44 的消息被永久丢弃，"HTTP 响应流式扫描"这个阶段名
    根本没机会显示。

    正确解法是把两件事拆开：**百分比对外钳制成只增不减，消息照发**。
    压制的唯一理由是"离上次发送太近"。
    """

    def __init__(self, interval_ms: int = ResourceLimits.PROGRESS_THROTTLE_MS):
        self._interval_ms = interval_ms
        self._last_emit_time = 0.0
        self._peak_percent = -1

    def next_percent(self, percent: int) -> Optional[int]:
        """返回本次该显示的百分比；None 表示这次压掉不发"""
        now = time.time()

        # 100% 是终态，任何情况下都要送达
        if percent >= 100:
            self._peak_percent = 100
            self._last_emit_time = now
            return 100

        shown = percent if percent > self._peak_percent else self._peak_percent
        advanced = shown > self._peak_percent
        due = (now - self._last_emit_time) * 1000.0 >= self._interval_ms

        if not advanced and not due:
            return None

        self._peak_percent = shown
        self._last_emit_time = now
        return shown

    def should_emit(self, percent: int) -> bool:
        """旧接口：只回答放不放行，不做钳制"""
        return self.next_percent(percent) is not None


@dataclass
class AnalysisOptions:
    detect_webshell: bool = True
    detect_owasp: bool = True
    extract_files: bool = True
    auto_decode: bool = True
    file_recovery: bool = True
    custom_keys: Dict[str, str] = field(default_factory=dict)
    throttle: ThrottleConfig = field(default_factory=ThrottleConfig)


class _HttpEvidencePacket:
    """Minimal PyShark-compatible view retained for protocol evidence passes."""

    def __init__(self, cookie: str = "") -> None:
        self.http = SimpleNamespace(cookie=cookie or "")


class StreamAnalysisWorker(QThread):
    """流式分析工作线程，带信号节流、内存回收、进度节流、结果上限"""

    progress = Signal(int, str)                # (百分比, 状态消息)
    batchResultsReady = Signal(list)           # 批量检测结果
    singleResultReady = Signal(object)         # 单条检测结果(兼容旧接口)
    protocolFindingFound = Signal(object)
    decodingResultFound = Signal(object)
    fileRecovered = Signal(object)
    analysisComplete = Signal(object)           # AnalysisSummary
    error = Signal(str)
    cancelled = Signal()
    # 内存告警：(等级, 说明文本)。等级为 "warn" / "critical"
    memoryWarning = Signal(str, str)

    def __init__(
        self,
        pcap_path: str,
        options: AnalysisOptions = None,
        tshark_path: Optional[str] = None
    ):
        super().__init__()
        self.pcap_path = pcap_path
        self.options = options or AnalysisOptions()
        self.tshark_path = tshark_path or self._find_tshark_robust()

        self._handler: Optional[TsharkProcessHandler] = None
        self._is_cancelled = False

        self._result_buffer = ResultBuffer(self.options.throttle)
        self._progress_throttler = ProgressThrottler()

        # 内存看护。psutil 缺失或构造失败时退化成"永远 ok"，不影响主流程
        self._memory_guard = (
            MemoryGuard(warn_mb=ResourceLimits.MEMORY_WARN_MB,
                        critical_mb=ResourceLimits.MEMORY_CRITICAL_MB)
            if MemoryGuard is not None else None
        )
        self._memory_degraded = False

        self._packet_count = 0
        self._detection_count = 0
        self._start_time = 0.0

        self._seen_keys: Set[str] = set()
        self._http_evidence_packets: List[_HttpEvidencePacket] = []
        self._http_request_uris: Dict[int, str] = {}
        self._http_frame_estimate = 0   # 协议统计给的 http 帧数，进度条分母
        self._gc_counter = 0
        self._packet_tick = 0           # record_packet 的本地攒批计数

        # 会话追踪器**每个 worker 一个**，不能用进程级单例：同时分析两个 pcap
        # 时，后启动的 worker 一 reset 就把前一个正在累积的会话状态清空了，
        # "上传→访问"这类跨请求的链会直接断掉；而且两个线程还要在同一把
        # RLock 上逐请求争用，主线程跟着一起卡。
        self._session_tracker = SessionTracker() if SessionTracker is not None else None

        # 全量 HTTP 请求的路径索引，供成功研判的维度 B 做"上传后回访"关联。
        # 同样每 worker 一份，理由和上面的会话追踪器一致。
        self._request_ledger = RequestLedger() if RequestLedger is not None else None
        # 帧号 -> 研判结论，_build_summary 时挂到 summary 上
        self._verdicts: Dict[int, Any] = {}

    def _find_tshark_robust(self) -> Optional[str]:
        """在常见位置找tshark"""
        return find_tshark()

    def cancel(self):
        self._is_cancelled = True
        handler = self._handler
        if handler:
            # handler.stop() 里要同步跑 taskkill /F /T（5 秒超时）、等子进程
            # 退出、再 join stderr 监控线程，最坏十几秒。而 cancel() 是被 UI
            # 线程直接调用的（用户点"停止分析"、关窗口、控制器批量停止），
            # 同步执行等于把界面锁死 —— 两个文件一起停就是十几秒的"未响应"。
            # _is_cancelled 已经能让工作线程的循环立刻退出，进程回收纯属善后，
            # 丢到后台线程去做即可。
            threading.Thread(
                target=self._safe_stop_handler, args=(handler,),
                name="tshark-stop", daemon=True,
            ).start()

    @staticmethod
    def _safe_stop_handler(handler) -> None:
        try:
            handler.stop()
        except Exception as e:  # 善后失败不该反过来影响界面
            logger.debug(f"tshark 停止异常: {e}")

    def run(self):
        self._start_time = time.time()
        self._is_cancelled = False

        try:
            self._emit_progress(0, "正在初始化流式分析引擎...")

            if not self.tshark_path:
                self.error.emit(
                    "未找到 TShark！\n\n"
                    "请安装 Wireshark: https://www.wireshark.org/download.html\n\n"
                    "或设置环境变量 WIRESHARK_PATH 指向 Wireshark 安装目录"
                )
                return

            if not os.path.exists(self.tshark_path):
                self.error.emit(f"TShark 路径无效: {self.tshark_path}")
                return

            self._handler = TsharkProcessHandler(self.tshark_path)

            if self._is_cancelled:
                self.cancelled.emit()
                return

            # 取消和异常都会从 _run_analysis 里提前跳出，引用计数必须在这一层
            # 用 try/finally 配对，否则漏掉一次之后就再也不会重置指标了
            self._begin_observability_run()
            try:
                summary = self._run_analysis()
            finally:
                self._end_observability_run()

            if self._is_cancelled:
                self.cancelled.emit()
                return

            self.analysisComplete.emit(summary)

        except TsharkNotFoundError as e:
            self.error.emit(f"未找到 TShark！\n{str(e)}")
        except TsharkPermissionError as e:
            self.error.emit(f"权限不足: {str(e)}\n\n请以管理员权限运行或检查文件访问权限")
        except TsharkProcessError as e:
            self.error.emit(f"TShark 执行错误: {str(e)}")
        except TsharkError as e:
            self.error.emit(f"TShark 错误: {str(e)}")
        except MemoryError:
            self.error.emit("内存不足！请关闭其他程序后重试，或分析较小的 PCAP 文件")
        except Exception as e:
            import traceback
            self.error.emit(f"分析错误: {str(e)}\n\n{traceback.format_exc()}")
        finally:
            self._flush_remaining_results()
            self._cleanup()

    # ObservabilityHub 是进程级单例，但 start_run() 会把上一轮指标清空。
    # 同时分析两个 pcap 时，后启动的 worker 一调就把先跑那个正在累积的数据
    # 抹掉了。并发是在这一层管的，引用计数就放在这一层。
    _obs_runs = 0
    _obs_lock = threading.Lock()

    @classmethod
    def _begin_observability_run(cls) -> None:
        if get_observability_hub is None:
            return
        with cls._obs_lock:
            cls._obs_runs += 1
            first = cls._obs_runs == 1
        if first:
            get_observability_hub().start_run()

    @classmethod
    def _end_observability_run(cls) -> None:
        if get_observability_hub is None:
            return
        with cls._obs_lock:
            cls._obs_runs = max(0, cls._obs_runs - 1)
            last = cls._obs_runs == 0
        if last:
            get_observability_hub().end_run()

    def _emit_progress(self, percent: int, message: str):
        shown = self._progress_throttler.next_percent(percent)
        if shown is not None:
            self.progress.emit(shown, message)

    # HTTP 流式分析占进度条 15%~43% 这一段
    _HTTP_STAGE_START = 15
    _HTTP_STAGE_SPAN = 28

    def _http_stage_percent(self, http_count: int) -> int:
        """HTTP 阶段的进度百分比

        旧实现是 `15 + int(http_count / total_packets * 28)`：分子是 **HTTP
        请求数**，分母是 **全部包数**。真实抓包里 HTTP 请求只占总包数的百分之
        几 —— 26327/1500000*28 = 0.49，int() 一抹就是 0，百分比恒等于 15。
        配上原来"百分比没变大就丢弃"的节流器，整个 HTTP 阶段几分钟里界面一个
        信号都收不到，看起来就是卡死。

        分母改用协议统计里的 http 帧数（含请求和响应，请求数约为其一半）。
        """
        estimate = getattr(self, "_http_frame_estimate", 0) or 0
        if estimate > 0:
            expected_requests = max(estimate / 2.0, 1.0)
            # 留出 10% 余量，估算偏小时不至于早早顶到头
            ratio = min(http_count / expected_requests, 1.0) * 0.9
        else:
            # 拿不到估算值（协议统计失败等）就走渐近曲线兜底：
            # 一直在动、永远逼近但不越过本阶段上限
            ratio = 1.0 - 1.0 / (1.0 + http_count / 5000.0)
        return self._HTTP_STAGE_START + int(min(ratio, 1.0) * self._HTTP_STAGE_SPAN)

    def _mark_stage(self, name: Optional[str]):
        """标记进入新阶段，顺带结束上一个阶段的计时

        流水线本来就是顺序执行的，所以用"线性标记"而不是给每段套 with——
        后者要把十来个代码块整体重新缩进，改动面大且容易出错。
        传 None 表示收尾（结束最后一个阶段）。
        """
        if get_observability_hub is None:
            return
        try:
            now = time.perf_counter()
            prev = getattr(self, "_cur_stage", None)
            if prev:
                started = getattr(self, "_cur_stage_start", now)
                get_observability_hub()._record_stage(prev, now - started, 0)
            self._cur_stage = name
            self._cur_stage_start = now
        except Exception as e:
            logger.debug(f"阶段计时失败: {e}")

    def _flush_remaining_results(self):
        remaining = self._result_buffer.flush()
        if remaining:
            self.batchResultsReady.emit(remaining)

    def _cleanup(self):
        if self._handler:
            self._handler.stop()
            self._handler = None

        self._result_buffer.clear()
        self._seen_keys.clear()
        self._http_evidence_packets.clear()
        self._http_request_uris.clear()
        gc.collect()

        logger.debug(f"Worker 清理完成: 处理 {self._packet_count} 包, 发现 {self._detection_count} 威胁")

    def _trigger_gc_if_needed(self):
        self._gc_counter += 1
        if self._gc_counter >= ResourceLimits.GC_INTERVAL:
            gc.collect(0)  # 只回收0代，快
            self._gc_counter = 0

    def _check_memory(self) -> str:
        """采样内存，越阈值时告警 + 自动降级

        可以放心在热循环里调，MemoryGuard 内部有双重节流（按次数 + 按时间）。

        降级只影响**证据驻留**和**跨包累积**，不影响检测覆盖：
        检测永远全量跑完，不会因为内存紧张而漏报 —— 漏报是取证工具的死罪，
        证据慢一点（点开时回 pcap 重取）只是体验问题。
        """
        guard = self._memory_guard
        if guard is None:
            return LEVEL_OK

        level = guard.check()
        if level == LEVEL_CRITICAL and not self._memory_degraded:
            self._memory_degraded = True
            gc.collect()
            logger.warning("内存达到 %.0f MB，转入降级模式（证据不再驻留内存）",
                           guard.rss_mb)
        if level != LEVEL_OK and guard.should_report(level):
            self.memoryWarning.emit(level, guard.describe(level))
        return level

    def _run_analysis(self) -> AnalysisSummary:
        results: List[DetectionResult] = []
        protocol_findings: List[ProtocolFinding] = []
        decoding_results: List[AutoDecodingResult] = []
        recovered_files: List[FileRecoveryResult] = []
        extracted_files: List[ExtractedFile] = []
        rtp_streams: List[RTPStreamInfo] = []

        # 会话追踪器是本 worker 私有的，开跑前清干净即可，
        # 不会影响同时在跑的另一个文件
        if self._session_tracker is not None:
            self._session_tracker.clear()

        # 指标是进程级共享的，start/end 由 run() 用 try/finally 配对管理
        self._cur_stage = None
        self._cur_stage_start = 0.0

        # 内存看护按轮重置，否则上一轮的告警记录会压掉这一轮的弹窗
        self._memory_degraded = False
        if self._memory_guard is not None:
            self._memory_guard.reset()

        self._emit_progress(5, "协议分级统计...")
        self._mark_stage("协议分级统计")
        protocol_counts, total_packets, protocol_hierarchy = self._run_protocol_stats()

        # HTTP 阶段进度条的分母。io,phs 统计出来的是 http 帧数（请求+响应），
        # 请求数约为其一半 —— 详见 _http_stage_percent
        self._http_frame_estimate = int((protocol_counts or {}).get("http", 0) or 0)

        if self._is_cancelled:
            return self._build_summary(results, [], protocol_findings, decoding_results, recovered_files, extracted_files, total_packets, rtp_streams)

        self._emit_progress(15, "HTTP 流式分析...")
        self._mark_stage("HTTP 流式分析")
        http_results = self._run_http_stream_analysis(total_packets)
        results.extend(http_results)

        # 响应扫描被提到了 AST 前面（原来排在它后面）。这不是顺手调的：
        # 成功研判的维度 A 全靠响应体指纹（uid=0(root)、root:x:0:0…），
        # 而 AST 现在只挖研判认为"打进来了"的那些流。响应还没挂上就先研判，
        # 维度 A 恒为空，AST 的候选集也就跟着塌了。
        self._emit_progress(40, "HTTP 响应流式扫描...")
        self._mark_stage("HTTP 响应流式扫描")
        extracted_files.extend(self._scan_http_responses(results))

        if self._is_cancelled:
            return self._build_summary(results, [], protocol_findings, decoding_results, recovered_files, extracted_files, total_packets, rtp_streams)

        self._emit_progress(43, "攻击成功研判...")
        self._mark_stage("攻击成功研判")
        ast_streams = self._run_success_adjudication(results)

        if self.options.detect_webshell and not self._is_cancelled:
            self._emit_progress(46, "WebShell AST 语义分析...")
            self._mark_stage("WebShell AST 语义分析")
            ast_results = self._run_webshell_ast_detection(ast_streams)
            if ast_results:
                # 这批是响应扫描跑完之后才产生的，得单独把响应证据补挂上，
                # 否则 payload_viewer 里这些条目的响应侧会是空的。
                self._fetch_http_responses(ast_results)
                results.extend(ast_results)

        if self._is_cancelled:
            return self._build_summary(results, [], protocol_findings, decoding_results, recovered_files, extracted_files, total_packets, rtp_streams)

        self._emit_progress(54, "ICMP 隐写检测...")
        self._mark_stage("ICMP 隐写检测")
        icmp_findings = self._run_icmp_analysis()
        protocol_findings.extend(icmp_findings)

        if self._is_cancelled:
            return self._build_summary(results, [], protocol_findings, decoding_results, recovered_files, extracted_files, total_packets, rtp_streams)

        self._emit_progress(58, "DNS 隧道分析...")
        self._mark_stage("DNS 隧道分析")
        dns_findings = self._run_dns_analysis()
        protocol_findings.extend(dns_findings)

        if self._is_cancelled:
            return self._build_summary(results, [], protocol_findings, decoding_results, recovered_files, extracted_files, total_packets, rtp_streams)

        self._emit_progress(62, "CS 通信检测...")
        self._mark_stage("CS 通信检测")
        cs_findings = self._run_cs_detection()
        protocol_findings.extend(cs_findings)

        if self._is_cancelled:
            return self._build_summary(results, [], protocol_findings, decoding_results, recovered_files, extracted_files, total_packets, rtp_streams)

        self._emit_progress(66, "RTP 音视频流检测...")
        self._mark_stage("RTP 音视频流检测")
        rtp_streams = self._run_rtp_analysis()

        if self._is_cancelled:
            return self._build_summary(results, [], protocol_findings, decoding_results, recovered_files, extracted_files, total_packets, rtp_streams)

        self._emit_progress(70, "深度协议分析 (SSH/TLS/SMB/RDP/Redis 等)...")
        self._mark_stage("深度协议分析")
        deep_findings, deep_extracted = self._run_deep_protocol_analysis(protocol_counts)
        protocol_findings.extend(deep_findings)
        for fp in deep_extracted:
            if os.path.isfile(fp):
                fname = os.path.basename(fp)
                fsize = os.path.getsize(fp)
                fext = os.path.splitext(fname)[1].lower()
                ftype = {"png": "image/png", "jpg": "image/jpeg", "jpeg": "image/jpeg"}.get(fext.lstrip("."), "application/octet-stream")
                extracted_files.append(ExtractedFile(
                    file_path=fp,
                    file_name=fname,
                    file_type=ftype,
                    file_size=fsize,
                    pcap_path=self.pcap_path
                ))

        if self._is_cancelled:
            return self._build_summary(results, [], protocol_findings, decoding_results, recovered_files, extracted_files, total_packets, rtp_streams)

        if self.options.auto_decode:
            self._emit_progress(75, f"自动解码 ({len(results)} 条结果)...")
            self._mark_stage("自动解码")
            decoding_results = self._run_auto_decoding(results)

        if self._is_cancelled:
            return self._build_summary(results, [], protocol_findings, decoding_results, recovered_files, extracted_files, total_packets, rtp_streams)

        if self.options.file_recovery:
            self._emit_progress(88, f"文件还原 ({len(extracted_files)} 个文件)...")
            self._mark_stage("文件还原")
            recovered_files = self._run_file_recovery(extracted_files)

        self._emit_progress(95, "生成分析报告...")
        self._mark_stage("生成分析报告")
        protocol_stats = self._build_protocol_stats(protocol_counts, total_packets, protocol_hierarchy)

        # 收尾：结束最后一个阶段的计时
        self._mark_stage(None)

        return self._build_summary(
            results, protocol_stats, protocol_findings,
            decoding_results, recovered_files, extracted_files, total_packets, rtp_streams
        )

    def _run_protocol_stats(self) -> tuple:
        try:
            return get_protocol_stats(self.pcap_path, self.tshark_path)
        except Exception as e:
            logger.warning(f"协议统计失败: {e}")
            return {}, 0, []

    def _run_success_adjudication(self, results: List[DetectionResult]) -> Optional[Set[str]]:
        """跑 A/B/C 三维成功研判，顺带算出 AST 阶段值得深挖的主机集合。

        返回一组"攻击者 IP"。**返回 None 表示研判不可用**，调用方必须退回
        全量扫描 —— 宁可慢，不可漏。

        为什么候选集的单位是主机而不是单条请求：一个攻击者探测失败 500 次、
        成功 1 次是常态，按请求筛会把他前面那些失败请求排除掉，而攻击链的
        上下文（他试过哪些路径、什么时候换的手法）恰恰在那些失败请求里。
        所以只要某个来源 IP 有**任意一条**非 failed 的检测，他的全部流量都
        进 AST；反过来，通篇只有 404 的扫描器就整个跳过 —— 那才是真正的
        资源浪费大头。
        """
        if build_adjudicator is None or not results:
            return None

        try:
            adjudicator = build_adjudicator(
                results,
                ledger=self._request_ledger,
                pcap_path=self.pcap_path,
                tshark_path=self.tshark_path or "",
                is_cancelled=lambda: self._is_cancelled,
            )
            verdicts = adjudicator.adjudicate_all(results)
        except Exception as error:
            logger.warning("成功研判失败，AST 退回全量扫描: %s", error)
            return None

        confirmed = suspected = failed = 0
        hosts: Set[str] = set()
        for index, verdict in verdicts.items():
            detection = results[index]
            frame = getattr(detection, "packet_number", 0) or 0
            if frame:
                self._verdicts[frame] = verdict

            outcome = getattr(verdict.outcome, "value", str(verdict.outcome))
            if outcome == "confirmed":
                confirmed += 1
            elif outcome == "suspected":
                suspected += 1
            elif outcome == "failed":
                failed += 1

            if outcome != "failed":
                src = str(getattr(detection, "source_ip", "") or "")
                if src:
                    hosts.add(src)

        # 没有任何主机入选时返回空集（而不是 None）：那是"研判确实认为
        # 无事发生"，跳过 AST 是正确结论，跟"研判没跑起来"必须区分开。
        logger.info(
            "成功研判完成：确认 %d 条 / 疑似 %d 条 / 明确失败 %d 条，"
            "AST 深挖 %d 个来源主机",
            confirmed, suspected, failed, len(hosts),
        )
        self._emit_progress(
            44, f"成功研判：确认 {confirmed} 条，疑似 {suspected} 条，"
                f"排除失败 {failed} 条")
        return hosts

    @staticmethod
    def _has_protocol(protocol_counts: Optional[Dict[str, int]], protocol: str) -> bool:
        if not protocol_counts:
            return False
        wanted = protocol.upper()
        return any(
            str(name).upper() == wanted and int(count or 0) > 0
            for name, count in protocol_counts.items()
        )

    @staticmethod
    def _build_ast_display_filter(ast_hosts: Optional[Set[str]]) -> str:
        """把研判圈出的主机翻译成 tshark display filter。

        用 ip.addr 而不是 tcp.stream：一个攻击者动辄开几百条连接，流号列表
        会把命令行撑爆，而主机集合通常只有个位数。ip.addr 同时匹配 src 和
        dst，所以攻击者发出的请求和服务器回给他的响应都会被带上 —— 冰蝎/
        哥斯拉的握手识别要靠这一对才成立。

        主机太多时（一场大规模扫描能有上千个来源）过滤器本身就不划算了，
        直接退回全量 http，让 tshark 少做点无用的比较。
        """
        if not ast_hosts:
            return "http"
        if len(ast_hosts) > 64:
            logger.info("可疑来源主机 %d 个，过滤器收益不大，AST 退回全量 HTTP 扫描",
                        len(ast_hosts))
            return "http"
        # IP 是从 tshark 自己解析出来的字段，不存在注入风险；仍然做一次
        # 白名单校验，防止上游哪天塞进来一个畸形值把整条命令搞坏。
        safe = [ip for ip in sorted(ast_hosts) if _IP_LITERAL_RE.match(ip)]
        if not safe:
            return "http"
        addrs = " || ".join(f"ip.addr=={ip}" for ip in safe)
        return f"http && ({addrs})"

    def _run_webshell_ast_detection(
        self, ast_hosts: Optional[Set[str]] = None
    ) -> List[DetectionResult]:
        """Run the existing WebShellDetector with its AST engine enabled.

        注意这里**不能**给 tshark 传 -c(max_packets)。tshark 的 -c 限制的是
        「从文件里读多少个包」，display filter 只在这前 N 个包里筛 —— 实测
        一个 100 包的文件里 HTTP 全在 #90 之后，加 `-c 50` 的命中数是 0。
        也就是说 -c 10000 的真实语义是「只看抓包文件的前 1 万个包，之后全不看」，
        几十 MB 的包就会触发，攻击者什么都不用做，后半段流量直接隐形。

        听澜是取证工具，这种静默漏检不可接受。改成：tshark 扫完整个文件，
        由 display filter 负责筛选，上限只加在 Python 收集侧（因此计的是
        HTTP 包数，不是原始包数），并且一旦截断必须留下明确告警。

        不做分批的原因：detect() 里有 pair_http_requests_responses、冰蝎密钥
        协商扫描、哥斯拉会话扫描这些**跨包关联**，切批会把握手和后续加密流量
        分到不同批里，正好毁掉"还原攻击路径"的能力。

        ── ast_hosts：把这一趟从「全量」收窄成「按研判结果深挖」 ──

        这个阶段真正的开销不是 AST 本身（AST 只跑在已命中 webshell 特征的
        结果上，见 webshell_detect._apply_ast_validation），而是**把整个文件
        用 EK/JSON 再解一遍**并为每个 HTTP 包造一个 Python 包装对象 —— 实测
        174MB 的抓包要 4.7 分钟，绝大部分花在给正常浏览流量建对象上。

        所以现在由成功研判先圈定「有非 failed 检测的来源主机」，display filter
        直接在 tshark 侧按 ip.addr 收窄，Python 侧根本不会看到无关流量。
        通篇只有 404 的扫描器整个跳过，这正是资源浪费的大头。

        三种入参语义必须分清：
          None      研判不可用 → 全量扫描（宁可慢，不可漏）
          非空集合  只深挖这些主机
          空集合    研判认为确实无事发生 → 跳过，不是 bug
        """
        if self._is_cancelled or not self.tshark_path:
            return []
        if ast_hosts is not None and not ast_hosts:
            logger.info("成功研判未发现任何得手迹象，跳过 WebShell AST 深挖")
            self._emit_progress(46, "WebShell AST：无得手迹象，跳过")
            return []

        packets = []
        handler = None
        results: List[DetectionResult] = []
        converters = {
            "antsword": DetectionResult.from_antsword_result,
            "caidao": DetectionResult.from_caidao_result,
            "behinder": DetectionResult.from_behinder_result,
            "godzilla": DetectionResult.from_godzilla_result,
        }

        try:
            from core.webshell_detect import WebShellDetector

            handler = TsharkProcessHandler(self.tshark_path)
            display_filter = self._build_ast_display_filter(ast_hosts)
            config = StreamConfig(
                pcap_path=self.pcap_path,
                display_filter=display_filter,
                output_format=OutputFormat.EK,
                # 故意不设 max_packets：见上面 docstring
                disable_name_resolution=True,
                line_buffered=True,
            )
            scope = ("全量 HTTP" if ast_hosts is None
                     else f"{len(ast_hosts)} 个可疑来源主机")
            http_limit = ResourceLimits.MAX_WEBSHELL_HTTP_PACKETS
            budget = ResourceLimits.WEBSHELL_MEMORY_BUDGET_BYTES
            expansion = ResourceLimits.EK_MEMORY_EXPANSION
            est_bytes = 0
            truncated = ""
            # 这个循环要把整个文件用 EK(JSON) 格式再扫一遍，在大包上是分钟级。
            # 之前它全程不发任何进度，界面就一直显示"44% WebShell AST 语义分析"
            # 一动不动 —— 实测 174MB 的包卡了 4.7 分钟，用户只会认为程序死了。
            #
            # 用 stream_packets 而不是 stream_pyshark_compatible：后者只给
            # wrapper，拿不到 ek_bytes，就没法按内存预算收口。EK 每包实测约
            # 20KB 常驻（FIELDS 的 16.7 倍），光按条数卡会直接吃穿内存。
            last_tick = time.time()
            for packet in handler.stream_packets(config):
                if self._is_cancelled:
                    return []
                wrapper = packet.wrapper
                if wrapper.has_layer("http"):
                    packets.append(wrapper)
                    est_bytes += int((packet.ek_bytes or 0) * expansion)
                    now = time.time()
                    if now - last_tick >= 0.5:
                        self._emit_progress(
                            46, f"WebShell AST 采集中（{scope}）... "
                                f"({len(packets)} 个 HTTP 包, "
                                f"{est_bytes / 1024 / 1024:.0f}MB)")
                        last_tick = now
                    if est_bytes >= budget:
                        truncated = "memory"
                        break
                    if self._check_memory() == LEVEL_CRITICAL:
                        truncated = "rss"
                        break
                    if len(packets) >= http_limit:
                        truncated = "count"
                        break

            if truncated:
                # 截断了就必须说出来，别让"少看了"看起来像"看完没事"
                why = (f"内存预算 {budget // 1024 // 1024}MB"
                       if truncated == "memory"
                       else "进程内存告急" if truncated == "rss"
                       else f"条数上限 {http_limit}")
                logger.warning(
                    "WebShell AST 分析在收满 %d 个 HTTP 包后停止（触发%s，"
                    "估算已占用 %.0fMB）。该抓包文件的剩余 HTTP 流量未做 AST "
                    "语义分析 —— 主检测链路(_run_http_stream_analysis)仍覆盖全量。",
                    len(packets), why, est_bytes / 1024 / 1024)
                self._emit_progress(
                    46, f"WebShell AST：已收 {len(packets)} 个 HTTP 包（{why}），剩余未分析")

            if not packets:
                return []

            detector = WebShellDetector()
            detector.enable_ast(True)
            self._emit_progress(
                47, f"WebShell AST 检测中... ({len(packets)} 个 HTTP 包，{scope})")
            detection_results = detector.detect(packets)
            for tool_name, converter in converters.items():
                for raw_result in detection_results.get(tool_name, []):
                    if self._is_cancelled:
                        break
                    detection = converter(raw_result)
                    results.append(detection)
                    self._detection_count += 1
                    if get_observability_hub is not None:
                        get_observability_hub().record_detection(
                            getattr(detection, 'threat_level', None))
                    batch = self._result_buffer.add(detection)
                    if batch:
                        self.batchResultsReady.emit(batch)

            remaining = self._result_buffer.flush()
            if remaining:
                self.batchResultsReady.emit(remaining)
            return results
        except Exception as error:
            logger.warning("WebShell AST analysis skipped: %s", error)
            return []
        finally:
            packets.clear()
            if handler:
                handler.stop()

    def _run_http_stream_analysis(
        self,
        total_packets: int,
        _allow_ek_fallback: bool = True,
        _existing_results: Optional[List[DetectionResult]] = None,
    ) -> List[DetectionResult]:
        """HTTP流式分析，带信号节流和结果上限"""
        logger.debug(f"_run_http_stream_analysis: total_packets={total_packets}")
        results = _existing_results if _existing_results is not None else []
        self._http_evidence_packets = []
        self._http_request_uris = {}

        try:
            from core.attack_detector import AttackDetector
            detector = AttackDetector()

            output_format = OutputFormat.FIELDS if _allow_ek_fallback else OutputFormat.EK
            config = StreamConfig(
                pcap_path=self.pcap_path,
                display_filter="http.request",
                output_format=output_format,
                fields=list(HTTP_REQUEST_FIELDS) if output_format is OutputFormat.FIELDS else [],
                disable_name_resolution=True,
                line_buffered=True
            )
            logger.debug(f"StreamConfig: {config.pcap_path}, filter={config.display_filter}")

            http_count = 0
            last_progress_time = time.time()

            for packet in self._handler.stream_packets(config):
                if self._is_cancelled:
                    break

                self._packet_count += 1
                http_count += 1

                # record_packet 每次都要抢 ObservabilityHub 的 RLock，而这把锁
                # 是进程级共享的 —— 两个 worker 逐包争用时，主线程也被拖着一起
                # 抢 GIL。指标只是诊断用途，攒够一批再记，锁的频率降两个数量级。
                self._packet_tick += 1
                if self._packet_tick >= 256:
                    if get_observability_hub is not None:
                        get_observability_hub().record_packet(self._packet_tick)
                    self._packet_tick = 0

                if http_count % 50 == 0:
                    logger.debug(f"已处理 {http_count} 个 HTTP 请求, 检测到 {len(results)} 威胁")

                self._trigger_gc_if_needed()
                self._check_memory()

                # CS 检测只看 Cookie，没有 Cookie 的请求存进去纯属浪费 ——
                # 大包里 HTTP 请求是百万级，每条一个对象足以吃掉几百 MB。
                cookie = getattr(packet, "http_cookie", "")
                if cookie:
                    self._http_evidence_packets.append(_HttpEvidencePacket(cookie))
                if packet.frame_number > 0:
                    self._http_request_uris[packet.frame_number] = packet.http_uri or ""

                # 流水账要记在**去重之前**。成功研判的维度 B 数的就是"上传后
                # 又回访了几次"，而回访往往是一模一样的 GET —— 正好会被下面
                # 的 dedup_key 全部合并掉。记在去重后面，这个维度就永远只能
                # 看到 1 次访问，"确认落地"降级成"疑似"，等于白做。
                if self._request_ledger is not None:
                    self._request_ledger.add(
                        frame=packet.frame_number,
                        ts=packet.timestamp_epoch,
                        src_ip=packet.src_ip,
                        dst_ip=packet.dst_ip,
                        uri=packet.http_uri or "",
                        method=packet.http_method or "",
                    )

                current_time = time.time()
                if current_time - last_progress_time >= 0.5:
                    self._emit_progress(
                        self._http_stage_percent(http_count),
                        f"HTTP分析中... ({http_count} 请求, {len(results)} 威胁)")
                    last_progress_time = current_time

                # 去重
                request_body = packet.http_request_body or b""
                if len(request_body) > 65536:
                    digest_input = request_body[:32768] + request_body[-32768:]
                else:
                    digest_input = request_body
                # 去重只需要一个抗碰撞的指纹，不需要密码学强度的 SHA-2。
                # blake2b 限定 16 字节摘要在纯 Python 侧比 sha256 明显快，
                # 而这是**每个 HTTP 请求都要走一次**的热路径。
                body_digest = hashlib.blake2b(
                    digest_input, digest_size=16).hexdigest()
                dedup_key = (
                    f"{packet.http_method}:{packet.http_host}:{packet.http_uri}:"
                    f"{packet.http_content_type}:{len(request_body)}:{body_digest}"
                )
                if dedup_key in self._seen_keys:
                    del packet
                    continue
                self._seen_keys.add(dedup_key)

                # 这里原来有一个 `len(results) >= max_detections: continue`。
                # 它是可绕过的安全洞：攻击者只要先灌满 N 条噪声（扫描器流量
                # 天然就能做到），后面真正的攻击就一个都不会被检测。
                # 现在改成全量检测，靠"证据字段按需懒加载"控内存
                # —— 见 _keep_full_evidence / _detect_packet。
                detection = self._detect_packet(detector, packet)
                del packet  # 检测完释放

                if detection:
                    results.append(detection)
                    self._detection_count += 1
                    if get_observability_hub is not None:
                        get_observability_hub().record_detection(
                            getattr(detection, 'threat_level', None))

                    batch = self._result_buffer.add(detection)
                    if batch:
                        self.batchResultsReady.emit(batch)

            remaining = self._result_buffer.flush()
            if remaining:
                self.batchResultsReady.emit(remaining)

            # 把攒着还没记的那批包数补上，否则统计会少最多 255 个
            if self._packet_tick and get_observability_hub is not None:
                get_observability_hub().record_packet(self._packet_tick)
            self._packet_tick = 0

            self._seen_keys.clear()

            self._emit_progress(43, f"HTTP分析完成: {http_count} 请求, {len(results)} 威胁")

        except TsharkError as e:
            if _allow_ek_fallback:
                logger.warning(f"FIELDS HTTP stream unavailable, retrying EK: {e}")
                return self._run_http_stream_analysis(total_packets, False, results)
            self._emit_progress(43, f"HTTP分析警告: {str(e)[:40]}")
            raise
        except Exception as e:
            if _allow_ek_fallback:
                logger.warning(f"FIELDS HTTP stream failed, retrying EK: {e}")
                return self._run_http_stream_analysis(total_packets, False, results)
            logger.warning(f"HTTP流式分析异常: {e}")

        return results

    def _keep_full_evidence(self) -> bool:
        """还要不要把原始报文留在内存里

        检测本身**不设上限**（上限可被噪声灌满绕过），但证据字段是内存大头，
        一条可能上百 KB。超过阈值后只留身份字段，点开时按帧号回 pcap 重取
        （见 controllers.analysis_controller.get_http_request_evidence）。

        两个触发条件，满足任一就停止驻留：
          1. 条数超过 FULL_EVIDENCE_DETECTIONS —— 静态预算
          2. 进程 RSS 越过 MEMORY_CRITICAL_MB —— 动态兜底，因为条数是坏代理，
             同样 2000 条，全是小 GET 和全是大文件上传能差两个数量级
        """
        if self._memory_degraded:
            return False
        return self._detection_count < ResourceLimits.FULL_EVIDENCE_DETECTIONS

    def _detect_packet(self, detector, packet: PacketData) -> Optional[DetectionResult]:
        try:
            body = packet.http_request_body
            if not body and packet.http_uri and '?' in packet.http_uri:
                query = packet.http_uri.split('?', 1)[1]
                body = query.encode('utf-8', errors='replace')
            if not body:
                body = (packet.http_uri or '').encode('utf-8', errors='replace')

            if not body:
                return None

            detection = detector.detect(
                data=body,
                method=packet.http_method,
                uri=packet.http_uri,
                content_type=packet.http_content_type
            )

            # 会话上下文。**每个请求都要喂给追踪器**，不能只喂命中的：
            # "上传 webshell → 随后访问它"这类攻击路径里，上传请求本身
            # 往往看着无害，只有把它记下来，后面那次访问才能被关联出来。
            signal = self._track_session(packet, body, detection)
            if signal is not None and signal.triggered:
                detection['total_weight'] = detection.get('total_weight', 0) + signal.bonus
                detection['session_signals'] = signal.to_dict()
                detection['tags'] = list(detection.get('tags') or []) + signal.tags
                if detection['total_weight'] >= 40:
                    detection['detected'] = True

            if detection.get('detected', False) and detection.get('total_weight', 0) >= 20:
                # 身份字段永远保留：它们很轻，而且是回 pcap 重取证据的钥匙
                detection['frame_number'] = packet.frame_number
                detection['src_ip'] = packet.src_ip
                detection['dst_ip'] = packet.dst_ip
                detection['tcp_stream'] = packet.tcp_stream
                detection['host'] = packet.http_host
                detection['timestamp'] = packet.timestamp

                if self._keep_full_evidence():
                    raw_headers = f"{packet.http_method} {packet.http_uri} HTTP/1.1\r\n"
                    raw_headers += f"Host: {packet.http_host}\r\n"
                    if packet.http_user_agent:
                        raw_headers += f"User-Agent: {packet.http_user_agent}\r\n"
                    if packet.http_content_type:
                        raw_headers += f"Content-Type: {packet.http_content_type}\r\n"
                    raw_headers += "\r\n"

                    raw_body_str = safe_display_text(body, max_length=50000)

                    # "_full" 这两个字段是给 payload_viewer 看完整请求用的。
                    # 原来完全不截断 —— 一次几 MB 的上传就原样留在内存里，
                    # 而且 raw_http_request_full = headers + body 又复制了一份。
                    # 1MB 足够覆盖真实场景里要人工看的请求。
                    raw_body_full = body[:_FULL_BODY_LIMIT].decode('utf-8', errors='replace')
                    if len(body) > _FULL_BODY_LIMIT:
                        raw_body_full += (
                            f"\n\n...[已截断，原始 body 共 {len(body)} 字节]")

                    detection['raw_request_headers'] = raw_headers
                    detection['raw_request_body'] = raw_body_str[:50000]
                    detection['raw_http_request'] = (raw_headers + raw_body_str)[:100000]
                    detection['raw_request_body_full'] = raw_body_full
                    detection['raw_http_request_full'] = raw_headers + raw_body_full
                else:
                    # 超过阈值：只留一条能自解释的占位，点开时按帧号回 pcap 重取。
                    # pcap_path / frame_number 必须一起带上，否则 UI 无从重取
                    # —— 这正是之前"承诺了但没实现"的那一环。
                    detection['evidence_lazy'] = True
                    detection['pcap_path'] = self.pcap_path
                    detection['raw_request_headers'] = (
                        f"{packet.http_method} {packet.http_uri} HTTP/1.1\r\n"
                        f"Host: {packet.http_host}\r\n\r\n")
                    detection['raw_http_request'] = (
                        f"[证据未驻留内存 — 本次分析检测数已超过 "
                        f"{ResourceLimits.FULL_EVIDENCE_DETECTIONS} 条]\n"
                        f"帧号 #{packet.frame_number}，点开时会自动回原始 pcap 取回完整请求")

                return DetectionResult.from_attack_result(detection)

        except Exception as e:
            logger.debug(f"检测失败: {e}")

        return None

    def _track_session(self, packet: PacketData, body: bytes, detection: Dict):
        """把一次请求喂给会话追踪器，拿回跨请求的上下文信号

        这是"还原攻击路径"的那一环：单看一个包判断不了的东西
        （上传后访问、探测→升级、固定周期的心跳），要靠同一会话里
        前后请求的关系才能看出来。追踪器只加分不减分，且有上限。
        """
        if self._session_tracker is None or RequestEvent is None:
            return None
        try:
            names = []
            if extract_uploaded_names is not None:
                names = extract_uploaded_names(body or b"",
                                               packet.http_content_type or "")
            event = RequestEvent(
                frame_number=packet.frame_number,
                ts=packet.timestamp_epoch,
                src_ip=packet.src_ip,
                dst_ip=packet.dst_ip,
                host=packet.http_host,
                method=packet.http_method,
                uri=packet.http_uri,
                content_type=packet.http_content_type,
                body_len=len(body or b""),
                entropy=float(detection.get('entropy') or 0.0),
                rule_weight=int(detection.get('total_weight') or 0),
                detected=bool(detection.get('detected')),
                attack_type=detection.get('detection_type') or "",
                uploaded_names=names,
            )
            return self._session_tracker.process(event)
        except Exception as e:
            logger.debug(f"会话追踪跳过: {e}")
            return None

    def _scan_http_responses(self, results: List[DetectionResult]) -> List[ExtractedFile]:
        """Stream every HTTP response once for response evidence and file artifacts."""
        if not self._handler:
            return []

        request_to_indices: Dict[int, List[int]] = {}
        stream_to_indices: Dict[int, List[int]] = {}
        for index, detection in enumerate(results):
            raw_result = detection.raw_result if isinstance(detection.raw_result, dict) else {}
            request_frame = raw_result.get("frame_number") or getattr(detection, "packet_number", 0)
            tcp_stream = raw_result.get("tcp_stream", getattr(detection, "tcp_stream", -1))
            try:
                request_frame = int(request_frame or 0)
            except (TypeError, ValueError):
                request_frame = 0
            try:
                tcp_stream = int(tcp_stream)
            except (TypeError, ValueError):
                tcp_stream = -1
            if request_frame > 0:
                request_to_indices.setdefault(request_frame, []).append(index)
            if tcp_stream >= 0:
                stream_to_indices.setdefault(tcp_stream, []).append(index)

        extracted_files: List[ExtractedFile] = []
        seen_hashes: Set[str] = set()
        seen_evidence_links: Set[Tuple[str, int]] = set()
        exact_response_matches: Set[int] = set()
        inspector = HttpResponseInspector()
        output_dir: Optional[str] = None
        packet_iter = None
        config = StreamConfig(
            pcap_path=self.pcap_path,
            display_filter="http.response",
            output_format=OutputFormat.FIELDS,
            fields=list(HTTP_RESPONSE_FIELDS),
            disable_name_resolution=True,
            line_buffered=True,
        )

        try:
            packet_iter = self._handler.stream_packets(config)
            resp_count = 0
            last_tick = time.time()
            for packet in packet_iter:
                if self._is_cancelled:
                    break

                # 这一阶段要把整个文件的 HTTP 响应再过一遍，大包上是分钟级。
                # 不发进度的话界面就停在"46% HTTP 响应流式扫描"不动，
                # 和之前卡在 15% 是同一类问题。
                resp_count += 1
                now = time.time()
                if now - last_tick >= 0.5:
                    # 46~52 这一段。拿不到响应总数，用渐近曲线保证只增不越界
                    pct = 46 + int((1.0 - 1.0 / (1.0 + resp_count / 20000.0)) * 6)
                    self._emit_progress(
                        pct,
                        f"HTTP 响应扫描中... ({resp_count} 个响应, "
                        f"{len(extracted_files)} 个对象)")
                    last_tick = now

                request_in = str(getattr(packet, "http_request_in", "") or "").strip()
                request_frame = 0
                target_indices: Optional[List[int]] = None
                evidence_key: Optional[Tuple[str, int]] = None
                if request_in:
                    try:
                        request_frame = int(request_in)
                    except (TypeError, ValueError):
                        request_frame = 0
                    target_indices = request_to_indices.get(request_frame)
                    evidence_key = ("request", request_frame)
                else:
                    target_indices = stream_to_indices.get(packet.tcp_stream)
                    evidence_key = ("stream", packet.tcp_stream)
                    if target_indices:
                        target_indices = [
                            index for index in target_indices
                            if index not in exact_response_matches
                        ]
                        if target_indices:
                            first_result = results[target_indices[0]]
                            first_raw = first_result.raw_result if isinstance(first_result.raw_result, dict) else {}
                            try:
                                request_frame = int(
                                    first_raw.get("frame_number")
                                    or getattr(first_result, "packet_number", 0)
                                    or 0
                                )
                            except (TypeError, ValueError):
                                request_frame = 0

                if target_indices and evidence_key not in seen_evidence_links:
                    seen_evidence_links.add(evidence_key)
                    self._attach_response_evidence(packet, results, target_indices)
                    if request_in:
                        exact_response_matches.update(target_indices)

                body = packet.http_response_body or b""
                match = inspector.inspect(
                    packet.frame_number,
                    body,
                    packet.http_content_type,
                    self._response_content_disposition(packet),
                    self._http_request_uris.get(request_frame, ""),
                )
                if not (self.options.extract_files and match and body):
                    continue

                body_hash = hashlib.sha256(body).hexdigest()
                if body_hash in seen_hashes:
                    continue
                if output_dir is None:
                    import tempfile

                    output_dir = tempfile.mkdtemp("tinglan_http_")
                file_path, filename = safe_unique_path(
                    output_dir,
                    match.filename,
                    fallback=f"frame_{packet.frame_number}.bin",
                )
                with open(file_path, "wb") as output_file:
                    output_file.write(body)
                seen_hashes.add(body_hash)
                extracted_files.append(
                    ExtractedFile(
                        file_path=file_path,
                        file_name=filename,
                        file_type=match.file_type,
                        file_size=len(body),
                        source_packet=packet.frame_number,
                        content_type=match.content_type,
                        pcap_path=self.pcap_path,
                    )
                )
        except Exception as error:
            logger.warning("HTTP response stream scan failed: %s", error)
            self._emit_progress(52, "HTTP 响应流式扫描失败")
        finally:
            close = getattr(packet_iter, "close", None)
            if close:
                close()

        if not self._is_cancelled:
            self._emit_progress(52, f"HTTP 响应扫描完成: {len(extracted_files)} 个对象")
        return extracted_files

    @staticmethod
    def _response_content_disposition(packet: PacketData) -> str:
        """Return Content-Disposition without depending on a version-specific field."""
        explicit = str(getattr(packet, "http_content_disposition", "") or "").strip()
        if explicit:
            return explicit
        return content_disposition_from_response_lines(
            getattr(packet, "http_response_lines", []) or []
        )

    def _attach_response_evidence(
        self,
        packet: PacketData,
        results: List[DetectionResult],
        target_indices: List[int],
    ) -> None:
        body_sample = (packet.http_response_body or b"")[:2000].decode("utf-8", errors="replace")
        status_code = str(packet.http_response_code or "")
        response_lines = getattr(packet, "http_response_lines", [])
        status_line = response_lines[0] if response_lines else ""
        if not status_line:
            status_line = f"HTTP/1.1 {status_code}" if status_code else ""
        response_headers = self._extract_response_headers(packet)
        response_data = status_line
        if response_headers:
            response_data += "\r\n" + response_headers
        response_data = (response_data + "\r\n\r\n" + body_sample)[:2000]

        for result_index in target_indices:
            detection = results[result_index]
            # 请求侧证据被省掉的那些条目，响应侧同样只留状态码。
            # 状态码很轻（几个字节）但信息量最大 —— 200 和 404 直接决定
            # 这次攻击有没有打成，后面的成功判定就靠它起步。
            lazy = bool(isinstance(detection.raw_result, dict)
                        and detection.raw_result.get("evidence_lazy"))
            if isinstance(detection.raw_result, dict):
                detection.raw_result["response_status"] = status_code
                if not lazy:
                    detection.raw_result["response_sample"] = body_sample
                    detection.raw_result["response_data"] = response_data
            if not lazy:
                detection.response_sample = body_sample
                detection.response_data = response_data

    def _fetch_http_responses(
        self,
        results: List[DetectionResult],
        _allow_ek_fallback: bool = True,
        _response_matches: Optional[List[Tuple[PacketData, List[int]]]] = None,
        _seen_response_links: Optional[Set[Tuple[str, int]]] = None,
    ) -> List[DetectionResult]:
        """检测完成后，按 tcp_stream 批量抓取对应的 HTTP 响应包"""
        if not results or not self._handler:
            return results

        stream_to_indices: Dict[int, List[int]] = {}
        request_to_indices: Dict[int, List[int]] = {}
        for idx, det in enumerate(results):
            tcp_stream = -1
            request_frame = 0
            if det.raw_result and isinstance(det.raw_result, dict):
                tcp_stream = det.raw_result.get('tcp_stream', -1)
                request_frame = det.raw_result.get("frame_number", 0)
            if not request_frame:
                request_frame = getattr(det, "packet_number", 0)
            if tcp_stream >= 0:
                stream_to_indices.setdefault(tcp_stream, []).append(idx)
            try:
                request_frame = int(request_frame or 0)
            except (TypeError, ValueError):
                request_frame = 0
            if request_frame > 0:
                request_to_indices.setdefault(request_frame, []).append(idx)

        if not stream_to_indices:
            return results

        if self._is_cancelled:
            return results

        stream_ids = set(stream_to_indices.keys())
        response_matches = _response_matches if _response_matches is not None else []
        seen_response_links = (
            _seen_response_links if _seen_response_links is not None else set()
        )
        matched_detection_indices: Set[int] = {
            idx
            for _packet, target_indices in response_matches
            for idx in target_indices
        }
        output_format = OutputFormat.FIELDS if _allow_ek_fallback else OutputFormat.EK
        config = StreamConfig(
            pcap_path=self.pcap_path,
            display_filter="http.response",
            output_format=output_format,
            fields=list(HTTP_RESPONSE_FIELDS) if output_format is OutputFormat.FIELDS else [],
            disable_name_resolution=True,
            line_buffered=True
        )

        try:
            packet_iter = self._handler.stream_packets(config)
            try:
                for packet in packet_iter:
                    if self._is_cancelled:
                        break

                    sid = packet.tcp_stream
                    request_in = getattr(packet, "http_request_in", "")
                    try:
                        request_frame = int(request_in) if request_in else 0
                    except (TypeError, ValueError):
                        request_frame = 0

                    if request_in:
                        target_indices = request_to_indices.get(request_frame)
                        response_key = ("request", request_frame)
                    else:
                        target_indices = stream_to_indices.get(sid)
                        response_key = ("stream", sid)

                    if not target_indices or response_key in seen_response_links:
                        del packet
                        continue

                    # A populated but unknown request link must not fall back to
                    # its TCP stream, otherwise pipelined requests are mispaired.
                    seen_response_links.add(response_key)
                    response_matches.append((packet, target_indices))
                    matched_detection_indices.update(target_indices)
                    if len(matched_detection_indices) >= len(results):
                        break
            finally:
                close = getattr(packet_iter, "close", None)
                if close:
                    close()
        except Exception as e:
            if _allow_ek_fallback:
                logger.warning(f"FIELDS response stream failed, retrying EK: {e}")
                return self._fetch_http_responses(
                    results,
                    False,
                    response_matches,
                    seen_response_links,
                )
            logger.warning(f"响应包抓取失败: {e}")

        for resp_pkt, target_indices in response_matches:
            status_code = resp_pkt.http_response_code or ""

            body = resp_pkt.http_response_body or b""

            body_str = ""
            if body:
                try:
                    body_str = body.decode('utf-8', errors='replace')
                except Exception:
                    body_str = repr(body)[:2000]

            resp_headers = self._extract_response_headers(resp_pkt)
            response_lines = getattr(resp_pkt, "http_response_lines", [])
            status_line = response_lines[0] if response_lines else ""
            if not status_line:
                status_line = f"HTTP/1.1 {status_code}" if status_code else ""

            response_text = status_line
            if resp_headers:
                response_text += "\r\n" + resp_headers
            response_text += "\r\n\r\n" + body_str

            for det_idx in target_indices:
                det = results[det_idx]
                if det.raw_result and isinstance(det.raw_result, dict):
                    det.raw_result['response_data'] = response_text
                    det.raw_result['response_sample'] = body_str[:2000]
                    det.raw_result['response_status'] = status_code
                det.response_data = response_text
                det.response_sample = body_str[:2000] if body_str else ""

            del resp_pkt

        response_matches.clear()
        return results

    def _extract_response_headers(self, packet: 'PacketData') -> str:
        """从 EK 原始数据中提取响应头"""
        layers = packet.raw_ek_data.get('layers', {})
        http = layers.get('http', {})
        if not http:
            return ""

        skip_keys = {
            'http_http_response_code', 'http_http_response_phrase',
            'http_http_file_data', 'http_http_response_for_uri',
            'http_http_request_method', 'http_http_request_uri',
            'http_http_chat', 'http_http_response_line',
            'http_http_request_line',
        }
        header_lines = []
        for key, value in http.items():
            if key.startswith('http_http_') and key not in skip_keys:
                field_name = key.replace('http_http_', '').replace('_', '-')
                val = value[0] if isinstance(value, list) else value
                if val:
                    header_lines.append(f"{field_name}: {val}")

        return "\r\n".join(header_lines)

    def _run_icmp_analysis(self) -> List[ProtocolFinding]:
        from core.protocol_analyzer import ICMPAnalyzer
        findings: List[ProtocolFinding] = []
        try:
            analyzer = ICMPAnalyzer()
            result = analyzer.analyze_pcap(self.pcap_path, display_filter="icmp")
            for af in result.findings:
                pf = ProtocolFinding.from_analyzer_finding(af)
                findings.append(pf)
                self.protocolFindingFound.emit(pf)
            self._emit_progress(56, f"ICMP分析完成: {len(findings)} 个发现")
        except Exception as e:
            logger.warning(f"ICMP 分析异常: {e}")
        return findings

    def _run_dns_analysis(self) -> List[ProtocolFinding]:
        from core.protocol_analyzer import DNSCovertChannelAnalyzer
        findings: List[ProtocolFinding] = []
        try:
            analyzer = DNSCovertChannelAnalyzer()
            result = analyzer.analyze_pcap(self.pcap_path, display_filter="dns")
            for af in result.findings:
                pf = ProtocolFinding.from_analyzer_finding(af)
                findings.append(pf)
                self.protocolFindingFound.emit(pf)
            self._emit_progress(60, f"DNS分析完成: {len(findings)} 个发现")
        except Exception as e:
            logger.warning(f"DNS 分析异常: {e}")
        return findings

    def _run_cs_detection(self) -> List[ProtocolFinding]:
        from core.protocol_analyzer import CobaltStrikeAnalyzer
        findings: List[ProtocolFinding] = []
        try:
            analyzer = CobaltStrikeAnalyzer()
            result = analyzer.analyze(self._http_evidence_packets)
            for af in result.findings:
                pf = ProtocolFinding.from_analyzer_finding(af)
                findings.append(pf)
                self.protocolFindingFound.emit(pf)
            self._emit_progress(64, f"CS检测完成: {len(findings)} 个发现")
        except Exception as e:
            logger.warning(f"CS 分析异常: {e}")
        return findings

    def _write_cs_payload_artifact(self, record: Dict[str, Any], body: bytes, index: int) -> None:
        """把完整 CS 加密帧落盘，GUI 只加载路径和预览，避免大 payload 卡死。"""
        try:
            from core.cs_payload_export import default_cs_payload_output_dir, write_cs_payload_artifact

            output_dir = default_cs_payload_output_dir(self.pcap_path)
            write_cs_payload_artifact(record, body, output_dir, index=index)
        except Exception as e:
            logger.debug(f"CS Payload 导出附件写入失败: {e}")

    def _run_rtp_analysis(self) -> List[RTPStreamInfo]:
        try:
            from core.rtp_analyzer import list_rtp_streams, parse_sdp_codecs

            streams = list_rtp_streams(self.pcap_path, self.tshark_path)
            if not streams:
                self._emit_progress(68, "未发现 RTP 音视频流")
                return []

            has_dynamic = any(s.payload_type >= 96 for s in streams)
            if has_dynamic:
                sdp_map = parse_sdp_codecs(self.pcap_path, self.tshark_path)
                for s in streams:
                    if s.payload_type >= 96 and s.payload_type in sdp_map:
                        name, mtype, rate = sdp_map[s.payload_type]
                        s.codec_name = name
                        s.media_type = mtype
                        s.sample_rate = rate

            self._emit_progress(68, f"发现 {len(streams)} 条 RTP 音视频流")
            return streams

        except Exception as e:
            logger.warning(f"RTP 分析异常: {e}")
            return []

    def _run_deep_protocol_analysis(
        self, protocol_counts: Optional[Dict[str, int]] = None
    ) -> Tuple[List[ProtocolFinding], List[str]]:
        """运行 ProtocolAnalyzerManager 中所有注册的协议分析器

        `protocol_counts` 是 5% 阶段那趟 `-z io,phs` 的产物，用来把"跑了也
        必然扫不出东西"的分析器摘掉 —— 详见
        ProtocolAnalyzerManager.select_runnable_protocols 的说明。拿不到统计
        时**全部照跑**，不做任何假设。

        Returns:
            (findings, extracted_file_paths) 双元组
        """
        findings: List[ProtocolFinding] = []
        extracted_file_paths: List[str] = []

        try:
            from core.protocol_analyzer import ProtocolAnalyzerManager, ProtocolType

            SKIP = {ProtocolType.ICMP, ProtocolType.DNS, ProtocolType.COBALT_STRIKE}

            manager = ProtocolAnalyzerManager()
            deep_protocols = [
                protocol for protocol in ProtocolType if protocol not in SKIP
            ]
            runnable, gated = ProtocolAnalyzerManager.select_runnable_protocols(
                deep_protocols, protocol_counts)
            if gated:
                names = ", ".join(sorted(p.value for p in gated))
                logger.info(
                    "协议分级统计里没有这些协议层，跳过对应分析器（跑了也必然"
                    "匹配 0 个包）：%s", names)
                self._emit_progress(70, f"深度协议分析：按协议统计跳过 {len(gated)} 个分析器")

            results = manager.analyze_all_pcap(
                self.pcap_path,
                enabled_protocols=runnable,
                generate_plot=True,
                progress_callback=self._emit_deep_protocol_progress,
                parallel=True,
                max_workers=4,
            )

            total_findings = 0
            for proto_type, result in results.items():
                if proto_type in SKIP:
                    continue
                if not result.has_findings():
                    continue
                for af in result.findings:
                    pf = ProtocolFinding.from_analyzer_finding(af)
                    findings.append(pf)
                    self.protocolFindingFound.emit(pf)
                    total_findings += 1
                extracted_file_paths.extend(
                    f for f in result.extracted_files if os.path.isfile(f)
                )

            self._emit_progress(74, f"深度协议分析完成: {len(results)} 个协议, {total_findings} 个发现")

        except Exception as e:
            logger.warning(f"深度协议分析异常: {e}")

        self._emit_progress(74, "深度协议分析完成")
        return findings, extracted_file_paths

    def _emit_deep_protocol_progress(
        self,
        index: int,
        total: int,
        protocol: Any,
    ) -> None:
        """Expose per-analyzer progress while the full manager pass is running."""
        if total <= 0:
            return
        completed = index + 1
        percent = 65 + ((completed * 9 + total - 1) // total)
        name = getattr(protocol, "value", str(protocol))
        self._emit_progress(
            min(percent, 74),
            f"深度协议分析 {completed}/{total}: {name}",
        )

    # 这里原来有 _export_http_objects / _export_http_objects_fallback 两个方法
    # （连同它们私有的 _guess_content_type / _get_file_type），共约 110 行。
    # 主流程早已改走 _scan_http_responses —— 响应扫描那一趟里顺便用
    # HttpResponseInspector 判定值不值得落盘，不需要再单独跑一次
    # tshark --export-objects。全库唯一的引用是一个测试的 monkeypatch
    # (raising=False)，属于死代码，删除。
    # controllers/analysis_controller.py 里那份同名方法是旧流水线自己的，
    # 仍在使用，不要一起删。

    def _run_auto_decoding(self, detections: List[DetectionResult]) -> List[AutoDecodingResult]:
        results: List[AutoDecodingResult] = []

        try:
            from core.auto_decoder import MagicDecoder

            decoder = MagicDecoder()

            total = len(detections)
            for i, detection in enumerate(detections):
                if self._is_cancelled:
                    break

                if i % 10 == 0:
                    pct = 75 + int((i / max(total, 1)) * 10)
                    self._emit_progress(pct, f"自动解码 {i+1}/{total}...")

                payloads_to_decode = []

                # 收集已解码的载荷
                if detection.payloads:
                    for payload in detection.payloads:
                        if payload.decoded_content and len(payload.decoded_content) > 4:
                            payloads_to_decode.append(
                                (f"payload:{payload.param_name}", payload.decoded_content)
                            )

                # 收集参数字典里的值
                if detection.payload and isinstance(detection.payload, dict):
                    for key, value in detection.payload.items():
                        if isinstance(value, dict):
                            decoded = value.get('decoded', '')
                            if decoded and len(str(decoded)) > 4:
                                payloads_to_decode.append((f"param:{key}", str(decoded)))

                # 收集原始请求体
                if detection.raw_result and isinstance(detection.raw_result, dict):
                    raw_body = detection.raw_result.get('raw_request_body', '')
                    if raw_body and len(raw_body) > 10:
                        payloads_to_decode.append(("request_body", str(raw_body)[:5000]))

                    # 提取 URI query string 参数
                    uri = detection.raw_result.get('uri', '') or detection.uri or ''
                    if '?' in uri:
                        query_string = uri.split('?', 1)[1]
                        if query_string and len(query_string) > 4:
                            payloads_to_decode.append(("uri_query", query_string))

                for source, data in payloads_to_decode:
                    try:
                        decode_result = decoder.decode_http_payload(data)

                        if (decode_result.total_layers > 0 or decode_result.flags_found) and decode_result.is_meaningful:
                            auto_result = AutoDecodingResult(
                                source=source,
                                original_data=data[:500],
                                final_data=decode_result.final_text[:1000],
                                decode_chain=decode_result.decode_chain,
                                total_layers=decode_result.total_layers,
                                is_meaningful=decode_result.is_meaningful,
                                confidence=decode_result.confidence,
                                detected_type=decode_result.detected_content_type,
                                flags_found=decode_result.flags_found,
                                associated_detection_id=detection.id
                            )
                            results.append(auto_result)
                            self.decodingResultFound.emit(auto_result)
                    except Exception as e:
                        logger.debug(f"解码失败: {e}")

            self._emit_progress(85, f"自动解码完成: {len(results)} 个结果")

        except Exception as e:
            logger.warning(f"自动解码异常: {e}")

        return results

    def _run_file_recovery(self, extracted_files: List[ExtractedFile]) -> List[FileRecoveryResult]:
        results: List[FileRecoveryResult] = []

        try:
            from core.file_restorer import FileRestorer
            restorer = FileRestorer()

            total = len(extracted_files)
            for i, ef in enumerate(extracted_files):
                if self._is_cancelled:
                    break

                if i % 20 == 0:
                    pct = 88 + int((i / max(total, 1)) * 6)
                    self._emit_progress(pct, f"文件分析 {i+1}/{total}...")

                if not os.path.exists(ef.file_path):
                    continue

                try:
                    with open(ef.file_path, 'rb') as f:
                        data = f.read(8192)

                    if not data:
                        continue

                    recovery = restorer.restore_file(data)

                    if recovery.detected:
                        file_result = FileRecoveryResult(
                            detected=True,
                            extension=recovery.extension,
                            description=recovery.description,
                            mime_type=recovery.mime_type,
                            category=recovery.category,
                            confidence=recovery.confidence,
                            size=ef.file_size,
                            offset=0,
                            source_packet=ef.source_packet,
                            saved_path=ef.file_path,
                            data_preview=self._format_hex_preview(data[:256])
                        )
                        results.append(file_result)
                        self.fileRecovered.emit(file_result)

                except Exception as e:
                    logger.debug(f"文件还原失败 {ef.file_path}: {e}")

            self._emit_progress(94, f"文件还原完成: {len(results)} 个文件")

        except Exception as e:
            logger.warning(f"文件还原异常: {e}")

        return results

    def _format_hex_preview(self, data: bytes) -> str:
        lines = []
        for i in range(0, min(len(data), 256), 16):
            chunk = data[i:i+16]
            offset = f"{i:04x}"
            hex_part = " ".join(f"{b:02x}" for b in chunk)
            ascii_part = "".join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
            lines.append(f"{offset}  {hex_part:<48}  |{ascii_part}|")
        return '\n'.join(lines)

    def _build_protocol_stats(self, protocol_counts: Dict[str, int], total: int, hierarchy: list = None) -> List[ProtocolStats]:
        if hierarchy:
            return build_hierarchy_stats(hierarchy, total)
        stats = []
        for proto, count in sorted(protocol_counts.items(), key=lambda x: -x[1]):
            pct = (count / total * 100) if total > 0 else 0
            stats.append(ProtocolStats(proto, count, pct))
        return stats

    def _build_summary(
        self,
        detections: List[DetectionResult],
        protocol_stats: List[ProtocolStats],
        protocol_findings: List[ProtocolFinding],
        decoding_results: List[AutoDecodingResult],
        recovered_files: List[FileRecoveryResult],
        extracted_files: List[ExtractedFile],
        total_packets: int,
        rtp_streams: List[RTPStreamInfo] = None
    ) -> AnalysisSummary:
        analysis_time = time.time() - self._start_time

        summary = AnalysisSummary(
            file_path=self.pcap_path,
            total_packets=total_packets,
            protocol_stats=protocol_stats,
            detections=detections,
            extracted_files=extracted_files,
            protocol_findings=protocol_findings,
            decoding_results=decoding_results,
            recovered_files=recovered_files,
            rtp_streams=rtp_streams or [],
            analysis_time=analysis_time
        )

        self._emit_progress(100, f"分析完成，耗时 {analysis_time:.2f}秒")
        return summary


class StreamAnalysisController(QObject):
    """分析控制器，支持多文件并发分析"""

    analysisStarted = Signal(str)               # file_path
    analysisProgress = Signal(str, int, str)    # file_path, 百分比, 状态消息
    detectionFound = Signal(object)
    batchDetectionsFound = Signal(list)
    protocolFindingFound = Signal(object)
    decodingResultFound = Signal(object)
    fileRecovered = Signal(object)
    analysisFinished = Signal(object)           # AnalysisSummary
    analysisError = Signal(str, str)            # file_path, 错误消息
    analysisCancelled = Signal(str)             # file_path
    # 内存告警：(file_path, 等级, 说明文本)
    memoryWarning = Signal(str, str, str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._workers: Dict[str, StreamAnalysisWorker] = {}

    def _norm(self, path: str) -> str:
        return os.path.normcase(os.path.abspath(path))

    @property
    def is_running(self) -> bool:
        return any(w.isRunning() for w in self._workers.values())

    def is_file_running(self, pcap_path: str) -> bool:
        key = self._norm(pcap_path)
        worker = self._workers.get(key)
        return worker is not None and worker.isRunning()

    @property
    def current_file(self) -> str:
        for key, w in self._workers.items():
            if w.isRunning():
                return w.pcap_path
        return ""

    def startAnalysis(self, pcap_path: str, options: Dict = None):
        key = self._norm(pcap_path)
        if key in self._workers:
            self._cleanup_worker(key)

        analysis_options = AnalysisOptions(
            detect_webshell=options.get("detect_webshell", True) if options else True,
            detect_owasp=options.get("detect_owasp", True) if options else True,
            extract_files=(
                options.get(
                    "extract_files",
                    options.get("extract_images", True),
                )
                if options
                else True
            ),
            auto_decode=options.get("auto_decode", True) if options else True,
            file_recovery=options.get("file_recovery", True) if options else True,
            custom_keys=options.get("custom_keys", {}) if options else {},
        )

        worker = StreamAnalysisWorker(pcap_path, analysis_options)
        self._workers[key] = worker

        fp = pcap_path
        worker.progress.connect(lambda p, m, f=fp: self.analysisProgress.emit(f, p, m))
        worker.batchResultsReady.connect(self.batchDetectionsFound.emit)
        worker.protocolFindingFound.connect(self.protocolFindingFound.emit)
        worker.decodingResultFound.connect(self.decodingResultFound.emit)
        worker.fileRecovered.connect(self.fileRecovered.emit)
        worker.analysisComplete.connect(self._onFinished)
        worker.error.connect(lambda msg, f=fp: self._onError(f, msg))
        worker.cancelled.connect(lambda f=fp: self._onCancelled(f))
        worker.memoryWarning.connect(
            lambda level, text, f=fp: self.memoryWarning.emit(f, level, text))

        self.analysisStarted.emit(pcap_path)
        worker.start()

    def _cleanup_worker(self, key: str):
        worker = self._workers.pop(key, None)
        if not worker:
            return
        self._disconnect_worker_obj(worker)
        worker.cancel()
        if not worker.wait(500):
            worker.finished.connect(worker.deleteLater)
            return
        worker.deleteLater()

    def _disconnect_worker_obj(self, worker):
        if not worker:
            return
        for sig in (
            worker.progress,
            worker.batchResultsReady,
            worker.singleResultReady,
            worker.protocolFindingFound,
            worker.decodingResultFound,
            worker.fileRecovered,
            worker.analysisComplete,
            worker.error,
            worker.cancelled,
            worker.memoryWarning,
        ):
            try:
                sig.disconnect()
            except (RuntimeError, TypeError):
                pass

    def stopAnalysis(self, pcap_path: str = None):
        if pcap_path:
            key = self._norm(pcap_path)
            worker = self._workers.get(key)
            if worker:
                worker.cancel()
        else:
            for worker in self._workers.values():
                worker.cancel()

    def _onFinished(self, summary: AnalysisSummary):
        key = self._norm(summary.file_path)
        worker = self._workers.pop(key, None)
        if worker:
            worker.deleteLater()
        self.analysisFinished.emit(summary)

    def _onError(self, file_path: str, error_msg: str):
        key = self._norm(file_path)
        worker = self._workers.pop(key, None)
        if worker:
            worker.deleteLater()
        self.analysisError.emit(file_path, error_msg)

    def _onCancelled(self, file_path: str):
        key = self._norm(file_path)
        worker = self._workers.pop(key, None)
        if worker:
            worker.deleteLater()
        self.analysisCancelled.emit(file_path)
