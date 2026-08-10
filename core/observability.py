# -*- coding: utf-8 -*-
"""observability.py - 观测中心

各模块把指标打到这里，GUI 的 metrics_dashboard 和 MCP 从这里取。

## 为什么它长这样

这个模块是**后写的**：`gui/widgets/metrics_dashboard.py` 和 `core/fast_filter.py`
里的埋点早就写好了，但中间这层一直空缺，导致 11 处 `hub.*` 调用全是死代码、
dashboard 的 `_refresh()` 一进去就 return。所以下面的公开 API **是由消费方
反推出来的契约，不能随意改名**：

    incr / set_gauge / timer              <- core/fast_filter.py 在用
    register_heartbeat_callback           <- metrics_dashboard.py:343
    get_dashboard_data()                  <- metrics_dashboard.py:438
        {"rates": {...}, "sampling": {...}, "alerts": {...}}

改 key 之前先搜一遍这两个文件。

## 线程模型

分析跑在 QThread 里，指标从工作线程写、UI 线程读，所有状态用 RLock 保护。

**心跳默认不启动**：从工作线程回调进 Qt 控件会直接崩。dashboard 自己有 QTimer
轮询，那条路是安全的。真要用心跳，调用方必须自己 marshal 到 UI 线程。
"""

import threading
import time
from collections import OrderedDict
from typing import Callable, Dict, List, Optional

import logging

logger = logging.getLogger(__name__)


class _TimerStats:
    """一个计时器的累计统计"""

    __slots__ = ("count", "total_s", "max_s")

    def __init__(self):
        self.count = 0
        self.total_s = 0.0
        self.max_s = 0.0

    def add(self, elapsed_s: float) -> None:
        self.count += 1
        self.total_s += elapsed_s
        if elapsed_s > self.max_s:
            self.max_s = elapsed_s

    @property
    def avg_ms(self) -> float:
        return (self.total_s / self.count * 1000.0) if self.count else 0.0

    def to_dict(self) -> Dict[str, object]:
        return {
            "count": self.count,
            "total_ms": round(self.total_s * 1000.0, 2),
            "avg_ms": round(self.avg_ms, 3),
            "max_ms": round(self.max_s * 1000.0, 2),
        }


class _StageStats:
    """流水线单个阶段的耗时与吞吐"""

    __slots__ = ("elapsed_s", "items", "runs")

    def __init__(self):
        self.elapsed_s = 0.0
        self.items = 0
        self.runs = 0

    def add(self, elapsed_s: float, items: int) -> None:
        self.elapsed_s += elapsed_s
        self.items += max(0, items)
        self.runs += 1

    @property
    def items_per_second(self) -> float:
        return (self.items / self.elapsed_s) if self.elapsed_s > 0 else 0.0

    def to_dict(self) -> Dict[str, object]:
        return {
            "runs": self.runs,
            "elapsed_ms": round(self.elapsed_s * 1000.0, 1),
            "items": self.items,
            "items_per_second": round(self.items_per_second, 1),
        }


class _TimerContext:
    """timer() 返回的上下文管理器

    fast_filter 里是手动 __enter__/__exit__ 调用的（不是 with 语句），
    所以这两个方法必须能独立工作。
    """

    __slots__ = ("_hub", "_name", "_start")

    def __init__(self, hub: "ObservabilityHub", name: str):
        self._hub = hub
        self._name = name
        self._start = 0.0

    def __enter__(self) -> "_TimerContext":
        self._start = time.perf_counter()
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        if self._start:
            self._hub._record_timer(self._name, time.perf_counter() - self._start)
        return False


class _StageContext:
    """stage() 返回的上下文管理器；items 可以在块内回填"""

    __slots__ = ("_hub", "_name", "_items", "_start")

    def __init__(self, hub: "ObservabilityHub", name: str, items: int = 0):
        self._hub = hub
        self._name = name
        self._items = items
        self._start = 0.0

    def set_items(self, items: int) -> None:
        """阶段结束前回填处理了多少条，用来算吞吐"""
        self._items = items

    def __enter__(self) -> "_StageContext":
        self._start = time.perf_counter()
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        elapsed = time.perf_counter() - self._start if self._start else 0.0
        self._hub._record_stage(self._name, elapsed, self._items)
        return False


class ObservabilityHub:
    """进程内指标汇总"""

    def __init__(self):
        self._lock = threading.RLock()
        self._counters: Dict[str, int] = {}
        self._gauges: Dict[str, float] = {}
        self._timers: Dict[str, _TimerStats] = {}
        self._stages: "OrderedDict[str, _StageStats]" = OrderedDict()

        self._packets = 0
        self._alerts = 0
        self._critical = 0
        self._run_started = 0.0
        self._run_ended = 0.0

        self._heartbeat_callbacks: List[Callable[[Dict], None]] = []
        self._heartbeat_thread: Optional[threading.Thread] = None
        self._heartbeat_stop = threading.Event()

    # ---------- 基础埋点 ----------

    def incr(self, name: str, n: int = 1) -> None:
        with self._lock:
            self._counters[name] = self._counters.get(name, 0) + n

    def set_gauge(self, name: str, value: float) -> None:
        with self._lock:
            self._gauges[name] = value

    def get_counter(self, name: str) -> int:
        with self._lock:
            return self._counters.get(name, 0)

    def get_gauge(self, name: str) -> Optional[float]:
        with self._lock:
            return self._gauges.get(name)

    def timer(self, name: str) -> _TimerContext:
        return _TimerContext(self, name)

    def stage(self, name: str, items: int = 0) -> _StageContext:
        """给流水线某个阶段计时。用法：

            with hub.stage("HTTP 流式分析") as st:
                results = do_work()
                st.set_items(len(results))
        """
        return _StageContext(self, name, items)

    def _record_timer(self, name: str, elapsed_s: float) -> None:
        with self._lock:
            stats = self._timers.get(name)
            if stats is None:
                stats = self._timers[name] = _TimerStats()
            stats.add(elapsed_s)

    def _record_stage(self, name: str, elapsed_s: float, items: int) -> None:
        with self._lock:
            stats = self._stages.get(name)
            if stats is None:
                stats = self._stages[name] = _StageStats()
            stats.add(elapsed_s, items)

    # ---------- 业务埋点 ----------

    def record_packet(self, n: int = 1) -> None:
        with self._lock:
            self._packets += n

    def record_detection(self, threat_level: object = None) -> None:
        """记一条告警。threat_level 可以是枚举、字符串或 None"""
        label = ""
        if threat_level is not None:
            label = str(getattr(threat_level, "value", threat_level)).lower()
        with self._lock:
            self._alerts += 1
            if label in ("critical", "high", "严重", "高危"):
                self._critical += 1
            if label:
                key = f"alerts.{label}"
                self._counters[key] = self._counters.get(key, 0) + 1

    # ---------- 运行周期 ----------

    def start_run(self) -> None:
        """一次分析开始。清空上一轮，避免跨 pcap 累计

        注意：并发分析多个文件时**不要**每个 worker 都调这个，后来者会把先跑
        的那个正在累积的指标抹掉。由调用方保证只有第一个进来的才调
        （见 StreamAnalysisWorker._begin_observability_run）。
        """
        with self._lock:
            self._counters.clear()
            self._gauges.clear()
            self._timers.clear()
            self._stages.clear()
            self._packets = 0
            self._alerts = 0
            self._critical = 0
            self._run_started = time.perf_counter()
            self._run_ended = 0.0

    def end_run(self) -> None:
        with self._lock:
            self._run_ended = time.perf_counter()

    def _elapsed_s(self) -> float:
        if not self._run_started:
            return 0.0
        end = self._run_ended or time.perf_counter()
        return max(end - self._run_started, 0.0)

    # ---------- 取数 ----------

    def _filter_stats(self) -> Dict[str, object]:
        """fast_filter 自己维护的两级缓存和覆盖率审计"""
        try:
            from core.fast_filter import get_filter_stats
            return get_filter_stats()
        except Exception:
            return {}

    def _ast_hit_rate(self) -> float:
        """过滤器放行率（0-100）

        **分母是"到达 fast_filter 的载荷"，不是"全部流量"。**
        `_run_shared_ast_analysis` 只在已有检测器命中时才被调用，纯净流量
        根本走不到过滤器这一层。看这个数时别当成全网放行比例。
        """
        with self._lock:
            analyzed = (self._counters.get("fast_filter.full_ast", 0)
                        + self._counters.get("fast_filter.fast_detect", 0))
            total = (analyzed
                     + self._counters.get("fast_filter.skipped", 0)
                     + self._counters.get("fast_filter.cache_hit", 0))
        return (analyzed / total * 100.0) if total else 0.0

    def _coverage_gap(self) -> float:
        """未被完整分析的比例（0.0-1.0）

        取证工具真正该盯的不是"丢了多少包"，而是"有多少流量没看全"。
        dashboard 那根红条显示的就是这个。
        """
        stats = self._filter_stats()
        coverage = stats.get("coverage") if isinstance(stats, dict) else None
        if not isinstance(coverage, dict):
            return 0.0
        seen = coverage.get("payloads_seen") or 0
        incomplete = coverage.get("incomplete_analysis") or 0
        return (incomplete / seen) if seen else 0.0

    def _avg_process_ms(self) -> float:
        with self._lock:
            count = sum(t.count for t in self._timers.values())
            total = sum(t.total_s for t in self._timers.values())
        return (total / count * 1000.0) if count else 0.0

    def get_dashboard_data(self) -> Dict[str, Dict]:
        """metrics_dashboard 消费的格式。改 key 前先看模块 docstring。"""
        with self._lock:
            packets = self._packets
            alerts = self._alerts
            critical = self._critical
        elapsed = self._elapsed_s()

        return {
            "rates": {
                "packets_per_second": round(packets / elapsed, 1) if elapsed > 0 else 0.0,
                # 0.0-1.0，dashboard 内部再乘 100
                "drop_rate": round(self._coverage_gap(), 4),
                "avg_process_time_ms": round(self._avg_process_ms(), 2),
            },
            "sampling": {
                # dashboard 会 strip 掉 '%' 再转 float
                "sample_hit_rate": f"{self._ast_hit_rate():.1f}%",
            },
            "alerts": {
                "total_alerts": alerts,
                "critical_count": critical,
            },
        }

    def _ast_metrics(self) -> Dict[str, object]:
        """AST 侧命中率

        attempted -> executed 之间会被 fast_filter / sink 检查 / 缓存拦掉一部分，
        这两个比率就是调过滤器阈值时最该看的东西。
        """
        with self._lock:
            attempted = self._counters.get("ast.attempted", 0)
            executed = self._counters.get("ast.executed", 0)
            with_findings = self._counters.get("ast.with_findings", 0)
            webshell = self._counters.get("ast.webshell", 0)
        return {
            "attempted": attempted,
            "executed": executed,
            "with_findings": with_findings,
            "likely_webshell": webshell,
            # 进到 AST 的比例：过滤器放行得多不多
            "execution_rate": f"{(executed / attempted * 100) if attempted else 0:.1f}%",
            # 跑了之后真出东西的比例：过滤器放行得准不准
            "finding_rate": f"{(with_findings / executed * 100) if executed else 0:.1f}%",
        }

    def get_full_report(self) -> Dict[str, object]:
        """完整指标，给 MCP / 日志 / 调优看，不受 dashboard 契约限制"""
        with self._lock:
            counters = dict(self._counters)
            gauges = dict(self._gauges)
            timers = {k: v.to_dict() for k, v in self._timers.items()}
            stages = {k: v.to_dict() for k, v in self._stages.items()}
            packets = self._packets
            alerts = self._alerts
            critical = self._critical
        elapsed = self._elapsed_s()

        return {
            "elapsed_s": round(elapsed, 3),
            "packets": packets,
            "packets_per_second": round(packets / elapsed, 1) if elapsed > 0 else 0.0,
            "alerts": {"total": alerts, "critical": critical},
            "ast": self._ast_metrics(),
            # 口径见 _ast_hit_rate 的 docstring：分母是到达过滤器的载荷
            "filter_admit_rate_of_filtered": f"{self._ast_hit_rate():.1f}%",
            "coverage_gap": f"{self._coverage_gap() * 100:.2f}%",
            "stages": stages,
            "timers": timers,
            "counters": counters,
            "gauges": gauges,
            "filter": self._filter_stats(),
        }

    # ---------- 心跳（默认关闭） ----------

    def register_heartbeat_callback(self, callback: Callable[[Dict], None]) -> None:
        """注册心跳回调

        注意：回调在心跳线程上执行，**不是 UI 线程**。Qt 消费方必须自己
        marshal（signal/QMetaObject.invokeMethod），否则直接崩。
        心跳默认不启动，metrics_dashboard 走的是自己的 QTimer 轮询。
        """
        with self._lock:
            if callback not in self._heartbeat_callbacks:
                self._heartbeat_callbacks.append(callback)

    def unregister_heartbeat_callback(self, callback: Callable[[Dict], None]) -> None:
        with self._lock:
            if callback in self._heartbeat_callbacks:
                self._heartbeat_callbacks.remove(callback)

    @property
    def heartbeat_running(self) -> bool:
        thread = self._heartbeat_thread
        return bool(thread and thread.is_alive())

    def start_heartbeat(self, interval_s: float = 1.0) -> None:
        """显式开启心跳。见 register_heartbeat_callback 的线程警告。"""
        if self.heartbeat_running:
            return
        self._heartbeat_stop.clear()

        def _loop():
            while not self._heartbeat_stop.wait(interval_s):
                try:
                    data = self.get_dashboard_data()
                except Exception as e:
                    logger.debug(f"心跳取数失败: {e}")
                    continue
                with self._lock:
                    callbacks = list(self._heartbeat_callbacks)
                for cb in callbacks:
                    try:
                        cb(data)
                    except Exception as e:
                        logger.debug(f"心跳回调异常: {e}")

        self._heartbeat_thread = threading.Thread(
            target=_loop, name="observability-heartbeat", daemon=True)
        self._heartbeat_thread.start()

    def stop_heartbeat(self) -> None:
        self._heartbeat_stop.set()
        thread = self._heartbeat_thread
        if thread and thread.is_alive():
            thread.join(timeout=2.0)
        self._heartbeat_thread = None


_hub_lock = threading.Lock()
_hub: Optional[ObservabilityHub] = None


def get_observability_hub() -> ObservabilityHub:
    global _hub
    if _hub is None:
        with _hub_lock:
            if _hub is None:
                _hub = ObservabilityHub()
    return _hub


def reset_observability_hub() -> None:
    """主要给测试用；生产上用 hub.start_run()"""
    global _hub
    with _hub_lock:
        if _hub is not None:
            _hub.stop_heartbeat()
        _hub = None
