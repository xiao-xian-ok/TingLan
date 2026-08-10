# -*- coding: utf-8 -*-
"""memory_guard.py - 分析过程中的内存看护

## 为什么按 RSS 而不是按条数/字节估算

`ResourceLimits` 里历史上有一堆 `MAX_*` 条数上限，它们有两个通病：

1. **条数是坏代理**。同样 1 万个 HTTP 包，全是小 GET 和全是大 POST 差几十倍。
2. **估算会漂**。EK 路径按 `ek_bytes × 4.5` 估算够用，但 DetectionResult
   带的证据、协议分析器的中间结果、tshark 子进程的缓冲，都不在估算里。

RSS 是操作系统看到的真实占用，把上面这些一起算进去了，所以用它当总闸。
按字节的预算（如 WEBSHELL_MEMORY_BUDGET_BYTES）仍然保留 —— 那是单个累积
容器的局部约束，这里是全局兜底，两者不冲突。

## 采样成本

`memory_info()` 在 Windows 上是一次系统调用，几十微秒。逐包调用在 50 万包
的文件上会累计到几十秒，所以内部做了双重节流：每 N 次调用、且距上次采样
超过 interval 秒，才真的去取一次。调用方可以放心地在热循环里调。

psutil 缺失时整个看护静默降级为"永远 ok"，不影响主流程。
"""

import logging
import threading
import time
from typing import Optional

logger = logging.getLogger(__name__)

try:
    import psutil
except ImportError:  # pragma: no cover - 没装就降级
    psutil = None


LEVEL_OK = "ok"
LEVEL_WARN = "warn"
LEVEL_CRITICAL = "critical"


class MemoryGuard:
    """采样进程 RSS，越过阈值时给出等级

    典型用法（热循环里直接调，节流在内部）：

        level = guard.check()
        if level == LEVEL_CRITICAL:
            # 停止累积重对象，转为降级模式
    """

    def __init__(self, warn_mb: int = 1500, critical_mb: int = 2500,
                 sample_every: int = 256, min_interval_s: float = 0.5):
        self.warn_mb = warn_mb
        self.critical_mb = critical_mb
        self._sample_every = max(1, sample_every)
        self._min_interval_s = min_interval_s

        self._lock = threading.Lock()
        self._calls = 0
        self._last_sample = 0.0
        self._last_rss_mb = 0.0
        self._peak_mb = 0.0
        self._level = LEVEL_OK
        self._reported = set()

        self._proc = None
        if psutil is not None:
            try:
                self._proc = psutil.Process()
            except Exception as e:  # pragma: no cover
                logger.debug(f"内存看护不可用: {e}")

    @property
    def available(self) -> bool:
        return self._proc is not None

    @property
    def rss_mb(self) -> float:
        return self._last_rss_mb

    @property
    def peak_mb(self) -> float:
        return self._peak_mb

    @property
    def level(self) -> str:
        return self._level

    def _sample(self) -> float:
        try:
            rss = self._proc.memory_info().rss / 1024.0 / 1024.0
        except Exception:  # pragma: no cover
            return self._last_rss_mb
        self._last_rss_mb = rss
        if rss > self._peak_mb:
            self._peak_mb = rss
        return rss

    def check(self, force: bool = False) -> str:
        """返回当前等级。内部节流，可以放心在热循环里调。"""
        if self._proc is None:
            return LEVEL_OK

        with self._lock:
            self._calls += 1
            now = time.time()
            due = (force
                   or (self._calls % self._sample_every == 0
                       and now - self._last_sample >= self._min_interval_s))
            if not due:
                return self._level

            self._last_sample = now
            rss = self._sample()

            if rss >= self.critical_mb:
                self._level = LEVEL_CRITICAL
            elif rss >= self.warn_mb:
                self._level = LEVEL_WARN
            else:
                # 回落后允许再次告警，但同一等级不重复刷屏由 should_report 控制
                self._level = LEVEL_OK
            return self._level

    def should_report(self, level: str) -> bool:
        """同一等级每次分析只报一次，避免弹窗刷屏"""
        if level in (LEVEL_OK, None):
            return False
        with self._lock:
            if level in self._reported:
                return False
            self._reported.add(level)
            return True

    def describe(self, level: str) -> str:
        if level == LEVEL_CRITICAL:
            return (f"内存占用已达 {self._last_rss_mb:.0f} MB"
                    f"（阈值 {self.critical_mb} MB）。\n\n"
                    f"为避免进程被系统终止，分析将转入降级模式：\n"
                    f"• 检测**照常全量进行**，不会漏报\n"
                    f"• 但原始报文不再驻留内存，点开某条时按帧号回 pcap 重取\n"
                    f"• WebShell 跨包关联的采集会提前收口\n\n"
                    f"如需完整驻留，建议拆分 pcap 后分批分析。")
        return (f"内存占用已达 {self._last_rss_mb:.0f} MB"
                f"（预警阈值 {self.warn_mb} MB）。\n\n"
                f"分析仍在正常进行。若继续增长到 {self.critical_mb} MB，"
                f"将自动转入降级模式以保证不崩溃。")

    def reset(self) -> None:
        with self._lock:
            self._calls = 0
            self._last_sample = 0.0
            self._peak_mb = 0.0
            self._level = LEVEL_OK
            self._reported.clear()
        if self._proc is not None:
            self._sample()
