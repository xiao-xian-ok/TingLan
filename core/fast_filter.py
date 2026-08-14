# fast_filter.py - AST前置过滤
#
# ============ 设计原则（改之前先读这段）============
#
# 听澜是**离线取证 / 威胁狩猎**工具，不是 inline 网关。两者的取舍是相反的：
#
#   网关：延迟预算 ~1ms，放过一条还有下一层兜底 -> 可以为了快而"不看"
#   狩猎：离线跑 PCAP，单包预算宽裕，漏一条 = 证据链断裂 = 工具失效
#         -> 绝不能因为"贵"就把流量从视野里抹掉
#
# 所以这里的过滤器只决定**看的顺序和深度**，不决定**哪些永远不看**。
# 任何 SKIP 都必须是"看完之后可证明安全"，而不是"没看所以不知道"。
#
# 历史上这里有过四个纯粹靠**填充/伪造请求头**就能绕过的静默跳过：
#   1. payload 超长 -> 直接 SKIP        （尾部塞 500KB 'A' 即可）
#   2. 只扫前 scan_limit 字节           （头部塞 10KB 'A' 即可）
#   3. Content-Type 命中"安全类型"->SKIP （攻击者自己设 image/jpeg 即可）
#   4. 低熵 -> SKIP
# 全部已改掉：扫描恒为全量（分块 + 前瞻，跨块不漏），3/4 降级为
# 「降权 + 留痕」而非跳过。详见 _filter_impl 与 _scan_keywords_full。
#
# 同类问题在 attack_detector._execute_shared_ast 里还有过一处
# （len(code) > MAX_AST_CODE_LEN 就 return None），已由 d144e93 直接
# 去掉长度上限修复 —— AST 现在无条件跑全量，所以这里不需要再切窗口。
#
# ============ 实现说明 ============
#
# 关键字扫描走 Aho-Corasick 一趟匹配（core/ac_matcher.py），
# 语义与老的大交替正则对齐；AC 不可用时自动回退正则。
# 实测：原正则是 50 个分支的大交替，re 引擎在每个位置逐分支重试是 O(n*k)，
# 而 AC 是 O(n)，所以即使纯 Python 的 AC 回退实现也比正则快一个数量级。
# payload 缓存前面挂了 Bloom 负向快筛（core/bloom_filter.py），
# Bloom 只用来"确定不在"，命中判定仍以精确 LRU 为准，不会造成漏检。

import re
import math
import hashlib
import threading
from typing import Optional, Dict, Set, Tuple, List, NamedTuple
from dataclasses import dataclass, field
from enum import Enum, auto
from functools import lru_cache
from collections import OrderedDict
import logging

logger = logging.getLogger(__name__)

try:
    from core.ac_matcher import (
        MultiPatternMatcher, PatternSpec, UnicodeLengthMismatch, HAS_AHOCORASICK
    )
except ImportError:  # 允许脚本方式直接跑
    try:
        from ac_matcher import (
            MultiPatternMatcher, PatternSpec, UnicodeLengthMismatch, HAS_AHOCORASICK
        )
    except ImportError:
        MultiPatternMatcher = None
        PatternSpec = None
        UnicodeLengthMismatch = ValueError
        HAS_AHOCORASICK = False

try:
    from core.bloom_filter import BloomFilter
except ImportError:
    try:
        from bloom_filter import BloomFilter
    except ImportError:
        BloomFilter = None


def _hub():
    """观测中心是可选依赖，取不到就返回 None，热路径不报错"""
    try:
        from core.observability import get_observability_hub
        return get_observability_hub()
    except Exception:
        return None



class FilterDecision(Enum):
    SKIP = auto()           # 跳过 AST —— 仅限"全量看完后可证明安全"
    FAST_DETECT = auto()    # 快速检测（简单模式匹配即可）
    FULL_AST = auto()       # 需要完整 AST 分析
    CACHED = auto()         # 命中缓存


@dataclass
class FilterResult:
    decision: FilterDecision
    reason: str = ""
    entropy: float = 0.0
    matched_keywords: List[str] = field(default_factory=list)
    cached_result: Optional[any] = None
    risk_score: int = 0  # 预估风险分 0-100

    # ---- 取证审计字段：证明"看到了多少"，别让跳过变成静默丢证据 ----
    payload_len: int = 0
    scanned_len: int = 0                 # 实际扫描覆盖到的字节数
    fully_scanned: bool = True           # False = 有未覆盖区域，结论不完整
    notes: List[str] = field(default_factory=list)   # 降权/截断等留痕


class _CoverageAudit:
    """记录"没有被完整分析"的载荷

    取证工具里，"我没看"和"我看了没问题"是完全不同的结论，不能混成一个 SKIP。
    这里把所有非完整覆盖的情况计数+采样，get_filter_stats() 暴露出去，
    让上层报告能说清"有 N 个包因为 X 没被完整分析"。
    """

    def __init__(self, sample_limit: int = 50):
        self._lock = threading.RLock()
        self._counts: Dict[str, int] = {}
        self._samples: List[Dict[str, object]] = []
        self._sample_limit = sample_limit
        self._seen = 0
        self._incomplete = 0

    def seen(self) -> None:
        with self._lock:
            self._seen += 1

    def record(self, reason: str, payload_len: int, scanned_len: int,
               keywords: Optional[List[str]] = None) -> None:
        with self._lock:
            self._incomplete += 1
            self._counts[reason] = self._counts.get(reason, 0) + 1
            if len(self._samples) < self._sample_limit:
                self._samples.append({
                    'reason': reason,
                    'payload_len': payload_len,
                    'scanned_len': scanned_len,
                    'keywords': list(keywords or [])[:10],
                })

    def get_stats(self) -> Dict[str, object]:
        with self._lock:
            rate = (self._incomplete / self._seen * 100) if self._seen else 0.0
            return {
                'payloads_seen': self._seen,
                'incomplete_analysis': self._incomplete,
                'incomplete_rate': f"{rate:.2f}%",
                'by_reason': dict(self._counts),
                'samples': list(self._samples),
            }

    def clear(self) -> None:
        with self._lock:
            self._counts.clear()
            self._samples.clear()
            self._seen = 0
            self._incomplete = 0


_coverage_audit = _CoverageAudit()


def get_coverage_audit() -> _CoverageAudit:
    return _coverage_audit


# 危险关键字，按风险等级分
class DangerKeywords:

    # 关键危险函数 - 直接触发 AST
    CRITICAL_SINKS = frozenset({
        # 代码执行
        'eval', 'assert', 'create_function', 'preg_replace',
        # 命令执行
        'system', 'exec', 'shell_exec', 'passthru', 'popen', 'proc_open',
        'pcntl_exec',
        # 回调执行
        'call_user_func', 'call_user_func_array',
        'array_map', 'array_filter', 'array_walk',
        'usort', 'uasort', 'uksort',
        # 反序列化
        'unserialize',
    })

    # 高危污点源 - 用户输入
    TAINT_SOURCES = frozenset({
        '$_GET', '$_POST', '$_REQUEST', '$_COOKIE', '$_FILES',
        '$_SERVER', '$_ENV', '$GLOBALS',
        'php://input', 'php://filter',
    })

    # 高危编码/混淆函数
    OBFUSCATION_FUNCS = frozenset({
        'base64_decode', 'base64_encode',
        'gzinflate', 'gzuncompress', 'gzdecode',
        'str_rot13', 'strrev',
        'chr', 'ord', 'pack', 'unpack',
        'hex2bin', 'bin2hex',
    })

    # 文件操作 (中等风险)
    FILE_FUNCS = frozenset({
        'file_put_contents', 'file_get_contents',
        'fopen', 'fwrite', 'fputs', 'fread',
        'include', 'include_once', 'require', 'require_once',
        'readfile', 'file',
    })

    # 动态特征 (需要 AST 分析)
    DYNAMIC_PATTERNS = frozenset({
        '$$',           # 变量的变量
        '${',           # 复杂变量语法
        '->(',          # 动态方法调用
        '::$',          # 静态变量访问
    })

    # 组合所有需要 AST 的关键字
    ALL_AST_TRIGGERS = CRITICAL_SINKS | TAINT_SOURCES | OBFUSCATION_FUNCS


class EntropyCalculator:
    ENTROPY_LOW = 4.0
    ENTROPY_NORMAL = 5.5
    ENTROPY_SUSPICIOUS = 6.5
    ENTROPY_HIGH = 7.5

    @staticmethod
    def calculate(data: bytes) -> float:  # 计算字节数据的信息熵
        if not data:
            return 0.0

        freq = [0] * 256
        for byte in data:
            freq[byte] += 1

        length = len(data)
        entropy = 0.0

        for count in freq:
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)

        return entropy

    @staticmethod
    def calculate_str(text: str) -> float:  # 字符串版本
        if not text:
            return 0.0
        return EntropyCalculator.calculate(text.encode('utf-8', errors='ignore'))

    @staticmethod
    @lru_cache(maxsize=1024)
    def calculate_cached(data_hash: str, data_len: int) -> float:  # 带缓存的，需要外部传hash
        return 0.0


class SensitivityProfile:
    """灵敏度 0-100 -> 一组阈值

    0   = 极速：判定阈值高，只把最明显的往下送
    50  = 平衡：判定阈值与历史默认**逐值相等**（60/30），升级不改判定
    100 = 全量：判定阈值低，几乎什么都往下送

    重要：这些旋钮只调**分析深度和优先级**，不调**可见性**。
    任何灵敏度下关键字扫描都是全量的——不会因为载荷长、或者
    Content-Type 看着像图片，就把一段流量从视野里抹掉。
    """

    __slots__ = ("value", "full_ast_threshold", "fast_detect_threshold",
                 "entropy_sample_limit", "hard_scan_ceiling",
                 "deprioritize_content_type", "deprioritize_low_entropy",
                 "never_skip_on_score")

    def __init__(self, value: int):
        value = max(0, min(100, int(value)))
        self.value = value

        # s=50 时分别落在 60 / 30，正好是改造前的硬编码值
        self.full_ast_threshold = int(round(90 - 0.6 * value))
        self.fast_detect_threshold = int(round(55 - 0.5 * value))

        # 熵是统计量，采样即可，不需要全量（这不影响关键字覆盖）
        self.entropy_sample_limit = int(2000 + 160 * value)

        # 关键字扫描的绝对上限，纯粹防 OOM/卡死。
        # 一旦触顶会标记 fully_scanned=False 并计入审计，不会静默。
        self.hard_scan_ceiling = 64 * 1024 * 1024

        # 只降权、不跳过。Content-Type 是攻击者可控的请求头，
        # 低熵也只是"看起来普通"，两者都不足以作为不看的理由。
        self.deprioritize_content_type = value < 90
        self.deprioritize_low_entropy = value < 90

        # 高灵敏度 = 真正的"不漏"模式：只要全量扫到了危险关键字，
        # 哪怕风险分很低也照样往下送，绝不因为分数低而丢掉。
        self.never_skip_on_score = value >= 90

    @property
    def mode(self) -> str:
        if self.value < 30:
            return "fast"
        if self.value < 70:
            return "balanced"
        return "full"

    def to_dict(self) -> Dict[str, object]:
        return {
            "sensitivity": self.value,
            "mode": self.mode,
            "full_ast_threshold": self.full_ast_threshold,
            "fast_detect_threshold": self.fast_detect_threshold,
            "entropy_sample_limit": self.entropy_sample_limit,
            "hard_scan_ceiling": self.hard_scan_ceiling,
            "deprioritize_content_type": self.deprioritize_content_type,
            "deprioritize_low_entropy": self.deprioritize_low_entropy,
            "never_skip_on_score": self.never_skip_on_score,
        }


DEFAULT_SENSITIVITY = 50
_sensitivity_lock = threading.RLock()
_sensitivity_profile = SensitivityProfile(DEFAULT_SENSITIVITY)


def set_sensitivity(value: int) -> SensitivityProfile:
    """调整过滤灵敏度，GUI 的灵敏度滑块直接调这个"""
    global _sensitivity_profile
    profile = SensitivityProfile(value)
    with _sensitivity_lock:
        _sensitivity_profile = profile
    logger.info(f"过滤灵敏度调整为 {profile.value} ({profile.mode})")
    hub = _hub()
    if hub:
        hub.set_gauge("filter.sensitivity", profile.value)
    return profile


def get_sensitivity() -> int:
    return _sensitivity_profile.value


def get_sensitivity_profile() -> SensitivityProfile:
    return _sensitivity_profile


class PayloadCache:  # LRU缓存，key是payload的sha256前16位
    """精确 LRU 缓存

    这里**默认不挂 Bloom**。实测（py -3.11，capacity=20000/p=0.01）：

        BloomFilter.might_contain  ~2.01 us/次
        它想省掉的 lock + OrderedDict 查找  ~0.34 us/次

    Bloom 比它替代的操作慢 6 倍 —— 一次 blake2b 加 7 次取模，本身就比
    查一次进程内字典贵。Bloom 的收益前提是"后端很贵"（磁盘/网络/RPC），
    挡在内存字典前面是纯亏。core/bloom_filter.py 保留给真正昂贵的后端用
    （见 BloomFrontedCache），这里只是不该用它。

    需要对比测量时可以显式传 use_bloom=True。
    """

    def __init__(self, max_size: int = 10000, use_bloom: bool = False):
        self._cache: OrderedDict = OrderedDict()
        self._max_size = max_size
        self._lock = threading.RLock()
        self._hits = 0
        self._misses = 0
        self._bloom_skips = 0
        # Bloom 只做"确定不在"的否定，容量给两倍留出 LRU 淘汰后的陈旧位余量
        self._bloom = (
            BloomFilter(capacity=max(max_size * 2, 1024), error_rate=0.01)
            if (use_bloom and BloomFilter is not None) else None
        )

    def _make_key(self, payload: str) -> str:
        return hashlib.sha256(payload.encode('utf-8', errors='ignore')).hexdigest()[:16]

    def get(self, payload: str) -> Optional[any]:
        key = self._make_key(payload)
        # Bloom 说不在就一定不在。注意这里是无锁读，与 set() 里的重建存在
        # 竞态：重建窗口内可能对确实在缓存里的 key 返回 False。后果只是
        # 多做一次分析（fail-safe 方向），不会造成漏检。
        if self._bloom is not None and not self._bloom.might_contain(key):
            self._bloom_skips += 1
            self._misses += 1
            return None
        with self._lock:
            if key in self._cache:
                self._cache.move_to_end(key)  # LRU
                self._hits += 1
                return self._cache[key]
            self._misses += 1
            return None

    def set(self, payload: str, result: any) -> None:
        key = self._make_key(payload)
        with self._lock:
            if key in self._cache:
                self._cache.move_to_end(key)
            else:
                if len(self._cache) >= self._max_size:
                    self._cache.popitem(last=False)
            self._cache[key] = result
            if self._bloom is not None:
                self._bloom.add(key)
                # 装载量到顶就按现存 key 重建，防止假阳性率无限抬高。
                # 触发判断必须用 O(1) 的 item_count —— 原来这里调 fill_ratio，
                # 那是 O(位图) 全量扫描，实测 2ms/次，等于每次插入白烧 2ms。
                if self._bloom.item_count >= self._bloom.capacity:
                    self._bloom.clear()
                    for existing in self._cache:
                        self._bloom.add(existing)

    def get_stats(self) -> Dict[str, int]:
        with self._lock:
            total = self._hits + self._misses
            hit_rate = (self._hits / total * 100) if total > 0 else 0
            stats = {
                'size': len(self._cache),
                'max_size': self._max_size,
                'hits': self._hits,
                'misses': self._misses,
                'hit_rate': f"{hit_rate:.1f}%"
            }
            if self._bloom is not None:
                skip_rate = (self._bloom_skips / total * 100) if total > 0 else 0
                stats['bloom_skips'] = self._bloom_skips
                stats['bloom_skip_rate'] = f"{skip_rate:.1f}%"
                stats['bloom_error_rate'] = round(self._bloom.estimated_error_rate(), 5)
            return stats

    def clear(self) -> None:
        with self._lock:
            self._cache.clear()
            self._hits = 0
            self._misses = 0
            self._bloom_skips = 0
            if self._bloom is not None:
                self._bloom.clear()



_payload_cache = PayloadCache(max_size=10000)
_ast_result_cache = PayloadCache(max_size=5000)


def get_payload_cache() -> PayloadCache:
    return _payload_cache


def get_ast_cache() -> PayloadCache:
    return _ast_result_cache


class FastFilter:

    # 长度限制
    # 只保留下限：短于这个长度装不下任何 sink+taint 组合，跳过可证明安全。
    # 上限（原 MAX_PAYLOAD_LEN / FAST_SCAN_LIMIT）已删除 —— 它们让"填充"
    # 成为一键绕过。超长载荷现在走全量扫 + 窗口化 AST，见 _filter_impl。
    MIN_PAYLOAD_LEN = 10

    # 预编译正则（AC 不可用时的回退路径）
    _KEYWORD_PATTERN = None
    _DYNAMIC_PATTERN = None

    # AC 自动机，进程内共享
    _KEYWORD_MATCHER = None
    _TAINT_MATCHER = None
    _MATCHER_LOCK = threading.Lock()

    def __init__(self, use_ac: bool = True):
        self._use_ac = use_ac and MultiPatternMatcher is not None
        self._compile_patterns()
        if self._use_ac:
            self._build_matchers()

    def _compile_patterns(self):
        if FastFilter._KEYWORD_PATTERN is None:
            # 构建关键字匹配正则
            all_keywords = list(DangerKeywords.CRITICAL_SINKS) + \
                          list(DangerKeywords.OBFUSCATION_FUNCS) + \
                          list(DangerKeywords.FILE_FUNCS)

            escaped = [re.escape(kw) for kw in all_keywords]
            pattern = r'\b(' + '|'.join(escaped) + r')\s*\('
            FastFilter._KEYWORD_PATTERN = re.compile(pattern, re.IGNORECASE)

            # 污点源模式
            taint_escaped = [re.escape(t) for t in DangerKeywords.TAINT_SOURCES]
            FastFilter._TAINT_PATTERN = re.compile(
                '(' + '|'.join(taint_escaped) + ')',
                re.IGNORECASE
            )

            # 动态特征模式
            # 注意：$$ 和 ${ 会重叠（"$${" 正则算 1 次、AC 会算 2 次），
            # 为了不改动风险分，这组短模式一直留在正则上，不迁 AC。
            dynamic_escaped = [re.escape(d) for d in DangerKeywords.DYNAMIC_PATTERNS]
            FastFilter._DYNAMIC_PATTERN = re.compile(
                '(' + '|'.join(dynamic_escaped) + ')'
            )

    @classmethod
    def _build_matchers(cls):
        """建 AC 自动机。关键字集要求 \\b + 尾随 \\s*( ，污点源是裸子串。"""
        if cls._KEYWORD_MATCHER is not None:
            return
        with cls._MATCHER_LOCK:
            if cls._KEYWORD_MATCHER is not None:
                return
            try:
                keyword_specs = []
                for kw in DangerKeywords.CRITICAL_SINKS:
                    keyword_specs.append(PatternSpec(kw, 'critical', True, True))
                for kw in DangerKeywords.OBFUSCATION_FUNCS:
                    keyword_specs.append(PatternSpec(kw, 'obfuscation', True, True))
                for kw in DangerKeywords.FILE_FUNCS:
                    keyword_specs.append(PatternSpec(kw, 'file', True, True))
                cls._KEYWORD_MATCHER = MultiPatternMatcher(keyword_specs)

                taint_specs = [
                    PatternSpec(t, 'taint', False, False)
                    for t in DangerKeywords.TAINT_SOURCES
                ]
                cls._TAINT_MATCHER = MultiPatternMatcher(taint_specs)

                logger.debug(
                    f"AC 自动机就绪: backend={cls._KEYWORD_MATCHER.backend}, "
                    f"keywords={cls._KEYWORD_MATCHER.pattern_count}, "
                    f"taints={cls._TAINT_MATCHER.pattern_count}"
                )
            except Exception as e:
                logger.warning(f"AC 自动机构建失败，退回正则: {e}")
                cls._KEYWORD_MATCHER = None
                cls._TAINT_MATCHER = None

    # ---------- 扫描 ----------

    # 分块大小。超长载荷分块扫，避免 lower() 一次性复制出几十 MB
    _SCAN_CHUNK = 262144
    _KW_MAXLEN = None

    @classmethod
    def _keyword_maxlen(cls) -> int:
        """最长关键字长度，用于分块时的右侧前瞻宽度"""
        if cls._KW_MAXLEN is None:
            all_kw = (list(DangerKeywords.CRITICAL_SINKS)
                      + list(DangerKeywords.OBFUSCATION_FUNCS)
                      + list(DangerKeywords.FILE_FUNCS)
                      + list(DangerKeywords.TAINT_SOURCES))
            cls._KW_MAXLEN = max((len(k) for k in all_kw), default=32)
        return cls._KW_MAXLEN

    def _scan_chunk(self, chunk: str, base: int):
        """扫一个分块，返回 (危险函数命中, 污点源命中, 后端)

        命中项是 (绝对偏移, 原文片段)。AC 路径与正则路径结果一致，
        tests/test_fast_filter_coverage.py 里有交叉验证。
        """
        if self._use_ac and FastFilter._KEYWORD_MATCHER is not None:
            try:
                # 两个 matcher 共用一次 lower()，省掉一次整块复制
                lowered = chunk.lower()
                func_hits = [
                    (base + h.start, h.raw)
                    for h in FastFilter._KEYWORD_MATCHER.find_all(chunk, lowered)
                ]
                taint_hits = [
                    (base + h.start, h.raw)
                    for h in FastFilter._TAINT_MATCHER.find_all(chunk, lowered)
                ]
                return func_hits, taint_hits, "ac"
            except UnicodeLengthMismatch:
                # lower() 改了长度，AC 偏移不可信，这一块走正则
                logger.debug("AC 偏移不可用(Unicode 大小写折叠)，本次退回正则")
            except Exception as e:
                logger.debug(f"AC 扫描异常，本次退回正则: {e}")

        func_hits = [(base + m.start(1), m.group(1))
                     for m in self._KEYWORD_PATTERN.finditer(chunk)]
        taint_hits = [(base + m.start(1), m.group(1))
                      for m in self._TAINT_PATTERN.finditer(chunk)]
        return func_hits, taint_hits, "regex"

    def _scan_keywords_full(self, payload: str, ceiling: int):
        """全量扫描整个载荷 —— 不按窗口截断，这是不可绕过的前提

        返回 (func_matches, taint_matches, backend, scanned_len, complete)

        分块时右侧多读 overlap 个字符做前瞻，保证跨块的关键字、以及
        `eval  (` 这种关键字与左括号被切开的情况都能命中；命中按绝对
        偏移去重，所以前瞻区不会造成重复计分。
        """
        n = len(payload)
        limit = min(n, ceiling)
        complete = (limit >= n)
        overlap = self._keyword_maxlen() + 64

        func_pos: Dict[int, str] = {}
        taint_pos: Dict[int, str] = {}
        backend = "regex"

        pos = 0
        while pos < limit:
            end = min(pos + self._SCAN_CHUNK, limit)
            # 右侧前瞻可以越过 limit 去看原文，只是不接受起点在 end 之后的命中
            look = min(end + overlap, n)
            fh, th, backend = self._scan_chunk(payload[pos:look], pos)
            for p, t in fh:
                if pos <= p < end:
                    func_pos.setdefault(p, t)
            for p, t in th:
                if pos <= p < end:
                    taint_pos.setdefault(p, t)
            pos = end

        func_matches = [func_pos[p] for p in sorted(func_pos)]
        taint_matches = [taint_pos[p] for p in sorted(taint_pos)]
        return func_matches, taint_matches, backend, limit, complete

    def filter(self, payload: str, content_type: str = "") -> FilterResult:  # 快速过滤，决定要不要跑AST
        profile = _sensitivity_profile
        hub = _hub()
        timer = hub.timer("fast_filter") if hub else None
        if timer:
            timer.__enter__()
        try:
            return self._filter_impl(payload, content_type, profile, hub)
        finally:
            if timer:
                timer.__exit__(None, None, None)

    def _filter_impl(self, payload: str, content_type: str,
                     profile: "SensitivityProfile", hub) -> FilterResult:
        payload_len = len(payload)
        _coverage_audit.seen()

        # 太短 —— 装不下任何 sink+taint 组合，这个跳过是可证明安全的
        if payload_len < self.MIN_PAYLOAD_LEN:
            return FilterResult(
                decision=FilterDecision.SKIP,
                reason="payload_too_short",
                payload_len=payload_len,
                scanned_len=payload_len
            )

        # 这里原来有一次 `_payload_cache.get(payload)`。它是**只读不写**的死查询：
        # 全库没有任何地方调用过 `_payload_cache.set()`，命中率恒为 0，却要为
        # 每一个载荷算一次全量 sha256（`_make_key` 对整段 payload 做哈希）。
        # AST 结果的缓存另有其人 —— attack_detector 用的是 `get_ast_cache()`，
        # 那个是真读真写的。所以这里直接去掉查询，纯赚。
        #
        # 对应地，FilterDecision.CACHED 现在不会再由本函数产出；
        # attack_detector 里那个分支保留着，属于防御性代码。

        # ---- 全量关键字扫描。这里绝不按窗口截断，否则头部填充就能绕过 ----
        (func_matches, taint_matches, backend,
         scanned_len, complete) = self._scan_keywords_full(
            payload, profile.hard_scan_ceiling)

        if hub:
            hub.incr(f"fast_filter.scan_backend.{backend}")

        notes: List[str] = []
        if not complete:
            notes.append(f"scan_ceiling_reached:{scanned_len}/{payload_len}")
            _coverage_audit.record("scan_ceiling", payload_len, scanned_len)
            if hub:
                hub.incr("fast_filter.scan_truncated")

        matched_keywords: List[str] = []
        risk_score = 0

        # 检查危险函数
        if func_matches:
            matched_keywords.extend(func_matches)
            for kw in func_matches:
                kw_lower = kw.lower()
                if kw_lower in DangerKeywords.CRITICAL_SINKS:
                    risk_score += 40
                elif kw_lower in DangerKeywords.OBFUSCATION_FUNCS:
                    risk_score += 25
                elif kw_lower in DangerKeywords.FILE_FUNCS:
                    risk_score += 15

        # 检查污点源
        if taint_matches:
            matched_keywords.extend(taint_matches)
            risk_score += len(taint_matches) * 20

        # 检查动态特征（保留正则：$$ / ${ 存在重叠，AC 会多算）
        dynamic_matches = self._DYNAMIC_PATTERN.findall(payload[:scanned_len])
        if dynamic_matches:
            matched_keywords.extend(dynamic_matches)
            risk_score += len(dynamic_matches) * 15

        # 没有任何危险关键字。只有在**全量扫完**的前提下这个结论才成立
        if not matched_keywords:
            if complete:
                if hub:
                    hub.incr("fast_filter.skipped")
                return FilterResult(
                    decision=FilterDecision.SKIP,
                    reason="no_dangerous_keywords",
                    payload_len=payload_len,
                    scanned_len=scanned_len
                )
            # 没扫全却没命中 -> 不能下"安全"的结论，降级继续查
            return FilterResult(
                decision=FilterDecision.FAST_DETECT,
                reason="incomplete_scan_no_keywords",
                payload_len=payload_len,
                scanned_len=scanned_len,
                fully_scanned=False,
                notes=notes
            )

        # 熵是统计量，采样即可（关键字覆盖已经是全量的了）
        entropy = EntropyCalculator.calculate_str(
            payload[:profile.entropy_sample_limit])

        # Content-Type 是攻击者可控的请求头，只降权，绝不作为跳过依据
        if (profile.deprioritize_content_type
                and self._is_low_priority_content_type(content_type)):
            risk_score = max(0, risk_score - 10)
            notes.append(f"deprioritized_content_type:{content_type}")
            if hub:
                hub.incr("fast_filter.deprioritized.content_type")

        # 低熵只说明"看着像普通文本"，同样只降权不跳过
        if (profile.deprioritize_low_entropy
                and entropy < EntropyCalculator.ENTROPY_LOW
                and risk_score < 30):
            risk_score = max(0, risk_score - 5)
            notes.append("deprioritized_low_entropy")

        # 高熵值加分
        if entropy > EntropyCalculator.ENTROPY_SUSPICIOUS:
            risk_score += 20

        risk_score = min(risk_score, 100)
        unique_keywords = list(set(matched_keywords))

        def _result(decision: FilterDecision, reason: str) -> FilterResult:
            return FilterResult(
                decision=decision,
                reason=reason,
                entropy=entropy,
                matched_keywords=unique_keywords,
                risk_score=risk_score,
                payload_len=payload_len,
                scanned_len=scanned_len,
                fully_scanned=complete,
                notes=notes
            )

        if risk_score >= profile.full_ast_threshold:
            if hub:
                hub.incr("fast_filter.full_ast")
            return _result(FilterDecision.FULL_AST, "high_risk")
        elif risk_score >= profile.fast_detect_threshold:
            if hub:
                hub.incr("fast_filter.fast_detect")
            return _result(FilterDecision.FAST_DETECT, "medium_risk")
        else:
            # 有关键字但分数低。这是"全量看过后判弱"，不是"没看"。
            # 高灵敏度下连这个也不跳 —— 命中即必查。
            if profile.never_skip_on_score:
                if hub:
                    hub.incr("fast_filter.fast_detect")
                return _result(FilterDecision.FAST_DETECT,
                               "low_risk_forced_by_sensitivity")
            # 仍然记进审计，便于事后复核阈值是否设得太高
            if hub:
                hub.incr("fast_filter.skipped")
            _coverage_audit.record(
                "low_risk_with_keywords", payload_len, scanned_len,
                unique_keywords)
            return _result(FilterDecision.SKIP, "low_risk")

    def _is_low_priority_content_type(self, content_type: str) -> bool:
        """这些 Content-Type 通常是静态资源

        只用来**降权**。请求头由攻击者控制，把它当跳过依据等于开后门：
        POST 一个 `Content-Type: image/jpeg` 就能让整段流量消失。
        """
        if not content_type:
            return False

        ct_lower = content_type.lower()

        safe_types = (
            'image/', 'video/', 'audio/',
            'font/', 'application/pdf',
            'application/zip', 'application/gzip',
            'text/css', 'text/plain',
        )

        for safe in safe_types:
            if safe in ct_lower:
                return True

        return False

    def should_use_ast(self, payload: str, content_type: str = "") -> Tuple[bool, str]:  # 简化接口，返回(要不要AST, 原因)
        result = self.filter(payload, content_type)

        if result.decision == FilterDecision.FULL_AST:
            return True, result.reason
        elif result.decision == FilterDecision.FAST_DETECT:
            return True, result.reason  # 中等风险也进行 AST
        else:
            return False, result.reason


class SelectiveAnalyzer:  # 按需污点追踪：先找sink再决定要不要回溯source

    # Sink 点正则 (函数调用)
    SINK_PATTERN = re.compile(
        r'\b(eval|assert|system|exec|shell_exec|passthru|'
        r'call_user_func|call_user_func_array|'
        r'create_function|preg_replace|'
        r'include|include_once|require|require_once|'
        r'file_put_contents|unserialize)\s*\(',
        re.IGNORECASE
    )

    # 硬编码字符串参数模式
    HARDCODED_ARG_PATTERN = re.compile(
        r'\(\s*["\'][^"\']*["\']\s*\)',  # func("string") 或 func('string')
        re.IGNORECASE
    )

    @classmethod
    def needs_taint_analysis(cls, code: str) -> Tuple[bool, List[str]]:  # 返回(需不需要污点追踪, 找到的sink列表)
        sinks = cls.SINK_PATTERN.findall(code)

        if not sinks:
            return False, []

        # 看参数是不是变量，是的话才需要污点追踪
        unique_sinks = list(set(s.lower() for s in sinks))

        # 检查是否有动态参数
        has_dynamic_arg = False

        for sink in unique_sinks:
            # 查找这个函数的调用
            pattern = re.compile(
                rf'\b{re.escape(sink)}\s*\(([^)]*)\)',
                re.IGNORECASE
            )

            for match in pattern.finditer(code):
                args = match.group(1).strip()

                # 如果参数包含变量 ($)，需要污点追踪
                if '$' in args:
                    has_dynamic_arg = True
                    break

                # 如果不是纯字符串参数
                if not cls.HARDCODED_ARG_PATTERN.match(f'({args})'):
                    has_dynamic_arg = True
                    break

            if has_dynamic_arg:
                break

        return has_dynamic_arg, unique_sinks

    @classmethod
    def find_sources_for_sinks(cls, code: str, sinks: List[str]) -> Dict[str, List[str]]:  # 找每个sink对应的source变量
        result = {}

        source_pattern = re.compile(
            r'(\$_(?:GET|POST|REQUEST|COOKIE|FILES|SERVER|ENV)\s*\[[^\]]+\]|\$GLOBALS\s*\[[^\]]+\])',
            re.IGNORECASE
        )

        sources = source_pattern.findall(code)

        if not sources:
            return result

        for sink in sinks:
            sink_pattern = re.compile(
                rf'\b{re.escape(sink)}\s*\(([^)]*)\)',
                re.IGNORECASE
            )

            for match in sink_pattern.finditer(code):
                args = match.group(1)

                for source in sources:
                    if source in args:
                        if sink not in result:
                            result[sink] = []
                        result[sink].append(source)

        return result


_fast_filter = FastFilter()

# 分析器单例，避免每次点击都重建实例
_ast_engine_singleton = None
_entropy_analyzer_singleton = None
_encoding_detector_singleton = None
_statistical_analyzer_singleton = None
_auto_decoder_singleton = None


def get_fast_filter() -> FastFilter:
    return _fast_filter


def get_filter_stats() -> Dict[str, object]:
    """过滤层自身的运行状态：匹配后端、灵敏度、两级缓存命中率"""
    matcher = FastFilter._KEYWORD_MATCHER
    return {
        'matcher_backend': matcher.backend if matcher else 'regex',
        'has_ahocorasick': HAS_AHOCORASICK,
        'keyword_patterns': matcher.pattern_count if matcher else 0,
        'taint_patterns': (
            FastFilter._TAINT_MATCHER.pattern_count
            if FastFilter._TAINT_MATCHER else 0
        ),
        'sensitivity': _sensitivity_profile.to_dict(),
        'payload_cache': _payload_cache.get_stats(),
        'ast_cache': _ast_result_cache.get_stats(),
        # 覆盖率审计：有多少载荷没被完整分析、因为什么
        'coverage': _coverage_audit.get_stats(),
    }



def quick_check(payload: str, content_type: str = "") -> FilterResult:
    return _fast_filter.filter(payload, content_type)


def should_analyze(payload: str, content_type: str = "") -> bool:
    need_ast, _ = _fast_filter.should_use_ast(payload, content_type)
    return need_ast


def _decode_for_breakdown(payload_data: bytes) -> str:
    """把原始报文过一遍**检测器同款**解码链。

    检测器跑的是 AutoDecoder 解码后的文本(attack_detector.py:1940 那段)，
    面板原来直接拿 raw_request_body 就扫 —— 两边压根不是同一个字符串。
    实测 `${@print(md5(acunetix_wvs_security_test))}` 在原始报文里长成
    `%24{%40print(md5(...))}`，`$` 被编码成 %24，关键字一个都命中不了，
    于是面板会给一条已经确认的 RCE 打 0 分。

    AutoDecoder 拿不到结果时退回一次 URL 解码 —— 退化路径也必须解 URL，
    那正是原来漏掉的那一层。
    """
    if not payload_data:
        return ""

    try:
        from core.auto_decoder import AutoDecoder
        global _auto_decoder_singleton
        if _auto_decoder_singleton is None:
            _auto_decoder_singleton = AutoDecoder()
        decoded = _auto_decoder_singleton.decode(payload_data, max_depth=6).final_text
        if decoded:
            return decoded
    except Exception as e:
        logger.debug(f"得分拆解解码失败，退回 URL 解码: {e}")

    raw = payload_data.decode('utf-8', errors='ignore')
    try:
        from urllib.parse import unquote_plus
        return unquote_plus(raw)
    except Exception:
        return raw


def get_score_breakdown(payload_data: bytes, content_type: str = "",
                        http_method: str = "", uri: str = "") -> Optional[dict]:
    """PayloadViewer用的得分拆解，整合AST/熵值/统计学/快速过滤几个模块的结果

    `payload_data` 是**原始**请求体，还带着 URL 编码，不能直接拿去扫 ——
    详见 `_decode_for_breakdown`。`uri` 也要一起看：POST 的攻击可能整个落在
    查询串里(`?rec=password_reset_post`)，那部分不在 body 里。

    两类维度喂的东西不一样，是故意的：
      - 语义类(格式/字符频率/AST/快速过滤)看**解码后**的文本，必须和检测器对齐；
      - 熵值和长度看**原始字节** —— 它们描述的是线上真实载荷，解码会改掉含义
        (熵值那行的 `[url]` 编码标记也正是从原文里看出来的)。
    """
    payload_str = payload_data.decode('utf-8', errors='ignore') if payload_data else ""

    scan_text = _decode_for_breakdown(payload_data)
    if uri:
        scan_text = f"{uri}\n{scan_text}" if scan_text else uri

    if len(scan_text) < 10:
        return None

    try:
        entropy_result = _analyze_entropy(payload_data, payload_str)
        structure_result = _analyze_structure(scan_text)
        char_freq_result = _analyze_char_frequency(scan_text)
        length_result = _analyze_payload_length(payload_data)
        ast_result = _analyze_ast(scan_text)
        filter_result = _fast_filter.filter(scan_text, content_type)

        combined_result = _calculate_combined_verdict(
            entropy_result, structure_result, char_freq_result,
            length_result, ast_result, filter_result, http_method
        )

        return {
            'sensitivity': combined_result['risk_score'],
            'entropy': entropy_result,
            'structure': structure_result,
            'char_frequency': char_freq_result,
            'payload_length': length_result,
            'ast_analysis': ast_result,
            'combined': combined_result
        }

    except Exception as e:
        logger.debug(f"get_score_breakdown 异常: {e}")
        import traceback
        traceback.print_exc()
        return None


def _analyze_entropy(payload_data: bytes, payload_str: str) -> dict:  # 熵值分析
    result = {
        'display': '熵值: --',
        'hit': False,
        'value': 0.0,
        'classification': 'unknown'
    }

    try:
        # 用单例，避免每次点击都重建实例
        try:
            from core.entropy_analyzer import EntropyAnalyzer, EncodingDetector
            global _entropy_analyzer_singleton, _encoding_detector_singleton
            if _entropy_analyzer_singleton is None:
                _entropy_analyzer_singleton = EntropyAnalyzer()
            if _encoding_detector_singleton is None:
                _encoding_detector_singleton = EncodingDetector()
            entropy_value = _entropy_analyzer_singleton.calculate_entropy(payload_data)
            classification = _entropy_analyzer_singleton.classify_entropy(entropy_value)

            # 编码检测
            encoding_type, encoding_conf = _encoding_detector_singleton.detect_encoding_type(payload_str)

            result['value'] = entropy_value
            result['classification'] = classification

            if entropy_value > 6.5:
                result['hit'] = True
                result['display'] = f"熵值: {entropy_value:.2f} (极高-加密/随机)"
            elif entropy_value > 5.5:
                result['hit'] = True
                result['display'] = f"熵值: {entropy_value:.2f} (高-可能混淆)"
            elif entropy_value > 4.5:
                result['display'] = f"熵值: {entropy_value:.2f} (中等)"
            else:
                result['display'] = f"熵值: {entropy_value:.2f} (正常)"

            if encoding_type and encoding_conf > 0.7:
                result['display'] += f" [{encoding_type}]"
                result['detected_encoding'] = encoding_type

        except ImportError:
            # 回退到基础计算
            entropy_value = EntropyCalculator.calculate(payload_data)
            result['value'] = entropy_value
            result['hit'] = entropy_value > EntropyCalculator.ENTROPY_SUSPICIOUS
            result['display'] = f"熵值: {entropy_value:.2f}"

    except Exception as e:
        logger.debug(f"熵值分析异常: {e}")

    return result


def _analyze_structure(payload_str: str) -> dict:  # 结构/格式分析
    result = {
        'display': '格式: 未知',
        'hit': False,
        'type': 'unknown',
        'details': []
    }

    try:
        structure_type = "未知"
        details = []

        # 检测 PHP 代码
        if '<?php' in payload_str.lower() or ('<?' in payload_str and '?>' in payload_str):
            structure_type = "PHP代码"
            result['hit'] = True
            details.append("PHP标签")

        # 检测危险函数调用
        dangerous_funcs = ['eval', 'assert', 'system', 'exec', 'shell_exec', 'passthru']
        for func in dangerous_funcs:
            if re.search(rf'\b{func}\s*\(', payload_str, re.IGNORECASE):
                details.append(f"{func}()")
                result['hit'] = True

        # 检测 JSON
        if payload_str.strip().startswith('{') and payload_str.strip().endswith('}'):
            try:
                import json
                json.loads(payload_str)
                structure_type = "JSON"
            except:
                structure_type = "类JSON"

        # 检测 XML/HTML
        elif payload_str.strip().startswith('<') and '>' in payload_str:
            if '<?xml' in payload_str.lower():
                structure_type = "XML"
            elif '<html' in payload_str.lower() or '<body' in payload_str.lower():
                structure_type = "HTML"
            else:
                structure_type = "XML/HTML"

        # 检测表单数据
        elif '=' in payload_str and '&' in payload_str:
            structure_type = "表单数据"
            # 检查是否有可疑参数
            if re.search(r'(cmd|shell|exec|eval|code|pass)\s*=', payload_str, re.IGNORECASE):
                details.append("可疑参数名")
                result['hit'] = True

        # 检测 Base64
        elif len(payload_str) > 50:
            clean = re.sub(r'\s', '', payload_str)
            if re.match(r'^[A-Za-z0-9+/=]+$', clean) and len(clean) % 4 == 0:
                structure_type = "Base64"
                result['hit'] = True
                details.append("疑似编码数据")

        result['type'] = structure_type
        result['details'] = details
        result['display'] = f"格式: {structure_type}"
        if details:
            result['display'] += f" ({', '.join(details[:3])})"

    except Exception as e:
        logger.debug(f"结构分析异常: {e}")

    return result


def _analyze_char_frequency(payload_str: str) -> dict:  # 字符频率统计
    result = {
        'display': '字符: 正常',
        'hit': False,
        'special_ratio': 0.0,
        'non_printable_ratio': 0.0,
        'alphanumeric_ratio': 0.0
    }

    try:
        # 用单例
        try:
            from core.statistical_analyzer import StatisticalAnalyzer
            global _statistical_analyzer_singleton
            if _statistical_analyzer_singleton is None:
                _statistical_analyzer_singleton = StatisticalAnalyzer()
            analyzer = _statistical_analyzer_singleton
            stats = analyzer.analyze(payload_str, include_details=False)

            result['special_ratio'] = stats.get('special_char_ratio', 0.0)
            result['non_printable_ratio'] = stats.get('non_printable_ratio', 0.0)
            result['alphanumeric_ratio'] = stats.get('alphanumeric_ratio', 0.0)

            if stats.get('special_char_level') in ['critical', 'high']:
                result['hit'] = True
                result['display'] = f"字符: 异常 (特殊:{result['special_ratio']:.0%})"
            elif stats.get('special_char_level') == 'medium':
                result['display'] = f"字符: 偏高 (特殊:{result['special_ratio']:.0%})"
            elif result['non_printable_ratio'] > 0.1:
                result['hit'] = True
                result['display'] = f"字符: 二进制 (不可打印:{result['non_printable_ratio']:.0%})"
            else:
                result['display'] = f"字符: 正常 (字母数字:{result['alphanumeric_ratio']:.0%})"

        except ImportError:
            # 回退到基础计算
            total_chars = len(payload_str)
            if total_chars > 0:
                special_chars = sum(1 for c in payload_str if not c.isalnum() and c not in ' \n\r\t')
                special_ratio = special_chars / total_chars
                result['special_ratio'] = special_ratio
                result['hit'] = special_ratio > 0.3

                if special_ratio < 0.1:
                    result['display'] = "字符: 正常"
                elif special_ratio < 0.3:
                    result['display'] = f"字符: 偏高 ({special_ratio:.0%})"
                else:
                    result['display'] = f"字符: 异常 ({special_ratio:.0%})"

    except Exception as e:
        logger.debug(f"字符频率分析异常: {e}")

    return result


def _analyze_payload_length(payload_data: bytes) -> dict:  # 载荷长度分析
    payload_len = len(payload_data)
    result = {
        'display': f"长度: {payload_len}B",
        'hit': False,
        'value': payload_len
    }

    if payload_len > 50000:
        result['hit'] = True
        result['display'] = f"长度: 超大 ({payload_len // 1024}KB)"
    elif payload_len > 10000:
        result['display'] = f"长度: 大 ({payload_len // 1024}KB)"
    elif payload_len > 1000:
        result['display'] = f"长度: 中等 ({payload_len}B)"
    elif payload_len < 50:
        result['display'] = f"长度: 短 ({payload_len}B)"

    return result


def _analyze_ast(payload_str: str) -> dict:  # AST语法树分析
    result = {
        'display': 'AST: 未分析',
        'hit': False,
        'dangerous_calls': [],
        'taint_sources': [],
        'obfuscation_score': 0.0,
        'findings': [],
        'is_likely_webshell': False,
        'confidence_adjustment': 0
    }

    try:
        # 检查是否像 PHP 代码
        if not ('<?' in payload_str or 'php' in payload_str.lower() or
                any(func in payload_str.lower() for func in ['eval', 'assert', 'system', 'exec'])):
            result['display'] = 'AST: 非PHP代码'
            return result

        # 用单例 PHPASTEngine
        try:
            from core.ast_engine import PHPASTEngine
            global _ast_engine_singleton
            if _ast_engine_singleton is None:
                _ast_engine_singleton = PHPASTEngine()
            ast_result = _ast_engine_singleton.analyze(payload_str)

            result['dangerous_calls'] = [
                {
                    'function': c.function_name,
                    'is_tainted': c.is_tainted,
                    'severity': c.severity,
                    'obfuscation': c.obfuscation_method
                }
                for c in ast_result.dangerous_calls
            ]
            result['taint_sources'] = list(ast_result.taint_sources)
            result['obfuscation_score'] = ast_result.obfuscation_score
            result['is_likely_webshell'] = ast_result.is_likely_webshell
            result['confidence_adjustment'] = ast_result.confidence_adjustment
            result['findings'] = [f.to_dict() for f in ast_result.findings[:5]]

            if ast_result.is_likely_webshell:
                result['hit'] = True
                result['display'] = f"AST: Webshell特征"
            elif ast_result.dangerous_calls:
                tainted_count = sum(1 for c in ast_result.dangerous_calls if c.is_tainted)
                if tainted_count > 0:
                    result['hit'] = True
                    result['display'] = f"AST: {tainted_count}个污染的危险调用"
                else:
                    result['display'] = f"AST: {len(ast_result.dangerous_calls)}个危险调用(未污染)"
            elif ast_result.obfuscation_score > 0.3:
                result['hit'] = True
                result['display'] = f"AST: 混淆代码 ({ast_result.obfuscation_score:.0%})"
            else:
                result['display'] = 'AST: 正常'

        except ImportError:
            result['display'] = 'AST: 模块不可用'

    except Exception as e:
        logger.debug(f"AST分析异常: {e}")
        result['display'] = f'AST: 分析失败'

    return result


def _calculate_combined_verdict(
    entropy_result: dict,
    structure_result: dict,
    char_freq_result: dict,
    length_result: dict,
    ast_result: dict,
    filter_result: FilterResult,
    http_method: str
) -> dict:  # 综合判定
    result = {
        'verdict': 'unknown',
        'reason': '',
        'force_audit': False,
        'risk_score': 0,
        'indicators': []
    }

    risk_score = filter_result.risk_score if filter_result else 0

    # AST 调整
    if ast_result.get('is_likely_webshell'):
        risk_score += 50
        result['indicators'].append('AST确认Webshell')
        result['force_audit'] = True

    if ast_result.get('confidence_adjustment', 0) > 0:
        risk_score += min(ast_result['confidence_adjustment'], 30)

    # 熵值调整
    if entropy_result.get('hit'):
        risk_score += 15
        result['indicators'].append(f"高熵值({entropy_result.get('value', 0):.1f})")

    # 结构调整
    if structure_result.get('hit'):
        risk_score += 10
        if structure_result.get('details'):
            result['indicators'].extend(structure_result['details'][:2])

    # 字符频率调整
    if char_freq_result.get('hit'):
        risk_score += 10
        result['indicators'].append('异常字符分布')

    # 危险函数加权
    if filter_result and filter_result.matched_keywords:
        critical_matches = [kw for kw in filter_result.matched_keywords
                          if kw.lower() in DangerKeywords.CRITICAL_SINKS]
        if critical_matches:
            result['force_audit'] = True
            result['indicators'].append(f"危险函数: {', '.join(critical_matches[:2])}")

    # POST 方法加权
    if http_method and http_method.upper() == 'POST':
        risk_score += 5

    risk_score = min(max(risk_score, 0), 100)
    result['risk_score'] = risk_score

    if risk_score >= 80 or result['force_audit']:
        result['verdict'] = 'audit'
        result['reason'] = '高风险，需要审计'
    elif risk_score >= 50:
        result['verdict'] = 'review'
        result['reason'] = '中等风险，建议检查'
    elif risk_score >= 30:
        result['verdict'] = 'notice'
        result['reason'] = '轻微可疑'
    else:
        result['verdict'] = 'skip'
        result['reason'] = '正常流量'

    if result['indicators']:
        result['reason'] = ', '.join(result['indicators'][:3])

    return result
