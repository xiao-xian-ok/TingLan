# attack_detector.py - OWASP攻击检测
# sqli/xss/rce/xxe/ssrf/upload 插件式检测

import re
import time
import hashlib
import threading
import json
import math
import concurrent.futures
from abc import ABC, abstractmethod
from enum import Enum, auto
from dataclasses import dataclass, field
from typing import (
    List, Dict, Optional, Any, Tuple, Set,
    Type, Callable, Union, Pattern
)
from functools import wraps
from urllib.parse import parse_qsl, unquote, urlparse
import logging

try:
    from core.auto_decoder import AutoDecoder, DecodingResult
except ImportError:
    from auto_decoder import AutoDecoder, DecodingResult

try:
    from core.entropy_analyzer import EntropyAnalyzer, MeaningfulnessAnalyzer
except ImportError:
    from entropy_analyzer import EntropyAnalyzer, MeaningfulnessAnalyzer

try:
    from core.ast_engine import PHPASTEngine, ASTAnalysisResult
except ImportError:
    from ast_engine import PHPASTEngine, ASTAnalysisResult

try:
    from core.fast_filter import (
        FastFilter, FilterDecision, FilterResult,
        get_fast_filter, get_ast_cache, get_payload_cache,
        SelectiveAnalyzer
    )
except ImportError:
    from fast_filter import (
        FastFilter, FilterDecision, FilterResult,
        get_fast_filter, get_ast_cache, get_payload_cache,
        SelectiveAnalyzer
    )

# ML 研判是可选的：拿不到就纯规则判定，不影响主流程
try:
    from core.ml_scorer import get_ml_scorer
except ImportError:
    try:
        from ml_scorer import get_ml_scorer
    except ImportError:
        get_ml_scorer = None

try:
    from core.pattern_prefilter import global_plan, register_patterns
except ImportError:
    try:
        from pattern_prefilter import global_plan, register_patterns
    except ImportError:  # pragma: no cover - 拿不到就退化成全量执行
        _PREFILTER_NAMES = set()

        def register_patterns(qualified):
            _PREFILTER_NAMES.update(qualified)

        def global_plan(_text):
            return {name: None for name in _PREFILTER_NAMES}

# 观测中心可选。热路径上调用，所以包一层不抛异常的薄封装。
try:
    from core.observability import get_observability_hub
except ImportError:
    get_observability_hub = None


def _obs_incr(name: str, n: int = 1) -> None:
    if get_observability_hub is None:
        return
    try:
        get_observability_hub().incr(name, n)
    except Exception:
        pass


logger = logging.getLogger(__name__)

_shared_executor: Optional[concurrent.futures.ThreadPoolExecutor] = None
_executor_lock = threading.Lock()
_ast_semaphore: Optional[threading.Semaphore] = None


def _get_shared_executor() -> concurrent.futures.ThreadPoolExecutor:
    global _shared_executor
    if _shared_executor is None:
        with _executor_lock:
            if _shared_executor is None:
                _shared_executor = concurrent.futures.ThreadPoolExecutor(
                    max_workers=4,
                    thread_name_prefix="detector_timeout"
                )
    return _shared_executor


def _get_ast_semaphore() -> threading.Semaphore:
    global _ast_semaphore
    if _ast_semaphore is None:
        _ast_semaphore = threading.Semaphore(2)
    return _ast_semaphore


def cleanup_shared_resources():
    global _shared_executor, _ast_semaphore
    if _shared_executor:
        _shared_executor.shutdown(wait=False)
        _shared_executor = None
    _ast_semaphore = None

    if get_payload_cache:
        get_payload_cache().clear()
    if get_ast_cache:
        get_ast_cache().clear()


def get_optimization_stats() -> Dict[str, any]:
    """获取缓存命中率、过滤统计等优化信息"""
    stats = {
        'fast_filter_enabled': FastFilter is not None,
        'ast_cache': {},
        'payload_cache': {},
    }

    if get_ast_cache:
        stats['ast_cache'] = get_ast_cache().get_stats()

    if get_payload_cache:
        stats['payload_cache'] = get_payload_cache().get_stats()

    return stats


def safe_decode(data: bytes, encoding: str = 'utf-8') -> str:
    """安全解码，utf-8失败就用replace降级"""
    if not data:
        return ""

    try:
        return data.decode(encoding, errors='strict')
    except UnicodeDecodeError:
        try:
            return data.decode(encoding, errors='replace')
        except Exception:
            # latin-1 不会失败
            return data.decode('latin-1', errors='replace')


def search_full(pattern: Pattern, text: str) -> Optional[re.Match]:
    """全量搜索：直接在整段文本上跑，语义等价于 `pattern.search(text)`。

    ── 为什么这里没有分块 ──

    这个函数的前身做过两件事，先后都被证明是错的：

    1. 最早是 `text[:50KB] + text[-50KB:]`，中段永远不过正则 —— 把 payload
       放在 50KB 之后即可绕过，长度完全由攻击者决定。

    2. 改成"分块 + 8KB 重叠扫，丢弃贴着块边界的命中"。丢弃规则的理由是
       "这类命中必然完整落在相邻块的重叠区里"，但那只在**命中长度 ≤ 重叠宽度**
       时成立。实测两条真实规则（file_upload 的 `boundary=[-\\w]+` 和
       `Content-Disposition...filename=...`）带无界量词、且匹配的是攻击者
       完全可控的内容：命中长度超过重叠宽度就在两边都被丢，命中长度超过
       块长时更是任何块都装不下 —— 一条 Evidence 凭空消失，合并权重掉到
       40 以下就是**整条检测消失**。

    根子在于"分块"给正确性引入了一个隐含不变量：**重叠宽度必须大于任何规则
    可能的最长命中**。这个不变量没人守得住（任何人加一条带 `.*` 的规则就破
    了），而且它换来的收益是负的 —— 分块要把文本复制成几百个块、重叠区被
    反复扫描，比让 re 自己线性扫一遍还慢。

    所以正确的做法是把这个不变量整个消掉：re 的 `search` 本身就没有长度上限，
    直接用它。这样"覆盖面"不再依赖任何常量，也不会因为规则库变化而变化。

    ── 仍然存在的取舍 ──

    输入很大时（`_extend_with_full_text` 最多接 64MB 原文）这一趟会很慢，
    但那是**时间**问题不是**覆盖**问题，且分块并不能减少总工作量。全局的
    wall-clock 兜底口径见 `AttackDetector.detect` 里的 TOTAL_TIMEOUT_S。
    """
    try:
        return pattern.search(text)
    except Exception:
        return None


def safe_regex_match(pattern: Pattern, text: str, max_len: int = 100000) -> Optional[re.Match]:
    """兼容入口。max_len 参数保留但不再用来截断输入 —— 截断即绕过。"""
    return search_full(pattern, text)


class AttackType(Enum):
    ANTSWORD = "antsword"
    CAIDAO = "caidao"
    BEHINDER = "behinder"
    GODZILLA = "godzilla"

    SQLI = "sqli"
    XSS = "xss"
    RCE = "rce"
    XXE = "xxe"
    SSRF = "ssrf"
    PATH_TRAVERSAL = "path_traversal"
    LFI = "lfi"
    DESERIALIZATION = "deserialization"
    COMMAND_INJECTION = "command_injection"
    FILE_UPLOAD = "file_upload"
    ENCRYPTED_HTTP = "encrypted_http"

    UNKNOWN = "unknown"

    @property
    def display_name(self) -> str:
        names = {
            "antsword": "蚁剑 (AntSword)",
            "caidao": "菜刀 (Caidao)",
            "behinder": "冰蝎 (Behinder)",
            "godzilla": "哥斯拉 (Godzilla)",
            "sqli": "SQL 注入",
            "xss": "跨站脚本 (XSS)",
            "rce": "远程代码执行 (RCE)",
            "xxe": "XML 外部实体 (XXE)",
            "ssrf": "服务端请求伪造 (SSRF)",
            "path_traversal": "目录穿越",
            "lfi": "本地文件包含 (LFI)",
            "deserialization": "不安全反序列化",
            "command_injection": "命令注入",
            "file_upload": "文件上传漏洞",
            "encrypted_http": "可疑加密 HTTP Payload",
            "unknown": "未知攻击",
        }
        return names.get(self.value, self.value)


class ThreatLevel(Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def severity_score(self) -> int:
        scores = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        return scores.get(self.value, 0)

    @classmethod
    def from_weight(cls, weight: int) -> "ThreatLevel":
        if weight >= 200:
            return cls.CRITICAL
        elif weight >= 150:
            return cls.HIGH
        elif weight >= 80:
            return cls.MEDIUM
        elif weight >= 40:
            return cls.LOW
        return cls.INFO


class ResourceLimits:
    MAX_BODY_SIZE = 1 * 1024 * 1024       # 超过1MB，递归解码改走抽样
    # 全量字面量匹配的绝对上限，纯粹防 OOM。触顶会计入覆盖率审计并打 warning，
    # 不会静默 —— 和 fast_filter.hard_scan_ceiling 是同一个性质的兜底。
    FULL_TEXT_CEILING = 64 * 1024 * 1024
    MAX_DECODE_DEPTH = 15
    MAX_DECODE_SIZE = 10 * 1024 * 1024
    REGEX_TIMEOUT_MS = 100
    AST_TIMEOUT_MS = 500
    TOTAL_TIMEOUT_S = 5.0

    SAMPLE_HEAD_SIZE = 64 * 1024
    SAMPLE_TAIL_SIZE = 64 * 1024
    SAMPLE_OFFSETS = [0.25, 0.5, 0.75]

    # 保留给外部调用方读取；search_full 不再用它做截断。
    # 历史上它是"正则只看前 100KB"的开关，那是可绕过的静默漏检。
    MAX_REGEX_INPUT_LEN = 100000
    MAX_PATTERN_MATCH_LEN = 500

    MAX_AST_CODE_LEN = 50000
    AST_CONCURRENT_LIMIT = 2


class DetectorTimeoutError(Exception):
    pass


def timeout_guard(timeout_ms: int):
    """超时装饰器，Windows不支持signal.alarm所以用线程池"""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            timeout_s = timeout_ms / 1000.0
            executor = _get_shared_executor()

            future = executor.submit(func, *args, **kwargs)
            try:
                return future.result(timeout=timeout_s)
            except concurrent.futures.TimeoutError:
                logger.debug(f"Function {func.__name__} timed out after {timeout_ms}ms")
                raise DetectorTimeoutError(f"Operation timed out after {timeout_ms}ms")

        return wrapper
    return decorator


def ast_timeout_guard(timeout_ms: int):
    """AST专用超时，用信号量限制并发，超时返回None不抛异常"""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            semaphore = _get_ast_semaphore()

            if not semaphore.acquire(blocking=False):
                logger.debug(f"AST analysis skipped: concurrent limit reached")
                return None

            try:
                timeout_s = timeout_ms / 1000.0
                executor = _get_shared_executor()

                future = executor.submit(func, *args, **kwargs)
                try:
                    return future.result(timeout=timeout_s)
                except concurrent.futures.TimeoutError:
                    logger.debug(f"AST analysis timed out after {timeout_ms}ms")
                    return None
            finally:
                semaphore.release()

        return wrapper
    return decorator


class SampledData:
    """大数据量的话只取头尾64KB + 中间几个采样点

    注意采样的用途已经收窄：它只决定**递归解码**看哪几段（解码很贵，且编码
    载荷基本都从 body 开头起），不再决定**字面量匹配**看哪几段。后者由
    AttackDetector.detect() 用 full_text 做全量覆盖 —— 否则"把 payload 放在
    2MB 偏移处"就是一键绕过，采样点只有 25%/50%/75% 三个 4KB 窗口。
    """

    def __init__(self, data: bytes):
        self.original_size = len(data)
        self.is_sampled = self.original_size > ResourceLimits.MAX_BODY_SIZE
        self.samples = []  # (offset, bytes) pairs

        if self.is_sampled:
            self._extract_samples(data)
        else:
            self.samples = [(0, data)]

    def _extract_samples(self, data: bytes) -> None:
        self.samples.append((0, data[:ResourceLimits.SAMPLE_HEAD_SIZE]))

        # 中间几个采样点
        for ratio in ResourceLimits.SAMPLE_OFFSETS:
            offset = int(self.original_size * ratio)
            sample = data[offset:offset + 4096]
            self.samples.append((offset, sample))

        tail_start = self.original_size - ResourceLimits.SAMPLE_TAIL_SIZE
        self.samples.append((tail_start, data[tail_start:]))

    def iter_samples(self):
        for offset, sample in self.samples:
            yield offset, sample

    @property
    def combined_bytes(self) -> bytes:
        """所有采样段拼起来。未采样时就是原始数据本身。"""
        if len(self.samples) == 1:
            return self.samples[0][1]
        return b''.join(s for _, s in self.samples)

    @property
    def combined_text(self) -> str:
        """合并样本为文本供正则用"""
        return safe_decode(self.combined_bytes)


@dataclass
class Evidence:
    pattern_name: str
    pattern: str = ""
    matched_text: str = ""
    weight: int = 0
    offset: int = 0
    description: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_indicator_dict(self) -> Dict:
        """转成 IndicatorMatch 兼容格式"""
        return {
            'name': self.pattern_name,
            'pattern': self.pattern,
            'matched_text': self.matched_text[:200],
            'weight': self.weight,
            'description': self.description
        }


@dataclass
class DetectionContext:
    raw_data: bytes = b""
    decoded_data: bytes = b""
    decoded_text: str = ""
    decode_chain: str = ""
    decode_layers: int = 0

    method: str = ""
    uri: str = ""
    content_type: str = ""
    headers: Dict[str, str] = field(default_factory=dict)

    entropy: float = 0.0
    entropy_class: str = ""
    is_code_like: bool = False
    is_binary_payload: bool = False
    text_detection_skipped: bool = False
    skip_reason: str = ""
    protocol_hint: str = ""

    is_json: bool = False
    json_values: List[str] = field(default_factory=list)

    # 所有检测器共享AST结果，只分析一次
    ast_result: Optional[Any] = None
    ast_analyzed: bool = False

    start_time: float = 0.0
    is_sampled: bool = False
    # 本条载荷有没有因为触到绝对上限而没被完整匹配
    coverage_truncated: bool = False
    # 有没有因为 TOTAL_TIMEOUT_S 而少跑了检测器，少跑了哪些
    timed_out: bool = False
    detectors_skipped: List[str] = field(default_factory=list)

    # 正则预筛的执行计划 + 它对应的那段文本（AC 一趟算出来，全检测器共用）
    pattern_plan: Optional[Dict[str, Any]] = None
    pattern_plan_text: Optional[str] = None


@dataclass
class DetectorResult:
    attack_type: AttackType = AttackType.UNKNOWN
    detected: bool = False
    weight: int = 0
    confidence: str = "none"
    evidences: List[Evidence] = field(default_factory=list)
    ast_findings: List[Dict] = field(default_factory=list)
    obfuscation_score: float = 0.0
    tainted_sinks: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    error: str = ""

    def merge(self, other: "DetectorResult") -> "DetectorResult":
        self.weight += other.weight
        self.evidences.extend(other.evidences)
        self.ast_findings.extend(other.ast_findings)
        self.obfuscation_score = max(self.obfuscation_score, other.obfuscation_score)
        self.tainted_sinks.extend(other.tainted_sinks)
        self.tags.extend(other.tags)
        if other.detected:
            self.detected = True
        return self


class BaseDetector(ABC):
    """检测器基类，子类实现detect()就行"""

    # 子类必须定义
    ATTACK_TYPE: AttackType = AttackType.UNKNOWN
    PRIORITY: int = 50

    def __init__(self):
        self._patterns: Dict[str, Tuple[Pattern, int]] = {}
        self._compiled = False

    def _compile_patterns(self, patterns: Dict[str, Tuple[str, int]]) -> None:
        """惰性编译正则"""
        if self._compiled:
            return

        for name, (pattern, weight) in patterns.items():
            try:
                self._patterns[name] = (re.compile(pattern, re.IGNORECASE | re.DOTALL), weight)
            except re.error as e:
                logger.error(f"Failed to compile pattern {name}: {e}")

        self._compiled = True
        # 登记进全局预筛器。键要全局唯一，用 `攻击类型:规则名`。
        try:
            register_patterns({
                f"{self.ATTACK_TYPE.value}:{n}": p
                for n, (p, _w) in self._patterns.items()
            })
        except Exception as e:      # pragma: no cover
            logger.debug(f"预筛登记失败，该检测器退回全量匹配: {e}")

    @abstractmethod
    def detect(self, context: DetectionContext) -> DetectorResult:
        pass

    def _match_patterns(self, text: str, context: DetectionContext) -> List[Evidence]:
        """跑所有正则，返回匹配到的证据

        不是把 119 条规则挨个在整段文本上跑一遍 —— 那样 7.8MB 正文要 6.7 秒，
        而 `re` 匹配期间不释放 GIL，UI 线程会被顶到几百毫秒的延迟。这里先用
        `PatternPrefilter` 一趟 AC 算出每条规则的执行计划：

          跳过        必含字面量不存在，可以证明它不可能匹配
          开窗        只在字面量命中点周围跑，窗口宽度由该规则自己的
                      **最大匹配长度上界**算出，保证装得下任何真命中
          完整文本    推不出有限上界（含 `*`/`+`/`{n,}`）或没有必含字面量

        注意开窗和被删掉的"分块扫描"不是一回事：分块按**固定长度**切、丢弃
        贴边命中，命中一长就两边都丢；这里的窗口宽度是从模式推出来的上界，
        推不出来就不开窗。取舍的对象是"规则"，不是"位置"。
        """
        evidences = []
        plan = self._pattern_plan(text, context)

        for name, (pattern, weight) in self._patterns.items():
            if name not in plan:
                continue            # 必含字面量不出现，可证明它不可能命中
            regions = plan[name]
            try:
                if regions is None:
                    match = self._search_full(pattern, text)
                else:
                    match = None
                    for start, end in regions:
                        match = pattern.search(text, start, end)
                        if match:
                            break
                if match:
                    matched_text = match.group(0)
                    if len(matched_text) > ResourceLimits.MAX_PATTERN_MATCH_LEN:
                        matched_text = matched_text[:ResourceLimits.MAX_PATTERN_MATCH_LEN] + "..."

                    evidences.append(Evidence(
                        pattern_name=f"{self.ATTACK_TYPE.value}:{name}",
                        pattern=pattern.pattern[:100],
                        matched_text=matched_text,
                        weight=weight,
                        description=f"Matched {name} pattern"
                    ))
            except Exception as e:
                logger.debug(f"Pattern match error for {name}: {e}")

        return evidences

    def _pattern_plan(self, text: str, context: DetectionContext):
        """取本检测器规则在这段文本上的执行计划

        AC 那一趟对整段文本只跑一次，结果缓存在 context 上给所有检测器共用
        —— 按检测器各扫一趟的话，10 个检测器就是 10 次 lower() + 10 趟 AC，
        预筛本身会比它要省掉的正则还贵。
        """
        prefix = f"{self.ATTACK_TYPE.value}:"
        cached = context.pattern_plan
        if cached is None or context.pattern_plan_text is not text:
            try:
                cached = global_plan(text)
            except Exception as e:      # 预筛坏了不能拖垮检测：退回全量
                logger.debug(f"预筛失败，退回全量匹配: {e}")
                cached = {f"{prefix}{n}": None for n in self._patterns}
            context.pattern_plan = cached
            context.pattern_plan_text = text
        return {
            name[len(prefix):]: regions
            for name, regions in cached.items()
            if name.startswith(prefix)
        }

    def _search_full(self, pattern: Pattern, text: str):
        """见模块级 search_full 的说明"""
        return search_full(pattern, text)

    def _safe_regex_search(self, pattern: Pattern, text: str):
        """保留给子类/外部调用方；全量搜索请用 _search_full"""
        return self._search_full(pattern, text)

    def _check_timeout(self, context: DetectionContext) -> bool:
        """检查是否超时"""
        elapsed = time.time() - context.start_time
        return elapsed > ResourceLimits.TOTAL_TIMEOUT_S


class ASTEnhancedDetector(BaseDetector):
    """带AST语义分析的检测器基类，用快速过滤+缓存+污点追踪减少误报"""

    # 子类可覆盖
    DANGEROUS_SINKS: Dict[str, int] = {}

    AST_ENABLED: bool = True
    FAST_FILTER_ENABLED: bool = True
    AST_THRESHOLD: int = 20

    def __init__(self):
        super().__init__()
        self._fast_filter = get_fast_filter() if get_fast_filter else None

    def _run_ast_analysis(self, text: str, result: DetectorResult, context: DetectionContext) -> None:
        """读取context里共享的AST结果，应用到本检测器"""
        if not self.AST_ENABLED:
            return

        if not context.is_code_like:
            return

        if result.weight < self.AST_THRESHOLD:
            return

        # 使用预计算的共享结果
        if not context.ast_analyzed:
            return

        if context.ast_result is not None:
            self._apply_cached_ast_result(context.ast_result, result)

    def _apply_cached_ast_result(self, cached: any, result: DetectorResult) -> None:
        if cached is None:
            return

        try:
            if hasattr(cached, 'to_dict'):
                self._apply_ast_result(cached, result)
            elif isinstance(cached, dict):
                result.ast_findings = cached.get('findings', [])
                result.obfuscation_score = cached.get('obfuscation_score', 0.0)
                if cached.get('is_likely_webshell'):
                    result.weight += 30
                    result.tags.append("ast:cached:webshell")
        except Exception as e:
            logger.debug(f"Failed to apply cached AST result: {e}")

    def _apply_ast_result(self, ast_result, result: DetectorResult) -> None:
        """把AST分析结果写入检测结果"""
        result.ast_findings = ast_result.to_dict().get('findings', [])
        result.obfuscation_score = ast_result.obfuscation_score

        tainted_count = 0
        untainted_count = 0

        for call in ast_result.dangerous_calls:
            func_name = call.function_name.lower()
            sink_weight = self._get_sink_weight(func_name)

            if sink_weight > 0:
                if call.is_tainted:
                    # 污点数据流入危险函数
                    tainted_count += 1
                    result.tainted_sinks.append(call.function_name)
                    result.weight += sink_weight
                    result.evidences.append(Evidence(
                        pattern_name=f"{self.ATTACK_TYPE.value}:tainted_sink:{call.function_name}",
                        weight=sink_weight,
                        description=f"用户输入流入危险函数 {call.function_name}()"
                    ))
                else:
                    untainted_count += 1

        if tainted_count > 0:
            result.weight += ast_result.confidence_adjustment
            result.tags.append("ast:tainted")
        elif untainted_count > 0 and tainted_count == 0 and result.weight < 100:
            # 有危险函数但没污点，降低权重减少误报
            adjustment = min(30, result.weight // 3)
            result.weight -= adjustment
            result.tags.append("ast:no_taint")

        if ast_result.obfuscation_score > 0.5:
            result.weight += int(ast_result.obfuscation_score * 30)
            result.tags.append(f"ast:obfuscated:{ast_result.obfuscation_score:.1f}")

    def _get_sink_weight(self, func_name: str) -> int:
        func_lower = func_name.lower()

        if func_lower in self.DANGEROUS_SINKS:
            return self.DANGEROUS_SINKS[func_lower]

        for sink, weight in self.DANGEROUS_SINKS.items():
            if sink in func_lower or func_lower in sink:
                return weight

        return 0


class SQLiDetector(ASTEnhancedDetector):
    """SQL注入检测"""

    ATTACK_TYPE = AttackType.SQLI
    PRIORITY = 10

    DANGEROUS_SINKS = {
        'mysql_query': 60,
        'mysqli_query': 60,
        'pg_query': 60,
        'sqlite_query': 60,
        'mssql_query': 60,
        'odbc_exec': 60,
        'db2_exec': 60,
        'oci_execute': 60,
        'pdo_query': 55,
        'query': 50,
        'execute': 45,
        'exec': 45,
        'raw': 40,
    }

    PATTERNS = {
        'union_select': (r"UNION\s{1,10}(ALL\s{1,10})?SELECT\s", 80),
        'union_select_null': (r"UNION\s{1,10}SELECT\s{1,10}NULL", 85),
        'or_true': (r"'\s{0,5}OR\s{0,5}'?\d{1,5}'\s{0,5}=\s{0,5}'?\d{1,5}", 70),
        'or_true_v2': (r"'\s{0,5}OR\s{0,5}1\s{0,5}=\s{0,5}1", 75),
        'and_true': (r"'\s{0,5}AND\s{0,5}1\s{0,5}=\s{0,5}1", 65),
        'and_false': (r"'\s{0,5}AND\s{0,5}'?\d{1,5}'\s{0,5}=\s{0,5}'?\d{1,5}", 60),
        'sleep_attack': (r"SLEEP\s{0,5}\(\s{0,5}\d{1,10}\s{0,5}\)", 90),
        'benchmark': (r"BENCHMARK\s{0,5}\(\s{0,5}\d{1,15}\s{0,5},", 90),
        'waitfor_delay': (r"WAITFOR\s{1,10}DELAY\s{1,10}['\"]", 90),

        'load_file': (r"LOAD_FILE\s{0,5}\(", 95),
        'into_outfile': (r"INTO\s{1,10}(OUT|DUMP)FILE\s", 95),

        'information_schema': (r"INFORMATION_SCHEMA\.(TABLES|COLUMNS|SCHEMATA)", 70),

        'line_comment': (r"--\s{0,3}$", 30),
        'hash_comment': (r"#\s{0,3}$", 30),
        'inline_comment_bypass': (r"/\*!\d{0,6}\s{0,5}\w{1,20}\s{0,5}\*/", 60),

        'hex_string': (r"0x[0-9a-fA-F]{8,64}", 40),
        'char_function': (r"CHAR\s{0,5}\(\s{0,5}\d{1,5}(\s{0,5},\s{0,5}\d{1,5}){0,20}\s{0,5}\)", 50),

        'extractvalue': (r"EXTRACTVALUE\s{0,5}\(", 70),
        'updatexml': (r"UPDATEXML\s{0,5}\(", 70),

        'stacked_query': (r";\s{0,5}(SELECT|INSERT|UPDATE|DELETE|DROP)\s", 80),
    }

    WAF_BYPASS_PATTERNS = {
        'case_bypass': (r"(?:UnIoN|sElEcT|SeLeCt|uNiOn)", 40),
        'space_bypass': (r"UNION\s*/\*\*/\s*SELECT", 50),
        'plus_bypass': (r"UNION\+SELECT", 45),
    }

    def __init__(self):
        super().__init__()
        self._compile_patterns(self.PATTERNS)
        self._waf_patterns: Dict[str, Tuple[Pattern, int]] = {}
        for name, (pattern, weight) in self.WAF_BYPASS_PATTERNS.items():
            try:
                self._waf_patterns[name] = (re.compile(pattern, re.IGNORECASE), weight)
            except re.error:
                pass

    def detect(self, context: DetectionContext) -> DetectorResult:
        result = DetectorResult(attack_type=self.ATTACK_TYPE)

        if self._check_timeout(context):
            result.error = "timeout"
            return result

        text = context.decoded_text

        if context.is_json and context.json_values:
            text = " ".join(context.json_values)
            result.tags.append("json_value_scan")

        evidences = self._match_patterns(text, context)

        for name, (pattern, weight) in self._waf_patterns.items():
            try:
                match = safe_regex_match(pattern, text)
                if match:
                    evidences.append(Evidence(
                        pattern_name=f"sqli:waf_bypass:{name}",
                        matched_text=match.group(0)[:100],
                        weight=weight,
                        description=f"WAF bypass technique: {name}"
                    ))
            except Exception:
                pass

        result.evidences = evidences
        result.weight = sum(e.weight for e in evidences)

        if self._check_quote_imbalance(text):
            result.evidences.append(Evidence(
                pattern_name="sqli:quote_imbalance",
                weight=20,
                description="Unbalanced quotes detected"
            ))
            result.weight += 20

        self._run_ast_analysis(text, result, context)

        result.detected = result.weight >= 40
        result.confidence = ThreatLevel.from_weight(result.weight).value

        return result

    def _check_quote_imbalance(self, text: str) -> bool:
        text = text[:10000]
        single = text.count("'") - text.count("\\'")
        double = text.count('"') - text.count('\\"')
        return single % 2 != 0 or double % 2 != 0


class XSSDetector(ASTEnhancedDetector):
    """XSS检测"""

    ATTACK_TYPE = AttackType.XSS
    PRIORITY = 15

    DANGEROUS_SINKS = {
        'echo': 50,
        'print': 50,
        'print_r': 45,
        'printf': 50,
        'sprintf': 45,
        'vprintf': 50,
        'document.write': 70,
        'document.writeln': 70,
        'innerhtml': 65,
        'outerhtml': 60,
        'insertadjacenthtml': 60,
        'eval': 80,
        'function': 40,
        'settimeout': 55,
        'setinterval': 55,
        'htmlspecialchars': -20,
        'htmlentities': -20,
        'strip_tags': -15,
    }

    PATTERNS = {
        'script_tag': (r"<script[^>]{0,200}>[^<]{0,1000}</script>", 80),
        'script_open': (r"<script[^>]{0,200}>", 60),
        'onerror': (r"\bon(error|load|click|mouseover|mouseout|keydown|keyup)\s{0,5}=", 70),
        'javascript_uri': (r"javascript\s{0,5}:", 75),
        'eval_call': (r"\beval\s{0,5}\(", 60),
        'document_write': (r"document\.(write|writeln)\s{0,5}\(", 55),
        'innerhtml': (r"\.innerHTML\s{0,5}=", 50),
        'document_cookie': (r"document\.cookie", 45),
        'svg_onload': (r"<svg[^>]{0,100}\bonload\s{0,5}=", 75),
        'img_onerror': (r"<img[^>]{0,100}\bonerror\s{0,5}=", 70),
        'location_assign': (r"location\s{0,5}=|location\.(href|assign|replace)\s{0,5}=", 50),
        'document_domain': (r"document\.domain\s{0,5}=", 55),
    }

    def __init__(self):
        super().__init__()
        self._compile_patterns(self.PATTERNS)

    def detect(self, context: DetectionContext) -> DetectorResult:
        result = DetectorResult(attack_type=self.ATTACK_TYPE)

        if self._check_timeout(context):
            result.error = "timeout"
            return result

        text = context.decoded_text

        if context.is_json and context.json_values:
            text = " ".join(context.json_values)
            result.tags.append("json_value_scan")

        evidences = self._match_patterns(text, context)
        result.evidences = evidences
        result.weight = sum(e.weight for e in evidences)

        self._run_ast_analysis(text, result, context)

        result.detected = result.weight >= 40
        result.confidence = ThreatLevel.from_weight(result.weight).value

        return result


class RCEDetector(ASTEnhancedDetector):
    """远程代码执行检测"""

    ATTACK_TYPE = AttackType.RCE
    PRIORITY = 5

    DANGEROUS_SINKS = {
        'eval': 100,
        'assert': 90,
        'create_function': 95,
        'call_user_func': 75,
        'call_user_func_array': 75,
        'preg_replace': 60,
        'system': 100,
        'exec': 100,
        'shell_exec': 100,
        'passthru': 100,
        'popen': 95,
        'proc_open': 95,
        'pcntl_exec': 100,
        'include': 85,
        'include_once': 85,
        'require': 85,
        'require_once': 85,
        'unserialize': 85,
        '__import__': 90,
        'subprocess': 95,
    }

    PATTERNS = {
        'eval': (r"\beval\s{0,5}\(", 90),
        'assert': (r"\bassert\s{0,5}\(", 80),
        'create_function': (r"\bcreate_function\s{0,5}\(", 85),
        'preg_replace_e': (r"preg_replace\s{0,5}\([^)]{0,100}['\"][^'\"]{0,50}e[imsuxADSUXJ]{0,10}['\"]", 95),
        'call_user_func': (r"call_user_func(_array)?\s{0,5}\(", 70),

        'system': (r"\bsystem\s{0,5}\(", 95),
        'exec': (r"\bexec\s{0,5}\(", 95),
        'shell_exec': (r"\bshell_exec\s{0,5}\(", 95),
        'passthru': (r"\bpassthru\s{0,5}\(", 95),
        'popen': (r"\b(popen|proc_open)\s{0,5}\(", 90),
        'backtick': (r"`[^`]{1,500}`", 80),

        'include_dynamic': (r"\b(include|require)(_once)?\s{0,5}\(\s{0,5}\$", 85),

        'variable_function': (r"\$[a-zA-Z_]\w{0,50}\s{0,5}\(", 60),
        'variable_variable': (r"\$\{\s{0,5}\$", 70),

        'unserialize': (r"\bunserialize\s{0,5}\(", 80),
        'phar_wrapper': (r"phar://", 85),

        'python_exec': (r"\bexec\s{0,5}\(|__import__\s{0,5}\(", 90),
        'os_system': (r"os\.(system|popen|spawn)", 90),
        'subprocess': (r"subprocess\.(call|run|Popen)", 90),

        'ssti_jinja': (r"\{\{\s{0,10}[^}]{1,200}\s{0,10}\}\}", 50),
        'ssti_freemarker': (r"\$\{\s{0,10}[^}]{1,200}\s{0,10}\}", 45),

        # Java/JSP Webshell
        'jsp_scriptlet': (r"<%[!@]?\s{0,10}(class|import|extends)", 70),
        'jsp_classloader': (r"extends\s{1,10}ClassLoader", 95),
        'jsp_defineclass': (r"defineClass\s{0,5}\(", 100),
        'jsp_runtime_exec': (r"Runtime\s{0,5}\.\s{0,5}getRuntime\s{0,5}\(\s{0,5}\)\s{0,5}\.\s{0,5}exec", 100),
        'jsp_processbuilder': (r"ProcessBuilder\s{0,5}\(", 90),
        'java_reflection': (r"\.getMethod\s{0,5}\(|\.invoke\s{0,5}\(|\.forName\s{0,5}\(", 75),
        'java_classforname': (r"Class\.forName\s{0,5}\(", 80),
        'godzilla_key': (r"String\s{1,10}xc\s{0,5}=\s{0,5}[\"'][0-9a-f]{16}[\"']", 95),
        'godzilla_md5': (r"md5\s{0,5}\(\s{0,5}pass\s{0,5}\+\s{0,5}xc\s{0,5}\)", 95),
        'behinder_java': (r"AES/CBC/PKCS5Padding|javax\.crypto\.Cipher", 80),
        'jsp_request_param': (r"request\.(getParameter|getInputStream)", 50),
        'jsp_response_write': (r"response\.(getWriter|getOutputStream)", 40),

        # Webshell初始化特征
        'webshell_ini_set': (r"@?ini_set\s{0,5}\(\s{0,5}['\"]display_errors['\"]", 60),
        'webshell_error_reporting': (r"@?error_reporting\s{0,5}\(\s{0,5}0\s{0,5}\)", 55),
        'webshell_set_time_limit': (r"@?set_time_limit\s{0,5}\(\s{0,5}0\s{0,5}\)", 50),
        'webshell_ignore_abort': (r"ignore_user_abort\s{0,5}\(\s{0,5}(true|1)\s{0,5}\)", 50),
        'webshell_openssl_decrypt': (r"openssl_decrypt\s{0,5}\([^)]{0,100}\$_(POST|GET|REQUEST)", 80),
        'webshell_openssl_aes': (r"openssl_decrypt\s{0,5}\([^)]{0,100}AES", 60),
        'webshell_base64_decode_post': (r"base64_decode\s{0,5}\(\s{0,5}\$_(POST|GET|REQUEST)", 75),
        'webshell_gzinflate': (r"gzinflate\s{0,5}\(\s{0,5}base64_decode", 80),
        'webshell_chr_concat': (r"chr\s{0,5}\(\s{0,5}\d+\s{0,5}\)\s{0,5}\.\s{0,5}chr\s{0,5}\(", 60),
    }

    def __init__(self):
        super().__init__()
        self._compile_patterns(self.PATTERNS)

    def detect(self, context: DetectionContext) -> DetectorResult:
        result = DetectorResult(attack_type=self.ATTACK_TYPE)

        if self._check_timeout(context):
            result.error = "timeout"
            return result

        text = context.decoded_text
        evidences = self._match_patterns(text, context)
        result.evidences = evidences
        result.weight = sum(e.weight for e in evidences)

        # AST
        self._run_ast_analysis(text, result, context)

        result.detected = result.weight >= 50
        result.confidence = ThreatLevel.from_weight(result.weight).value

        return result


class XXEDetector(ASTEnhancedDetector):
    """XXE检测"""

    ATTACK_TYPE = AttackType.XXE
    PRIORITY = 20

    DANGEROUS_SINKS = {
        'simplexml_load_string': 70,
        'simplexml_load_file': 75,
        'dom_import_simplexml': 60,
        'xml_parse': 65,
        'xmlreader': 60,
        'domdocument': 65,
        'loadxml': 70,
        'load': 50,
        'libxml_disable_entity_loader': -50,
    }

    PATTERNS = {
        'entity_system': (r"<!ENTITY\s{1,10}\w{1,50}\s{1,10}SYSTEM\s{1,10}['\"]", 90),
        'entity_public': (r"<!ENTITY\s{1,10}\w{1,50}\s{1,10}PUBLIC\s{1,10}['\"]", 85),
        'parameter_entity': (r"<!ENTITY\s{1,10}%\s{0,5}\w{1,50}\s{1,10}(SYSTEM|PUBLIC)", 90),
        'external_dtd': (r"<!DOCTYPE[^>]{0,200}SYSTEM\s{1,10}['\"][^'\"]{1,500}['\"]", 85),
        'file_protocol': (r"file://[^'\"\s>]{1,500}", 95),
        'php_protocol': (r"php://(input|filter|data)", 95),
        'expect_protocol': (r"expect://", 100),
    }

    DANGEROUS_PROTOCOLS = {
        'file://': 100, 'php://': 95, 'expect://': 100,
        'gopher://': 90, 'dict://': 80, 'data://': 70,
    }

    def __init__(self):
        super().__init__()
        self._compile_patterns(self.PATTERNS)

    def detect(self, context: DetectionContext) -> DetectorResult:
        result = DetectorResult(attack_type=self.ATTACK_TYPE)

        if self._check_timeout(context):
            result.error = "timeout"
            return result

        text = context.decoded_text

        if not self._looks_like_xml(text):
            return result

        evidences = self._match_patterns(text, context)
        result.evidences = evidences
        result.weight = sum(e.weight for e in evidences)

        text_lower = text.lower()
        for protocol, weight in self.DANGEROUS_PROTOCOLS.items():
            if protocol.lower() in text_lower:
                result.evidences.append(Evidence(
                    pattern_name=f"xxe:protocol:{protocol}",
                    weight=weight,
                    description=f"Dangerous protocol: {protocol}"
                ))
                result.weight += weight
                break

        self._run_ast_analysis(text, result, context)

        result.detected = result.weight >= 50
        result.confidence = ThreatLevel.from_weight(result.weight).value

        return result

    def _looks_like_xml(self, text: str) -> bool:
        text_upper = text.upper()
        return ('<?XML' in text_upper or '<!DOCTYPE' in text_upper or
                '<!ENTITY' in text_upper or text.strip().startswith('<'))


class SSRFDetector(ASTEnhancedDetector):
    """SSRF检测"""

    ATTACK_TYPE = AttackType.SSRF
    PRIORITY = 25

    DANGEROUS_SINKS = {
        'file_get_contents': 70,
        'fopen': 60,
        'curl_init': 75,
        'curl_exec': 80,
        'curl_setopt': 50,
        'fsockopen': 85,
        'pfsockopen': 85,
        'socket_connect': 85,
        'get_headers': 60,
        'getimagesize': 55,
        'imagecreatefromjpeg': 50,
        'imagecreatefrompng': 50,
        'imagecreatefromgif': 50,
        'requests.get': 70,
        'requests.post': 70,
        'urllib.request.urlopen': 75,
        'httplib': 65,
    }

    PATTERNS = {
        'loopback': (r"\b127\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", 100),
        'localhost': (r"\blocalhost\b", 100),
        'class_a_private': (r"\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", 80),
        'class_b_private': (r"\b172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}\b", 80),
        'class_c_private': (r"\b192\.168\.\d{1,3}\.\d{1,3}\b", 80),
        'aws_metadata': (r"\b169\.254\.169\.254\b", 100),
        'file_scheme': (r"\bfile://", 90),
        'gopher_scheme': (r"\bgopher://", 90),
        'dict_scheme': (r"\bdict://", 85),
        'ipv6_localhost': (r"\[::1\]|\[0:0:0:0:0:0:0:1\]", 100),
        'decimal_ip_in_url': (r"https?://\d{8,10}\b", 70),
    }

    def __init__(self):
        super().__init__()
        self._compile_patterns(self.PATTERNS)

    def detect(self, context: DetectionContext) -> DetectorResult:
        result = DetectorResult(attack_type=self.ATTACK_TYPE)

        if self._check_timeout(context):
            result.error = "timeout"
            return result

        text = context.decoded_text

        if context.is_json and context.json_values:
            text = " ".join(context.json_values)
            result.tags.append("json_value_scan")

        evidences = self._match_patterns(text, context)
        result.evidences = evidences
        result.weight = sum(e.weight for e in evidences)

        self._run_ast_analysis(text, result, context)

        result.detected = result.weight >= 50
        result.confidence = ThreatLevel.from_weight(result.weight).value

        return result


class PathTraversalDetector(ASTEnhancedDetector):
    """目录穿越检测"""

    ATTACK_TYPE = AttackType.PATH_TRAVERSAL
    PRIORITY = 30

    DANGEROUS_SINKS = {
        'file_get_contents': 70,
        'file': 60,
        'fopen': 65,
        'fread': 60,
        'readfile': 70,
        'highlight_file': 75,
        'show_source': 75,
        'include': 85,
        'include_once': 85,
        'require': 85,
        'require_once': 85,
        'opendir': 50,
        'readdir': 45,
        'scandir': 55,
        'glob': 50,
        'basename': -20,
        'realpath': -25,
    }

    PATTERNS = {
        'dot_dot_slash': (r"\.\.(/|\\)", 40),
        'url_encoded': (r"%2e%2e(%2f|%5c|/|\\)", 50),
        'double_encoded': (r"%252e%252e%252f", 60),
        'null_byte': (r"%00|\\x00", 60),
        'unicode_bypass': (r"%c0%ae%c0%ae|%e0%40%ae", 55),
    }

    SENSITIVE_FILES = {
        '/etc/passwd': 100, '/etc/shadow': 100,
        '.ssh/id_rsa': 95, 'win.ini': 80,
        'web.config': 70, '.htaccess': 60, '.env': 75,
        'wp-config.php': 80, 'config.php': 70,
    }

    def __init__(self):
        super().__init__()
        self._compile_patterns(self.PATTERNS)

    def detect(self, context: DetectionContext) -> DetectorResult:
        result = DetectorResult(attack_type=self.ATTACK_TYPE)

        if self._check_timeout(context):
            result.error = "timeout"
            return result

        text = context.decoded_text
        decoded = self._recursive_url_decode(text)

        evidences = self._match_patterns(text, context)
        if decoded != text:
            evidences.extend(self._match_patterns(decoded, context))

        result.evidences = evidences
        result.weight = sum(e.weight for e in evidences)

        depth = self._calculate_traversal_depth(decoded)
        if depth >= 2:
            result.evidences.append(Evidence(
                pattern_name="path_traversal:depth",
                weight=depth * 20,
                description=f"Traversal depth: {depth}"
            ))
            result.weight += depth * 20

        decoded_lower = decoded.lower()
        for filepath, weight in self.SENSITIVE_FILES.items():
            if filepath.lower() in decoded_lower:
                result.evidences.append(Evidence(
                    pattern_name="path_traversal:sensitive_file",
                    weight=weight,
                    matched_text=filepath
                ))
                result.weight += weight
                break

        self._run_ast_analysis(text, result, context)

        result.detected = result.weight >= 50
        result.confidence = ThreatLevel.from_weight(result.weight).value

        return result

    def _recursive_url_decode(self, text: str, max_rounds: int = 5) -> str:
        for _ in range(max_rounds):
            decoded = unquote(text)
            if decoded == text:
                break
            text = decoded
        return text

    def _calculate_traversal_depth(self, path: str) -> int:
        normalized = path.replace('\\', '/')
        depth = 0
        current = 0
        for comp in normalized.split('/'):
            if comp == '..':
                current += 1
                depth = max(depth, current)
            elif comp and comp != '.':
                current = max(0, current - 1)
        return depth


class CommandInjectionDetector(ASTEnhancedDetector):
    """命令注入检测"""

    ATTACK_TYPE = AttackType.COMMAND_INJECTION
    PRIORITY = 8

    DANGEROUS_SINKS = {
        'system': 100,
        'exec': 100,
        'shell_exec': 100,
        'passthru': 100,
        'popen': 95,
        'proc_open': 95,
        'pcntl_exec': 100,
        'backticks': 90,
        'os.system': 100,
        'os.popen': 95,
        'subprocess.call': 95,
        'subprocess.run': 95,
        'subprocess.popen': 100,
        'escapeshellcmd': -30,
        'escapeshellarg': -30,
    }

    PATTERNS = {
        'semicolon': (r";\s{0,10}(ls|cat|id|whoami|pwd|uname|curl|wget|nc|bash|sh)\b", 80),
        'pipe': (r"\|\s{0,10}(ls|cat|id|whoami|pwd|bash|sh)\b", 75),
        'ampersand': (r"&{1,2}\s{0,10}(ls|cat|id|whoami|pwd)\b", 70),
        'backtick_cmd': (r"`[^`]{1,200}`", 70),
        'dollar_paren': (r"\$\([^)]{1,200}\)", 70),
        'reverse_shell': (r"(nc|ncat|netcat)\s{1,20}[^\s]{1,50}\s{1,20}\d{1,5}\s{1,10}-e\s{1,10}(ba)?sh", 100),
        'bash_reverse': (r"bash\s{1,10}-i\s{1,10}>&", 100),
        'curl_pipe': (r"curl\s{1,50}[^\|]{1,200}\|\s{0,10}(ba)?sh", 90),
        'wget_pipe': (r"wget\s{1,50}[^\|]{1,200}\|\s{0,10}(ba)?sh", 90),
    }

    def __init__(self):
        super().__init__()
        self._compile_patterns(self.PATTERNS)

    def detect(self, context: DetectionContext) -> DetectorResult:
        result = DetectorResult(attack_type=self.ATTACK_TYPE)

        if self._check_timeout(context):
            result.error = "timeout"
            return result

        text = context.decoded_text
        evidences = self._match_patterns(text, context)
        result.evidences = evidences
        result.weight = sum(e.weight for e in evidences)

        self._run_ast_analysis(text, result, context)

        result.detected = result.weight >= 50
        result.confidence = ThreatLevel.from_weight(result.weight).value

        return result


class DeserializationDetector(ASTEnhancedDetector):
    """反序列化检测"""

    ATTACK_TYPE = AttackType.DESERIALIZATION
    PRIORITY = 35

    DANGEROUS_SINKS = {
        'unserialize': 90,
        'maybe_unserialize': 85,
        '__wakeup': 60,
        '__destruct': 60,
        '__toString': 50,
        '__call': 55,
        'pickle.loads': 95,
        'pickle.load': 95,
        'cPickle.loads': 95,
        'ObjectInputStream': 90,
        'readObject': 85,
        'yaml.load': 85,
        'yaml.unsafe_load': 100,
        'json_decode': -10,
        'yaml.safe_load': -20,
    }

    PATTERNS = {
        'php_serialize': (r'[OaCsrib]:\d{1,10}:', 60),
        'php_object': (r'O:\d{1,10}:"[^"]{1,100}":\d{1,5}:', 70),
        'java_magic': (r'(\xac\xed\x00\x05|rO0AB)', 80),
        'pickle_reduce': (r'c__builtin__|cposix|cos\n', 80),
        'yaml_tag': (r'!!python/object', 85),
        'dotnet_type': (r'\$type["\']?\s{0,5}:', 75),
    }

    def __init__(self):
        super().__init__()
        self._compile_patterns(self.PATTERNS)

    def detect(self, context: DetectionContext) -> DetectorResult:
        result = DetectorResult(attack_type=self.ATTACK_TYPE)

        if self._check_timeout(context):
            result.error = "timeout"
            return result

        text = context.decoded_text
        evidences = self._match_patterns(text, context)
        result.evidences = evidences
        result.weight = sum(e.weight for e in evidences)

        self._run_ast_analysis(text, result, context)

        result.detected = result.weight >= 50
        result.confidence = ThreatLevel.from_weight(result.weight).value

        return result


class FileUploadDetector(ASTEnhancedDetector):
    """文件上传漏洞检测"""

    ATTACK_TYPE = AttackType.FILE_UPLOAD
    PRIORITY = 3

    DANGEROUS_SINKS = {
        'move_uploaded_file': 80,
        'copy': 60,
        'file_put_contents': 70,
        'fwrite': 55,
        'fputs': 55,
        'pathinfo': 30,
        'basename': 20,
        'getimagesize': -15,
        'finfo_file': -20,
        'exif_imagetype': -20,
    }

    DANGEROUS_EXTENSIONS = {
        '.php': 100, '.php3': 95, '.php4': 95, '.php5': 95, '.phtml': 95, '.phar': 95,
        '.jsp': 100, '.jspx': 95, '.jsw': 90, '.jsv': 90,
        '.asp': 100, '.aspx': 100, '.asa': 95, '.asax': 90, '.ascx': 90, '.ashx': 90,
        '.cfm': 90, '.cfc': 90,
        '.exe': 100, '.dll': 95, '.bat': 90, '.cmd': 90, '.com': 90,
        '.sh': 85, '.bash': 85, '.zsh': 85,
        '.py': 80, '.pl': 80, '.rb': 80,
        '.htaccess': 90, '.htpasswd': 90,
        'web.config': 85, '.config': 70,
    }

    PATTERNS = {
        'content_disposition': (r'Content-Disposition[^;]*filename\s*=\s*["\']?([^"\';\r\n]+)', 30),
        'multipart_boundary': (r'boundary=[-\w]+', 20),
        'php_magic': (r'<\?php|<\?=', 80),
        'jsp_magic': (r'<%@\s*page|<%\s*import', 80),
        'asp_magic': (r'<%\s*@\s*language|<script\s+runat\s*=\s*["\']?server', 80),
        'double_extension': (r'\.(php|jsp|asp|aspx|exe)\.(jpg|png|gif|jpeg|bmp|ico)', 90),
        'null_byte_bypass': (r'\.(php|jsp|asp|aspx|exe)%00\.(jpg|png|gif)', 95),
    }

    def __init__(self):
        super().__init__()
        self._compile_patterns(self.PATTERNS)

    def detect(self, context: DetectionContext) -> DetectorResult:
        result = DetectorResult(attack_type=self.ATTACK_TYPE)

        if self._check_timeout(context):
            result.error = "timeout"
            return result

        # 检查是否是文件上传
        content_type = context.content_type.lower()
        is_upload = 'multipart/form-data' in content_type

        if not is_upload:
            if context.method.upper() not in ('PUT', 'POST'):
                return result

        text = context.decoded_text

        evidences = self._match_patterns(text, context)

        filenames = self._extract_filenames(text)
        for filename in filenames:
            ext_weight = self._check_dangerous_extension(filename)
            if ext_weight > 0:
                evidences.append(Evidence(
                    pattern_name=f"file_upload:dangerous_ext",
                    matched_text=filename,
                    weight=ext_weight,
                    description=f"Dangerous file extension in: {filename}"
                ))

            # 双扩展名
            if self._is_double_extension(filename):
                evidences.append(Evidence(
                    pattern_name="file_upload:double_extension",
                    matched_text=filename,
                    weight=90,
                    description=f"Double extension bypass attempt: {filename}"
                ))

        # multipart上传加点基础权重
        if is_upload and evidences:
            evidences.append(Evidence(
                pattern_name="file_upload:multipart",
                weight=20,
                description="File upload via multipart/form-data"
            ))

        result.evidences = evidences
        result.weight = sum(e.weight for e in evidences)

        self._run_ast_analysis(text, result, context)

        result.detected = result.weight >= 50
        result.confidence = ThreatLevel.from_weight(result.weight).value

        return result

    def _extract_filenames(self, text: str) -> List[str]:
        filenames = []

        # Content-Disposition: form-data; name="file"; filename="shell.php"
        pattern = re.compile(r'filename\s*=\s*["\']?([^"\';\r\n]+)', re.IGNORECASE)
        matches = pattern.findall(text)
        filenames.extend(matches)

        uri_pattern = re.compile(r'/([^/\s?]+\.\w{2,5})(?:\?|$|\s)')
        uri_matches = uri_pattern.findall(text)
        filenames.extend(uri_matches)

        return filenames

    def _check_dangerous_extension(self, filename: str) -> int:
        filename_lower = filename.lower()

        for ext, weight in self.DANGEROUS_EXTENSIONS.items():
            if filename_lower.endswith(ext):
                return weight

        return 0

    def _is_double_extension(self, filename: str) -> bool:
        filename_lower = filename.lower()
        dangerous_exts = ['.php', '.jsp', '.asp', '.aspx', '.exe', '.sh', '.py']
        image_exts = ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.ico']

        for dext in dangerous_exts:
            for iext in image_exts:
                if dext in filename_lower and filename_lower.endswith(iext):
                    return True
        return False


class SuspiciousEncryptedHTTPDetector(BaseDetector):
    """Fast generic heuristic for suspicious high-entropy HTTP payloads."""

    ATTACK_TYPE = AttackType.ENCRYPTED_HTTP
    PRIORITY = 4

    SCRIPT_EXT_RE = re.compile(r'\.(php\d*|phtml|phar|jsp|jspx|asp|aspx|ashx)\b', re.IGNORECASE)
    SUSPICIOUS_PATH_RE = re.compile(r'/(uploads?|upload|files?|assets?|cache|tmp|temp)/', re.IGNORECASE)
    DANGEROUS_PARAM_RE = re.compile(
        r'^(cmd|exec|shell|payload|code|pass|password|key|data|action|method)$',
        re.IGNORECASE,
    )
    RANDOM_PARAM_RE = re.compile(r'^[a-z][a-z0-9]{9,24}$', re.IGNORECASE)
    BASE64_SEGMENT_RE = re.compile(r'^[A-Za-z0-9+/]{40,}={0,2}$')

    # body 解析窗口。这不是"只看这么多"——超出部分仍然会被 detect() 的
    # 全量字面量匹配覆盖，这里只是限制 parse_qsl 建列表的规模，避免一个
    # 50MB 的表单体把内存打爆。触顶会留痕。
    MAX_BODY_PARSE = 8 * 1024 * 1024
    # MAX_PARAMS 已删除：原来是 params[:32]，前面垫 32 个无害参数就能把
    # 真 payload 挤出视野，参数顺序完全由攻击者决定。
    MAX_VALUE_SAMPLE = 8192
    MIN_LONG_VALUE = 128
    HIGH_ENTROPY_THRESHOLD = 4.75

    def detect(self, context: DetectionContext) -> DetectorResult:
        result = DetectorResult(attack_type=self.ATTACK_TYPE)

        if self._check_timeout(context):
            result.error = "timeout"
            return result

        method = (context.method or "").upper()
        if method not in {"POST", "PUT", "PATCH"}:
            return result

        body = context.raw_data or context.decoded_data or b""
        if len(body) < 64:
            return result

        uri = context.uri or "/"
        content_type = (context.content_type or "").lower()
        text = safe_decode(body[:self.MAX_BODY_PARSE])
        looks_form = (
            "application/x-www-form-urlencoded" in content_type
            or ("=" in text and "&" in text[:4096])
        )
        if not looks_form:
            return result

        params = self._parse_form_params(text)
        if not params:
            return result

        evidences: List[Evidence] = []
        has_script_target = bool(self.SCRIPT_EXT_RE.search(uri))
        has_suspicious_path = bool(self.SUSPICIOUS_PATH_RE.search(uri))
        high_entropy_params = []
        segmented_params = []
        dangerous_params = []
        random_param_count = 0

        if has_script_target:
            evidences.append(Evidence(
                pattern_name="encrypted_http:post_to_script",
                matched_text=uri.split("?", 1)[0][-120:],
                weight=20,
                description="POST/PUT/PATCH request targets an executable script",
            ))

        if has_suspicious_path:
            evidences.append(Evidence(
                pattern_name="encrypted_http:suspicious_script_path",
                matched_text=uri.split("?", 1)[0][-120:],
                weight=20,
                description="Script target is under upload/cache/temp-like path",
            ))

        if "application/x-www-form-urlencoded" in content_type:
            evidences.append(Evidence(
                pattern_name="encrypted_http:urlencoded_form",
                matched_text=content_type[:120],
                weight=10,
                description="URL-encoded form body",
            ))

        for name, value in params:
            if self.DANGEROUS_PARAM_RE.match(name):
                dangerous_params.append(name)

            if self._looks_random_param_name(name):
                random_param_count += 1

            clean_value = value.strip()
            if len(clean_value) < self.MIN_LONG_VALUE:
                continue

            value_sample = clean_value[:self.MAX_VALUE_SAMPLE]
            entropy = self._calculate_entropy(value_sample)
            if entropy >= self.HIGH_ENTROPY_THRESHOLD:
                high_entropy_params.append((name, len(clean_value), entropy))

            segments = [s for s in clean_value.split("|") if s]
            long_b64_segments = sum(1 for s in segments if self.BASE64_SEGMENT_RE.match(s))
            if len(segments) >= 3 and long_b64_segments >= 3:
                segmented_params.append((name, len(segments), long_b64_segments))

        for name in dangerous_params[:3]:
            evidences.append(Evidence(
                pattern_name="encrypted_http:dangerous_param_name",
                matched_text=name,
                weight=25,
                description="Parameter name is commonly used to carry commands or encrypted payloads",
            ))

        if random_param_count >= 2:
            evidences.append(Evidence(
                pattern_name="encrypted_http:randomized_param_names",
                matched_text=f"random_params={random_param_count}",
                weight=15,
                description="Multiple randomized-looking parameter names",
            ))

        for name, value_len, entropy in high_entropy_params[:3]:
            weight = 45 if entropy >= 5.2 else 35
            if value_len >= 1024:
                weight += 10
            evidences.append(Evidence(
                pattern_name="encrypted_http:high_entropy_form_param",
                matched_text=f"{name}: len={value_len}, entropy={entropy:.2f}",
                weight=weight,
                description="Long high-entropy form parameter",
            ))

        for name, segment_count, b64_count in segmented_params[:2]:
            evidences.append(Evidence(
                pattern_name="encrypted_http:segmented_base64_payload",
                matched_text=f"{name}: segments={segment_count}, base64_segments={b64_count}",
                weight=30,
                description="Form parameter contains multiple long Base64-like chunks",
            ))

        if len(body) >= 2048:
            evidences.append(Evidence(
                pattern_name="encrypted_http:large_form_body",
                matched_text=f"body_len={len(body)}",
                weight=10,
                description="Large form body",
            ))

        target_context = has_script_target or has_suspicious_path or bool(dangerous_params)
        encrypted_payload = bool(high_entropy_params) or bool(segmented_params)
        if not (target_context and encrypted_payload):
            return result

        result.evidences = evidences
        result.weight = sum(e.weight for e in evidences)
        result.detected = result.weight >= 70
        result.confidence = ThreatLevel.from_weight(result.weight).value
        result.tags.extend(["encrypted_http_heuristic", "form_param_entropy"])
        return result

    def _parse_form_params(self, text: str) -> List[Tuple[str, str]]:
        try:
            return [
                (k, v)
                for k, v in parse_qsl(text, keep_blank_values=True, strict_parsing=False)
                if k
            ]
        except Exception:
            params = []
            for pair in text.split("&"):
                if "=" not in pair:
                    continue
                key, value = pair.split("=", 1)
                key = unquote(key.strip())
                value = unquote(value.strip())
                if key:
                    params.append((key, value))
            return params

    def _looks_random_param_name(self, name: str) -> bool:
        if not self.RANDOM_PARAM_RE.match(name):
            return False
        digit_count = sum(1 for ch in name if ch.isdigit())
        return digit_count >= 3 or len(set(name.lower())) >= 8

    @staticmethod
    def _calculate_entropy(value: str) -> float:
        if not value:
            return 0.0
        counts: Dict[str, int] = {}
        for ch in value:
            counts[ch] = counts.get(ch, 0) + 1
        length = len(value)
        entropy = 0.0
        for count in counts.values():
            p = count / length
            entropy -= p * math.log2(p)
        return entropy


class DetectorRegistry:

    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._detectors: Dict[str, Type[BaseDetector]] = {}
                    cls._instance._instances: Dict[str, BaseDetector] = {}
        return cls._instance

    def register(self, detector_class: Type[BaseDetector]) -> None:
        name = detector_class.ATTACK_TYPE.value
        self._detectors[name] = detector_class
        logger.debug(f"Registered detector: {name}")

    def get_all_detectors(self) -> List[BaseDetector]:
        """按优先级返回所有检测器实例"""
        for name, cls in self._detectors.items():
            if name not in self._instances:
                self._instances[name] = cls()

        detectors = list(self._instances.values())
        detectors.sort(key=lambda d: d.PRIORITY)
        return detectors

    def list_registered(self) -> List[str]:
        return list(self._detectors.keys())


_registry = DetectorRegistry()


def register_detector(cls: Type[BaseDetector]) -> Type[BaseDetector]:
    _registry.register(cls)
    return cls


register_detector(FileUploadDetector)
register_detector(SuspiciousEncryptedHTTPDetector)
register_detector(SQLiDetector)
register_detector(XSSDetector)
register_detector(RCEDetector)
register_detector(XXEDetector)
register_detector(SSRFDetector)
register_detector(PathTraversalDetector)
register_detector(CommandInjectionDetector)
register_detector(DeserializationDetector)


class JSONSemanticAnalyzer:
    """提取JSON值用于检测，区分键名和攻击载荷"""

    SAFE_KEY_PATTERNS = {
        r'^(id|name|title|description|email|username|password|token|key)$',
        r'^(created_at|updated_at|timestamp|date|time)$',
        r'^(status|type|category|level|priority)$',
        r'^(url|uri|path|file|image|avatar)$',
        r'^(count|total|page|limit|offset|size)$',
    }

    def __init__(self):
        self._safe_patterns = [re.compile(p, re.IGNORECASE) for p in self.SAFE_KEY_PATTERNS]

    def extract_values(self, json_text: str) -> Tuple[bool, List[str]]:
        """返回 (is_valid_json, values)"""
        try:
            data = json.loads(json_text)
            values = []
            self._extract_recursive(data, values)
            return True, values
        except json.JSONDecodeError:
            return False, []

    def _extract_recursive(self, obj: Any, values: List[str], depth: int = 0) -> None:
        if depth > 10:
            return

        if isinstance(obj, dict):
            for key, value in obj.items():
                self._extract_recursive(value, values, depth + 1)
        elif isinstance(obj, list):
            for item in obj:
                self._extract_recursive(item, values, depth + 1)
        elif isinstance(obj, str):
            if len(obj) > 2:
                values.append(obj)

    def is_safe_key(self, key: str) -> bool:
        return any(p.match(key) for p in self._safe_patterns)


class ContextAnalyzer:
    """降噪用，排除swagger/静态资源/health check等

    这些规则会**下调**权重，所以每一条都是潜在的绕过面：判据必须是攻击者
    改不动的东西。两处加固：

      1. URI 只拿 path 部分去匹配。原来是拿整条 URI（含 query）匹配
         `\\.(js|css|png…)$`，于是 `/x.php?a=<payload>&z=.js` 直接 −100 分。
      2. 已经有强证据（单条 ≥70 权重的指标，或污点流入 sink）时不再降权。
         静态资源路径上出现 `union select` 这种东西，恰恰更值得看，而不是
         更不值得看。
    """

    WHITELIST_RULES = {
        'swagger_docs': {'uri_patterns': [r'/swagger', r'/api-docs', r'/openapi'], 'weight_adjustment': -50},
        'static_resource': {'uri_patterns': [r'\.(js|css|png|jpg|gif|ico|woff|svg)$'], 'weight_adjustment': -100},
        'health_check': {'uri_patterns': [r'/(health|ping|status|ready|live)$'], 'weight_adjustment': -80},
        'metrics': {'uri_patterns': [r'/metrics', r'/prometheus'], 'weight_adjustment': -60},
    }

    def __init__(self):
        self._compiled_rules = {}
        for name, rule in self.WHITELIST_RULES.items():
            self._compiled_rules[name] = {
                'content_types': rule.get('content_types', []),
                'uri_patterns': [re.compile(p, re.IGNORECASE) for p in rule.get('uri_patterns', [])],
                'weight_adjustment': rule.get('weight_adjustment', 0),
            }
        self._json_analyzer = JSONSemanticAnalyzer()

    def analyze_json_context(self, context: DetectionContext) -> None:
        if 'application/json' in context.content_type.lower():
            is_json, values = self._json_analyzer.extract_values(context.decoded_text)
            context.is_json = is_json
            context.json_values = values

    STRONG_EVIDENCE_WEIGHT = 70

    @staticmethod
    def _uri_path(uri: str) -> str:
        """只取 path。query 和 fragment 是攻击者随手就能改的，不能进白名单判据。"""
        if not uri:
            return "/"
        path = uri.split("#", 1)[0].split("?", 1)[0].strip()
        return path or "/"

    def _has_strong_evidence(self, result: DetectorResult) -> bool:
        if result.tainted_sinks:
            return True
        return any(e.weight >= self.STRONG_EVIDENCE_WEIGHT for e in result.evidences)

    def apply_noise_reduction(self, result: DetectorResult, context: DetectionContext) -> DetectorResult:

        if context.is_json and not context.json_values:
            result.weight = int(result.weight * 0.5)
            result.tags.append("noise_reduced:empty_json")

        strong = self._has_strong_evidence(result)
        uri_path = self._uri_path(context.uri)

        for name, rule in self._compiled_rules.items():
            # Content-Type 匹配
            if rule['content_types'] and context.content_type not in rule['content_types']:
                continue

            # URI 匹配（只看 path）
            uri_matched = False
            for pattern in rule['uri_patterns']:
                if pattern.search(uri_path):
                    uri_matched = True
                    break

            if not uri_matched and rule['uri_patterns']:
                continue

            if rule['weight_adjustment'] < 0 and strong:
                # 有硬证据时不降权，但要留痕：报告里能看出这条命中过白名单
                result.tags.append(f"noise_rule_suppressed:{name}")
                continue

            result.weight += rule['weight_adjustment']
            result.tags.append(f"noise_reduced:{name}")

        result.weight = max(0, result.weight)
        result.confidence = ThreatLevel.from_weight(result.weight).value

        return result


class AttackDetector:
    """中央调度器：协调各检测器、解码、降噪、输出结果"""

    def __init__(self):
        self._registry = DetectorRegistry()
        self._auto_decoder = AutoDecoder() if AutoDecoder else None
        self._entropy_analyzer = EntropyAnalyzer() if EntropyAnalyzer else None
        self._context_analyzer = ContextAnalyzer()

        self._ast_engine = PHPASTEngine() if PHPASTEngine else None
        self._fast_filter = get_fast_filter() if get_fast_filter else None

    def detect(
        self,
        data: bytes,
        method: str = "GET",
        uri: str = "/",
        content_type: str = "",
        headers: Dict[str, str] = None
    ) -> Dict[str, Any]:
        """执行检测，返回兼容DetectionResult的字典"""
        start_time = time.time()
        headers = headers or {}

        # 大数据量的话先抽样
        sampled = SampledData(data)

        # 搞个context出来
        context = DetectionContext(
            raw_data=data,
            method=method,
            uri=uri,
            content_type=content_type,
            headers=headers,
            start_time=start_time,
            is_sampled=sampled.is_sampled
        )

        # 递归解码
        if self._auto_decoder:
            try:
                decode_result = self._auto_decoder.decode(
                    sampled.combined_bytes,
                    max_depth=ResourceLimits.MAX_DECODE_DEPTH
                )
                context.decoded_data = decode_result.final_data
                context.decoded_text = decode_result.final_text
                context.decode_chain = decode_result.decode_chain
                context.decode_layers = decode_result.total_layers
            except Exception as e:
                logger.debug(f"Decoding failed: {e}")
                context.decoded_data = data
                context.decoded_text = safe_decode(data)
        else:
            context.decoded_data = data
            context.decoded_text = safe_decode(data)

        # 采样过的话，把整段原文接回来做字面量覆盖。
        #
        # 递归解码只喂采样段是合理的（解码贵，且编码载荷基本从 body 开头起），
        # 但**匹配**不能只看采样段：中间三个采样点各只有 4KB，攻击者把
        # `union select` 放在 2MB 偏移处就整个消失了。字面量匹配是 O(n) 的，
        # 分块扫描（_search_full）也已经不怕长文本，所以这里把原文补回去。
        # 同一条规则最多产出一个 Evidence，重复覆盖不会重复计分。
        if sampled.is_sampled:
            context.decoded_text = self._extend_with_full_text(context, data)
        # 熵分析
        if self._entropy_analyzer:
            try:
                context.entropy = self._entropy_analyzer.calculate_entropy(context.decoded_data)
                context.entropy_class = self._entropy_analyzer.classify_entropy(context.entropy)
            except Exception:
                pass

        if self._should_skip_text_detection(context):
            context.text_detection_skipped = True
            context.is_binary_payload = True
            result = DetectorResult()
            result.tags.append("binary_payload:text_detection_skipped")
            return self._to_dict(result, context)

        # 判断是不是代码
        context.is_code_like = self._looks_like_code(context.decoded_text)

        # JSON语义分析
        self._context_analyzer.analyze_json_context(context)

        # 共享AST分析
        if context.is_code_like:
            self._run_shared_ast_analysis(context)

        # 跑所有检测器
        #
        # TOTAL_TIMEOUT_S 是真生效的，而它**必须留痕**：超时被跳过的检测器
        # 输出的结果 weight=0，不会进 all_results，最终的 dict 和"跑完了什么
        # 也没发现"长得一模一样。而 registry 是按 PRIORITY 排序的，`break`
        # 掉的永远是尾部那几个 —— 反序列化检测在大 body 上会被系统性跳过。
        # 触发门槛也不高：16MB 正文过完 119 条规则就要 8 秒多。
        all_results: List[DetectorResult] = []
        detectors = self._registry.get_all_detectors()
        for index, detector in enumerate(detectors):
            if time.time() - start_time > ResourceLimits.TOTAL_TIMEOUT_S:
                skipped = [d.ATTACK_TYPE.value for d in detectors[index:]]
                context.timed_out = True
                context.detectors_skipped = skipped
                logger.warning(
                    "检测超时（>%.1fs），以下检测器未执行：%s。"
                    "本条结论不完整（uri=%s, body=%d 字节）",
                    ResourceLimits.TOTAL_TIMEOUT_S, ", ".join(skipped),
                    uri[:120], len(data),
                )
                break

            try:
                result = detector.detect(context)
                if result.error == "timeout":
                    # 检测器自己发现超时并提前返回，同样要记下来
                    context.timed_out = True
                    name = detector.ATTACK_TYPE.value
                    if name not in context.detectors_skipped:
                        context.detectors_skipped.append(name)
                if result.detected or result.weight > 0:
                    all_results.append(result)
            except Exception as e:
                logger.error(f"Detector {detector.ATTACK_TYPE.value} failed: {e}")

        # 合并 + 降噪 + ML 研判 + 输出
        final_result = self._merge_results(all_results)
        final_result = self._context_analyzer.apply_noise_reduction(final_result, context)
        ml_verdict = self._apply_ml_fusion(final_result, context)
        return self._to_dict(final_result, context, ml_verdict)

    def _extend_with_full_text(self, context: DetectionContext, data: bytes) -> str:
        """把整段 body 的原文接到解码结果后面，供全量字面量匹配用

        超过 FULL_TEXT_CEILING 时只接前面那一段，并且**必须留痕**：
        计进覆盖率审计 + 打 warning + 在结果里挂 tag，不能让"少看了"
        看起来像"看完没事"。这个上限是纯粹的 OOM 兜底，不是性能开关。
        """
        ceiling = ResourceLimits.FULL_TEXT_CEILING
        raw = data
        truncated = False
        if len(raw) > ceiling:
            raw = raw[:ceiling]
            truncated = True

        try:
            full_text = safe_decode(raw)
        except Exception as e:
            logger.debug(f"Full-body decode failed: {e}")
            return context.decoded_text

        if truncated:
            context.coverage_truncated = True
            logger.warning(
                "HTTP body 共 %d 字节，超过全量匹配上限 %d，仅前 %d 字节参与"
                "字面量匹配，本条结论不完整", len(data), ceiling, ceiling,
            )
            try:
                from core.fast_filter import get_coverage_audit
                get_coverage_audit().record(
                    "attack_detector_full_text_ceiling", len(data), ceiling)
            except Exception:
                pass

        if not context.decoded_text:
            return full_text
        return context.decoded_text + "\n" + full_text

    def _apply_ml_fusion(self, result: "DetectorResult", context: DetectionContext):
        """ML 研判：**只加分，不减分**

        ml_scorer.fuse() 本身在灰区(30-70)内是可加可减的，但听澜是取证/威胁
        狩猎工具，漏检的代价远大于误报。一个未经训练数据验证的模型（当前随包
        发的是人工标定权重）不该有把真实检测压到告警阈值以下的权力，所以这里
        把负向调整钳掉。

        钳掉的只是"生效"，不是"记录"：ML 概率、贡献特征、以及被忽略的负向
        建议都会完整写进结果，供人工研判参考。
        """
        if get_ml_scorer is None:
            return None

        try:
            verdict = get_ml_scorer().fuse(
                result.weight,
                context.decoded_text,
                method=context.method,
                content_type=context.content_type,
                uri=context.uri,
            )
        except Exception as e:
            logger.debug(f"ML fusion skipped: {e}")
            return None

        if verdict is None:
            return None

        if verdict.applied and verdict.adjustment > 0:
            # 这里原来是 min(result.weight + adjustment, 100)。当前撞不到这个
            # 上限（ML 只在灰区 30-70 生效，加满 25 也才 95），但它是颗地雷：
            # GRAY_HIGH 一旦上调，一条 weight=300 的 CRITICAL 会被"加分"操作
            # 直接压成 100，也就是 MEDIUM。加分不该有能力降级。
            result.weight = result.weight + verdict.adjustment
            result.confidence = ThreatLevel.from_weight(result.weight).value
            result.detected = result.weight >= 40
            result.tags.append("ml_boosted")
        elif verdict.adjustment < 0:
            # 记录建议但不执行 —— ML 不得下调判定
            verdict.reason = (verdict.reason
                              + "；负向调整已忽略(ML 不得下调取证判定)")
            verdict.applied = False
            verdict.adjustment = 0

        return verdict

    def _merge_results(self, results: List[DetectorResult]) -> DetectorResult:
        if not results:
            return DetectorResult()

        results.sort(key=lambda r: r.weight, reverse=True)
        merged = results[0]

        for result in results[1:]:
            merged.weight += result.weight
            merged.evidences.extend(result.evidences)
            merged.ast_findings.extend(result.ast_findings)
            merged.obfuscation_score = max(merged.obfuscation_score, result.obfuscation_score)
            merged.tainted_sinks.extend(result.tainted_sinks)
            merged.tags.extend(result.tags)

        merged.confidence = ThreatLevel.from_weight(merged.weight).value
        merged.detected = merged.weight >= 40

        return merged

    def _to_dict(self, result: DetectorResult, context: DetectionContext,
                 ml_verdict=None) -> Dict[str, Any]:
        threat_level = ThreatLevel.from_weight(result.weight)

        return {
            'detection_type': result.attack_type.value,
            'threat_level': threat_level.value,
            'method': context.method,
            'uri': context.uri,
            'total_weight': result.weight,
            'confidence': result.confidence,
            # ML 研判留痕（只加分不减分，被忽略的负向建议也在 reason 里）
            'ml': ml_verdict.to_dict() if ml_verdict is not None else None,
            'indicators': [e.to_indicator_dict() for e in result.evidences],
            'payloads': {
                'decoded': {
                    'decoded': context.decoded_text[:1000],
                    'method': context.decode_chain,
                    'type': context.entropy_class,
                }
            } if context.decode_layers > 0 else {},
            'ast_findings': result.ast_findings,
            'obfuscation_score': result.obfuscation_score,
            'semantic_validated': len(result.tainted_sinks) > 0,
            'tags': list(set(result.tags)),
            'entropy': context.entropy,
            'entropy_class': context.entropy_class,
            'decode_chain': context.decode_chain,
            'decode_layers': context.decode_layers,
            'is_sampled': context.is_sampled,
            'coverage_truncated': context.coverage_truncated,
            # 超时留痕：没有这两个字段，"超时少跑了检测器"和"跑完了什么也
            # 没发现"在输出上完全一样
            'timeout': context.timed_out,
            'detectors_skipped': list(context.detectors_skipped),
            'is_binary_payload': context.is_binary_payload,
            'text_detection_skipped': context.text_detection_skipped,
            'skip_reason': context.skip_reason,
            'protocol_hint': context.protocol_hint,
            'is_json': context.is_json,
            'tainted_sinks': result.tainted_sinks,
            'detected': result.detected,
            'error': result.error,
        }

    def _should_skip_text_detection(self, context: DetectionContext) -> bool:
        """不要把高熵二进制 HTTP body 当成 Web 攻击文本跑正则。"""
        data = context.decoded_data or context.raw_data
        if not data or len(data) < 32:
            return False

        content_type = (context.content_type or "").lower()
        textual_types = (
            "text/",
            "application/json",
            "application/xml",
            "application/x-www-form-urlencoded",
            "multipart/form-data",
        )
        if any(token in content_type for token in textual_types):
            return False

        binary_type = any(token in content_type for token in (
            "application/octet-stream",
            "application/x-binary",
            "binary/octet-stream",
        ))
        sample = data[:4096]
        control_ratio = sum(1 for b in sample if b < 32 and b not in (9, 10, 13)) / len(sample)
        high_ratio = sum(1 for b in sample if b >= 128) / len(sample)
        replacement_ratio = (context.decoded_text[:4096].count("\ufffd") / max(len(context.decoded_text[:4096]), 1))
        high_entropy = context.entropy >= 7.0 or context.entropy_class in {"random", "encrypted", "compressed"}

        if binary_type and (high_entropy or control_ratio > 0.03 or replacement_ratio > 0.01):
            context.skip_reason = "binary_content_type_high_entropy"
            context.protocol_hint = self._binary_protocol_hint(data, context)
            return True

        if high_entropy and (control_ratio > 0.08 or (high_ratio > 0.40 and replacement_ratio > 0.01)):
            context.skip_reason = "high_entropy_non_text_body"
            context.protocol_hint = self._binary_protocol_hint(data, context)
            return True

        return False

    def _binary_protocol_hint(self, data: bytes, context: DetectionContext) -> str:
        try:
            from core.protocol_analyzer import CobaltStrikeAnalyzer
            if CobaltStrikeAnalyzer.detect_encrypted_http_payload(
                data,
                method=context.method,
                content_type=context.content_type,
                uri=context.uri,
            ):
                return "cobalt_strike_encrypted_http"
        except Exception:
            pass
        return ""

    def _looks_like_code(self, text: str) -> bool:
        text = text[:5000]
        patterns = [
            r'\bfunction\s{1,10}\w{1,50}\s{0,5}\(',
            r'\bclass\s{1,10}\w{1,50}',
            r'\b(if|for|while)\s{0,5}\(',
            r'\$\w{1,50}\s{0,5}=',
            r'\beval\s{0,5}\(',
            r'<\?php',
        ]
        for p in patterns:
            if re.search(p, text, re.IGNORECASE):
                return True
        return False

    def list_detectors(self) -> List[str]:
        return self._registry.list_registered()

    def _run_shared_ast_analysis(self, context: DetectionContext) -> None:
        """统一跑一次AST，结果放context.ast_result里"""
        text = context.decoded_text

        if context.ast_analyzed:
            return

        context.ast_analyzed = True
        _obs_incr("ast.attempted")

        if not self._ast_engine:
            return

        if self._fast_filter and FilterDecision is not None:
            try:
                filter_result = self._fast_filter.filter(text, context.content_type)

                if filter_result.decision == FilterDecision.SKIP:
                    logger.debug(f"Shared AST skipped by fast filter: {filter_result.reason}")
                    return

                if filter_result.decision == FilterDecision.CACHED:
                    context.ast_result = filter_result.cached_result
                    return
            except Exception as e:
                logger.debug(f"Fast filter error: {e}")

        if get_ast_cache:
            try:
                ast_cache = get_ast_cache()
                cached = ast_cache.get(text)
                if cached is not None:
                    context.ast_result = cached
                    return
            except Exception:
                pass

        # 检查sink点
        if SelectiveAnalyzer:
            try:
                need_taint, sinks = SelectiveAnalyzer.needs_taint_analysis(text)
                if not sinks:
                    logger.debug("Shared AST skipped: no sink points found")
                    return
            except Exception:
                pass

        # 跑AST
        try:
            _obs_incr("ast.executed")
            ast_result = self._execute_shared_ast(text)
            if ast_result:
                context.ast_result = ast_result
                if getattr(ast_result, "dangerous_calls", None) or \
                        getattr(ast_result, "findings", None):
                    _obs_incr("ast.with_findings")
                if getattr(ast_result, "is_likely_webshell", False):
                    _obs_incr("ast.webshell")
                if get_ast_cache:
                    get_ast_cache().set(text, ast_result)
        except Exception as e:
            logger.debug(f"Shared AST analysis failed: {e}")

    def _execute_shared_ast(self, code: str):
        """直接调用AST，不走线程池(Windows上submit开销太大)"""
        return self._ast_engine.analyze(code)


def detect_attack(
    data: Union[bytes, str],
    method: str = "GET",
    uri: str = "/",
    content_type: str = "",
    headers: Dict[str, str] = None
) -> Dict[str, Any]:
    if isinstance(data, str):
        data = data.encode('utf-8')

    return AttackDetector().detect(data, method, uri, content_type, headers)


def get_detector_registry() -> DetectorRegistry:
    return DetectorRegistry()


def detect_attacks(data: str) -> Dict[str, Any]:
    return detect_attack(data)


def is_malicious(data: str, threshold: int = 40) -> bool:
    result = detect_attack(data)
    return result.get('total_weight', 0) >= threshold


def get_attack_types(data: str) -> List[str]:
    result = detect_attack(data)
    return [result.get('detection_type', 'unknown')]
