# attack_detector.py - OWASP攻击检测
# sqli/xss/rce/xxe/ssrf/upload 插件式检测

import re
import time
import hashlib
import threading
import json
import concurrent.futures
from abc import ABC, abstractmethod
from enum import Enum, auto
from dataclasses import dataclass, field
from typing import (
    List, Dict, Optional, Any, Tuple, Set,
    Type, Callable, Union, Pattern
)
from functools import wraps
from urllib.parse import unquote, urlparse
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


def safe_regex_match(pattern: Pattern, text: str, max_len: int = 100000) -> Optional[re.Match]:
    """正则匹配，截断超长输入防ReDoS"""
    if len(text) > max_len:
        text = text[:max_len // 2] + text[-max_len // 2:]

    try:
        return pattern.search(text)
    except Exception:
        return None


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
    MAX_BODY_SIZE = 1 * 1024 * 1024       # 超过1MB就抽样
    MAX_DECODE_DEPTH = 15
    MAX_DECODE_SIZE = 10 * 1024 * 1024
    REGEX_TIMEOUT_MS = 100
    AST_TIMEOUT_MS = 500
    TOTAL_TIMEOUT_S = 5.0

    SAMPLE_HEAD_SIZE = 64 * 1024
    SAMPLE_TAIL_SIZE = 64 * 1024
    SAMPLE_OFFSETS = [0.25, 0.5, 0.75]

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
    """大数据量的话只取头尾64KB + 中间几个采样点"""

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
    def combined_text(self) -> str:
        """合并样本为文本供正则用"""
        combined = b''.join(s for _, s in self.samples)
        return safe_decode(combined)


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

    is_json: bool = False
    json_values: List[str] = field(default_factory=list)

    # 所有检测器共享AST结果，只分析一次
    ast_result: Optional[Any] = None
    ast_analyzed: bool = False

    start_time: float = 0.0
    is_sampled: bool = False


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

    @abstractmethod
    def detect(self, context: DetectionContext) -> DetectorResult:
        pass

    def _match_patterns(self, text: str, context: DetectionContext) -> List[Evidence]:
        """跑所有正则，返回匹配到的证据"""
        evidences = []

        if len(text) > ResourceLimits.MAX_REGEX_INPUT_LEN:
            text = text[:ResourceLimits.MAX_REGEX_INPUT_LEN // 2] + \
                   text[-ResourceLimits.MAX_REGEX_INPUT_LEN // 2:]

        for name, (pattern, weight) in self._patterns.items():
            try:
                match = self._safe_regex_search(pattern, text)
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

    def _safe_regex_search(self, pattern: Pattern, text: str):
        """输入已截断，直接search就行"""
        return pattern.search(text)

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
    """降噪用，排除swagger/静态资源/health check等"""

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

    def apply_noise_reduction(self, result: DetectorResult, context: DetectionContext) -> DetectorResult:

        if context.is_json and not context.json_values:
            result.weight = int(result.weight * 0.5)
            result.tags.append("noise_reduced:empty_json")

        for name, rule in self._compiled_rules.items():
            # Content-Type 匹配
            if rule['content_types'] and context.content_type not in rule['content_types']:
                continue

            # URI 匹配
            uri_matched = False
            for pattern in rule['uri_patterns']:
                if pattern.search(context.uri):
                    uri_matched = True
                    break

            if not uri_matched and rule['uri_patterns']:
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
                    sampled.samples[0][1] if sampled.samples else data,
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
        # 熵分析
        if self._entropy_analyzer:
            try:
                context.entropy = self._entropy_analyzer.calculate_entropy(context.decoded_data)
                context.entropy_class = self._entropy_analyzer.classify_entropy(context.entropy)
            except Exception:
                pass

        # 判断是不是代码
        context.is_code_like = self._looks_like_code(context.decoded_text)

        # JSON语义分析
        self._context_analyzer.analyze_json_context(context)

        # 共享AST分析
        if context.is_code_like:
            self._run_shared_ast_analysis(context)

        # 跑所有检测器
        all_results: List[DetectorResult] = []
        for detector in self._registry.get_all_detectors():
            if time.time() - start_time > ResourceLimits.TOTAL_TIMEOUT_S:
                break

            try:
                result = detector.detect(context)
                if result.detected or result.weight > 0:
                    all_results.append(result)
            except Exception as e:
                logger.error(f"Detector {detector.ATTACK_TYPE.value} failed: {e}")

        # 合并 + 降噪 + 输出
        final_result = self._merge_results(all_results)
        final_result = self._context_analyzer.apply_noise_reduction(final_result, context)
        return self._to_dict(final_result, context)

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

    def _to_dict(self, result: DetectorResult, context: DetectionContext) -> Dict[str, Any]:
        threat_level = ThreatLevel.from_weight(result.weight)

        return {
            'detection_type': result.attack_type.value,
            'threat_level': threat_level.value,
            'method': context.method,
            'uri': context.uri,
            'total_weight': result.weight,
            'confidence': result.confidence,
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
            'is_json': context.is_json,
            'tainted_sinks': result.tainted_sinks,
            'detected': result.detected,
            'error': result.error,
        }

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
            ast_result = self._execute_shared_ast(text)
            if ast_result:
                context.ast_result = ast_result
                if get_ast_cache:
                    get_ast_cache().set(text, ast_result)
        except Exception as e:
            logger.debug(f"Shared AST analysis failed: {e}")

    def _execute_shared_ast(self, code: str):
        """直接调用AST，不走线程池(Windows上submit开销太大)"""
        if len(code) > ResourceLimits.MAX_AST_CODE_LEN:
            logger.debug(f"AST skipped: code too long ({len(code)})")
            return None
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
