# fast_filter.py - AST前置过滤
# 先快速扫一遍，把明显安全的流量过滤掉，省得全部跑AST

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


class FilterDecision(Enum):
    SKIP = auto()           # 跳过 AST 分析（安全流量）
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


class PayloadCache:  # LRU缓存，key是payload的sha256前16位

    def __init__(self, max_size: int = 10000):
        self._cache: OrderedDict = OrderedDict()
        self._max_size = max_size
        self._lock = threading.RLock()
        self._hits = 0
        self._misses = 0

    def _make_key(self, payload: str) -> str:
        return hashlib.sha256(payload.encode('utf-8', errors='ignore')).hexdigest()[:16]

    def get(self, payload: str) -> Optional[any]:
        key = self._make_key(payload)
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

    def get_stats(self) -> Dict[str, int]:
        with self._lock:
            total = self._hits + self._misses
            hit_rate = (self._hits / total * 100) if total > 0 else 0
            return {
                'size': len(self._cache),
                'max_size': self._max_size,
                'hits': self._hits,
                'misses': self._misses,
                'hit_rate': f"{hit_rate:.1f}%"
            }

    def clear(self) -> None:
        with self._lock:
            self._cache.clear()
            self._hits = 0
            self._misses = 0


_payload_cache = PayloadCache(max_size=10000)
_ast_result_cache = PayloadCache(max_size=5000)


def get_payload_cache() -> PayloadCache:
    return _payload_cache


def get_ast_cache() -> PayloadCache:
    return _ast_result_cache


class FastFilter:

    # 长度限制
    MIN_PAYLOAD_LEN = 10
    MAX_PAYLOAD_LEN = 500000
    FAST_SCAN_LIMIT = 10000

    # 预编译正则
    _KEYWORD_PATTERN = None
    _DYNAMIC_PATTERN = None

    def __init__(self):
        self._compile_patterns()

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
            dynamic_escaped = [re.escape(d) for d in DangerKeywords.DYNAMIC_PATTERNS]
            FastFilter._DYNAMIC_PATTERN = re.compile(
                '(' + '|'.join(dynamic_escaped) + ')'
            )

    def filter(self, payload: str, content_type: str = "") -> FilterResult:  # 快速过滤，决定要不要跑AST
        # 长度太短直接跳过
        payload_len = len(payload)

        if payload_len < self.MIN_PAYLOAD_LEN:
            return FilterResult(
                decision=FilterDecision.SKIP,
                reason="payload_too_short"
            )

        if payload_len > self.MAX_PAYLOAD_LEN:
            return FilterResult(
                decision=FilterDecision.SKIP,
                reason="payload_too_long"
            )

        # 查缓存
        cached = _payload_cache.get(payload)
        if cached is not None:
            return FilterResult(
                decision=FilterDecision.CACHED,
                reason="cache_hit",
                cached_result=cached
            )

        # Content-Type 过滤
        if self._should_skip_by_content_type(content_type):
            return FilterResult(
                decision=FilterDecision.SKIP,
                reason=f"safe_content_type:{content_type}"
            )

        # 取前面一截来扫描
        scan_text = payload[:self.FAST_SCAN_LIMIT]

        # 关键字扫描
        matched_keywords = []
        risk_score = 0

        # 检查危险函数
        func_matches = self._KEYWORD_PATTERN.findall(scan_text)
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
        taint_matches = self._TAINT_PATTERN.findall(scan_text)
        if taint_matches:
            matched_keywords.extend(taint_matches)
            risk_score += len(taint_matches) * 20

        # 检查动态特征
        dynamic_matches = self._DYNAMIC_PATTERN.findall(scan_text)
        if dynamic_matches:
            matched_keywords.extend(dynamic_matches)
            risk_score += len(dynamic_matches) * 15

        # 没有任何危险关键字就跳过
        if not matched_keywords:
            return FilterResult(
                decision=FilterDecision.SKIP,
                reason="no_dangerous_keywords"
            )

        entropy = EntropyCalculator.calculate_str(scan_text)

        # 低熵值就是普通文本
        if entropy < EntropyCalculator.ENTROPY_LOW and risk_score < 30:
            return FilterResult(
                decision=FilterDecision.SKIP,
                reason="low_entropy_normal_text",
                entropy=entropy
            )

        # 高熵值加分
        if entropy > EntropyCalculator.ENTROPY_SUSPICIOUS:
            risk_score += 20

        # 根据前面的结果决定要不要跑AST
        risk_score = min(risk_score, 100)

        if risk_score >= 60:
            return FilterResult(
                decision=FilterDecision.FULL_AST,
                reason="high_risk",
                entropy=entropy,
                matched_keywords=list(set(matched_keywords)),
                risk_score=risk_score
            )
        elif risk_score >= 30:
            return FilterResult(
                decision=FilterDecision.FAST_DETECT,
                reason="medium_risk",
                entropy=entropy,
                matched_keywords=list(set(matched_keywords)),
                risk_score=risk_score
            )
        else:
            return FilterResult(
                decision=FilterDecision.SKIP,
                reason="low_risk",
                entropy=entropy,
                matched_keywords=list(set(matched_keywords)),
                risk_score=risk_score
            )

    def _should_skip_by_content_type(self, content_type: str) -> bool:
        if not content_type:
            return False

        ct_lower = content_type.lower()

        # 安全的静态资源类型
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


def get_fast_filter() -> FastFilter:
    return _fast_filter


def quick_check(payload: str, content_type: str = "") -> FilterResult:
    return _fast_filter.filter(payload, content_type)


def should_analyze(payload: str, content_type: str = "") -> bool:
    need_ast, _ = _fast_filter.should_use_ast(payload, content_type)
    return need_ast


def get_score_breakdown(payload_data: bytes, content_type: str = "", http_method: str = "") -> Optional[dict]:
    """PayloadViewer用的得分拆解，整合AST/熵值/统计学/快速过滤几个模块的结果"""
    if not payload_data or len(payload_data) < 10:
        return None

    try:
        # 转换为字符串进行分析
        try:
            payload_str = payload_data.decode('utf-8', errors='ignore')
        except:
            payload_str = str(payload_data)

        entropy_result = _analyze_entropy(payload_data, payload_str)
        structure_result = _analyze_structure(payload_str)
        char_freq_result = _analyze_char_frequency(payload_str)
        length_result = _analyze_payload_length(payload_data)
        ast_result = _analyze_ast(payload_str)
        filter_result = _fast_filter.filter(payload_str, content_type)

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
