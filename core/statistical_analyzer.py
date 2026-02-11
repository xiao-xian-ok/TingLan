# statistical_analyzer.py
# 统计分析，算各种指标

import re
import math
import base64
import logging
from typing import Dict, List, Optional, Any, Tuple

logger = logging.getLogger(__name__)


class StatisticalConfig:

    ENTROPY_THRESHOLDS = {
        'critical': 6.5,    # 接近随机噪声
        'high': 5.5,        # 高度加密/混淆
        'medium': 4.5,      # 可能混淆
        'normal_max': 4.0,
    }

    SPECIAL_CHAR_THRESHOLDS = {
        'critical': 0.5,
        'high': 0.35,
        'medium': 0.25,
        'normal_max': 0.15,
    }

    NON_PRINTABLE_THRESHOLDS = {
        'high': 0.3,
        'medium': 0.1,
        'low': 0.05,
    }

    ALPHANUMERIC_THRESHOLDS = {
        'low': 0.4,
        'normal_min': 0.5,
    }

    WEIGHTS = {
        'entropy_critical': 70,
        'entropy_high': 50,
        'entropy_medium': 30,
        'special_char_critical': 60,
        'special_char_high': 45,
        'special_char_medium': 25,
        'non_printable_high': 45,
        'non_printable_medium': 25,
        'low_alphanumeric': 20,
        'combined_anomaly': 30,  # 多指标异常组合加权
    }

    DETECTION_THRESHOLD = 30
    SUSPICIOUS_THRESHOLD = 50
    HIGH_CONFIDENCE_THRESHOLD = 80


class StatisticalAnalyzer:
    """用熵值、特殊字符比例等统计指标检测混淆/加密流量"""

    def __init__(self):
        self.config = StatisticalConfig()

    @staticmethod
    def calculate_entropy(data: str) -> float:
        """Shannon信息熵, H = -sum(p(x)*log2(p(x))), 加密数据通常>5.5"""
        if not data:
            return 0.0

        freq = {}
        for c in data:
            freq[c] = freq.get(c, 0) + 1

        length = len(data)
        entropy = 0.0
        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)

        return entropy

    @staticmethod
    def calculate_byte_entropy(data: bytes) -> float:
        """字节级信息熵，用于二进制数据"""
        if not data:
            return 0.0

        freq = {}
        for b in data:
            freq[b] = freq.get(b, 0) + 1

        length = len(data)
        entropy = 0.0
        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)

        return entropy

    @staticmethod
    def calculate_special_char_ratio(data: str) -> Tuple[float, Dict[str, int]]:
        """混淆代码的特殊字符(^$(){}@!~等)比例通常畸高"""
        if not data:
            return 0.0, {}

        special_chars = set('^$(){}[]@!~`|\\<>%&*+=;:\'"')

        char_counts = {}
        total_special = 0

        for c in data:
            if c in special_chars:
                total_special += 1
                char_counts[c] = char_counts.get(c, 0) + 1

        ratio = total_special / len(data) if len(data) > 0 else 0.0
        return ratio, char_counts

    @staticmethod
    def calculate_non_printable_ratio(data: str) -> float:
        if not data:
            return 0.0

        non_printable = sum(1 for c in data if ord(c) < 32 or ord(c) > 126)
        return non_printable / len(data)

    @staticmethod
    def calculate_alphanumeric_ratio(data: str) -> float:
        if not data:
            return 0.0

        alnum_count = sum(1 for c in data if c.isalnum())
        return alnum_count / len(data)

    @staticmethod
    def calculate_digit_ratio(data: str) -> float:
        if not data:
            return 0.0

        digit_count = sum(1 for c in data if c.isdigit())
        return digit_count / len(data)

    @staticmethod
    def calculate_uppercase_ratio(data: str) -> float:
        """大写比例，Base64数据有特定的大小写分布"""
        if not data:
            return 0.0

        letters = [c for c in data if c.isalpha()]
        if not letters:
            return 0.0

        uppercase_count = sum(1 for c in letters if c.isupper())
        return uppercase_count / len(letters)

    @staticmethod
    def is_likely_base64(data: str) -> Tuple[bool, float]:
        if not data or len(data) < 20:
            return False, 0.0

        clean = re.sub(r'\s', '', data)

        base64_chars = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=')
        non_base64 = sum(1 for c in clean if c not in base64_chars)

        if non_base64 > 0:
            ratio = 1 - (non_base64 / len(clean))
            if ratio < 0.95:
                return False, ratio
        else:
            ratio = 1.0

        padding = clean.count('=')
        if padding > 2:
            return False, 0.0

        try:
            base64.b64decode(clean)
            return True, ratio
        except Exception:
            return False, ratio * 0.5

    @staticmethod
    def detect_repetition_patterns(data: str) -> Dict:
        """检测重复模式，某些混淆技术会产生重复代码模式"""
        if not data or len(data) < 50:
            return {'has_repetition': False, 'repetition_ratio': 0.0, 'common_patterns': []}

        patterns = {}
        for length in range(3, 11):
            for i in range(len(data) - length):
                pattern = data[i:i+length]
                if pattern.isalnum() or len(set(pattern)) < 2:
                    continue
                patterns[pattern] = patterns.get(pattern, 0) + 1

        common_patterns = [(p, c) for p, c in patterns.items() if c >= 3]
        common_patterns.sort(key=lambda x: x[1], reverse=True)

        total_repetition = sum(len(p) * c for p, c in common_patterns[:10])
        repetition_ratio = total_repetition / len(data) if len(data) > 0 else 0.0

        return {
            'has_repetition': repetition_ratio > 0.1,
            'repetition_ratio': repetition_ratio,
            'common_patterns': common_patterns[:5]
        }

    def analyze(self, data: str, include_details: bool = True) -> Dict:
        """综合统计学分析，返回各项指标和置信度"""
        result = {
            'entropy': 0.0,
            'entropy_level': 'normal',
            'special_char_ratio': 0.0,
            'special_char_level': 'normal',
            'non_printable_ratio': 0.0,
            'alphanumeric_ratio': 0.0,
            'digit_ratio': 0.0,
            'uppercase_ratio': 0.0,
            'is_likely_base64': False,
            'base64_confidence': 0.0,
            'total_weight': 0,
            'confidence': 'none',
            'indicators': [],
            'recommendation': ''
        }

        if not data or len(data) < 20:
            return result

        # 算各项指标
        entropy = self.calculate_entropy(data)
        special_ratio, special_chars = self.calculate_special_char_ratio(data)
        non_print_ratio = self.calculate_non_printable_ratio(data)
        alnum_ratio = self.calculate_alphanumeric_ratio(data)
        digit_ratio = self.calculate_digit_ratio(data)
        uppercase_ratio = self.calculate_uppercase_ratio(data)
        is_base64, base64_conf = self.is_likely_base64(data)

        result['entropy'] = entropy
        result['special_char_ratio'] = special_ratio
        result['non_printable_ratio'] = non_print_ratio
        result['alphanumeric_ratio'] = alnum_ratio
        result['digit_ratio'] = digit_ratio
        result['uppercase_ratio'] = uppercase_ratio
        result['is_likely_base64'] = is_base64
        result['base64_confidence'] = base64_conf

        if include_details:
            result['special_char_counts'] = special_chars

        thresholds = self.config

        # 信息熵
        if entropy >= thresholds.ENTROPY_THRESHOLDS['critical']:
            result['entropy_level'] = 'critical'
            result['total_weight'] += thresholds.WEIGHTS['entropy_critical']
            result['indicators'].append({
                'name': 'critical_entropy',
                'weight': thresholds.WEIGHTS['entropy_critical'],
                'description': f'极高信息熵({entropy:.2f})，数据接近随机噪声，高度可疑',
                'matched_text': f'entropy={entropy:.2f} (临界值:{thresholds.ENTROPY_THRESHOLDS["critical"]})'
            })
        elif entropy >= thresholds.ENTROPY_THRESHOLDS['high']:
            result['entropy_level'] = 'high'
            result['total_weight'] += thresholds.WEIGHTS['entropy_high']
            result['indicators'].append({
                'name': 'high_entropy',
                'weight': thresholds.WEIGHTS['entropy_high'],
                'description': f'高信息熵({entropy:.2f})，数据高度加密/混淆',
                'matched_text': f'entropy={entropy:.2f}'
            })
        elif entropy >= thresholds.ENTROPY_THRESHOLDS['medium']:
            result['entropy_level'] = 'medium'
            result['total_weight'] += thresholds.WEIGHTS['entropy_medium']
            result['indicators'].append({
                'name': 'medium_entropy',
                'weight': thresholds.WEIGHTS['entropy_medium'],
                'description': f'中等信息熵({entropy:.2f})，可能存在混淆',
                'matched_text': f'entropy={entropy:.2f}'
            })

        # 特殊字符比例
        if special_ratio >= thresholds.SPECIAL_CHAR_THRESHOLDS['critical']:
            result['special_char_level'] = 'critical'
            result['total_weight'] += thresholds.WEIGHTS['special_char_critical']
            result['indicators'].append({
                'name': 'critical_special_char_ratio',
                'weight': thresholds.WEIGHTS['special_char_critical'],
                'description': f'特殊字符比例极高({special_ratio:.1%})，严重异常',
                'matched_text': f'special_chars={special_ratio:.1%}'
            })
        elif special_ratio >= thresholds.SPECIAL_CHAR_THRESHOLDS['high']:
            result['special_char_level'] = 'high'
            result['total_weight'] += thresholds.WEIGHTS['special_char_high']
            result['indicators'].append({
                'name': 'high_special_char_ratio',
                'weight': thresholds.WEIGHTS['special_char_high'],
                'description': f'特殊字符比例畸高({special_ratio:.1%})，严重混淆特征',
                'matched_text': f'special_chars={special_ratio:.1%}'
            })
        elif special_ratio >= thresholds.SPECIAL_CHAR_THRESHOLDS['medium']:
            result['special_char_level'] = 'medium'
            result['total_weight'] += thresholds.WEIGHTS['special_char_medium']
            result['indicators'].append({
                'name': 'medium_special_char_ratio',
                'weight': thresholds.WEIGHTS['special_char_medium'],
                'description': f'特殊字符比例较高({special_ratio:.1%})，可能混淆',
                'matched_text': f'special_chars={special_ratio:.1%}'
            })

        # 不可打印字符
        if non_print_ratio >= thresholds.NON_PRINTABLE_THRESHOLDS['high']:
            result['total_weight'] += thresholds.WEIGHTS['non_printable_high']
            result['indicators'].append({
                'name': 'high_non_printable',
                'weight': thresholds.WEIGHTS['non_printable_high'],
                'description': f'不可打印字符比例高({non_print_ratio:.1%})，可能是加密/二进制数据',
                'matched_text': f'non_printable={non_print_ratio:.1%}'
            })
        elif non_print_ratio >= thresholds.NON_PRINTABLE_THRESHOLDS['medium']:
            result['total_weight'] += thresholds.WEIGHTS['non_printable_medium']
            result['indicators'].append({
                'name': 'medium_non_printable',
                'weight': thresholds.WEIGHTS['non_printable_medium'],
                'description': f'不可打印字符比例中等({non_print_ratio:.1%})',
                'matched_text': f'non_printable={non_print_ratio:.1%}'
            })

        # 低字母数字比例，结合其他指标看
        if alnum_ratio < thresholds.ALPHANUMERIC_THRESHOLDS['low']:
            if entropy > 4.0 or special_ratio > 0.2:
                result['total_weight'] += thresholds.WEIGHTS['low_alphanumeric']
                result['indicators'].append({
                    'name': 'low_alphanumeric',
                    'weight': thresholds.WEIGHTS['low_alphanumeric'],
                    'description': f'字母数字比例低({alnum_ratio:.1%})，结合其他指标可疑',
                    'matched_text': f'alphanumeric={alnum_ratio:.1%}'
                })

        # 多指标异常组合
        anomaly_count = 0
        if result['entropy_level'] in ['high', 'critical']:
            anomaly_count += 1
        if result['special_char_level'] in ['high', 'critical']:
            anomaly_count += 1
        if non_print_ratio >= thresholds.NON_PRINTABLE_THRESHOLDS['medium']:
            anomaly_count += 1

        if anomaly_count >= 2:
            result['total_weight'] += thresholds.WEIGHTS['combined_anomaly']
            result['indicators'].append({
                'name': 'combined_anomaly',
                'weight': thresholds.WEIGHTS['combined_anomaly'],
                'description': f'多指标异常组合({anomaly_count}项)，高度可疑',
                'matched_text': f'{anomaly_count} anomalies detected'
            })

        # Base64检测
        if is_base64 and base64_conf > 0.9:
            result['indicators'].append({
                'name': 'base64_detected',
                'weight': 20,
                'description': f'检测到Base64编码数据(置信度:{base64_conf:.1%})',
                'matched_text': f'base64_confidence={base64_conf:.1%}'
            })
            result['total_weight'] += 20

        # 置信度判定
        if result['total_weight'] >= thresholds.HIGH_CONFIDENCE_THRESHOLD:
            result['confidence'] = 'high'
            result['recommendation'] = '强烈建议进一步分析，高度可疑的混淆/加密流量'
        elif result['total_weight'] >= thresholds.SUSPICIOUS_THRESHOLD:
            result['confidence'] = 'medium'
            result['recommendation'] = '建议进一步分析，存在可疑的统计学特征'
        elif result['total_weight'] >= thresholds.DETECTION_THRESHOLD:
            result['confidence'] = 'low'
            result['recommendation'] = '轻微异常，可能需要关注'
        else:
            result['confidence'] = 'none'
            result['recommendation'] = '统计学特征正常'

        return result

    def analyze_http_body(self, body: str, content_type: str = None) -> Dict:
        result = self.analyze(body)

        if content_type:
            ct_lower = content_type.lower()

            # 正常的二进制类型不报
            if any(t in ct_lower for t in ['image/', 'audio/', 'video/', 'font/', 'application/pdf']):
                result['recommendation'] = '正常的二进制内容类型，忽略统计学异常'
                result['confidence'] = 'none'
                return result

            # multipart/form-data可能含二进制，降低不可打印字符的权重
            if 'multipart/form-data' in ct_lower:
                for ind in result['indicators']:
                    if 'non_printable' in ind['name']:
                        ind['weight'] = ind['weight'] // 2
                        result['total_weight'] -= ind['weight']

        return result


def analyze_data(data: str) -> Dict:
    analyzer = StatisticalAnalyzer()
    return analyzer.analyze(data)


def calculate_entropy(data: str) -> float:
    return StatisticalAnalyzer.calculate_entropy(data)


def is_suspicious(data: str, threshold: int = 30) -> Tuple[bool, Dict]:
    analyzer = StatisticalAnalyzer()
    result = analyzer.analyze(data)
    return result['total_weight'] >= threshold, result
