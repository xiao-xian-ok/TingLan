# entropy_analyzer.py - 信息熵分析

import math
from typing import Dict, Tuple, Optional
from collections import Counter


# 英文字母频率表 (chi-squared检测用)
ENGLISH_FREQ = {
    'a': 0.0817, 'b': 0.0149, 'c': 0.0278, 'd': 0.0425, 'e': 0.1270,
    'f': 0.0223, 'g': 0.0202, 'h': 0.0609, 'i': 0.0697, 'j': 0.0015,
    'k': 0.0077, 'l': 0.0403, 'm': 0.0241, 'n': 0.0675, 'o': 0.0751,
    'p': 0.0193, 'q': 0.0010, 'r': 0.0599, 's': 0.0633, 't': 0.0906,
    'u': 0.0276, 'v': 0.0098, 'w': 0.0236, 'x': 0.0015, 'y': 0.0197,
    'z': 0.0007
}

BASE64_CHARS = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
HEX_CHARS = set("0123456789abcdefABCDEF")
PRINTABLE_ASCII = set(range(32, 127))


class EntropyAnalyzer:

    ENTROPY_RANDOM = 7.5
    ENTROPY_COMPRESSED = 7.0
    ENTROPY_ENCODED = 5.5
    ENTROPY_TEXT = 4.5
    ENTROPY_STRUCTURED = 3.0

    def __init__(self):
        pass

    def calculate_entropy(self, data: bytes) -> float:
        """计算Shannon熵，返回0.0~8.0"""
        if not data:
            return 0.0

        byte_counts = Counter(data)
        total_bytes = len(data)

        entropy = 0.0
        for count in byte_counts.values():
            if count > 0:
                probability = count / total_bytes
                entropy -= probability * math.log2(probability)

        return entropy

    def calculate_entropy_str(self, text: str, encoding: str = 'utf-8') -> float:
        try:
            return self.calculate_entropy(text.encode(encoding))
        except (UnicodeEncodeError, UnicodeDecodeError):
            return self._calculate_char_entropy(text)

    def _calculate_char_entropy(self, text: str) -> float:
        if not text:
            return 0.0

        char_counts = Counter(text)
        total_chars = len(text)

        entropy = 0.0
        for count in char_counts.values():
            if count > 0:
                probability = count / total_chars
                entropy -= probability * math.log2(probability)

        return entropy

    def classify_entropy(self, entropy: float) -> str:
        """按熵值区间分类"""
        if entropy >= self.ENTROPY_RANDOM:
            return "random"
        elif entropy >= self.ENTROPY_COMPRESSED:
            return "compressed"
        elif entropy >= self.ENTROPY_ENCODED:
            return "encoded"
        elif entropy >= self.ENTROPY_TEXT:
            return "text"
        elif entropy >= self.ENTROPY_STRUCTURED:
            return "structured"
        else:
            return "empty"

    def is_meaningful_data(self, data: bytes) -> Tuple[bool, float, str]:
        """判断数据是否有意义，返回(有意义, 熵值, 分类)"""
        entropy = self.calculate_entropy(data)
        classification = self.classify_entropy(entropy)

        is_meaningful = (self.ENTROPY_STRUCTURED <= entropy <= self.ENTROPY_COMPRESSED)

        return is_meaningful, entropy, classification


class LanguageDetector:
    """基于字符频率做语言检测"""

    CHI_SQUARED_THRESHOLD = 100.0

    def __init__(self):
        pass

    def detect_english(self, text: str) -> Tuple[bool, float]:
        """用chi-squared检验判断是不是英文，返回(是否英文, chi值)"""
        if not text:
            return False, float('inf')

        text_lower = text.lower()
        letter_counts = Counter(c for c in text_lower if c.isalpha())
        total_letters = sum(letter_counts.values())

        if total_letters < 10:
            return False, float('inf')

        chi_squared = 0.0
        for letter, expected_freq in ENGLISH_FREQ.items():
            observed = letter_counts.get(letter, 0)
            expected = expected_freq * total_letters
            if expected > 0:
                chi_squared += ((observed - expected) ** 2) / expected

        is_english = chi_squared < self.CHI_SQUARED_THRESHOLD
        return is_english, chi_squared

    def get_printable_ratio(self, data: bytes) -> float:
        """可打印字符占多少比例"""
        if not data:
            return 0.0

        printable_count = sum(1 for b in data if b in PRINTABLE_ASCII)
        return printable_count / len(data)

    def is_readable_text(self, text: str, min_printable_ratio: float = 0.85) -> bool:
        """可打印字符比例够高就算可读"""
        if not text:
            return False

        try:
            data = text.encode('utf-8')
            ratio = self.get_printable_ratio(data)
            return ratio >= min_printable_ratio
        except UnicodeEncodeError:
            return False


class EncodingDetector:
    """识别base64/hex/url编码"""

    def __init__(self):
        pass

    def detect_base64(self, text: str) -> Tuple[bool, float]:
        """检查是不是base64，返回(是否, 置信度)"""
        if not text or len(text) < 4:
            return False, 0.0

        text = text.strip()

        base64_ratio = sum(1 for c in text if c in BASE64_CHARS) / len(text)
        if base64_ratio < 0.95:
            return False, base64_ratio

        # base64输出长度必须是4的倍数
        if len(text) % 4 != 0:
            return False, 0.5

        # padding最多2个=且只能在末尾
        padding_count = text.count('=')
        if padding_count > 2:
            return False, 0.3
        if padding_count > 0 and not text.endswith('=' * padding_count):
            return False, 0.3

        return True, 0.9 + (0.1 * (1 if padding_count <= 2 else 0))

    def detect_hex(self, text: str) -> Tuple[bool, float]:
        """检查是不是hex编码"""
        if not text or len(text) < 2:
            return False, 0.0

        # 去掉0x、\x这些前缀
        text = text.strip()
        if text.startswith(('0x', '0X')):
            text = text[2:]
        if text.startswith('\\x'):
            text = text.replace('\\x', '')

        hex_ratio = sum(1 for c in text if c in HEX_CHARS) / len(text) if text else 0
        if hex_ratio < 0.95:
            return False, hex_ratio

        # hex长度应该是偶数
        if len(text) % 2 != 0:
            return False, 0.5

        return True, 0.85 + (0.15 * hex_ratio)

    def detect_url_encoded(self, text: str) -> Tuple[bool, float]:
        """检查是不是URL编码(%XX格式)"""
        if not text:
            return False, 0.0

        percent_count = text.count('%')
        if percent_count == 0:
            return False, 0.0

        # 找%XX模式
        import re
        url_encoded_pattern = re.compile(r'%[0-9A-Fa-f]{2}')
        matches = url_encoded_pattern.findall(text)

        if not matches:
            return False, 0.0

        encoded_chars = len(matches) * 3  # %XX占3字符
        encoding_ratio = encoded_chars / len(text)

        is_url_encoded = encoding_ratio > 0.1 and len(matches) == percent_count
        confidence = min(0.95, 0.5 + encoding_ratio)

        return is_url_encoded, confidence

    def detect_encoding_type(self, text: str) -> Tuple[Optional[str], float]:
        """挨个试一遍，返回最匹配的编码类型和置信度"""
        detectors = [
            ('base64', self.detect_base64),
            ('hex', self.detect_hex),
            ('url', self.detect_url_encoded),
        ]

        best_match = (None, 0.0)
        for encoding_name, detector in detectors:
            is_match, confidence = detector(text)
            if is_match and confidence > best_match[1]:
                best_match = (encoding_name, confidence)

        return best_match


class MeaningfulnessAnalyzer:
    """把熵分析、语言检测、编码检测组合起来综合判断"""

    def __init__(self):
        self.entropy_analyzer = EntropyAnalyzer()
        self.language_detector = LanguageDetector()
        self.encoding_detector = EncodingDetector()

    def analyze(self, data: bytes) -> Dict:
        """综合分析，返回熵值、分类、编码类型等"""
        result = {
            'entropy': 0.0,
            'entropy_class': 'empty',
            'is_meaningful': False,
            'printable_ratio': 0.0,
            'is_english': False,
            'chi_squared': float('inf'),
            'detected_encoding': None,
            'encoding_confidence': 0.0,
            'confidence_score': 0.0
        }

        if not data:
            return result

        is_meaningful, entropy, entropy_class = self.entropy_analyzer.is_meaningful_data(data)
        result['entropy'] = entropy
        result['entropy_class'] = entropy_class
        result['is_meaningful'] = is_meaningful

        # 可打印字符占比
        result['printable_ratio'] = self.language_detector.get_printable_ratio(data)

        # 试着当文本解码做进一步分析
        try:
            text = data.decode('utf-8', errors='ignore')
            is_english, chi_squared = self.language_detector.detect_english(text)
            result['is_english'] = is_english
            result['chi_squared'] = chi_squared

            # 看看是什么编码
            detected_encoding, encoding_confidence = self.encoding_detector.detect_encoding_type(text)
            result['detected_encoding'] = detected_encoding
            result['encoding_confidence'] = encoding_confidence
        except:
            pass

        # 算个综合分
        result['confidence_score'] = self._calculate_confidence(result)

        return result

    def _calculate_confidence(self, result: Dict) -> float:
        score = 0.0

        # 熵值在合理范围加分
        entropy = result['entropy']
        if 3.5 <= entropy <= 6.5:
            score += 0.3

        printable_ratio = result['printable_ratio']
        score += 0.3 * printable_ratio

        if result['is_english']:
            score += 0.2

        if result['is_meaningful']:
            score += 0.2

        return min(1.0, score)


# 快捷方式
def calculate_entropy(data: bytes) -> float:
    return EntropyAnalyzer().calculate_entropy(data)


def is_meaningful_text(text: str) -> bool:
    analyzer = MeaningfulnessAnalyzer()
    try:
        result = analyzer.analyze(text.encode('utf-8'))
        return result['confidence_score'] >= 0.5
    except:
        return False


def detect_encoding(text: str) -> Optional[str]:
    detector = EncodingDetector()
    encoding_type, confidence = detector.detect_encoding_type(text)
    return encoding_type if confidence > 0.7 else None
