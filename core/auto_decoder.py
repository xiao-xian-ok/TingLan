# auto_decoder.py - 自动解码器
# 类似CyberChef的多层自动解码，base64/url/hex/rot13/gzip都能解
# 递归解到解不动为止

import base64
import binascii
import gzip
import zlib
import re
import math
import codecs
from typing import List, Optional, Tuple, Dict, Any
from dataclasses import dataclass, field
from enum import Enum
from collections import Counter
import uuid
from html import unescape as html_unescape


class DecodingMethod(Enum):
    BASE64 = "base64"
    BASE64_URL = "base64url"
    BASE32 = "base32"
    BASE58 = "base58"
    HEX = "hex"
    HEX_SPACED = "hex_spaced"
    URL = "url"
    BINARY = "binary"
    OCTAL = "octal"
    DECIMAL = "decimal"
    HTML_ENTITY = "html_entity"
    MORSE = "morse"
    GZIP = "gzip"
    ZLIB = "zlib"
    ROT13 = "rot13"
    XOR = "xor"
    REVERSE = "reverse"
    RAW = "raw"


@dataclass
class DecodingCheck:
    method: DecodingMethod
    pattern: Optional[re.Pattern] = None
    args: Dict[str, Any] = field(default_factory=dict)
    entropy_range: Optional[Tuple[float, float]] = None
    min_length: int = 4
    priority: int = 50


@dataclass
class DecodingStep:  # 单步解码记录
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    method: DecodingMethod = DecodingMethod.RAW
    input_data: bytes = b""
    output_data: bytes = b""
    success: bool = False
    error: str = ""
    confidence: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def input_preview(self) -> str:
        try:
            text = self.input_data.decode('utf-8', errors='replace')
            return text[:100] + "..." if len(text) > 100 else text
        except:
            return self.input_data[:50].hex() + "..."

    @property
    def output_preview(self) -> str:
        try:
            text = self.output_data.decode('utf-8', errors='replace')
            return text[:100] + "..." if len(text) > 100 else text
        except:
            return self.output_data[:50].hex() + "..."


@dataclass
class DecodingResult:  # 最终解码结果
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    original_data: bytes = b""
    final_data: bytes = b""
    steps: List[DecodingStep] = field(default_factory=list)
    total_layers: int = 0
    is_meaningful: bool = False
    confidence: float = 0.0
    detected_content_type: str = ""
    flags_found: List[str] = field(default_factory=list)
    score: float = float('inf')

    @property
    def decode_chain(self) -> str:
        if not self.steps:
            return "RAW"
        return " -> ".join([s.method.value for s in self.steps if s.success])

    @property
    def final_text(self) -> str:
        try:
            return self.final_data.decode('utf-8', errors='replace')
        except:
            return ""

    def to_dict(self) -> Dict:
        return {
            'id': self.id,
            'original_data': self.original_data.hex() if self.original_data else "",
            'final_data': self.final_data.hex() if self.final_data else "",
            'final_text': self.final_text,
            'decode_chain': self.decode_chain,
            'total_layers': self.total_layers,
            'is_meaningful': self.is_meaningful,
            'confidence': self.confidence,
            'detected_content_type': self.detected_content_type,
            'flags_found': self.flags_found,
            'score': self.score
        }


# 各种编码的正则匹配
BASE64_PATTERNS = [
    # 标准 Base64
    (re.compile(r'^\s*(?:[A-Za-z0-9+/]{4})+(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?\s*$'),
     {'alphabet': 'standard'}),
    # URL-safe Base64，至少20字符
    (re.compile(r'^\s*[A-Za-z0-9\-_]{20,}\s*$'),
     {'alphabet': 'url_safe'}),
]

# Base32
BASE32_PATTERN = re.compile(
    r'^(?:[A-Z2-7]{8})+(?:[A-Z2-7]{2}={6}|[A-Z2-7]{4}={4}|[A-Z2-7]{5}={3}|[A-Z2-7]{7}=)?$'
)

# Hex，支持多种分隔符
HEX_PATTERNS = [
    (re.compile(r'^(?:[0-9A-Fa-f]{2})+$'), {'delimiter': 'none'}),
    (re.compile(r'^[0-9A-Fa-f]{2}(?: [0-9A-Fa-f]{2})+$'), {'delimiter': 'space'}),
    # MAC地址风格
    (re.compile(r'^[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2})+$'), {'delimiter': 'colon'}),
    (re.compile(r'^(?:0x[0-9A-Fa-f]{2})+$', re.IGNORECASE), {'delimiter': '0x'}),
    (re.compile(r'^(?:\\x[0-9A-Fa-f]{2})+$', re.IGNORECASE), {'delimiter': '\\x'}),
]

# URL编码，至少4个%XX
URL_PATTERN = re.compile(r'.*(?:%[0-9A-Fa-f]{2}.*){4}')

# Binary 8位一组
BINARY_PATTERNS = [
    (re.compile(r'^(?:[01]{8})+$'), {'delimiter': 'none'}),
    (re.compile(r'^[01]{8}(?: [01]{8})+$'), {'delimiter': 'space'}),
]

# Octal 值0-377
OCTAL_PATTERNS = [
    (re.compile(r'^(?:[0-7]{1,3})(?: (?:[0-7]{1,3}))+$'), {'delimiter': 'space'}),
    (re.compile(r'^(?:[0-7]{1,3})(?:,(?:[0-7]{1,3}))+$'), {'delimiter': 'comma'}),
]

# Decimal 值0-255
DECIMAL_PATTERNS = [
    (re.compile(r'^(?:\d{1,2}|1\d{2}|2[0-4]\d|25[0-5])(?: (?:\d{1,2}|1\d{2}|2[0-4]\d|25[0-5]))+$'),
     {'delimiter': 'space'}),
    (re.compile(r'^(?:\d{1,2}|1\d{2}|2[0-4]\d|25[0-5])(?:,(?:\d{1,2}|1\d{2}|2[0-4]\d|25[0-5]))+$'),
     {'delimiter': 'comma'}),
]

# HTML Entity
HTML_ENTITY_PATTERN = re.compile(r'&(?:#\d{2,5}|#x[0-9A-Fa-f]{2,4}|[a-zA-Z]{2,8});')

# Base58 (Bitcoin那套)
BASE58_PATTERN = re.compile(r'^[1-9A-HJ-NP-Za-km-z]{20,}$')

# Morse
MORSE_PATTERN = re.compile(r'^[-.\s]+$|^[_.\s]+$', re.IGNORECASE)

GZIP_MAGIC = b'\x1f\x8b\x08'
ZLIB_HEADERS = [b'\x78\x01', b'\x78\x9c', b'\x78\xda']

# 常见flag格式
FLAG_PATTERNS = [
    re.compile(r'flag\{[^}]+\}', re.IGNORECASE),
    re.compile(r'ctf\{[^}]+\}', re.IGNORECASE),
    re.compile(r'key\{[^}]+\}', re.IGNORECASE),
    # MD5，排除纯二进制串
    re.compile(r'(?=.*[2-9a-f])[a-f0-9]{32}', re.IGNORECASE),
    # SHA256
    re.compile(r'(?=.*[2-9a-f])[a-f0-9]{64}', re.IGNORECASE),
]

# 英文字母频率，算chi-squared用
ENGLISH_FREQ = {
    'a': 0.0817, 'b': 0.0149, 'c': 0.0278, 'd': 0.0425, 'e': 0.1270,
    'f': 0.0223, 'g': 0.0202, 'h': 0.0609, 'i': 0.0697, 'j': 0.0015,
    'k': 0.0077, 'l': 0.0403, 'm': 0.0241, 'n': 0.0675, 'o': 0.0751,
    'p': 0.0193, 'q': 0.0010, 'r': 0.0599, 's': 0.0633, 't': 0.0906,
    'u': 0.0276, 'v': 0.0098, 'w': 0.0236, 'x': 0.0015, 'y': 0.0197,
    'z': 0.0007
}

# Morse码表
MORSE_TABLE = {
    '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E',
    '..-.': 'F', '--.': 'G', '....': 'H', '..': 'I', '.---': 'J',
    '-.-': 'K', '.-..': 'L', '--': 'M', '-.': 'N', '---': 'O',
    '.--.': 'P', '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T',
    '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X', '-.--': 'Y',
    '--..': 'Z', '.----': '1', '..---': '2', '...--': '3', '....-': '4',
    '.....': '5', '-....': '6', '--...': '7', '---..': '8', '----.': '9',
    '-----': '0', ' ': ' '
}


class AutoDecoder:
    """自动解码引擎，投机执行所有匹配解码器，评分选最优"""

    MAX_DEPTH = 15
    MIN_DATA_LENGTH = 4
    GARBLED_THRESHOLD = 0.5  # 超过一半乱码就别继续了

    def __init__(self):
        self._checks = self._build_checks()

    def _build_checks(self) -> List[DecodingCheck]:
        """把所有解码规则注册进来"""
        checks = []

        # Base64最常见，排前面
        for pattern, args in BASE64_PATTERNS:
            checks.append(DecodingCheck(
                method=DecodingMethod.BASE64 if args.get('alphabet') == 'standard' else DecodingMethod.BASE64_URL,
                pattern=pattern,
                args=args,
                min_length=4,
                priority=10
            ))

        # Base32
        checks.append(DecodingCheck(
            method=DecodingMethod.BASE32,
            pattern=BASE32_PATTERN,
            min_length=8,
            priority=15
        ))

        # Base58，CTF和加密货币里常见
        checks.append(DecodingCheck(
            method=DecodingMethod.BASE58,
            pattern=BASE58_PATTERN,
            min_length=20,
            priority=18
        ))

        # Hex
        for pattern, args in HEX_PATTERNS:
            checks.append(DecodingCheck(
                method=DecodingMethod.HEX if args.get('delimiter') == 'none' else DecodingMethod.HEX_SPACED,
                pattern=pattern,
                args=args,
                min_length=2,
                priority=20
            ))

        # URL编码
        checks.append(DecodingCheck(
            method=DecodingMethod.URL,
            pattern=URL_PATTERN,
            min_length=4,
            priority=25
        ))

        # Binary
        for pattern, args in BINARY_PATTERNS:
            checks.append(DecodingCheck(
                method=DecodingMethod.BINARY,
                pattern=pattern,
                args=args,
                min_length=8,
                priority=30
            ))

        # Decimal
        for pattern, args in DECIMAL_PATTERNS:
            checks.append(DecodingCheck(
                method=DecodingMethod.DECIMAL,
                pattern=pattern,
                args=args,
                min_length=2,
                priority=35
            ))

        # Octal
        for pattern, args in OCTAL_PATTERNS:
            checks.append(DecodingCheck(
                method=DecodingMethod.OCTAL,
                pattern=pattern,
                args=args,
                min_length=2,
                priority=40
            ))

        # HTML Entity
        checks.append(DecodingCheck(
            method=DecodingMethod.HTML_ENTITY,
            pattern=HTML_ENTITY_PATTERN,
            min_length=4,
            priority=45
        ))

        # Morse
        checks.append(DecodingCheck(
            method=DecodingMethod.MORSE,
            pattern=MORSE_PATTERN,
            min_length=5,
            priority=50
        ))

        # Gzip，魔数检测优先
        checks.append(DecodingCheck(
            method=DecodingMethod.GZIP,
            pattern=None,
            entropy_range=(7.0, 8.0),
            min_length=10,
            priority=5
        ))

        # Zlib
        checks.append(DecodingCheck(
            method=DecodingMethod.ZLIB,
            pattern=None,
            entropy_range=(7.0, 8.0),
            min_length=2,
            priority=5
        ))

        # ROT13
        checks.append(DecodingCheck(
            method=DecodingMethod.ROT13,
            pattern=re.compile(r'^[A-Za-z\s]+$'),
            min_length=10,
            priority=60
        ))

        # 按优先级排
        checks.sort(key=lambda c: c.priority)
        return checks

    def find_matching_ops(self, data: bytes) -> List[DecodingCheck]:
        """找出所有模式匹配的解码器"""
        matches = []

        try:
            text = data.decode('utf-8', errors='ignore').strip()
        except:
            text = ""

        # 计算熵值
        entropy = self._calc_entropy(data)

        for check in self._checks:
            if len(data) < check.min_length:
                continue

            if check.entropy_range:
                if entropy < check.entropy_range[0] or entropy > check.entropy_range[1]:
                    # 压缩格式还得看魔数
                    if check.method == DecodingMethod.GZIP:
                        if not data.startswith(GZIP_MAGIC):
                            continue
                    elif check.method == DecodingMethod.ZLIB:
                        if not any(data.startswith(h) for h in ZLIB_HEADERS):
                            continue
                    else:
                        continue

            # 正则匹配
            if check.pattern:
                if not check.pattern.search(text):
                    continue
            else:
                # 没正则就靠魔数
                if check.method == DecodingMethod.GZIP:
                    if not data.startswith(GZIP_MAGIC):
                        continue
                elif check.method == DecodingMethod.ZLIB:
                    if not any(data.startswith(h) for h in ZLIB_HEADERS):
                        continue

            matches.append(check)

        return matches

    def speculative_execution(
        self,
        data: bytes,
        depth: int = 3,
        crib: Optional[re.Pattern] = None,
        recipe: List[DecodingStep] = None,
        visited: set = None
    ) -> List[DecodingResult]:
        """递归尝试所有匹配解码器，解到解不动或乱码为止"""
        if recipe is None:
            recipe = []
        if visited is None:
            visited = set()

        results = []

        # 到深度了，收工
        if depth <= 0:
            result = DecodingResult(
                original_data=recipe[0].input_data if recipe else data,
                final_data=data,
                steps=list(recipe),
                total_layers=len(recipe)
            )
            self._analyze_result(result, crib)
            if result.total_layers > 0:
                results.append(result)
            return results

        # 防循环
        data_hash = hash(data)
        if data_hash in visited:
            return results
        visited = visited | {data_hash}

        # 找匹配的解码器
        matching_ops = self.find_matching_ops(data)

        # 逐个试
        has_deeper_result = False
        for check in matching_ops:
            step = self._execute_decode(data, check)

            if not step.success:
                continue

            # 空输出
            if not step.output_data:
                continue

            # 输出跟输入一样，没意义
            if step.output_data == data:
                continue

            # 乱码太多就别往下了
            if not self._output_check_passes(step.output_data):
                continue

            has_deeper_result = True

            # 继续往下递归
            new_recipe = list(recipe) + [step]
            sub_results = self.speculative_execution(
                step.output_data,
                depth - 1,
                crib,
                new_recipe,
                visited
            )

            results.extend(sub_results)

        # 解到底了，记录结果
        if not has_deeper_result and recipe:
            leaf_result = DecodingResult(
                original_data=recipe[0].input_data if recipe else data,
                final_data=data,
                steps=list(recipe),
                total_layers=len(recipe)
            )
            self._analyze_result(leaf_result, crib)
            results.append(leaf_result)
        elif recipe:
            # 中间结果如果有意义也留着
            current_result = DecodingResult(
                original_data=recipe[0].input_data if recipe else data,
                final_data=data,
                steps=list(recipe),
                total_layers=len(recipe)
            )
            self._analyze_result(current_result, crib)
            if current_result.is_meaningful:
                results.append(current_result)

        # 评分排序
        for result in results:
            result.score = self._calculate_score(result, crib)

        results.sort(key=lambda r: r.score)

        return results

    def decode(self, data: bytes, max_depth: int = None, crib: str = None) -> DecodingResult:
        """主入口，自动解码数据。crib是已知明文的正则"""
        if max_depth is None:
            max_depth = self.MAX_DEPTH

        # 纯重复字符的数据跳过，不可能是编码
        if len(data) > 100:
            try:
                text = data.decode('utf-8', errors='ignore')
                if len(text) > 100:
                    sample = text[:500]
                    char_counts = {}
                    for c in sample:
                        char_counts[c] = char_counts.get(c, 0) + 1
                    if char_counts:
                        max_count = max(char_counts.values())
                        # 80%以上是同一字符就算了
                        if max_count / len(sample) > 0.8:
                            result = DecodingResult(original_data=data, final_data=data)
                            self._analyze_result(result, None)
                            return result
            except:
                pass

        # 编译crib
        crib_pattern = None
        if crib:
            try:
                crib_pattern = re.compile(crib, re.IGNORECASE)
            except:
                pass

        # 开搞
        results = self.speculative_execution(data, max_depth, crib_pattern)

        # 拿最好的结果
        if results:
            best = results[0]
            # 有crib的话优先返回匹配的
            if crib_pattern:
                for r in results:
                    if r.flags_found:
                        return r
            return best

        # 啥也解不出来
        result = DecodingResult(original_data=data, final_data=data)
        self._analyze_result(result, crib_pattern)
        return result

    def decode_text(self, text: str, max_depth: int = None, crib: str = None) -> DecodingResult:
        try:
            data = text.encode('utf-8')
        except UnicodeEncodeError:
            data = text.encode('latin-1')
        return self.decode(data, max_depth, crib)

    def _execute_decode(self, data: bytes, check: DecodingCheck) -> DecodingStep:
        step = DecodingStep(method=check.method, input_data=data)

        try:
            if check.method == DecodingMethod.BASE64:
                step = self._decode_base64(data, check.args)
            elif check.method == DecodingMethod.BASE64_URL:
                step = self._decode_base64url(data)
            elif check.method == DecodingMethod.BASE32:
                step = self._decode_base32(data)
            elif check.method == DecodingMethod.BASE58:
                step = self._decode_base58(data)
            elif check.method in (DecodingMethod.HEX, DecodingMethod.HEX_SPACED):
                step = self._decode_hex(data, check.args)
            elif check.method == DecodingMethod.URL:
                step = self._decode_url(data)
            elif check.method == DecodingMethod.BINARY:
                step = self._decode_binary(data, check.args)
            elif check.method == DecodingMethod.DECIMAL:
                step = self._decode_decimal(data, check.args)
            elif check.method == DecodingMethod.OCTAL:
                step = self._decode_octal(data, check.args)
            elif check.method == DecodingMethod.HTML_ENTITY:
                step = self._decode_html_entity(data)
            elif check.method == DecodingMethod.MORSE:
                step = self._decode_morse(data)
            elif check.method == DecodingMethod.GZIP:
                step = self._decode_gzip(data)
            elif check.method == DecodingMethod.ZLIB:
                step = self._decode_zlib(data)
            elif check.method == DecodingMethod.ROT13:
                step = self._decode_rot13(data)
        except Exception as e:
            step.error = str(e)
            step.success = False

        return step

    def _decode_base64(self, data: bytes, args: Dict) -> DecodingStep:
        step = DecodingStep(method=DecodingMethod.BASE64, input_data=data)
        try:
            text = data.decode('utf-8', errors='ignore').strip()
            # 补padding
            missing = len(text) % 4
            if missing:
                text += '=' * (4 - missing)
            decoded = base64.b64decode(text)
            step.output_data = decoded
            step.success = True
            step.confidence = 0.9
        except Exception as e:
            step.error = str(e)
        return step

    def _decode_base64url(self, data: bytes) -> DecodingStep:
        step = DecodingStep(method=DecodingMethod.BASE64_URL, input_data=data)
        try:
            text = data.decode('utf-8', errors='ignore').strip()
            missing = len(text) % 4
            if missing:
                text += '=' * (4 - missing)
            decoded = base64.urlsafe_b64decode(text)
            step.output_data = decoded
            step.success = True
            step.confidence = 0.85
        except Exception as e:
            step.error = str(e)
        return step

    def _decode_base32(self, data: bytes) -> DecodingStep:
        step = DecodingStep(method=DecodingMethod.BASE32, input_data=data)
        try:
            text = data.decode('utf-8', errors='ignore').strip().upper()
            # 补padding
            missing = len(text) % 8
            if missing:
                text += '=' * (8 - missing)
            decoded = base64.b32decode(text)
            step.output_data = decoded
            step.success = True
            step.confidence = 0.85
        except Exception as e:
            step.error = str(e)
        return step

    def _decode_base58(self, data: bytes) -> DecodingStep:
        step = DecodingStep(method=DecodingMethod.BASE58, input_data=data)
        try:
            text = data.decode('utf-8', errors='ignore').strip()
            # Base58 字母表 (Bitcoin)
            ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

            # 排除重复字符的误判
            if len(text) >= 10:
                char_counts = {}
                for c in text:
                    char_counts[c] = char_counts.get(c, 0) + 1
                max_count = max(char_counts.values())
                if max_count / len(text) > 0.8:
                    step.error = "Repetitive pattern detected, not Base58"
                    return step

            # 解码
            num = 0
            for char in text:
                num = num * 58 + ALPHABET.index(char)

            result = []
            while num > 0:
                result.append(num % 256)
                num //= 256
            result = bytes(reversed(result))

            # 前导1代表0x00
            pad_size = len(text) - len(text.lstrip('1'))
            result = b'\x00' * pad_size + result

            # 看看解出来的东西靠不靠谱
            printable_count = sum(1 for b in result if 32 <= b <= 126 or b in (9, 10, 13))
            if len(result) > 0:
                printable_ratio = printable_count / len(result)
                if printable_ratio < 0.5:
                    # 除非是已知二进制格式
                    if not (result.startswith(b'\x1f\x8b') or  # gzip
                            result.startswith(b'PK') or        # zip
                            result.startswith(b'\x78')):       # zlib
                        step.error = "Decoded output not readable"
                        return step

            step.output_data = result
            step.success = True
            step.confidence = 0.8
        except Exception as e:
            step.error = str(e)
        return step

    def _decode_hex(self, data: bytes, args: Dict) -> DecodingStep:
        method = DecodingMethod.HEX if args.get('delimiter') == 'none' else DecodingMethod.HEX_SPACED
        step = DecodingStep(method=method, input_data=data)
        try:
            text = data.decode('utf-8', errors='ignore').strip()

            # 去掉各种分隔符
            delimiter = args.get('delimiter', 'none')
            if delimiter == 'space':
                text = text.replace(' ', '')
            elif delimiter == 'colon':
                text = text.replace(':', '')
            elif delimiter == '0x':
                text = text.replace('0x', '').replace('0X', '')
            elif delimiter == '\\x':
                text = text.replace('\\x', '').replace('\\X', '')

            decoded = binascii.unhexlify(text)
            step.output_data = decoded
            step.success = True
            step.confidence = 0.9
        except Exception as e:
            step.error = str(e)
        return step

    def _decode_url(self, data: bytes) -> DecodingStep:
        step = DecodingStep(method=DecodingMethod.URL, input_data=data)
        try:
            from urllib.parse import unquote_to_bytes
            text = data.decode('utf-8', errors='ignore')
            decoded = unquote_to_bytes(text)
            if decoded != data:
                step.output_data = decoded
                step.success = True
                step.confidence = 0.85
        except Exception as e:
            step.error = str(e)
        return step

    def _decode_binary(self, data: bytes, args: Dict) -> DecodingStep:
        step = DecodingStep(method=DecodingMethod.BINARY, input_data=data)
        try:
            text = data.decode('utf-8', errors='ignore').strip()

            delimiter = args.get('delimiter', 'space')
            if delimiter == 'space':
                parts = text.split(' ')
            else:
                # 没分隔符就每8位切
                parts = [text[i:i+8] for i in range(0, len(text), 8)]

            decoded = bytes([int(p, 2) for p in parts if p])
            step.output_data = decoded
            step.success = True
            step.confidence = 0.85
        except Exception as e:
            step.error = str(e)
        return step

    def _decode_decimal(self, data: bytes, args: Dict) -> DecodingStep:
        step = DecodingStep(method=DecodingMethod.DECIMAL, input_data=data)
        try:
            text = data.decode('utf-8', errors='ignore').strip()

            delimiter = args.get('delimiter', 'space')
            if delimiter == 'space':
                parts = text.split(' ')
            elif delimiter == 'comma':
                parts = text.split(',')
            else:
                parts = text.split()

            decoded = bytes([int(p) for p in parts if p])
            step.output_data = decoded
            step.success = True
            step.confidence = 0.8
        except Exception as e:
            step.error = str(e)
        return step

    def _decode_octal(self, data: bytes, args: Dict) -> DecodingStep:
        step = DecodingStep(method=DecodingMethod.OCTAL, input_data=data)
        try:
            text = data.decode('utf-8', errors='ignore').strip()

            delimiter = args.get('delimiter', 'space')
            if delimiter == 'space':
                parts = text.split(' ')
            elif delimiter == 'comma':
                parts = text.split(',')
            else:
                parts = text.split()

            decoded = bytes([int(p, 8) for p in parts if p])
            step.output_data = decoded
            step.success = True
            step.confidence = 0.8
        except Exception as e:
            step.error = str(e)
        return step

    def _decode_html_entity(self, data: bytes) -> DecodingStep:
        step = DecodingStep(method=DecodingMethod.HTML_ENTITY, input_data=data)
        try:
            text = data.decode('utf-8', errors='ignore')
            decoded_text = html_unescape(text)
            if decoded_text != text:
                step.output_data = decoded_text.encode('utf-8')
                step.success = True
                step.confidence = 0.85
        except Exception as e:
            step.error = str(e)
        return step

    def _decode_morse(self, data: bytes) -> DecodingStep:
        step = DecodingStep(method=DecodingMethod.MORSE, input_data=data)
        try:
            text = data.decode('utf-8', errors='ignore').strip()

            text = text.replace('_', '-').replace('·', '.')

            # 双空格分词，或者用/
            words = text.split('  ')
            if len(words) == 1:
                words = text.split('/')

            decoded_words = []
            for word in words:
                letters = word.strip().split(' ')
                decoded_letters = []
                for letter in letters:
                    letter = letter.strip()
                    if letter in MORSE_TABLE:
                        decoded_letters.append(MORSE_TABLE[letter])
                if decoded_letters:
                    decoded_words.append(''.join(decoded_letters))

            if decoded_words:
                decoded_text = ' '.join(decoded_words)
                step.output_data = decoded_text.encode('utf-8')
                step.success = True
                step.confidence = 0.75
        except Exception as e:
            step.error = str(e)
        return step

    def _decode_gzip(self, data: bytes) -> DecodingStep:
        step = DecodingStep(method=DecodingMethod.GZIP, input_data=data)
        try:
            if data.startswith(GZIP_MAGIC):
                decoded = gzip.decompress(data)
                step.output_data = decoded
                step.success = True
                step.confidence = 0.95
        except Exception as e:
            step.error = str(e)
        return step

    def _decode_zlib(self, data: bytes) -> DecodingStep:
        step = DecodingStep(method=DecodingMethod.ZLIB, input_data=data)
        try:
            if any(data.startswith(h) for h in ZLIB_HEADERS):
                decoded = zlib.decompress(data)
                step.output_data = decoded
                step.success = True
                step.confidence = 0.95
        except Exception as e:
            step.error = str(e)
        return step

    def _decode_rot13(self, data: bytes) -> DecodingStep:
        step = DecodingStep(method=DecodingMethod.ROT13, input_data=data)
        try:
            text = data.decode('utf-8', errors='ignore')
            decoded_text = codecs.decode(text, 'rot_13')

            # 解完应该更像英文才对
            chi_before = self._chi_squared_english(text)
            chi_after = self._chi_squared_english(decoded_text)

            if chi_after < chi_before:
                step.output_data = decoded_text.encode('utf-8')
                step.success = True
                step.confidence = 0.6
        except Exception as e:
            step.error = str(e)
        return step

    def _calc_entropy(self, data: bytes) -> float:
        """Shannon熵"""
        if not data:
            return 0.0
        byte_counts = Counter(data)
        total = len(data)
        entropy = 0.0
        for count in byte_counts.values():
            if count > 0:
                p = count / total
                entropy -= p * math.log2(p)
        return entropy

    def _chi_squared_english(self, text: str) -> float:
        """跟英文字母频率比较，越小越像英文"""
        if not text:
            return float('inf')

        text_lower = text.lower()
        letter_counts = Counter(c for c in text_lower if c.isalpha())
        total = sum(letter_counts.values())

        if total < 10:
            return float('inf')

        chi_sq = 0.0
        for letter, expected_freq in ENGLISH_FREQ.items():
            observed = letter_counts.get(letter, 0)
            expected = expected_freq * total
            if expected > 0:
                chi_sq += ((observed - expected) ** 2) / expected

        return chi_sq

    def _is_valid_utf8(self, data: bytes) -> bool:
        try:
            data.decode('utf-8')
            return True
        except:
            return False

    def _output_check_passes(self, data: bytes) -> bool:
        """乱码太多就返回False，不继续解了"""
        if not data or len(data) < self.MIN_DATA_LENGTH:
            return False

        garbled = self._calc_garbled_ratio(data)
        if garbled > self.GARBLED_THRESHOLD:
            return False

        return True

    def _calc_garbled_ratio(self, data: bytes) -> float:
        """统计乱码占比，0.0=完全可读，1.0=全是乱码"""
        if not data:
            return 1.0

        try:
            text = data.decode('utf-8', errors='replace')
        except Exception:
            return 1.0

        if not text:
            return 1.0

        garbled = 0
        for ch in text:
            cp = ord(ch)
            if ch == '\ufffd':
                garbled += 1
            elif cp < 32 and ch not in '\n\r\t':
                garbled += 1
            elif 0x80 <= cp <= 0x9f:
                garbled += 1

        return garbled / len(text)

    def _calculate_score(self, result: DecodingResult, crib: Optional[re.Pattern]) -> float:
        """给结果打分，分越低越好"""
        data = result.final_data

        # 乱码越多分越高
        garbled = self._calc_garbled_ratio(data)
        score = garbled * 1000

        # 解得越深越好
        score -= result.total_layers * 20

        # 像英文的加分
        try:
            text = data.decode('utf-8', errors='replace')
            chi_sq = self._chi_squared_english(text)
            if chi_sq == float('inf'):
                chi_sq = 10000.0
            # 归一化
            score += min(chi_sq / 50, 200)
        except Exception:
            score += 200

        # UTF-8有效加分
        if self._is_valid_utf8(data):
            score -= 100

        # 匹配crib大加分
        if crib and result.final_text:
            if crib.search(result.final_text):
                score -= 500

        # 找到flag也加分
        if result.flags_found:
            score -= 300

        return score

    def _analyze_result(self, result: DecodingResult, crib: Optional[re.Pattern] = None):
        """分析解码结果，判断有没有意义"""
        data = result.final_data

        if not data:
            return

        # 乱码占比
        garbled = self._calc_garbled_ratio(data)

        # 低于30%乱码就算有意义
        result.is_meaningful = garbled < 0.3

        # 猜内容类型
        if self._is_valid_utf8(data):
            try:
                text = data.decode('utf-8')
                chi_sq = self._chi_squared_english(text)
                if chi_sq < 100:
                    result.detected_content_type = "text:english"
                elif garbled < 0.1:
                    result.detected_content_type = "text:readable"
                else:
                    result.detected_content_type = "text:unknown"
            except Exception:
                result.detected_content_type = "binary"
        else:
            entropy = self._calc_entropy(data)
            if entropy > 7.5:
                result.detected_content_type = "binary:compressed"
            else:
                result.detected_content_type = "binary:unknown"

        # 找flag
        try:
            text = data.decode('utf-8', errors='replace')
            for pattern in FLAG_PATTERNS:
                matches = pattern.findall(text)
                result.flags_found.extend(matches)

            # crib也找找
            if crib:
                crib_matches = crib.findall(text)
                for m in crib_matches:
                    if m not in result.flags_found:
                        result.flags_found.append(m)
        except Exception:
            pass

        # 置信度
        if result.flags_found:
            result.confidence = 0.95
        elif garbled < 0.05:
            result.confidence = 0.9  # 基本没乱码
        elif garbled < 0.15:
            result.confidence = 0.8
        elif result.is_meaningful:
            result.confidence = 0.7
        else:
            result.confidence = 0.3


class MultiLayerDecoder:
    """针对HTTP流量里多层编码的场景"""
    def __init__(self):
        self.auto_decoder = AutoDecoder()

    def decode_http_payload(self, payload: str, crib: str = None) -> DecodingResult:
        """先URL解码一层再丢给自动解码器"""
        from urllib.parse import unquote
        try:
            decoded_once = unquote(payload)
        except:
            decoded_once = payload

        # 默认搜索flag格式
        if crib is None:
            crib = r'flag\{[^}]+\}'

        return self.auto_decoder.decode_text(decoded_once, crib=crib)

    def decode_webshell_param(self, param_value: str) -> DecodingResult:
        return self.auto_decoder.decode_text(param_value, max_depth=5)


# 快捷函数
def auto_decode(data: bytes, crib: str = None) -> DecodingResult:
    return AutoDecoder().decode(data, crib=crib)


def auto_decode_text(text: str, crib: str = None) -> DecodingResult:
    return AutoDecoder().decode_text(text, crib=crib)


def find_flags(data: bytes) -> List[str]:
    result = AutoDecoder().decode(data, crib=r'flag\{[^}]+\}|ctf\{[^}]+\}')
    return result.flags_found
