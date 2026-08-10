# auto_decoder.py - 自动解码器
# CyberChef Magic 风格的多层自动解码引擎
# 递归 + 迭代循环解码，直到无法继续解码为止

import base64
import binascii
import bz2
import gzip
import lzma
import zlib
import re
import math
import codecs
import logging
from typing import Callable, List, Optional, Tuple, Dict, Any
from dataclasses import dataclass, field
from enum import Enum
from collections import Counter
import uuid
from html import unescape as html_unescape

logger = logging.getLogger(__name__)


class DecodingMethod(Enum):
    BASE64 = "base64"
    BASE64_URL = "base64url"
    BASE32 = "base32"
    BASE58 = "base58"
    BASE85 = "base85"
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
    BZIP2 = "bzip2"
    LZMA = "lzma"
    ROT13 = "rot13"
    XOR_BRUTE = "xor_brute"
    XOR = "xor"
    REVERSE = "reverse"
    RAW = "raw"


@dataclass
class DecodingCheck:
    method: DecodingMethod
    pattern: Optional[re.Pattern] = None
    # 有些判据用正则表达是错的（比如"至少 N 个 %XX"），给一个可调用的口子。
    # 设了 predicate 就以它为准，不再跑 pattern。
    predicate: Optional[Callable[[str], bool]] = None
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
# 单个 URL 转义序列。线性，没有可回溯的空间。
URL_PATTERN = re.compile(r'%[0-9A-Fa-f]{2}')

# 判据是"文本里至少有 4 个 %XX"，这件事**不该用一条正则表达**。
#
# 原来写的是 `.*(?:%[0-9A-Fa-f]{2}.*){4}` —— 教科书级的灾难性回溯：开头一个
# `.*`，重复组 `{4}` 里又是 `.*`，引擎要穷举"这 4 个 %XX 分别落在哪里"的所有
# 切分。在不含 %XX 的文本上（base64 密文、JSP 页面）61KB 输入要 **23.9 秒**，
# 把 AttackDetector 的 5 秒预算整个烧光，10 个检测器一个都没跑起来 ——
# 日志表现是"检测超时，以下检测器未执行：<全部>"，看着像检测器坏了。
#
# 第一次改写用的是 `(?:[^%]*%[0-9A-Fa-f]{2}){4}`，看着"没有嵌套 `.*`"，
# 实际仍是 O(n²)：文本里没有 `%` 时，`[^%]*` 在**每一个起始位置**都扫到串尾
# 才失败。64KB 上 1.3 秒。**"看起来线性"不等于线性，得量。**
#
# 数一遍、够了就停，才是这件事真正的复杂度。
_MIN_URL_ESCAPES = 4


def looks_url_encoded(text: str, need: int = _MIN_URL_ESCAPES) -> bool:
    """文本里是否出现至少 need 个 %XX（数够就停，不扫完）"""
    if not text:
        return False
    count = 0
    for _ in URL_PATTERN.finditer(text):
        count += 1
        if count >= need:
            return True
    return False

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

# Base85 (Ascii85 / Z85)
BASE85_PATTERN = re.compile(r'^<~[!-u\s]+~>$')  # Ascii85 带 <~ ~> 包裹
BASE85_RAW_PATTERN = re.compile(r'^[0-9A-Za-z!#$%&()*+\-;<=>?@^_`{|}~]{20,}$')

# Morse
MORSE_PATTERN = re.compile(r'^[-.\s]+$|^[_.\s]+$', re.IGNORECASE)

GZIP_MAGIC = b'\x1f\x8b\x08'
ZLIB_HEADERS = [b'\x78\x01', b'\x78\x9c', b'\x78\xda']
BZIP2_MAGIC = b'BZ'
LZMA_MAGIC = b'\x5d\x00'
XZ_MAGIC = b'\xfd7zXZ'

# 常见flag格式
FLAG_PATTERNS = [
    re.compile(r'flag\{[^}]+\}', re.IGNORECASE),
    re.compile(r'ctf\{[^}]+\}', re.IGNORECASE),
    re.compile(r'key\{[^}]+\}', re.IGNORECASE),
    # MD5 / SHA256，排除纯二进制串（只由 0/1 组成的等长串）。
    #
    # 原写法是 `(?=.*[2-9a-f])[a-f0-9]{32}`：前瞻里的 `.*` 让引擎在**每一个
    # 起始位置**都把剩余全文重扫一遍，是 O(n²)，61KB 上单条 0.5 秒。
    # 而且语义也不对——它检查的是"这一行后面某处有非 0/1 字符"，而不是
    # "这 32 个字符里有非 0/1 字符"，注释说的排除条件根本没生效。
    # 改成有界前瞻：只在这一串自己的 32/64 个字符里找，线性且符合本意。
    re.compile(r'(?=[a-f0-9]{0,31}[2-9a-f])[a-f0-9]{32}', re.IGNORECASE),
    re.compile(r'(?=[a-f0-9]{0,63}[2-9a-f])[a-f0-9]{64}', re.IGNORECASE),
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


# 高价值内容标记：解出这些东西就是有价值的结果，不该被整体乱码率淹没。
#
# 这是修"前缀填充打掉解码链"用的。`'A'*50 + base64(shell)` 解出来是
# 「一堆 NUL + 真 shell」，乱码率一高就被 _output_check_passes 挡在门外、
# 也在打分时输给"不解码"。但对取证来说，**结果里有没有 `<?php eval(`
# 比"��体好不好看"重要得多**。
_HIGH_VALUE_MARKERS = (
    b"<?php", b"<?=", b"<%@", b"<script", b"eval(", b"assert(", b"system(",
    b"exec(", b"shell_exec(", b"passthru(", b"popen(", b"proc_open(",
    b"base64_decode(", b"gzinflate(", b"$_post", b"$_get", b"$_request",
    b"php://input", b"flag{", b"ctf{", b"key{",
    b"union select", b"/etc/passwd", b"cmd.exe", b"/bin/sh", b"powershell",
)


def contains_high_value(data: bytes) -> bool:
    """解码结果里有没有一眼就值钱的东西"""
    if not data:
        return False
    lowered = data.lower()
    return any(marker in lowered for marker in _HIGH_VALUE_MARKERS)


# 各编码的"候选子串"形态。用来在**整段不是一条完整编码**时捞回嵌在里面的那段。
_EMBEDDED_RUNS = (
    ("base64", re.compile(rb'[A-Za-z0-9+/]{24,}={0,2}'), 4),
    ("base64url", re.compile(rb'[A-Za-z0-9\-_]{24,}={0,2}'), 4),
    ("hex", re.compile(rb'[0-9A-Fa-f]{32,}'), 2),
)

# 这里**故意没有段数上限**。每段的开销正比于段长，总开销是 O(块数 × 总长)，
# 与段数无关；加一个"最多看 N 段"只会变成新的可绕过上限 —— 攻击者在前面垫
# 64 段短 base64，真 payload 就永远排在后面。


class AutoDecoder:
    """自动解码引擎，投机执行所有匹配解码器，评分选最优"""

    MAX_DEPTH = 15
    MIN_DATA_LENGTH = 4
    GARBLED_THRESHOLD = 0.3  # 超过30%乱码就别继续了

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

        # Base85 (Ascii85 带 <~ ~> 包裹)
        checks.append(DecodingCheck(
            method=DecodingMethod.BASE85,
            pattern=BASE85_PATTERN,
            args={'variant': 'ascii85'},
            min_length=5,
            priority=16
        ))

        # Base85 (raw, 无包裹)
        checks.append(DecodingCheck(
            method=DecodingMethod.BASE85,
            pattern=BASE85_RAW_PATTERN,
            args={'variant': 'raw'},
            min_length=20,
            priority=19
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
            predicate=looks_url_encoded,
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

        # Bzip2，魔数 BZ
        checks.append(DecodingCheck(
            method=DecodingMethod.BZIP2,
            pattern=None,
            entropy_range=(7.0, 8.0),
            min_length=10,
            priority=5
        ))

        # LZMA，魔数 \x5d\x00
        checks.append(DecodingCheck(
            method=DecodingMethod.LZMA,
            pattern=None,
            entropy_range=(7.0, 8.0),
            min_length=10,
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
                    elif check.method == DecodingMethod.BZIP2:
                        if not data.startswith(BZIP2_MAGIC):
                            continue
                    elif check.method == DecodingMethod.LZMA:
                        if not (data.startswith(LZMA_MAGIC) or data.startswith(XZ_MAGIC)):
                            continue
                    else:
                        continue

            # 判据：predicate 优先
            if check.predicate is not None:
                if not check.predicate(text):
                    continue
            elif check.pattern:
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
                elif check.method == DecodingMethod.BZIP2:
                    if not data.startswith(BZIP2_MAGIC):
                        continue
                elif check.method == DecodingMethod.LZMA:
                    if not (data.startswith(LZMA_MAGIC) or data.startswith(XZ_MAGIC)):
                        continue

            matches.append(check)

        return matches

    def speculative_execution(
        self,
        data: bytes,
        depth: int = None,
        crib: Optional[re.Pattern] = None,
        recipe: List[DecodingStep] = None,
        visited: set = None
    ) -> List[DecodingResult]:
        """递归尝试所有匹配解码器，解到解不动或乱码为止"""
        if depth is None:
            depth = self.MAX_DEPTH
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

        # 只有**整个 buffer 从头到尾都是同一个字节**时才跳过。
        #
        # 这里原来的判据是"前 500 字符里某个字符占比 > 80% 就整段放弃"，
        # 是教科书级的可绕过上限：判据只看前 500 字符，结论却作用于整个 body。
        # 攻击者在开头垫 400 个 'A'、后面挂任意长度的编码 payload，整条解码链
        # 一次都不会跑，而且 return 的是个 chain=RAW 的正常结果，**不留任何痕迹**。
        #
        # 现在的判据是可证明安全的：单一字节重复到底的数据里装不下任何信息，
        # 解出来也只能是同一个字节的重复。用 bytes.count 走 C 层，O(n) 但常数极低。
        if len(data) > 100 and data.count(data[0:1]) == len(data):
            logger.debug("整段数据是单一字节重复 %d 次，跳过解码", len(data))
            result = DecodingResult(original_data=data, final_data=data)
            self._analyze_result(result, None)
            return result

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
            if best.total_layers > 0:
                return best

        # 整段没解出东西 —— 再试一次"嵌在里面的那段"
        salvaged = self._salvage_embedded(data, crib_pattern)
        if salvaged is not None:
            return salvaged

        if results:
            return results[0]

        # 啥也解不出来
        result = DecodingResult(original_data=data, final_data=data)
        self._analyze_result(result, crib_pattern)
        return result

    def _salvage_embedded(self, data: bytes,
                          crib_pattern=None) -> Optional[DecodingResult]:
        """整段解不出来时，捞回**嵌在里面**的那段编码内容。

        为什么需要这一步：`find_matching_ops` 的判据是"**整个 buffer** 是不是
        一条完整编码"（BASE64_PATTERNS 等都带 `^...$`）。攻击者在 payload 前面
        垫几十个字符，两道闸门会依次关上：

          1. 垫的字符数不是 4 的倍数 → 整串长度对不齐 → base64 的整串正则不匹配
             → **这一层压根不会被尝试**（实测 20 个字符就够）
          2. 就算对齐了，解出来是「一堆 NUL + 真 shell」，乱码率把它挡在
             `_output_check_passes` 外面，打分时也输给"不解码"

        所以这里换个提问方式：不问"整段是不是 base64"，而问"里面有没有一段
        是 base64"。找出足够长的编码字符游程，对每种对齐方式各试一次
        （base64 只有 4 种，hex 只有 2 种，是常数次）。

        **只在解出高价值内容时才采纳**（`<?php` / `eval(` / `flag{` …），
        避免把随机的 base64 样字符串解成垃圾当结果 —— 这条兜底是为"填充绕过"
        准备的，不是为了扩大召回面而降低精度。
        """
        if not data or len(data) < 24:
            return None

        seen_runs = 0
        for name, run_re, block in _EMBEDDED_RUNS:
            for match in run_re.finditer(data):
                run = match.group(0)
                if len(run) < 24:
                    continue
                # 单一字符重复的游程解出来只能是单一字节的重复，装不下任何
                # 标记（所有标记都至少有两个不同字符）。这个跳过是可证明安全的，
                # 而且专治 `'A'*4096` 这类填充 —— 不然光解它们就要几百毫秒。
                if run.count(run[0:1]) == len(run):
                    continue
                seen_runs += 1
                for offset in range(block):
                    decoded = self._try_run(name, run, offset, block)
                    if decoded is None or not contains_high_value(decoded):
                        continue
                    step = DecodingStep(
                        method=(DecodingMethod.HEX if name == "hex"
                                else DecodingMethod.BASE64_URL if name == "base64url"
                                else DecodingMethod.BASE64),
                        input_data=run, output_data=decoded, success=True,
                        metadata={"embedded_offset": match.start() + offset},
                    )
                    result = DecodingResult(
                        original_data=data, final_data=decoded,
                        steps=[step], total_layers=1,
                    )
                    self._analyze_result(result, crib_pattern)
                    result.is_meaningful = True
                    logger.debug(
                        "嵌入 %s 探测命中：原文偏移 %d，解出 %d 字节",
                        name, match.start() + offset, len(decoded))
                    return result
        return None

    @staticmethod
    def _try_run(name: str, run: bytes, offset: int, block: int) -> Optional[bytes]:
        """按给定对齐方式解一段游程；解不动返回 None"""
        chunk = run[offset:]
        usable = len(chunk) - (len(chunk) % block)
        if usable < 16:
            return None
        chunk = chunk[:usable]
        try:
            if name == "hex":
                return binascii.unhexlify(chunk)
            if name == "base64url":
                return base64.urlsafe_b64decode(chunk + b"=" * (-len(chunk) % 4))
            return base64.b64decode(chunk, validate=True)
        except Exception:
            return None

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
            elif check.method == DecodingMethod.BASE85:
                step = self._decode_base85(data, check.args)
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
            elif check.method == DecodingMethod.BZIP2:
                step = self._decode_bzip2(data)
            elif check.method == DecodingMethod.LZMA:
                step = self._decode_lzma(data)
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

    def _decode_bzip2(self, data: bytes) -> DecodingStep:
        step = DecodingStep(method=DecodingMethod.BZIP2, input_data=data)
        try:
            if data.startswith(BZIP2_MAGIC):
                decoded = bz2.decompress(data)
                step.output_data = decoded
                step.success = True
                step.confidence = 0.95
        except Exception as e:
            step.error = str(e)
        return step

    def _decode_lzma(self, data: bytes) -> DecodingStep:
        step = DecodingStep(method=DecodingMethod.LZMA, input_data=data)
        try:
            if data.startswith(LZMA_MAGIC) or data.startswith(XZ_MAGIC):
                decoded = lzma.decompress(data)
                step.output_data = decoded
                step.success = True
                step.confidence = 0.95
        except Exception as e:
            step.error = str(e)
        return step

    def _decode_base85(self, data: bytes, args: Dict) -> DecodingStep:
        step = DecodingStep(method=DecodingMethod.BASE85, input_data=data)
        try:
            text = data.decode('utf-8', errors='ignore').strip()
            variant = args.get('variant', 'raw')

            if variant == 'ascii85':
                # 去掉 <~ ~> 包裹
                if text.startswith('<~') and text.endswith('~>'):
                    text = text[2:-2]
                decoded = base64.a85decode(text)
            else:
                decoded = base64.b85decode(text)

            step.output_data = decoded
            step.success = True
            step.confidence = 0.85
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
        """乱码太多就返回False，不继续解了。但压缩格式除外。"""
        if not data or len(data) < self.MIN_DATA_LENGTH:
            return False

        # 压缩格式的魔数检测：二进制是正常的，不能按乱码处理
        if (data.startswith(GZIP_MAGIC) or
            any(data.startswith(h) for h in ZLIB_HEADERS) or
            data.startswith(BZIP2_MAGIC) or
            data.startswith(LZMA_MAGIC) or
            data.startswith(XZ_MAGIC)):
            return True

        garbled = self._calc_garbled_ratio(data)
        if garbled > self.GARBLED_THRESHOLD:
            return False

        return True

    def _calc_garbled_ratio(self, data: bytes) -> float:
        """统计乱码占比，0.0=完全可读，1.0=全是乱码

        增强检测：
        - UTF-8 替换字符 (U+FFFD)
        - 控制字符 (除 \\n\\r\\t)
        - C1 控制字符 (0x80-0x9F)
        - Latin-1 mojibake 模式：连续 2+ 个非 ASCII Latin 扩展字符
          (如 àáØû 这类在非 CJK 上下文中视为乱码)
        """
        if not data:
            return 1.0

        try:
            text = data.decode('utf-8', errors='replace')
        except Exception:
            return 1.0

        if not text:
            return 1.0

        garbled = 0
        consecutive_latin_ext = 0
        has_cjk = any(0x4E00 <= ord(ch) <= 0x9FFF for ch in text[:200])

        for ch in text:
            cp = ord(ch)
            if ch == '\ufffd':
                garbled += 1
                consecutive_latin_ext = 0
            elif cp < 32 and ch not in '\n\r\t':
                garbled += 1
                consecutive_latin_ext = 0
            elif 0x80 <= cp <= 0x9f:
                garbled += 1
                consecutive_latin_ext = 0
            elif not has_cjk and 0xA0 <= cp <= 0xFF:
                # Latin-1 扩展区：在非 CJK 上下文中，连续出现视为 mojibake
                consecutive_latin_ext += 1
                if consecutive_latin_ext >= 2:
                    garbled += 1
            else:
                consecutive_latin_ext = 0

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


class MagicDecoder:
    """CyberChef Magic 风格解码器

    核心思路:
    1. 优先调用 CyberChef npm 的 Magic 操作（通过 Node.js 桥接器）
    2. 如果 Node.js / CyberChef 不可用，回退到 Python AutoDecoder
    3. Python 模式: 迭代循环调用 AutoDecoder，每轮取最优解码结果
    可选 intensive 模式进行单字节 XOR 暴力破解。
    """

    MAX_ITERATIONS = 20   # 迭代上限，防止无限循环
    XOR_SAMPLE_SIZE = 256  # intensive 模式 XOR 采样字节数

    def __init__(self, intensive: bool = False, bridge=None):
        self._intensive = intensive
        self._decoder = AutoDecoder()
        self._bridge = bridge  # CyberChefBridge 实例（外部注入或延迟初始化）
        self._bridge_checked = bridge is not None

    def decode(self, data: bytes, crib: str = None) -> DecodingResult:
        """主入口：优先 CyberChef，回退 Python 迭代解码"""
        if not data or len(data) < AutoDecoder.MIN_DATA_LENGTH:
            result = DecodingResult(original_data=data, final_data=data)
            self._decoder._analyze_result(result, None)
            return result

        # 优先尝试 CyberChef
        cyberchef_result = self._try_cyberchef(data, crib)
        if cyberchef_result is not None:
            return cyberchef_result

        # 回退到 Python 解码
        return self._decode_python(data, crib)

    def _get_bridge(self):
        """延迟初始化 CyberChefBridge"""
        if not self._bridge_checked:
            self._bridge_checked = True
            try:
                from core.cyberchef_bridge import CyberChefBridge
                bridge = CyberChefBridge()
                if bridge.is_available():
                    self._bridge = bridge
                else:
                    self._bridge = None
            except Exception as e:
                logger.debug(f"CyberChef bridge 初始化失败: {e}")
                self._bridge = None
        return self._bridge

    def _try_cyberchef(self, data: bytes, crib: str = None) -> Optional[DecodingResult]:
        """尝试用 CyberChef Magic 解码，成功返回 DecodingResult，否则 None"""
        bridge = self._get_bridge()
        if bridge is None:
            return None

        try:
            # CyberChef 接受字符串输入
            text = data.decode('utf-8', errors='replace')

            response = bridge.magic(
                data=text,
                depth=3,
                intensive=self._intensive,
                crib=crib or "",
            )

            if not response.ok:
                logger.debug(f"CyberChef Magic 失败: {response.error}")
                return None

            # 遍历所有结果，找最有意义的
            crib_pattern = None
            if crib:
                try:
                    crib_pattern = re.compile(crib, re.IGNORECASE)
                except Exception:
                    pass

            best_candidate = None
            best_score = float('inf')

            for candidate_result in response.results:
                if not candidate_result.recipe:
                    continue

                candidate_data = candidate_result.data
                candidate_bytes = candidate_data.encode('utf-8', errors='replace')

                # 跳过仍然是编码数据的结果（不可读或高熵）
                candidate_garbled = self._decoder._calc_garbled_ratio(candidate_bytes)
                if candidate_result.entropy > 7.0:
                    continue
                if candidate_result.entropy > 5.0 and candidate_garbled > 0.2:
                    continue

                # 计算候选质量分数（越低越好）
                score = candidate_result.entropy
                score += len(candidate_result.recipe)  # 短 recipe 更好

                # crib 匹配：大幅降低分数
                if crib_pattern and crib_pattern.search(candidate_data):
                    score -= 1000

                # 有 flag 模式：大幅降低分数
                flag_match = re.search(
                    r'(flag|ctf|key)\{[^}]+\}', candidate_data, re.IGNORECASE
                )
                if flag_match:
                    score -= 500

                # UTF-8 可读文本：降低分数
                if candidate_result.is_utf8:
                    score -= 50

                # 可打印字符比例高：降低分数
                printable_ratio = sum(
                    1 for c in candidate_data[:200]
                    if c.isprintable() or c in '\r\n\t'
                ) / max(len(candidate_data[:200]), 1)
                if printable_ratio > 0.8:
                    score -= 100 * printable_ratio

                if score < best_score:
                    best_score = score
                    best_candidate = candidate_result

            if best_candidate is None:
                return None

            # 验证结果质量：如果输出不比输入更有意义则回退
            final_data = best_candidate.data.encode('utf-8', errors='replace')
            if final_data == data:
                return None

            # 检查是否还是编码数据（只解了一半）
            final_text = best_candidate.data
            still_encoded = (
                # Base64 模式
                (re.fullmatch(r'[A-Za-z0-9+/=\s]{20,}', final_text.strip())
                 and not re.search(r'[{}\[\]()!@#$%^&*]', final_text))
                # Hex 模式
                or re.fullmatch(r'(?:[0-9A-Fa-f]{2}[\s:]*){10,}', final_text.strip())
                # URL 编码残留
                or len(re.findall(r'%[0-9A-Fa-f]{2}', final_text)) > 4
            )
            if still_encoded:
                # 仍然像 base64，CyberChef 没有完全解开，回退 Python
                return None

            steps = []
            for step_info in best_candidate.recipe:
                op_name = step_info.get("op", "")
                method = self._cyberchef_op_to_method(op_name)
                step = DecodingStep(
                    method=method,
                    input_data=data,
                    output_data=final_data,
                    success=True,
                    confidence=0.9,
                    metadata={
                        "cyberchef_op": op_name,
                        "cyberchef_args": step_info.get("args", []),
                    },
                )
                steps.append(step)

            result = DecodingResult(
                original_data=data,
                final_data=final_data,
                steps=steps,
                total_layers=len(steps),
            )
            self._decoder._analyze_result(result, crib_pattern)
            result.score = self._decoder._calculate_score(result, crib_pattern)

            logger.debug(
                f"CyberChef Magic 成功: {best_candidate.decode_chain} "
                f"({best_candidate.total_layers} 层, score={result.score:.1f})"
            )
            return result

        except Exception as e:
            logger.debug(f"CyberChef Magic 异常: {e}")
            return None

    @staticmethod
    def _cyberchef_op_to_method(op_name: str) -> DecodingMethod:
        """将 CyberChef 操作名映射到 DecodingMethod"""
        mapping = {
            "From Base64": DecodingMethod.BASE64,
            "From Base32": DecodingMethod.BASE32,
            "From Base58": DecodingMethod.BASE58,
            "From Base85": DecodingMethod.BASE85,
            "From Hex": DecodingMethod.HEX,
            "From Hexdump": DecodingMethod.HEX,
            "URL Decode": DecodingMethod.URL,
            "From Binary": DecodingMethod.BINARY,
            "From Octal": DecodingMethod.OCTAL,
            "From Decimal": DecodingMethod.DECIMAL,
            "From HTML Entity": DecodingMethod.HTML_ENTITY,
            "From Morse Code": DecodingMethod.MORSE,
            "Gunzip": DecodingMethod.GZIP,
            "Zlib Inflate": DecodingMethod.ZLIB,
            "Bzip2 Decompress": DecodingMethod.BZIP2,
            "ROT13": DecodingMethod.ROT13,
            "XOR": DecodingMethod.XOR,
        }
        return mapping.get(op_name, DecodingMethod.RAW)

    def _decode_python(self, data: bytes, crib: str = None) -> DecodingResult:
        """Python 回退解码：迭代循环直到稳定"""
        crib_pattern = None
        if crib:
            try:
                crib_pattern = re.compile(crib, re.IGNORECASE)
            except Exception:
                pass

        original_data = data
        all_steps: List[DecodingStep] = []
        visited_hashes = {hash(data)}

        for iteration in range(self.MAX_ITERATIONS):
            # 用 AutoDecoder 的 speculative_execution 做一轮解码
            round_result = self._decoder.decode(data, crib=crib)

            # 本轮没有解出新东西
            if round_result.total_layers == 0:
                break

            # 输出跟输入一样 — 稳定了
            if round_result.final_data == data:
                break

            # 防循环：之前见过这个输出
            output_hash = hash(round_result.final_data)
            if output_hash in visited_hashes:
                break
            visited_hashes.add(output_hash)

            # 记录本轮的解码步骤
            all_steps.extend(round_result.steps)
            data = round_result.final_data

            # 找到 flag 就可以提前结束
            if round_result.flags_found:
                break

            logger.debug(
                f"Magic 迭代 {iteration + 1}: "
                f"{round_result.decode_chain} -> {len(data)} bytes"
            )

        # intensive 模式：尝试 XOR 暴力破解
        # 仅当结果还没找到 flag 时才尝试
        if self._intensive and len(data) <= 1024:
            temp = DecodingResult(original_data=data, final_data=data)
            self._decoder._analyze_result(temp, crib_pattern)
            # 已经找到 flag 就不需要再 XOR
            # 有 crib 但没匹配到 → 应该尝试 XOR
            # 没有 crib 且数据不可读 → 应该尝试 XOR
            crib_not_matched = crib_pattern and not crib_pattern.search(
                data.decode('utf-8', errors='replace')
            )
            should_try_xor = (
                not temp.flags_found
                and (crib_not_matched or not temp.is_meaningful)
            )
            if should_try_xor:
                xor_result = self._xor_brute_force(data, crib_pattern)
                if xor_result and xor_result.total_layers > 0:
                    all_steps.extend(xor_result.steps)
                    data = xor_result.final_data

        # 组装最终结果
        final = DecodingResult(
            original_data=original_data,
            final_data=data,
            steps=all_steps,
            total_layers=len([s for s in all_steps if s.success]),
        )
        self._decoder._analyze_result(final, crib_pattern)
        final.score = self._decoder._calculate_score(final, crib_pattern)
        return final

    def decode_text(self, text: str, crib: str = None) -> DecodingResult:
        try:
            data = text.encode('utf-8')
        except UnicodeEncodeError:
            data = text.encode('latin-1')
        return self.decode(data, crib=crib)

    def decode_http_payload(self, payload: str, crib: str = None) -> DecodingResult:
        """解码 HTTP 载荷：先完全 URL 解码，再 Magic 循环解码

        增强：
        - URL 解码后检查是否已是可读明文，避免误解码
        - 最终输出验证：乱码率过高则丢弃解码结果
        - 检查解码结果与原文是否实质相同
        """
        from urllib.parse import unquote

        # 循环 URL 解码直到稳定
        current = payload
        for _ in range(10):
            try:
                decoded = unquote(current)
            except Exception:
                break
            if decoded == current:
                break
            current = decoded

        # 检查 URL 解码后是否已是可读明文
        # 如果乱码率极低且无编码模式特征，直接返回 URL 解码结果
        url_decoded_bytes = current.encode('utf-8', errors='replace')
        garbled_after_url = self._decoder._calc_garbled_ratio(url_decoded_bytes)
        has_encoding_pattern = bool(
            re.search(r'[A-Za-z0-9+/]{20,}={0,2}', current)  # Base64
            or re.search(r'(?:[0-9A-Fa-f]{2}){10,}', current)  # Hex
            or re.search(r'(?:%[0-9A-Fa-f]{2}){4,}', current)  # URL encoding residual
        )

        if garbled_after_url < 0.05 and not has_encoding_pattern:
            # 已是明文，构造一个仅含 URL 解码步骤的结果
            result = DecodingResult(
                original_data=payload.encode('utf-8', errors='replace'),
                final_data=url_decoded_bytes,
                steps=[DecodingStep(
                    method=DecodingMethod.URL,
                    input_data=payload.encode('utf-8', errors='replace'),
                    output_data=url_decoded_bytes,
                    success=True if current != payload else False,
                    confidence=0.95,
                )] if current != payload else [],
                total_layers=1 if current != payload else 0,
            )
            self._decoder._analyze_result(result, None)
            return result

        if crib is None:
            crib = r'flag\{[^}]+\}'

        result = self.decode_text(current, crib=crib)

        # 最终输出验证：检查 final_data 乱码率
        final_garbled = self._decoder._calc_garbled_ratio(result.final_data)
        if final_garbled > 0.2 and not result.flags_found:
            # 乱码率太高，丢弃解码结果，回退到 URL 解码后的数据
            result = DecodingResult(
                original_data=payload.encode('utf-8', errors='replace'),
                final_data=url_decoded_bytes,
                steps=[],
                total_layers=0,
            )
            self._decoder._analyze_result(result, None)
            return result

        # 检查 final_text 与 URL 解码后的原文是否实质相同
        final_text = result.final_text.strip()
        original_text = current.strip()
        if final_text == original_text and result.total_layers > 0:
            # 解码前后没变化，层数归零
            result = DecodingResult(
                original_data=payload.encode('utf-8', errors='replace'),
                final_data=url_decoded_bytes,
                steps=[],
                total_layers=0,
            )
            self._decoder._analyze_result(result, None)

        return result

    def decode_webshell_param(self, param_value: str) -> DecodingResult:
        return self.decode_text(param_value)

    def _xor_brute_force(
        self, data: bytes, crib: Optional[re.Pattern]
    ) -> Optional[DecodingResult]:
        """单字节 XOR 暴力破解 (CyberChef intensive 模式)"""
        sample = data[:self.XOR_SAMPLE_SIZE]
        best_result = None
        best_score = float('inf')

        for key in range(1, 256):
            xored = bytes(b ^ key for b in sample)

            # 快速检查：可读字符占比
            printable = sum(1 for b in xored if 32 <= b <= 126 or b in (9, 10, 13))
            if printable / len(xored) < 0.7:
                continue

            # 全量 XOR
            full_xored = bytes(b ^ key for b in data)

            # 检查是否匹配 crib
            try:
                text = full_xored.decode('utf-8', errors='replace')
            except Exception:
                continue

            matched_crib = crib and crib.search(text)

            # 检查 flag
            has_flag = any(p.search(text) for p in FLAG_PATTERNS)

            if not matched_crib and not has_flag:
                # 检查英文可读性
                chi = self._decoder._chi_squared_english(text)
                if chi > 500:
                    continue

            step = DecodingStep(
                method=DecodingMethod.XOR_BRUTE,
                input_data=data,
                output_data=full_xored,
                success=True,
                confidence=0.7,
                metadata={'xor_key': key, 'xor_key_hex': f'0x{key:02x}'}
            )

            candidate = DecodingResult(
                original_data=data,
                final_data=full_xored,
                steps=[step],
                total_layers=1,
            )
            self._decoder._analyze_result(candidate, crib)
            candidate.score = self._decoder._calculate_score(candidate, crib)

            if candidate.score < best_score:
                best_score = candidate.score
                best_result = candidate

        return best_result


class MultiLayerDecoder:
    """向后兼容的包装器，内部委托给 MagicDecoder"""
    def __init__(self):
        self._magic = MagicDecoder()

    def decode_http_payload(self, payload: str, crib: str = None) -> DecodingResult:
        return self._magic.decode_http_payload(payload, crib=crib)

    def decode_webshell_param(self, param_value: str) -> DecodingResult:
        return self._magic.decode_webshell_param(param_value)


# 快捷函数
def auto_decode(data: bytes, crib: str = None) -> DecodingResult:
    return MagicDecoder().decode(data, crib=crib)


def auto_decode_text(text: str, crib: str = None) -> DecodingResult:
    return MagicDecoder().decode_text(text, crib=crib)


def find_flags(data: bytes) -> List[str]:
    result = MagicDecoder().decode(data, crib=r'flag\{[^}]+\}|ctf\{[^}]+\}')
    return result.flags_found
