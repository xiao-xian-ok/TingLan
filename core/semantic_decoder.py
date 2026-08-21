# -*- coding: utf-8 -*-
"""semantic_decoder.py - AST 专用的语义解码器
#
# ============ 它和 auto_decoder 是什么关系 ============
#
# `core/auto_decoder.py` 是**通用**多层解码器：拿到一段字节，猜它是什么编码，
# 递归解到解不动为止。它服务于"整段载荷"。
#
# 这里这个是**语义**解码器，只服务于 AST：当语法树告诉我们"这个字符串字面量
# 是 base64_decode() 的第一个实参"时，编码方式**不用猜** —— 函数名已经写在
# 代码里了。这个先验带来三个通用解码器给不了的好处：
#
#   1. 不会走错分支。auto_decoder 实测会把 `gzdeflate+base64` 判成 base85 解出
#      乱码；这里 `gzinflate(base64_decode(x))` 的解码链是从函数名读出来的，
#      没有歧义。
#   2. 不受长度门槛限制。auto_decoder 的 `_salvage_embedded` 有 24 字符游程
#      门槛（防误报必需），所以 `eval(base64_decode("<18字符>"))` 会被漏掉。
#      这里位置先验足够强，短串照解。
#   3. 不需要 `contains_high_value` 兜底。通用扫描必须证明"解出来的东西值钱"
#      才敢采纳，否则满屏垃圾；这里解的是 sink 的实参，本来就该看。
#
# ============ 为什么需要它（这个洞长什么样）============
#
# `eval(base64_decode("<硬编码的 system('id')>"))` 是哥斯拉/冰蝎解密后最典型的
# 形状，正常代码里不可能出现。但修复前的链路上它两头都漏：
#
#   AST 侧    只看到 eval 的参数是个字符串字面量，不看里面装了什么
#   解码器侧  整段是可打印 ASCII 的 PHP 源码，不匹配任何编码启发式，
#             实测 `layers=0 chain='RAW'`，动都不动它
#
# 还有更隐蔽的一层：attack_detector 在入口跑过 auto_decoder 之后，
# `context.decoded_text` 只剩**内层**（实测外层 `eval(base64_decode(...))`
# 结构被吃掉了），于是混淆证据消失、`obfuscation_score` 恒为 0、分类还错成了
# path_traversal。所以这里的原则是**两份都留**：外层记混淆手法，内层记真实
# 意图，谁也不覆盖谁。
#
# ============ 预算 ============
#
# 上限设得小是**故意**的：这一层只负责把"编码字面量里藏着 sink"这个形状捞出来，
# 深层嵌套交给后面的研判回捞。真实样本 2~3 层足够覆盖。
#
# 但注意上限的性质 —— 它是**资源保护**，不是检测开关：
#   * 超限一律留痕（notes），绝不静默丢弃，"没看"和"看了没事"是两个结论
#   * 触发条件是语法位置（sink/解码函数的实参），不是载荷长度，
#     所以攻击者没法靠填充把自己撑出视野（对照 fast_filter 头部那四个绕过）
"""

import base64
import binascii
import codecs
import gzip
import re
import urllib.parse
import zlib
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional


@dataclass
class DecodeBudget:
    """一次顶层分析共享的解码预算

    小而明确。耗尽不是错误，是"这条到此为止"，但必须能说出来（exhausted）。

    主约束是**字节**不是**次数**，这个区别很重要：
      次数上限可以靠填充绕过 —— 前面摆 N 个能成功解码的诱饵 sink，真 payload
      排在第 N+1 位就永远解不到，而参数顺序完全由攻击者决定（这正是
      webshell_detect 的 MAX_PAYLOADS=3 和 fast_filter 那四个绕过的同款错误）。
      字节上限则不然：诱饵要吃掉预算，自己就得足够长，而那会把载荷撑到别的
      检测层眼皮底下。

    所以 max_attempts 给得很松，它是**防病态输入的天花板**（几万个 sink 的
    畸形载荷），不是常规约束；常规约束交给 max_total_output。
    """

    max_depth: int = 3
    max_single_output: int = 256 * 1024
    max_total_output: int = 1024 * 1024
    max_attempts: int = 256

    _spent_output: int = 0
    _attempts: int = 0
    exhausted: List[str] = field(default_factory=list)

    def note_exhausted(self, reason: str) -> None:
        if reason not in self.exhausted:
            self.exhausted.append(reason)

    def can_attempt(self) -> bool:
        if self._attempts >= self.max_attempts:
            self.note_exhausted(f"max_attempts:{self.max_attempts}")
            return False
        if self._spent_output >= self.max_total_output:
            self.note_exhausted(f"max_total_output:{self.max_total_output}")
            return False
        return True

    def charge(self, produced: int) -> None:
        self._attempts += 1
        self._spent_output += produced

    @property
    def attempts(self) -> int:
        return self._attempts


@dataclass
class DecodeResult:
    ok: bool
    output: str = ""
    method: str = ""
    reason: str = ""
    truncated: bool = False


def _limited_inflate(data: bytes, wbits: int, limit: int) -> bytes:
    """带输出上限的解压

    必须用 decompressobj 的 max_length，不能先解完再截断 —— gzinflate 的
    压缩比可以做到几千倍，`zlib.decompress()` 一把梭就是解压炸弹的入口。
    """
    obj = zlib.decompressobj(wbits)
    return obj.decompress(data, limit)


def _dec_base64(raw: bytes, limit: int) -> bytes:
    # PHP 的 base64_decode 默认宽松模式：忽略字母表外的字符
    cleaned = re.sub(rb'[^A-Za-z0-9+/=]', b'', raw)
    if not cleaned:
        raise ValueError("no base64 chars")
    cleaned += b'=' * (-len(cleaned) % 4)
    return base64.b64decode(cleaned)[:limit]


def _dec_base64url(raw: bytes, limit: int) -> bytes:
    cleaned = re.sub(rb'[^A-Za-z0-9\-_=]', b'', raw)
    if not cleaned:
        raise ValueError("no base64url chars")
    cleaned += b'=' * (-len(cleaned) % 4)
    return base64.urlsafe_b64decode(cleaned)[:limit]


def _dec_hex(raw: bytes, limit: int) -> bytes:
    cleaned = re.sub(rb'[^0-9A-Fa-f]', b'', raw)
    if len(cleaned) < 2:
        raise ValueError("no hex chars")
    if len(cleaned) % 2:
        cleaned = cleaned[:-1]
    return binascii.unhexlify(cleaned)[:limit]


def _dec_rot13(raw: bytes, limit: int) -> bytes:
    return codecs.encode(raw.decode('latin-1'), 'rot_13').encode('latin-1')[:limit]


def _dec_strrev(raw: bytes, limit: int) -> bytes:
    return raw[::-1][:limit]


def _dec_urldecode(raw: bytes, limit: int) -> bytes:
    return urllib.parse.unquote_to_bytes(raw.replace(b'+', b' '))[:limit]


def _dec_rawurldecode(raw: bytes, limit: int) -> bytes:
    return urllib.parse.unquote_to_bytes(raw)[:limit]


def _dec_gzinflate(raw: bytes, limit: int) -> bytes:
    return _limited_inflate(raw, -15, limit)      # raw deflate


def _dec_gzuncompress(raw: bytes, limit: int) -> bytes:
    return _limited_inflate(raw, 15, limit)       # zlib wrapper


def _dec_gzdecode(raw: bytes, limit: int) -> bytes:
    try:
        return _limited_inflate(raw, 31, limit)   # gzip wrapper
    except zlib.error:
        return gzip.decompress(raw)[:limit]


def _dec_stripslashes(raw: bytes, limit: int) -> bytes:
    return re.sub(rb'\\(.)', rb'\1', raw)[:limit]


def _dec_uudecode(raw: bytes, limit: int) -> bytes:
    return binascii.a2b_uu(raw)[:limit]


def _dec_identity(raw: bytes, limit: int) -> bytes:
    return raw[:limit]


# PHP 函数名 -> 解码实现。键是**小写**函数名，和 ast_engine 的表对齐。
#
# 只收**确定性**的解码/变换：给定输入唯一确定输出。像 str_replace 这种要看
# 实参才知道怎么变的不在这里 —— 那属于常量传播的活，不是解码。
DECODERS: Dict[str, Callable[[bytes, int], bytes]] = {
    'base64_decode': _dec_base64,
    'base64url_decode': _dec_base64url,
    'str_rot13': _dec_rot13,
    'strrev': _dec_strrev,
    'urldecode': _dec_urldecode,
    'rawurldecode': _dec_rawurldecode,
    'gzinflate': _dec_gzinflate,
    'gzuncompress': _dec_gzuncompress,
    'gzdecode': _dec_gzdecode,
    'hex2bin': _dec_hex,
    'pack': _dec_hex,                 # pack("H*", ...) 是最常见的用法
    'stripslashes': _dec_stripslashes,
    'convert_uudecode': _dec_uudecode,
    'utf8_decode': _dec_identity,
}

# 这些函数出现在解码链里本身就是混淆信号（用于打 obfuscation 分）。
# 不含 urldecode/stripslashes —— 那两个在正常代码里太常见。
OBFUSCATION_DECODERS = frozenset({
    'base64_decode', 'base64url_decode', 'str_rot13', 'strrev',
    'gzinflate', 'gzuncompress', 'gzdecode', 'hex2bin', 'pack',
    'convert_uudecode',
})


def is_decoder(func_name: str) -> bool:
    return func_name.lower() in DECODERS


def _to_bytes(payload: str) -> bytes:
    """把 PHP 字符串字面量还原成字节

    PHP 的 string 本来就是**字节串**，源码里 `"\\x1f\\x8b"` 这类转义在
    tokenizer 之后是码点 < 256 的字符。所以 latin-1 才是保真的往返方式；
    用 utf-8 会把 0x80~0xFF 编成两字节，gzinflate/gzuncompress 这些吃二进制
    的解码器直接就解不动了（这个 bug 第一版就踩了）。
    """
    try:
        return payload.encode('latin-1')
    except UnicodeEncodeError:
        # 真有多字节字符，说明这段不是二进制载荷，按 utf-8 处理
        return payload.encode('utf-8', errors='surrogateescape')


def decode_by_name(func_name: str, payload: str,
                   budget: Optional[DecodeBudget] = None) -> DecodeResult:
    """按 PHP 函数名解一层。编码方式不猜，从函数名读。"""
    name = (func_name or "").lower()
    fn = DECODERS.get(name)
    if fn is None:
        return DecodeResult(False, method=name, reason="unknown_decoder")

    budget = budget or DecodeBudget()
    if not budget.can_attempt():
        return DecodeResult(False, method=name, reason="budget_exhausted")

    limit = min(budget.max_single_output,
                max(0, budget.max_total_output - budget._spent_output))
    if limit <= 0:
        budget.note_exhausted(f"max_total_output:{budget.max_total_output}")
        return DecodeResult(False, method=name, reason="budget_exhausted")

    raw = _to_bytes(payload)

    try:
        # 多要一个字节，用来判断是不是被上限截断了
        out = fn(raw, limit + 1)
    except Exception as e:
        budget.charge(0)
        return DecodeResult(False, method=name,
                            reason=f"decode_failed:{type(e).__name__}")

    truncated = len(out) > limit
    if truncated:
        out = out[:limit]
        budget.note_exhausted(f"single_output_limit:{limit}")

    budget.charge(len(out))

    if not out:
        return DecodeResult(False, method=name, reason="empty_output")

    # 输出一律用 latin-1 转 str，和 _to_bytes 构成**无损往返**。
    #
    # 这里原来是 `out.decode('utf-8', errors='replace')`，会把中间层的二进制
    # 打成 U+FFFD —— `eval(gzinflate(base64_decode(x)))` 这种两层链，第一层
    # base64 解出来是 deflate 字节流，被 replace 破坏之后第二层 gzinflate 就
    # 再也解不动了。多层嵌套正是这个闭环要解决的问题，不能死在中间层上。
    #
    # 代价是最终明文若为 UTF-8 中文会显示成 mojibake，但判定用的模式全是
    # ASCII（latin-1 对 ASCII 完全保真），不影响检测；展示侧要好看可以在
    # 最外层再按 utf-8 试解一次。
    text = out.decode('latin-1')
    return DecodeResult(True, output=text, method=name, truncated=truncated)


# 解出来的东西**像不像代码**。不像就别往下递归了 —— 图片、证书、序列化
# 二进制解出来是一堆噪声，继续建 AST 只是烧 CPU。
_CODE_HINTS = re.compile(
    r'(<\?php|<\?=|\$\w+\s{0,3}=|\b(?:eval|assert|system|exec|shell_exec|'
    r'passthru|popen|proc_open|include|require|call_user_func|'
    r'file_put_contents|file_get_contents|base64_decode|gzinflate|'
    r'str_rot13|preg_replace|create_function|unserialize)\s{0,3}\(|'
    r'\becho\b|\bprint\b|\bfunction\s{1,5}\w)',
    re.IGNORECASE,
)


def looks_like_code(text: str) -> bool:
    if not text or len(text) < 4:
        return False

    # 二进制先挡掉：解出来是图片/证书/压缩包的话，继续建 AST 只是烧 CPU。
    #
    # 判据用**不可打印字符比例**，不能数 U+FFFD —— decode_by_name 现在用
    # latin-1 输出（保二进制往返），永远不会产生替换字符。
    sample = text[:4096]
    unprintable = sum(
        1 for ch in sample
        if ord(ch) < 32 and ch not in '\t\n\r' or ord(ch) == 127
    )
    if unprintable > len(sample) * 0.15:
        return False

    return _CODE_HINTS.search(text) is not None
