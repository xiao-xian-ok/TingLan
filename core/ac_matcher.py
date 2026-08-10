# ac_matcher.py - Aho-Corasick 多模式匹配
# 一趟扫描把几十上百个危险关键字全找出来，替掉 fast_filter 里的大交替正则
#
# 语义要和原来的正则完全对齐，否则风险分会飘：
#   1. 原正则是 \b(kw1|kw2|...)\s*\( —— 有词边界、有尾随左括号
#   2. 原正则用 findall，是非重叠的 leftmost-first
#   3. 原正则带 re.IGNORECASE
# AC 本身只做裸子串匹配且返回重叠结果，所以下面补了边界校验和重叠消解。

import re
import logging
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

logger = logging.getLogger(__name__)

try:
    import ahocorasick  # pyahocorasick
    HAS_AHOCORASICK = True
except ImportError:
    ahocorasick = None
    HAS_AHOCORASICK = False


# 词字符集，用来复刻 \b。PHP 变量带 $，函数名带 _
_WORD_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789_"
)


class UnicodeLengthMismatch(ValueError):
    """text.lower() 改变了字符串长度，AC 偏移不可用，调用方应降级到正则"""


@dataclass(frozen=True)
class PatternSpec:
    """一条待匹配的字面量模式"""
    keyword: str
    category: str = ""
    require_call: bool = False   # 命中后面必须跟 \s*(
    word_boundary: bool = False  # 命中前后必须是 \b


@dataclass(frozen=True)
class MatchHit:
    keyword: str      # 规范化后的关键字(小写)
    category: str
    start: int
    end: int          # 不含
    raw: str          # 原文中实际命中的片段(保留大小写)


class _PurePythonAutomaton:
    """pyahocorasick 不可用时的回退实现

    goto/fail/output 三张表，构建一次反复用。关键字数量在百级别，
    构建耗时可以忽略；匹配是纯 O(n + z)。
    """

    __slots__ = ("_goto", "_fail", "_output", "_size")

    def __init__(self) -> None:
        self._goto: List[Dict[str, int]] = [{}]
        self._fail: List[int] = [0]
        self._output: List[List[str]] = [[]]
        self._size = 1

    def _new_node(self) -> int:
        self._goto.append({})
        self._fail.append(0)
        self._output.append([])
        self._size += 1
        return self._size - 1

    def add(self, word: str) -> None:
        node = 0
        for ch in word:
            nxt = self._goto[node].get(ch)
            if nxt is None:
                nxt = self._new_node()
                self._goto[node][ch] = nxt
            node = nxt
        self._output[node].append(word)

    def build(self) -> None:
        from collections import deque

        queue = deque()
        for child in self._goto[0].values():
            self._fail[child] = 0
            queue.append(child)

        while queue:
            node = queue.popleft()
            for ch, child in self._goto[node].items():
                queue.append(child)
                state = self._fail[node]
                while state and ch not in self._goto[state]:
                    state = self._fail[state]
                self._fail[child] = self._goto[state].get(ch, 0)
                if self._fail[child] == child:
                    self._fail[child] = 0
                self._output[child].extend(self._output[self._fail[child]])

    def iter(self, text: str) -> Iterable[Tuple[int, str]]:
        """yield (end_index_inclusive, keyword)"""
        node = 0
        goto = self._goto
        fail = self._fail
        output = self._output

        for idx, ch in enumerate(text):
            while node and ch not in goto[node]:
                node = fail[node]
            node = goto[node].get(ch, 0)
            if output[node]:
                for word in output[node]:
                    yield idx, word


class MultiPatternMatcher:
    """多模式匹配器

    用法:
        m = MultiPatternMatcher([PatternSpec('eval', 'sink', require_call=True), ...])
        for hit in m.find_all(text):
            ...

    大小写：内部统一按小写建自动机，扫描时对文本做 lower()。
    极少数 Unicode 字符 lower() 后长度会变（比如 'İ'），那样偏移就对不上了，
    这种情况直接降级到正则路径，别硬算。
    """

    def __init__(self, specs: Sequence[PatternSpec], allow_overlaps: bool = False):
        self._specs: Dict[str, PatternSpec] = {}
        for spec in specs:
            key = spec.keyword.lower()
            if not key:
                continue
            # 同一个关键字被登记多次时，**保留约束更弱的那条**。
            #
            # 注释原来写的是"保留约束更强的"，实现却是"保留第一条"，两边对不上。
            # 按听澜的取舍应该取弱：约束越强命中越少，而漏一条的代价远大于多看
            # 一条。举例——'eval' 如果既以 require_call=True 又以 False 登记，
            # 取强会让裸 `eval` 从视野里消失。
            existing = self._specs.get(key)
            if existing is None:
                self._specs[key] = PatternSpec(
                    keyword=key,
                    category=spec.category,
                    require_call=spec.require_call,
                    word_boundary=spec.word_boundary,
                )
            else:
                self._specs[key] = PatternSpec(
                    keyword=key,
                    category=existing.category or spec.category,
                    require_call=existing.require_call and spec.require_call,
                    word_boundary=existing.word_boundary and spec.word_boundary,
                )

        self._allow_overlaps = allow_overlaps
        self._backend = ""
        self._automaton = None
        self._fallback_pattern: Optional[re.Pattern] = None
        self._build()

    # ---------- 构建 ----------

    def _build(self) -> None:
        if not self._specs:
            self._backend = "empty"
            return

        if HAS_AHOCORASICK:
            try:
                automaton = ahocorasick.Automaton()
                for key in self._specs:
                    automaton.add_word(key, key)
                automaton.make_automaton()
                self._automaton = automaton
                self._backend = "pyahocorasick"
                return
            except Exception as e:  # pragma: no cover - 库异常极少见
                logger.warning(f"pyahocorasick 构建失败，回退纯 Python AC: {e}")

        try:
            automaton = _PurePythonAutomaton()
            for key in self._specs:
                automaton.add(key)
            automaton.build()
            self._automaton = automaton
            self._backend = "python-ac"
        except Exception as e:  # pragma: no cover
            logger.warning(f"纯 Python AC 构建失败，回退正则: {e}")
            self._build_regex_fallback()

    def _build_regex_fallback(self) -> None:
        escaped = sorted((re.escape(k) for k in self._specs), key=len, reverse=True)
        self._fallback_pattern = re.compile("(" + "|".join(escaped) + ")", re.IGNORECASE)
        self._backend = "regex"

    @property
    def backend(self) -> str:
        return self._backend

    @property
    def pattern_count(self) -> int:
        return len(self._specs)

    # ---------- 匹配 ----------

    def find_all(self, text: str, lowered: Optional[str] = None) -> List[MatchHit]:
        """扫一段文本。

        `lowered` 允许调用方把 `text.lower()` 的结果传进来复用 —— 同一段文本
        通常要过好几个 matcher（关键字表、污点源表各一个），每个都自己 lower
        一遍等于把整段文本反复复制。传进来时调用方要保证它确实是 text.lower()。
        """
        if not text or not self._specs:
            return []

        if lowered is None:
            lowered = text.lower()
        if len(lowered) != len(text):
            # lower() 改变了长度，偏移不可靠，交给调用方走正则
            raise UnicodeLengthMismatch(
                "lower() changed text length; AC offsets unreliable"
            )

        raw_hits = self._raw_hits(lowered)
        if not raw_hits:
            return []

        checked = [h for h in raw_hits if self._passes_constraints(lowered, h)]
        if not checked:
            return []

        if not self._allow_overlaps:
            checked = self._resolve_overlaps(checked)

        return [
            MatchHit(
                keyword=start_end[2],
                category=self._specs[start_end[2]].category,
                start=start_end[0],
                end=start_end[1],
                raw=text[start_end[0]:start_end[1]],
            )
            for start_end in checked
        ]

    def _raw_hits(self, lowered: str) -> List[Tuple[int, int, str]]:
        """返回 (start, end, keyword)，end 不含"""
        hits: List[Tuple[int, int, str]] = []

        if self._backend == "pyahocorasick":
            for end_idx, key in self._automaton.iter(lowered):
                hits.append((end_idx - len(key) + 1, end_idx + 1, key))
        elif self._backend == "python-ac":
            for end_idx, key in self._automaton.iter(lowered):
                hits.append((end_idx - len(key) + 1, end_idx + 1, key))
        elif self._backend == "regex" and self._fallback_pattern:
            for m in self._fallback_pattern.finditer(lowered):
                hits.append((m.start(), m.end(), m.group(0)))

        return hits

    def _passes_constraints(self, lowered: str, hit: Tuple[int, int, str]) -> bool:
        start, end, key = hit
        spec = self._specs.get(key)
        if spec is None:
            return False

        if spec.word_boundary:
            if start > 0 and lowered[start - 1] in _WORD_CHARS:
                return False
            # 尾边界：require_call 的场景由下面的括号检查兜住，
            # 但 kw 后面直接跟词字符(比如 file_get_contents 里的 file)必须排除
            if end < len(lowered) and lowered[end] in _WORD_CHARS:
                return False

        if spec.require_call:
            idx = end
            n = len(lowered)
            # 复刻 \s* —— Python re 的 \s 含 \t\n\r\f\v 和空格
            while idx < n and lowered[idx] in " \t\n\r\f\v":
                idx += 1
            if idx >= n or lowered[idx] != "(":
                return False

        return True

    @staticmethod
    def _resolve_overlaps(hits: List[Tuple[int, int, str]]) -> List[Tuple[int, int, str]]:
        """leftmost-longest 贪心去重叠

        约束过滤之后，我们的关键字集里同一个起点不会有两个合法命中
        （require_call + word_boundary 已经把 file / file_get_contents 这类
        前缀关系排干净了），所以这里主要是防御性的。
        """
        hits.sort(key=lambda h: (h[0], -(h[1] - h[0])))
        kept: List[Tuple[int, int, str]] = []
        cursor = -1
        for start, end, key in hits:
            if start < cursor:
                continue
            kept.append((start, end, key))
            cursor = end
        return kept


def build_matcher(
    groups: Dict[str, Iterable[str]],
    require_call: bool = False,
    word_boundary: bool = False,
    allow_overlaps: bool = False,
) -> MultiPatternMatcher:
    """从 {category: [keyword, ...]} 快速建一个匹配器"""
    specs: List[PatternSpec] = []
    for category, keywords in groups.items():
        for kw in keywords:
            specs.append(PatternSpec(
                keyword=kw,
                category=category,
                require_call=require_call,
                word_boundary=word_boundary,
            ))
    return MultiPatternMatcher(specs, allow_overlaps=allow_overlaps)
