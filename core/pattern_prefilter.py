# -*- coding: utf-8 -*-
"""正则预筛 —— 用"必含字面量"决定某条规则**要不要跑**

## 为什么需要它

`search_full` 改成全量扫描（修掉分块丢命中的洞）之后，覆盖面对了，但成本
真实化了：119 条规则各自在整段文本上跑一趟，7.8MB 正文实测 6.74 秒。而
**Python 的 `re` 在匹配期间不释放 GIL** —— 一次 `pattern.search()` 是单个
不可抢占的 C 调用，最慢的单条规则能占住 GIL 350ms，UI 线程的事件循环延迟
被顶到 400ms 以上，界面看起来就是卡死。

修 P0-1 之前那个 `text[:100000]` 的截断顺带充当了 GIL 让渡点。截断是安全洞，
不能退回去；缺的那个让渡点得用别的东西补上。

## 它凭什么是"不漏"的

一条正则如果**必须**包含某个字面量（该字面量在模式里处于顶层、非可选、
不在字符类里、且模式顶层没有 `|` 分支可以绕开它），那么：

    正则能匹配这段文本  ⟹  该字面量出现在这段文本里

逆否即：字面量不出现 ⟹ 正则必然不匹配 ⟹ **跑它就是白跑**。

这和协议门控"该协议层帧数为 0 → 分析器扫也扫不出东西"是同一个论证形式，
跳过是"看完之后可证明安全"，不是"没看所以不知道"。

## 它和被删掉的"分块扫描"有什么本质区别

分块是按**位置**做取舍——"这一段我不在这儿看"，于是命中长度一超过重叠宽度
就两边都丢，而且这个上限没人守得住。

预筛是按**规则**做取舍——"这条规则在整段文本上都不可能命中"。它**不改变
任何一条实际执行的匹配的输入**：决定跑，就在完整文本上跑。所以不存在
"命中太长装不下"这类失效模式。

**预筛只决定跑不跑，不决定在哪跑。**

## 保守性

提取器只在能完全看懂模式结构时才给出字面量；遇到顶层 `|`、看不懂的构造、
或者字面量全是可选的，一律返回空串 = **这条规则永远照跑**。宁可多跑，
不可少跑。AC 后端不可用时整个预筛自动关闭。
"""

import re
import threading
from typing import Dict, FrozenSet, Iterable, List, Optional, Pattern, Set, Tuple
import logging

logger = logging.getLogger(__name__)

try:
    import ahocorasick  # pyahocorasick
    HAS_AC = True
except ImportError:  # pragma: no cover
    ahocorasick = None
    HAS_AC = False


# `\x` 后面跟这些字母时是零宽断言或字符组，不是字面量
_NON_LITERAL_ESCAPES = set("sSdDwWbBAZzGNpPuUxc0123456789")

# 太短的字面量选择性差（几乎每段文本都有），但仍然是**正确**的判据。
# 保留 1 个字符：像反引号、`${` 这种规则，正常二进制上传里确实不会出现。
_MIN_LITERAL = 1


def _skip_class(source: str, i: int) -> int:
    """跳过字符类 `[...]`，返回 `]` 之后的下标"""
    n = len(source)
    i += 1                       # 跳过 '['
    if i < n and source[i] == "^":
        i += 1
    if i < n and source[i] == "]":   # 首位的 ] 是普通字符
        i += 1
    while i < n:
        if source[i] == "\\":
            i += 2
            continue
        if source[i] == "]":
            return i + 1
        i += 1
    return n


def _skip_group(source: str, i: int) -> int:
    """跳过 `(...)`（含嵌套、字符类、转义），返回 `)` 之后的下标"""
    n = len(source)
    depth = 0
    while i < n:
        ch = source[i]
        if ch == "\\":
            i += 2
            continue
        if ch == "[":
            i = _skip_class(source, i)
            continue
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return n


def _quantifier_min_zero(source: str, i: int) -> Tuple[bool, int, bool]:
    """判断 i 处是不是量词，返回 (是量词, 量词之后的下标, 最小次数是否为 0)"""
    ch = source[i]
    if ch in "*?":
        return True, i + 1, True
    if ch == "+":
        return True, i + 1, False
    if ch == "{":
        end = source.find("}", i)
        if end == -1:
            return False, i, False
        body = source[i + 1:end]
        if not re.fullmatch(r"\d*(,\d*)?", body) or body in ("", ","):
            return False, i, False        # 不是量词，是字面的花括号
        low = body.split(",")[0]
        return True, end + 1, (low == "" or int(low) == 0)
    return False, i, False


def required_literal(source: str) -> str:
    """从正则源码里提取一个**必含**字面量；提不出就返回空串。

    只认顶层（不在任何 `(...)` / `[...]` 里）、非可选的字面字符序列。
    模式里只要出现顶层 `|`，整条直接放弃 —— 分支意味着任何一段都可能被绕开。
    """
    n = len(source)
    i = 0
    depth_zero_runs: List[str] = []
    run: List[str] = []
    last_was_quantifiable = False     # 上一个 token 是不是"可被量词修饰的字面字符"

    while i < n:
        ch = source[i]

        # 量词：修饰前一个 token
        is_quant, next_i, min_zero = _quantifier_min_zero(source, i)
        if is_quant:
            if min_zero and last_was_quantifiable and run:
                run.pop()             # 这个字符可以出现 0 次，不是必需的
            # 量词可能允许出现多次，字面量的连续性到此为止
            if run:
                depth_zero_runs.append("".join(run))
                run = []
            last_was_quantifiable = False
            # 惰性/占有量词后缀
            if next_i < n and source[next_i] in "?+":
                next_i += 1
            i = next_i
            continue

        if ch == "\\":
            if i + 1 >= n:
                break
            nxt = source[i + 1]
            if nxt in _NON_LITERAL_ESCAPES:
                if run:
                    depth_zero_runs.append("".join(run))
                    run = []
                last_was_quantifiable = False
            else:
                run.append(nxt)
                last_was_quantifiable = True
            i += 2
            continue

        if ch == "[":
            if run:
                depth_zero_runs.append("".join(run))
                run = []
            last_was_quantifiable = False
            i = _skip_class(source, i)
            continue

        if ch == "(":
            if run:
                depth_zero_runs.append("".join(run))
                run = []
            last_was_quantifiable = False
            i = _skip_group(source, i)
            continue

        if ch == "|":
            # 顶层分支：任何一段都可能被绕开，整条放弃
            return ""

        if ch in "^$":
            if run:
                depth_zero_runs.append("".join(run))
                run = []
            last_was_quantifiable = False
            i += 1
            continue

        if ch == ".":
            if run:
                depth_zero_runs.append("".join(run))
                run = []
            last_was_quantifiable = False
            i += 1
            continue

        if ch == ")":
            # 括号不配对，看不懂就整条放弃
            return ""

        run.append(ch)
        last_was_quantifiable = True
        i += 1

    if run:
        depth_zero_runs.append("".join(run))

    best = ""
    for candidate in depth_zero_runs:
        if len(candidate) > len(best):
            best = candidate
    return best if len(best) >= _MIN_LITERAL else ""


class _Unbounded(Exception):
    """模式的最大匹配长度没有有限上界"""


# 一次递归下降同时算两样东西：
#   lits   —— 必含字面量的**候选集**。语义是"任何一次匹配都至少包含其中一个"。
#             None 表示推不出来（该规则必须无条件跑）。
#   maxlen —— 最大匹配长度上界，None 表示无界。
#
# 分支必须整体处理：`\bexec\s{0,5}\(|__import__\s{0,5}\(` 的两个分支各有
# 必含字面量，取并集之后仍然是有效判据。这类规则恰恰是最贵的一批 ——
# 顶层带 `|` 时 re 用不上字面量快路径，只能逐字符扫，实测单条 166ms。
_Analysis = Tuple[Optional[FrozenSet[str]], Optional[int]]


def _combine_alt(parts: List[_Analysis]) -> _Analysis:
    """分支：字面量取并集（**任一分支推不出就整体放弃**），长度取最大"""
    lits: Optional[Set[str]] = set()
    for branch_lits, _ in parts:
        if branch_lits is None or lits is None:
            lits = None
            break
        lits |= branch_lits

    maxlen: Optional[int] = 0
    for _, branch_len in parts:
        if branch_len is None:
            maxlen = None
            break
        maxlen = max(maxlen, branch_len)
    return (frozenset(lits) if lits else None), maxlen


def _combine_concat(parts: List[_Analysis]) -> _Analysis:
    """串联：每一段都是必需的，所以**任选一段**的字面量即可；长度求和

    选哪一段？选最"挑剔"的那个——候选集里最短的字面量越长，选择性越好。
    """
    best: Optional[FrozenSet[str]] = None
    best_score = -1
    for part_lits, _ in parts:
        if not part_lits:
            continue
        score = min(len(l) for l in part_lits)
        if score > best_score:
            best, best_score = part_lits, score

    total: Optional[int] = 0
    for _, part_len in parts:
        if part_len is None:
            total = None
            break
        total += part_len
    return best, total


def _analyze_alt(source: str, i: int) -> Tuple[_Analysis, int]:
    branches: List[_Analysis] = []
    branch, i = _analyze_concat(source, i)
    branches.append(branch)
    while i < len(source) and source[i] == "|":
        branch, i = _analyze_concat(source, i + 1)
        branches.append(branch)
    return _combine_alt(branches), i


def _analyze_concat(source: str, i: int) -> Tuple[_Analysis, int]:
    parts: List[_Analysis] = []
    run: List[str] = []
    n = len(source)

    def flush():
        if run:
            parts.append((frozenset({"".join(run).lower()}), len(run)))
            run.clear()

    while i < n and source[i] not in "|)":
        atom, next_i, atom_is_char = _analyze_atom(source, i)
        quant = _read_quantifier(source, next_i)
        if quant is None:
            if atom_is_char is not None:
                run.append(atom_is_char)
                i = next_i
                continue
            flush()
            parts.append(atom)
            i = next_i
            continue

        min_zero, repeat, after = quant
        if atom_is_char is not None:
            if min_zero:
                # 可以出现 0 次，这个字符不是必需的
                flush()
                parts.append((None, None if repeat is None else repeat))
            else:
                run.append(atom_is_char)
                flush()
                parts.append((None, None if repeat is None else repeat - 1))
        else:
            flush()
            lits, length = atom
            parts.append((
                None if min_zero else lits,
                None if (repeat is None or length is None) else length * repeat,
            ))
        i = after

    flush()
    if not parts:
        return (None, 0), i
    return _combine_concat(parts), i


def _read_quantifier(source: str, i: int):
    """返回 (最小次数是否为 0, 最大重复次数 or None, 量词之后的下标)"""
    n = len(source)
    if i >= n:
        return None
    ch = source[i]
    if ch in "*+?":
        i += 1
        if i < n and source[i] in "?+":
            i += 1
        if ch == "?":
            return True, 1, i
        return (ch == "*"), None, i
    if ch == "{":
        end = source.find("}", i)
        if end == -1:
            return None
        body = source[i + 1:end]
        if not re.fullmatch(r"\d*(,\d*)?", body) or body in ("", ","):
            return None
        if "," in body:
            low, high = body.split(",", 1)
            repeat = None if high == "" else int(high)
            min_zero = (low == "" or int(low) == 0)
        else:
            repeat = int(body)
            min_zero = repeat == 0
        end += 1
        if end < n and source[end] in "?+":
            end += 1
        return min_zero, repeat, end
    return None


def _analyze_atom(source: str, i: int) -> Tuple[_Analysis, int, Optional[str]]:
    """返回 ((字面量集, 最大长度), 下一个下标, 若是单个字面字符则给出该字符)"""
    n = len(source)
    ch = source[i]

    if ch == "(":
        if source.startswith("(?", i):
            head = source[i:i + 4]
            if (head.startswith("(?=") or head.startswith("(?!")
                    or head.startswith("(?<=") or head.startswith("(?<!")):
                return (None, 0), _skip_group(source, i), None   # 断言零宽
            inline = re.match(r"\(\?[aiLmsux]+\)", source[i:])
            if inline:
                return (None, 0), i + inline.end(), None
            if head.startswith("(?:"):
                inner, j = _analyze_alt(source, i + 3)
            else:
                named = re.match(r"\(\?P<\w+>", source[i:])
                if not named:
                    return (None, None), _skip_group(source, i), None
                inner, j = _analyze_alt(source, i + named.end())
            if j >= n or source[j] != ")":
                return (None, None), n, None
            return inner, j + 1, None
        inner, j = _analyze_alt(source, i + 1)
        if j >= n or source[j] != ")":
            return (None, None), n, None
        return inner, j + 1, None

    if ch == "[":
        return (None, 1), _skip_class(source, i), None

    if ch == "\\":
        if i + 1 >= n:
            return (None, None), n, None
        nxt = source[i + 1]
        if nxt in "bBAZzG":
            return (None, 0), i + 2, None
        if nxt.isdigit():
            return (None, None), i + 2, None        # 反向引用，看不懂
        if nxt == "x" and re.match(r"[0-9a-fA-F]{2}", source[i + 2:i + 4] or ""):
            return (None, 1), i + 4, chr(int(source[i + 2:i + 4], 16))
        if nxt in _NON_LITERAL_ESCAPES:
            return (None, 1), i + 2, None
        if nxt in "nrtf":
            return (None, 1), i + 2, {"n": "\n", "r": "\r", "t": "\t", "f": "\f"}[nxt]
        return (None, 1), i + 2, nxt

    if ch in "^$":
        return (None, 0), i + 1, None

    if ch == ".":
        return (None, 1), i + 1, None

    return (None, 1), i + 1, ch


def _analyze(source: str) -> _Analysis:
    try:
        result, index = _analyze_alt(source, 0)
    except Exception as error:          # pragma: no cover - 兜底
        logger.debug("模式分析失败(%s)，按不可门控处理: %s", source[:40], error)
        return None, None
    if index != len(source):
        return None, None               # 没吃完 = 没看懂
    return result


def required_literals(source: str) -> Optional[FrozenSet[str]]:
    """必含字面量候选集：任何一次匹配都至少包含其中一个。None = 推不出来"""
    lits, _maxlen = _analyze(source)
    if not lits:
        return None
    return frozenset(l for l in lits if len(l) >= _MIN_LITERAL) or None


def required_literal(source: str) -> str:
    """候选集恰好只有一个时返回它，否则空串（给单元测试和排查用）"""
    lits = required_literals(source)
    if lits and len(lits) == 1:
        return next(iter(lits))
    return ""


def max_match_len(source: str) -> Optional[int]:
    """推导一条正则**最大可能的匹配长度**；无界或看不懂时返回 None。

    窗口宽度就是从这里来的：一个包含位置 p 的完整命中，起点不可能早于
    `p - maxlen`，终点不可能晚于 `p + maxlen`。所以只要 maxlen 有限，
    按它开出来的窗口**必然装得下任何一个真命中** —— 这是"开窗不漏"的
    全部依据，不是经验值。
    """
    _lits, maxlen = _analyze(source)
    return maxlen


def _pattern_source(entry) -> Optional[str]:
    """从各种形状里取出正则源码；取不出返回 None。

    为什么要兼容多种形状：`BaseDetector._patterns` 存的是
    `{名字: (编译好的 Pattern, 权重)}` **元组**，而这里天然想要的是
    `{名字: Pattern}`。传错时 `getattr(tuple, "pattern", "")` 会安静地返回
    空串 —— 提不出字面量 → 全部落进 `_always_run` → **预筛完全空转，
    加速比 1.00x，而结果依然正确**。

    "降级成正确但无效"是最难���现的一类失效：不报错、不变红、不漏检，
    只是白干。所以这里两种形状都吃，取不出时 `logger.warning` 出声。
    """
    if entry is None:
        return None
    source = getattr(entry, "pattern", None)
    if isinstance(source, str):
        return source
    if isinstance(entry, str):
        return entry
    if isinstance(entry, (tuple, list)) and entry:
        # (Pattern, weight) 这类打包形状
        return _pattern_source(entry[0])
    return None


class PatternPrefilter:
    """一组规则的预筛器。线程安全，构建一次反复用。"""

    # 合并后的窗口总长度超过原文的这个比例时，直接全量扫 —— 开一堆窗口
    # 反而比让 re 线性走一趟更慢。纯性能启发，不影响正确性。
    _WINDOW_GIVEUP_RATIO = 0.5

    def __init__(self, patterns: Dict[str, Pattern]):
        self._always_run: Set[str] = set()
        self._by_literal: Dict[str, Set[str]] = {}
        self._span: Dict[str, Optional[int]] = {}     # 规则名 -> 最大匹配长度
        self._literal_of: Dict[str, FrozenSet[str]] = {}   # 规则名 -> 必含字面量候选集
        self._automaton = None
        self._lock = threading.Lock()

        for name, entry in patterns.items():
            source = _pattern_source(entry)
            if source is None:
                # 看不出是个正则就当它不可门控，但要出声：静默降级成"全跑"
                # 结果虽然正确，却一点不加速，而且没人会发现
                logger.warning(
                    "预筛拿不到规则 %s 的模式源码（类型 %s），该规则退回全量匹配",
                    name, type(entry).__name__)
                self._always_run.add(name)
                self._span[name] = None
                continue
            lits, span = _analyze(source)
            self._span[name] = span
            lits = frozenset(l for l in (lits or ()) if len(l) >= _MIN_LITERAL)
            if not lits:
                self._always_run.add(name)
            else:
                # 一条规则可以挂在多个字面量下（分支各自的必含字面量），
                # 任一命中就要跑它
                self._literal_of[name] = lits
                for literal in lits:
                    self._by_literal.setdefault(literal, set()).add(name)

        if self._by_literal and HAS_AC:
            try:
                automaton = ahocorasick.Automaton()
                for literal in self._by_literal:
                    automaton.add_word(literal, literal)
                automaton.make_automaton()
                self._automaton = automaton
            except Exception as error:      # pragma: no cover
                logger.warning("预筛自动机构建失败，退回全量执行: %s", error)
                self._automaton = None

        if self._automaton is None:
            # 没有 AC 后端就整体关闭预筛：正确性优先，慢一点无所谓
            self._always_run |= set(self._literal_of)
            self._by_literal = {}
            self._literal_of = {}

    @property
    def gated_count(self) -> int:
        return len(self._literal_of)

    @property
    def always_count(self) -> int:
        return len(self._always_run)

    def bounded_count(self) -> int:
        return sum(1 for name in self._literal_of if self._span.get(name) is not None)

    # ---------------------------------------------------------------- 扫描

    def _literal_hits(self, lowered: str) -> Dict[str, List[int]]:
        """一趟 AC 拿到每个字面量的全部出现位置（起点）"""
        hits: Dict[str, List[int]] = {}
        for end, literal in self._automaton.iter(lowered):
            hits.setdefault(literal, []).append(end - len(literal) + 1)
        return hits

    def plan(self, text: str) -> "List[Tuple[str, Optional[List[Tuple[int, int]]]]]":
        """给出每条规则的执行计划。

        返回 [(规则名, 区间列表 or None)]：
          - 不在列表里     = 可以证明它在这段文本上不可能匹配，**跳过**
          - 区间列表为 None = 必须在**完整文本**上跑
          - 区间列表非空   = 只在这些区间上跑，区间是按该规则自身的最大匹配
                             长度算出来的，**保证任何一个完整命中都落在某个
                             区间内**

        第三种情况就是"按 AC 命中点开窗"。窗口宽度不是拍脑袋定的常数，而是
        从模式本身推出来的上界：一个包含位置 p 的命中，起点不可能早于
        `p - maxlen`，终点不可能晚于 `p + maxlen`。推不出有限上界的规则
        （含 `*` / `+` / `{n,}`）一律退回完整文本，不给它开窗。
        """
        plans: List[Tuple[str, Optional[List[Tuple[int, int]]]]] = [
            (name, None) for name in self._always_run
        ]
        if not self._literal_of or not text:
            return plans

        try:
            lowered = text.lower()
        except Exception:               # pragma: no cover
            return plans + [(n, None) for n in self._literal_of]
        if len(lowered) != len(text):
            # lower() 改了长度（极少数 Unicode），偏移不可信，全部退回全量
            return plans + [(n, None) for n in self._literal_of]

        hits = self._literal_hits(lowered)
        total = len(text)
        if not hits:
            return plans

        for name, literals in self._literal_of.items():
            positions: List[int] = []
            longest = 0
            missing = False
            for literal in literals:
                found = hits.get(literal)
                if not found:
                    missing = True
                    continue
                positions.extend(found)
                longest = max(longest, len(literal))
            if not positions:
                continue        # 该规则的全部必含字面量都不出现 → 跑也是白跑

            span = self._span.get(name)
            if span is None:
                plans.append((name, None))          # 最大长度无界，只能全量
                continue

            positions.sort()
            regions = _merge_regions(positions, longest, span, total)
            covered = sum(end - start for start, end in regions)
            if covered >= total * self._WINDOW_GIVEUP_RATIO:
                plans.append((name, None))          # 窗口铺满了，不如直接全量
            else:
                plans.append((name, regions))
        return plans

    def candidates(self, text: str) -> Set[str]:
        """只回答"哪些规则需要跑"，不关心在哪跑"""
        return {name for name, _regions in self.plan(text)}


def _merge_regions(positions: List[int], literal_len: int, span: int,
                   total: int) -> List[Tuple[int, int]]:
    """把每个字面量出现位置扩成窗口并合并重叠区间

    包含位置 p..p+literal_len 的完整命中，起点 >= p - span，终点 <= p + span
    （span 是该规则的最大匹配长度上界），所以窗口取 [p-span, p+literal_len+span)
    一定能装下它。
    """
    regions: List[Tuple[int, int]] = []
    for pos in positions:
        start = max(0, pos - span)
        end = min(total, pos + literal_len + span)
        if regions and start <= regions[-1][1]:
            prev_start, prev_end = regions[-1]
            regions[-1] = (prev_start, max(prev_end, end))
        else:
            regions.append((start, end))
    return regions



_cache_lock = threading.Lock()
_prefilter_cache: "Dict[int, PatternPrefilter]" = {}

# 全局预筛器：所有检测器的规则合到一个自动机里，一段文本**只扫一趟**。
# 之前按检测器各建一个，10 个检测器就是 10 次 lower() + 10 趟 AC，
# 7.8MB 上实测把预筛本身变成了瓶颈（比它要省掉的正则还贵）。
_global_lock = threading.Lock()
_global_patterns: "Dict[str, Pattern]" = {}
_global_prefilter: "Optional[PatternPrefilter]" = None


def register_patterns(qualified: Dict[str, Pattern]) -> None:
    """把一组规则登记进全局预筛器（键要全局唯一，用 `攻击类型:规则名`）"""
    global _global_prefilter
    with _global_lock:
        changed = False
        for name, pattern in qualified.items():
            if name not in _global_patterns:
                _global_patterns[name] = pattern
                changed = True
        if changed:
            _global_prefilter = None        # 下次用时重建


def global_plan(text: str) -> "Dict[str, Optional[List[Tuple[int, int]]]]":
    """对整段文本算一次执行计划，返回 {规则名: 区间列表 or None}

    不在返回值里的规则 = 可以证明它在这段文本上不可能命中。
    """
    global _global_prefilter
    prefilter = _global_prefilter
    if prefilter is None:
        with _global_lock:
            if _global_prefilter is None:
                _global_prefilter = PatternPrefilter(dict(_global_patterns))
            prefilter = _global_prefilter
    return dict(prefilter.plan(text))


def get_prefilter(owner_key: int, patterns: Dict[str, Pattern]) -> PatternPrefilter:
    """按拥有者（检测器实例）缓存预筛器"""
    prefilter = _prefilter_cache.get(owner_key)
    if prefilter is None:
        with _cache_lock:
            prefilter = _prefilter_cache.get(owner_key)
            if prefilter is None:
                prefilter = PatternPrefilter(patterns)
                _prefilter_cache[owner_key] = prefilter
    return prefilter
