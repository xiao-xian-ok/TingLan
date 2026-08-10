# ml_scorer.py - 轻量 ML 辅助评分
#
# 定位说明（很重要，别把它当主判定用）：
#
# 这个项目里没有带标签的训练语料。如果用规则引擎自己的输出当标签去训模型，
# 模型学到的就是规则本身，融合回去等于同一个信号被加权两次 —— 只会放大误报。
# 所以这里的设计是：
#
#   1. 特征提取和推理引擎是真的（纯 Python，运行时不依赖 sklearn/numpy）
#   2. 随包发的默认模型是**人工标定的逻辑回归**，作用保守，不是训练出来的
#   3. 真正的随机森林靠 tools/train_payload_classifier.py 用你自己的标注数据离线训，
#      导出同格式 JSON 后这里直接加载替换
#   4. 融合只在"规则自己也拿不准"的灰区生效，调整幅度硬上限 ±MAX_ADJUST，
#      且规则权重为 0（完全没证据）时 ML 不允许无中生有
#
# 在灌入真实标注数据之前，它对准确度的提升接近 0。框架先备好。

import json
import math
import os
import re
import threading
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple
import logging

logger = logging.getLogger(__name__)


# 特征顺序是模型契约的一部分，导出的 JSON 里会带一份做校验，不要随意插入/重排
FEATURE_NAMES: Tuple[str, ...] = (
    "log_length",
    "entropy",
    "printable_ratio",
    "alpha_ratio",
    "digit_ratio",
    "special_ratio",
    "upper_ratio",
    "whitespace_ratio",
    "non_ascii_ratio",
    "distinct_char_ratio",
    "log_max_token_len",
    "base64_alphabet_ratio",
    "hex_ratio",
    "url_encoded_density",
    "log_param_count",
    "log_max_param_value_len",
    "log_avg_param_value_len",
    "keyword_density_per_kb",
    "max_special_run",
    "is_write_method",
)

FEATURE_COUNT = len(FEATURE_NAMES)

_B64_ALPHABET = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
_HEX_ALPHABET = frozenset("0123456789abcdefABCDEF")
_TOKEN_RE = re.compile(r"[A-Za-z0-9+/=_\-]{4,}")
_PCT_RE = re.compile(r"%[0-9A-Fa-f]{2}")

_DANGER_WORDS = (
    "eval", "assert", "system", "exec", "shell_exec", "passthru", "popen",
    "base64_decode", "gzinflate", "str_rot13", "unserialize", "call_user_func",
    "file_put_contents", "file_get_contents", "preg_replace", "create_function",
    "$_post", "$_get", "$_request", "$_cookie", "php://input", "cmd", "whoami",
    "select", "union", "<script", "onerror", "../", "/etc/passwd",
)


def _safe_log1p(value: float) -> float:
    return math.log1p(max(0.0, value))


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    ent = 0.0
    for c in freq:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return ent


@dataclass
class FeatureVector:
    values: List[float] = field(default_factory=list)

    def as_dict(self) -> Dict[str, float]:
        return dict(zip(FEATURE_NAMES, self.values))


def extract_features(
    payload,
    method: str = "",
    content_type: str = "",
    uri: str = "",
    max_sample: int = 65536,
) -> FeatureVector:
    """把一段载荷压成固定长度的数值向量

    payload 接受 bytes 或 str。超过 max_sample 只取头部采样，保证是 O(1) 开销。
    """
    if payload is None:
        payload = b""
    if isinstance(payload, str):
        raw = payload.encode("utf-8", errors="ignore")
        text = payload
    else:
        raw = bytes(payload)
        text = raw.decode("utf-8", errors="ignore")

    full_len = len(raw)
    raw = raw[:max_sample]
    text = text[:max_sample]
    n = len(text)

    if n == 0:
        return FeatureVector([0.0] * FEATURE_COUNT)

    alpha = digit = upper = space = special = non_ascii = printable = 0
    b64_chars = hex_chars = 0
    distinct = set()
    max_special_run = 0
    cur_special_run = 0

    # 一趟循环把所有逐字符统计做完。原来 b64/hex 两项各自又起了一个
    # `sum(1 for ch in text ...)`，等于把整段文本多扫两遍。
    for ch in text:
        distinct.add(ch)
        code = ord(ch)
        if code > 127:
            non_ascii += 1
        if 32 <= code < 127 or ch in "\t\n\r":
            printable += 1
        if ch in _B64_ALPHABET:
            b64_chars += 1
        if ch in _HEX_ALPHABET:
            hex_chars += 1
        if ch.isalpha():
            alpha += 1
            if ch.isupper():
                upper += 1
            cur_special_run = 0
        elif ch.isdigit():
            digit += 1
            cur_special_run = 0
        elif ch.isspace():
            space += 1
            cur_special_run = 0
        else:
            special += 1
            cur_special_run += 1
            if cur_special_run > max_special_run:
                max_special_run = cur_special_run

    tokens = _TOKEN_RE.findall(text)
    max_token_len = max((len(t) for t in tokens), default=0)

    pct_count = len(_PCT_RE.findall(text))

    # 参数统计：body 是表单就按 body 拆，否则退回 URI 的 query
    param_source = text
    if "=" not in param_source and "?" in uri:
        param_source = uri.split("?", 1)[1]
    params: List[Tuple[str, str]] = []
    if "=" in param_source:
        for pair in param_source.split("&")[:256]:
            if "=" in pair:
                k, v = pair.split("=", 1)
                params.append((k, v))
    value_lens = [len(v) for _, v in params] or [0]

    lowered = text.lower()
    keyword_hits = sum(lowered.count(w) for w in _DANGER_WORDS)
    keyword_density = keyword_hits / max(n / 1024.0, 0.001)

    write_method = 1.0 if (method or "").upper() in ("POST", "PUT", "PATCH") else 0.0

    values = [
        _safe_log1p(full_len),                               # log_length
        _shannon_entropy(raw),                               # entropy
        printable / n,                                       # printable_ratio
        alpha / n,                                           # alpha_ratio
        digit / n,                                           # digit_ratio
        special / n,                                         # special_ratio
        upper / max(alpha, 1),                               # upper_ratio
        space / n,                                           # whitespace_ratio
        non_ascii / n,                                       # non_ascii_ratio
        len(distinct) / n,                                   # distinct_char_ratio
        _safe_log1p(max_token_len),                          # log_max_token_len
        b64_chars / n,                                       # base64_alphabet_ratio
        hex_chars / n,                                       # hex_ratio
        (pct_count * 3) / n,                                 # url_encoded_density
        _safe_log1p(len(params)),                            # log_param_count
        _safe_log1p(max(value_lens)),                        # log_max_param_value_len
        _safe_log1p(sum(value_lens) / len(value_lens)),      # log_avg_param_value_len
        min(keyword_density, 200.0),                         # keyword_density_per_kb
        float(min(max_special_run, 100)),                    # max_special_run
        write_method,                                        # is_write_method
    ]
    return FeatureVector(values)


# ---------------------------------------------------------------- 模型

class BaseModel:
    kind = "base"

    def predict_proba(self, features: Sequence[float]) -> float:
        raise NotImplementedError

    def describe(self) -> Dict[str, object]:
        return {"kind": self.kind}


class LogisticModel(BaseModel):
    """标准化 + 逻辑回归。z = (x - mean) / std, p = sigmoid(w·z + b)"""

    kind = "logistic"

    def __init__(self, weights: Sequence[float], bias: float = 0.0,
                 mean: Optional[Sequence[float]] = None,
                 std: Optional[Sequence[float]] = None,
                 source: str = "builtin"):
        if len(weights) != FEATURE_COUNT:
            raise ValueError(
                f"weights 长度 {len(weights)} 与特征数 {FEATURE_COUNT} 不符")
        self.weights = list(weights)
        self.bias = float(bias)
        self.mean = list(mean) if mean else [0.0] * FEATURE_COUNT
        self.std = [s if s else 1.0 for s in (std or [1.0] * FEATURE_COUNT)]
        self.source = source

    def predict_proba(self, features: Sequence[float]) -> float:
        z = self.bias
        for w, x, m, s in zip(self.weights, features, self.mean, self.std):
            z += w * ((x - m) / s)
        # 防溢出
        if z >= 0:
            return 1.0 / (1.0 + math.exp(-min(z, 60.0)))
        e = math.exp(max(z, -60.0))
        return e / (1.0 + e)

    def describe(self) -> Dict[str, object]:
        return {"kind": self.kind, "source": self.source, "features": FEATURE_COUNT}


class DecisionTree:
    """sklearn tree_ 的纯 Python 遍历版，字段名与 sklearn 完全一致，导出即用"""

    __slots__ = ("children_left", "children_right", "feature", "threshold", "value")

    def __init__(self, children_left, children_right, feature, threshold, value):
        self.children_left = children_left
        self.children_right = children_right
        self.feature = feature
        self.threshold = threshold
        self.value = value

    def predict_proba(self, features: Sequence[float]) -> float:
        node = 0
        # 叶子节点在 sklearn 里 children_left == -1
        while self.children_left[node] != -1:
            f = self.feature[node]
            if features[f] <= self.threshold[node]:
                node = self.children_left[node]
            else:
                node = self.children_right[node]
        counts = self.value[node]
        total = sum(counts)
        if total <= 0:
            return 0.0
        return counts[1] / total if len(counts) > 1 else 0.0


class RandomForestModel(BaseModel):
    kind = "random_forest"

    def __init__(self, trees: Sequence[DecisionTree], source: str = "file"):
        if not trees:
            raise ValueError("random forest 至少要有一棵树")
        self.trees = list(trees)
        self.source = source

    def predict_proba(self, features: Sequence[float]) -> float:
        return sum(t.predict_proba(features) for t in self.trees) / len(self.trees)

    def describe(self) -> Dict[str, object]:
        return {"kind": self.kind, "source": self.source, "trees": len(self.trees)}


def load_model_from_dict(payload: Dict, source: str = "file") -> BaseModel:
    kind = payload.get("type") or payload.get("kind")

    declared = payload.get("features")
    if declared and list(declared) != list(FEATURE_NAMES):
        raise ValueError(
            "模型特征列表与当前 FEATURE_NAMES 不一致，拒绝加载（请重新导出模型）"
        )

    if kind == "logistic":
        return LogisticModel(
            weights=payload["weights"],
            bias=payload.get("bias", 0.0),
            mean=payload.get("mean"),
            std=payload.get("std"),
            source=source,
        )

    if kind == "random_forest":
        trees = [
            DecisionTree(
                children_left=t["children_left"],
                children_right=t["children_right"],
                feature=t["feature"],
                threshold=t["threshold"],
                value=t["value"],
            )
            for t in payload["trees"]
        ]
        return RandomForestModel(trees, source=source)

    raise ValueError(f"不支持的模型类型: {kind!r}")


# 人工标定的兜底权重。方向来自经验，不是训练结果：
# 高熵 + 长 token + 高 base64 占比 + 危险关键字密度 -> 偏恶意；
# 大量普通参数 + 高字母占比 + 低熵 -> 偏正常。
_BUILTIN_WEIGHTS = {
    "log_length": 0.15,
    "entropy": 0.55,
    "printable_ratio": -0.20,
    "alpha_ratio": -0.45,
    "digit_ratio": -0.10,
    "special_ratio": 0.50,
    "upper_ratio": 0.10,
    "whitespace_ratio": -0.15,
    "non_ascii_ratio": 0.25,
    "distinct_char_ratio": -0.20,
    "log_max_token_len": 0.45,
    "base64_alphabet_ratio": 0.30,
    "hex_ratio": 0.15,
    "url_encoded_density": 0.35,
    "log_param_count": -0.30,
    "log_max_param_value_len": 0.30,
    "log_avg_param_value_len": 0.10,
    "keyword_density_per_kb": 0.60,
    "max_special_run": 0.20,
    "is_write_method": 0.25,
}

# 标准化用的经验均值/标准差，量级参照一批常见 HTTP body
_BUILTIN_MEAN = {
    "log_length": 5.5, "entropy": 4.2, "printable_ratio": 0.98, "alpha_ratio": 0.55,
    "digit_ratio": 0.15, "special_ratio": 0.18, "upper_ratio": 0.12,
    "whitespace_ratio": 0.06, "non_ascii_ratio": 0.01, "distinct_char_ratio": 0.25,
    "log_max_token_len": 2.5, "base64_alphabet_ratio": 0.70, "hex_ratio": 0.30,
    "url_encoded_density": 0.05, "log_param_count": 1.6,
    "log_max_param_value_len": 2.8, "log_avg_param_value_len": 2.2,
    "keyword_density_per_kb": 1.0, "max_special_run": 2.0, "is_write_method": 0.5,
}

_BUILTIN_STD = {
    "log_length": 1.8, "entropy": 1.1, "printable_ratio": 0.08, "alpha_ratio": 0.20,
    "digit_ratio": 0.15, "special_ratio": 0.15, "upper_ratio": 0.15,
    "whitespace_ratio": 0.10, "non_ascii_ratio": 0.05, "distinct_char_ratio": 0.20,
    "log_max_token_len": 1.2, "base64_alphabet_ratio": 0.20, "hex_ratio": 0.20,
    "url_encoded_density": 0.12, "log_param_count": 1.0,
    "log_max_param_value_len": 1.5, "log_avg_param_value_len": 1.3,
    "keyword_density_per_kb": 4.0, "max_special_run": 3.0, "is_write_method": 0.5,
}


def _builtin_model() -> LogisticModel:
    return LogisticModel(
        weights=[_BUILTIN_WEIGHTS[n] for n in FEATURE_NAMES],
        bias=-1.2,
        mean=[_BUILTIN_MEAN[n] for n in FEATURE_NAMES],
        std=[_BUILTIN_STD[n] for n in FEATURE_NAMES],
        source="builtin-calibrated",
    )


# ---------------------------------------------------------------- 融合

DEFAULT_MODEL_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data", "ml", "payload_clf.json",
)


@dataclass
class MLVerdict:
    probability: float = 0.0
    adjustment: int = 0
    applied: bool = False
    reason: str = ""
    model: str = ""
    top_features: List[Tuple[str, float]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, object]:
        return {
            "probability": round(self.probability, 4),
            "adjustment": self.adjustment,
            "applied": self.applied,
            "reason": self.reason,
            "model": self.model,
            "top_features": [(n, round(v, 4)) for n, v in self.top_features],
        }


class MLScorer:
    """规则 + ML 融合器

    融合规则（保守优先）：
      - rule_weight <= 0                 -> 不调整（ML 不能无中生有）
      - rule_weight < GRAY_LOW           -> 不调整（证据太弱，交给规则）
      - rule_weight > GRAY_HIGH          -> 不调整（规则已经很确定，别添乱）
      - 灰区内                            -> delta = (p - 0.5) * 2 * MAX_ADJUST
    """

    GRAY_LOW = 30
    GRAY_HIGH = 70
    MAX_ADJUST = 25

    def __init__(self, model: Optional[BaseModel] = None, enabled: bool = True):
        self._model = model or _builtin_model()
        self._enabled = enabled
        self._lock = threading.RLock()
        self._invocations = 0
        self._applied = 0
        self._sum_prob = 0.0

    # ---------- 模型管理 ----------

    @property
    def model(self) -> BaseModel:
        return self._model

    def set_model(self, model: BaseModel) -> None:
        with self._lock:
            self._model = model

    def load_model_file(self, path: str) -> bool:
        try:
            with open(path, "r", encoding="utf-8") as fh:
                payload = json.load(fh)
            model = load_model_from_dict(payload, source=os.path.basename(path))
            self.set_model(model)
            logger.info(f"已加载 ML 模型: {path} ({model.describe()})")
            return True
        except FileNotFoundError:
            logger.debug(f"未找到 ML 模型文件，继续使用内置权重: {path}")
        except Exception as e:
            logger.warning(f"加载 ML 模型失败，继续使用内置权重: {e}")
        return False

    def set_enabled(self, enabled: bool) -> None:
        self._enabled = bool(enabled)

    @property
    def enabled(self) -> bool:
        return self._enabled

    # ---------- 打分 ----------

    def score(self, payload, method: str = "", content_type: str = "",
              uri: str = "") -> Tuple[float, FeatureVector]:
        fv = extract_features(payload, method=method,
                              content_type=content_type, uri=uri)
        prob = self._model.predict_proba(fv.values)
        with self._lock:
            self._invocations += 1
            self._sum_prob += prob
        return prob, fv

    def fuse(self, rule_weight: int, payload, method: str = "",
             content_type: str = "", uri: str = "") -> MLVerdict:
        verdict = MLVerdict(model=self._model.describe().get("kind", "?"))

        if not self._enabled:
            verdict.reason = "ml_disabled"
            return verdict

        if rule_weight <= 0:
            verdict.reason = "no_rule_evidence"
            return verdict

        prob, fv = self.score(payload, method=method,
                              content_type=content_type, uri=uri)
        verdict.probability = prob
        verdict.top_features = self._top_features(fv)

        if rule_weight < self.GRAY_LOW:
            verdict.reason = f"below_gray_zone(<{self.GRAY_LOW})"
            return verdict
        if rule_weight > self.GRAY_HIGH:
            verdict.reason = f"above_gray_zone(>{self.GRAY_HIGH})"
            return verdict

        delta = int(round((prob - 0.5) * 2 * self.MAX_ADJUST))
        if delta == 0:
            verdict.reason = "neutral"
            return verdict

        verdict.adjustment = delta
        verdict.applied = True
        verdict.reason = (
            f"灰区({self.GRAY_LOW}-{self.GRAY_HIGH})内 ML 置信度 {prob:.2f}，"
            f"调整 {delta:+d}"
        )
        with self._lock:
            self._applied += 1
        return verdict

    def _top_features(self, fv: FeatureVector, k: int = 4) -> List[Tuple[str, float]]:
        """只有线性模型能给出可解释的贡献度；森林就返回原始值最大的几维"""
        model = self._model
        if isinstance(model, LogisticModel):
            contribs = [
                (name, w * ((x - m) / s))
                for name, w, x, m, s in zip(
                    FEATURE_NAMES, model.weights, fv.values, model.mean, model.std)
            ]
            contribs.sort(key=lambda p: abs(p[1]), reverse=True)
            return contribs[:k]
        pairs = list(zip(FEATURE_NAMES, fv.values))
        pairs.sort(key=lambda p: abs(p[1]), reverse=True)
        return pairs[:k]

    # ---------- 观测 ----------

    def get_stats(self) -> Dict[str, object]:
        with self._lock:
            avg = (self._sum_prob / self._invocations) if self._invocations else 0.0
            return {
                "enabled": self._enabled,
                "model": self._model.describe(),
                "invocations": self._invocations,
                "adjustments_applied": self._applied,
                "avg_probability": round(avg, 4),
                "gray_zone": [self.GRAY_LOW, self.GRAY_HIGH],
                "max_adjust": self.MAX_ADJUST,
            }


_scorer_lock = threading.Lock()
_ml_scorer: Optional[MLScorer] = None


def get_ml_scorer() -> MLScorer:
    global _ml_scorer
    if _ml_scorer is None:
        with _scorer_lock:
            if _ml_scorer is None:
                scorer = MLScorer()
                if os.path.exists(DEFAULT_MODEL_PATH):
                    scorer.load_model_file(DEFAULT_MODEL_PATH)
                _ml_scorer = scorer
    return _ml_scorer
