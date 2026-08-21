"""威胁等级排序与噪声收敛策略。

GUI 里"先看什么"和"什么可以不看"这两件事原本散在树模型、表格模型和
主窗口三处，各自写了一份等级映射，其中树模型两处还是**升序**的
（信息在最前、严重在最后），正好和取证需要的顺序相反。这里收敛成一份。

两条策略：

1. **优先加载**：严重 / 高危 / 中危排在最前，低危和信息垫底。同一等级
   内按权重再降序，权重高的更可能是真事。

2. **噪声收敛**：一次分析命中的攻击超过 ATTACK_OVERLOAD_THRESHOLD 条时，
   低危和信息级不再进入界面。这个量级的结果基本来自扫描器噪声，全部铺开
   只会把真正的攻击淹掉；数据本身仍在 summary 里，导出不受影响。
"""

from typing import Iterable, List, Sequence

from models.detection_result import ThreatLevel

# 等级优先级，数字越大越紧急
_PRIORITY = {
    ThreatLevel.CRITICAL: 4,
    ThreatLevel.HIGH: 3,
    ThreatLevel.MEDIUM: 2,
    ThreatLevel.LOW: 1,
    ThreatLevel.INFO: 0,
}

# 字符串形式的等级（AttackDetectionInfo.risk_level 用的是裸字符串）
_PRIORITY_BY_NAME = {level.value: value for level, value in _PRIORITY.items()}

# 优先呈现的等级
PRIORITY_LEVELS = frozenset({
    ThreatLevel.CRITICAL,
    ThreatLevel.HIGH,
    ThreatLevel.MEDIUM,
})

# 超量时收敛掉的等级
NOISE_LEVELS = frozenset({
    ThreatLevel.LOW,
    ThreatLevel.INFO,
})

NOISE_LEVEL_NAMES = frozenset(level.value for level in NOISE_LEVELS)

# 攻击条数超过这个值就收敛低危/信息级
ATTACK_OVERLOAD_THRESHOLD = 2000


def level_priority(level) -> int:
    """取威胁等级的优先级，认不出来的按中危处理（不敢当噪声丢）。"""
    if isinstance(level, ThreatLevel):
        return _PRIORITY[level]
    return _PRIORITY_BY_NAME.get(str(level).lower(), _PRIORITY[ThreatLevel.MEDIUM])


def is_noise_level(level) -> bool:
    """是否属于超量时要收敛掉的低价值等级。"""
    if isinstance(level, ThreatLevel):
        return level in NOISE_LEVELS
    return str(level).lower() in NOISE_LEVEL_NAMES


def is_priority_level(level) -> bool:
    """是否属于优先呈现的严重/高危/中危。"""
    if isinstance(level, ThreatLevel):
        return level in PRIORITY_LEVELS
    return str(level).lower() in {lvl.value for lvl in PRIORITY_LEVELS}


def should_suppress_noise(attack_count: int) -> bool:
    """攻击条数是否已经多到该收敛低危/信息级。"""
    return attack_count > ATTACK_OVERLOAD_THRESHOLD


def effective_level_of(detection):
    """取一条检测**用于排序和收敛**的等级。

    优先用 `effective_threat_level` —— 它是原始判定叠加研判结论之后的等级：
    响应确实是 404/403 且研判为 FAILED、又没有反弹连接/主机证据/污点/带外
    这些豁免时降档（高危/严重降 1 档，中危/低危降 2 档）。原因见
    DetectionResult.effective_threat_level。

    没有这个属性的对象（AttackDetectionInfo 用的是裸字符串 risk_level）
    退回 threat_level，行为与接入前一致。
    """
    level = getattr(detection, "effective_threat_level", None)
    if level is None:
        level = getattr(detection, "threat_level", ThreatLevel.MEDIUM)
    return level


def sort_by_severity(detections: Sequence) -> List:
    """按 (威胁等级, 权重) 降序返回**新列表**，原列表不动。

    等级取 `effective_threat_level`：一屏 404 扫描器噪声本来会靠原始高危
    霸占列表顶部，把真正打成的那几条挤到下面去。权重仍用原始 total_weight，
    同等级内部的相对顺序不变。

    Python 的 sorted 是稳定排序，同等级同权重的条目保持原有先后（通常是
    抓包顺序），时间线不会被打乱。
    """
    return sorted(
        detections,
        key=lambda d: (
            level_priority(effective_level_of(d)),
            getattr(d, "total_weight", 0) or 0,
        ),
        reverse=True,
    )


def sort_attacks_by_severity(attacks: Sequence) -> List:
    """AttackDetectionInfo 版本，等级字段是裸字符串 risk_level。"""
    return sorted(
        attacks,
        key=lambda a: (
            level_priority(getattr(a, "risk_level", "medium")),
            getattr(a, "weight", 0) or 0,
        ),
        reverse=True,
    )


def filter_noise(detections: Iterable) -> List:
    """滤掉低危/信息级，返回新列表。"""
    return [d for d in detections if not is_noise_level(effective_level_of(d))]
