# bloom_filter.py - Bloom 前置负缓存
#
# 重要设计约束（别改成"权威判定"）：
#
# Bloom 有假阳性、没有假阴性。如果拿它直接拍板"这个 payload 见过、是正常的，跳过检测"，
# 那一次假阳性 = 静默漏掉一个从没见过的恶意载荷，而且不可复现、不可审计。
# 所以这里只把它当成精确缓存前面的**负向快筛**：
#
#   might_contain(k) == False  -> 数学上保证不在缓存里，直接跳过加锁+字典查找
#   might_contain(k) == True   -> 仍然走精确缓存校验
#
# 这样假阳性最坏只是多做一次精确查表，永远不会造成漏检。

import hashlib
import math
import threading
from typing import Dict, Optional, Union

BytesLike = Union[str, bytes]


class BloomFilter:
    """标准位图 Bloom Filter

    用一次 blake2b 摘要切出两个 32 位种子，再用 Kirsch-Mitzenmacher 双哈希
    生成 k 个下标，省掉 k 次独立哈希。
    """

    __slots__ = (
        "_bits", "_size", "_hashes", "_capacity", "_error_rate",
        "_count", "_lock", "_queries", "_negatives",
    )

    def __init__(self, capacity: int = 100000, error_rate: float = 0.01):
        if capacity <= 0:
            raise ValueError("capacity must be positive")
        if not (0.0 < error_rate < 1.0):
            raise ValueError("error_rate must be in (0, 1)")

        self._capacity = capacity
        self._error_rate = error_rate

        # m = -n*ln(p) / (ln2)^2 ; k = m/n * ln2
        size = int(math.ceil(-capacity * math.log(error_rate) / (math.log(2) ** 2)))
        self._size = max(size, 8)
        self._hashes = max(1, int(round(self._size / capacity * math.log(2))))

        self._bits = bytearray((self._size + 7) // 8)
        self._count = 0
        self._queries = 0
        self._negatives = 0
        self._lock = threading.Lock()

    # ---------- 内部 ----------

    @staticmethod
    def _to_bytes(key: BytesLike) -> bytes:
        if isinstance(key, bytes):
            return key
        return key.encode("utf-8", errors="ignore")

    def _indices(self, key: BytesLike):
        digest = hashlib.blake2b(self._to_bytes(key), digest_size=16).digest()
        h1 = int.from_bytes(digest[:8], "little")
        h2 = int.from_bytes(digest[8:], "little") | 1  # 奇数，保证遍历性更好
        size = self._size
        for i in range(self._hashes):
            yield (h1 + i * h2) % size

    # ---------- 公开 ----------

    def add(self, key: BytesLike) -> None:
        bits = self._bits
        with self._lock:
            for idx in self._indices(key):
                bits[idx >> 3] |= 1 << (idx & 7)
            self._count += 1

    def might_contain(self, key: BytesLike) -> bool:
        """False = 一定不存在；True = 可能存在，需要精确校验"""
        bits = self._bits
        self._queries += 1  # GIL 下的自增有竞争但只影响统计精度，不加锁避免热路径开销
        for idx in self._indices(key):
            if not (bits[idx >> 3] >> (idx & 7)) & 1:
                self._negatives += 1
                return False
        return True

    __contains__ = might_contain

    def clear(self) -> None:
        with self._lock:
            self._bits = bytearray((self._size + 7) // 8)
            self._count = 0
            self._queries = 0
            self._negatives = 0

    @property
    def item_count(self) -> int:
        """已插入元素数。O(1)，用来做重建触发判断"""
        return self._count

    @property
    def capacity(self) -> int:
        return self._capacity

    @property
    def fill_ratio(self) -> float:
        """已置位比例，逼近 1 说明假阳性率已经失控，该 clear 了

        注意：这是 **O(位图大小)** 的全量扫描，20000 容量下实测约 2ms。
        绝对不要放在 add()/查询的热路径上——用 item_count 或
        estimated_error_rate()（都是 O(1)）做触发判断，这个只用于统计上报。
        """
        set_bits = 0
        for byte in self._bits:
            set_bits += bin(byte).count("1")
        return set_bits / self._size if self._size else 0.0

    def estimated_error_rate(self) -> float:
        """按当前装载量估算实际假阳性率"""
        if self._count <= 0:
            return 0.0
        exponent = -self._hashes * self._count / self._size
        return (1.0 - math.exp(exponent)) ** self._hashes

    def get_stats(self) -> Dict[str, object]:
        total = self._queries
        skip_rate = (self._negatives / total * 100) if total else 0.0
        return {
            "capacity": self._capacity,
            "bits": self._size,
            "hash_count": self._hashes,
            "items": self._count,
            "queries": total,
            "definite_miss": self._negatives,
            "skip_rate": f"{skip_rate:.1f}%",
            "target_error_rate": self._error_rate,
            "estimated_error_rate": round(self.estimated_error_rate(), 5),
        }


class BloomFrontedCache:
    """Bloom 前置 + 精确后端的两级缓存

    后端由调用方传入，只要求实现 get(key)/set(key, value)。
    Bloom 只负责"确定不在"的快速否定，命中判定永远以精确后端为准。

    LRU 淘汰会让 Bloom 里残留已被淘汰的 key（陈旧位）。这只会让
    might_contain 多返回几个 True，退化成一次精确查表，不影响正确性。
    fill_ratio 超过阈值时自动重建 Bloom，避免假阳性率无限抬高。
    """

    REBUILD_FILL_RATIO = 0.6

    def __init__(self, backend, capacity: int = 100000, error_rate: float = 0.01):
        self._backend = backend
        self._bloom = BloomFilter(capacity=capacity, error_rate=error_rate)
        self._skipped = 0
        self._probed = 0
        self._lock = threading.Lock()

    def get(self, key: str):
        if not self._bloom.might_contain(key):
            self._skipped += 1
            return None
        self._probed += 1
        return self._backend.get(key)

    def set(self, key: str, value) -> None:
        self._backend.set(key, value)
        self._bloom.add(key)
        if self._bloom.fill_ratio > self.REBUILD_FILL_RATIO:
            self._rebuild()

    def _rebuild(self) -> None:
        with self._lock:
            if self._bloom.fill_ratio <= self.REBUILD_FILL_RATIO:
                return
            self._bloom.clear()
            # 用后端现存 key 重新灌入，保持"确定不在"的语义不出错
            keys = getattr(self._backend, "keys", None)
            if callable(keys):
                try:
                    for k in list(keys()):
                        self._bloom.add(k)
                except Exception:
                    pass

    def clear(self) -> None:
        self._bloom.clear()
        self._skipped = 0
        self._probed = 0
        backend_clear = getattr(self._backend, "clear", None)
        if callable(backend_clear):
            backend_clear()

    def get_stats(self) -> Dict[str, object]:
        total = self._skipped + self._probed
        skip_rate = (self._skipped / total * 100) if total else 0.0
        stats = {
            "bloom_skipped": self._skipped,
            "backend_probed": self._probed,
            "bloom_skip_rate": f"{skip_rate:.1f}%",
            "bloom": self._bloom.get_stats(),
        }
        backend_stats = getattr(self._backend, "get_stats", None)
        if callable(backend_stats):
            try:
                stats["backend"] = backend_stats()
            except Exception:
                pass
        return stats
