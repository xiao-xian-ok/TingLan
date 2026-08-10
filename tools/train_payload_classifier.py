#!/usr/bin/env python
# train_payload_classifier.py - 离线训练载荷分类器，导出给 core/ml_scorer.py 用
#
# 为什么需要它：core/ml_scorer.py 随包发的是**人工标定**的逻辑回归权重，不是训练结果。
# 只有用你自己的真实标注数据训出来的模型，融合进检测流程才有实际收益。
#
# 输入（二选一）：
#   1. JSONL：每行 {"payload": "...", "label": 0|1, "method": "POST",
#                   "content_type": "...", "uri": "..."}
#      载荷是二进制时用 "payload_b64" 代替 "payload"
#   2. 目录：<dir>/benign/*  和 <dir>/malicious/*，每个文件是一条原始载荷
#
# 训练后端：
#   - 装了 sklearn  -> RandomForestClassifier（推荐）
#   - 没装 sklearn  -> 纯 Python 批量梯度下降逻辑回归（无第三方依赖，够用）
#
# 用法:
#   py -3.11 tools/train_payload_classifier.py --jsonl samples.jsonl --out data/ml/payload_clf.json
#   py -3.11 tools/train_payload_classifier.py --dir samples/ --model logistic --report

import argparse
import base64
import json
import math
import os
import random
import sys
from typing import Dict, List, Optional, Sequence, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.ml_scorer import FEATURE_NAMES, FEATURE_COUNT, extract_features  # noqa: E402


# ---------------------------------------------------------------- 数据装载

def load_jsonl(path: str) -> List[Tuple[List[float], int]]:
    samples: List[Tuple[List[float], int]] = []
    skipped = 0
    with open(path, "r", encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                skipped += 1
                continue

            if "payload_b64" in rec:
                try:
                    payload = base64.b64decode(rec["payload_b64"])
                except Exception:
                    skipped += 1
                    continue
            else:
                payload = rec.get("payload", "")

            label = rec.get("label")
            if label not in (0, 1, "0", "1", True, False):
                skipped += 1
                continue

            fv = extract_features(
                payload,
                method=rec.get("method", ""),
                content_type=rec.get("content_type", ""),
                uri=rec.get("uri", ""),
            )
            samples.append((fv.values, int(label)))

    if skipped:
        print(f"[warn] 跳过 {skipped} 行无效记录")
    return samples


def load_dir(root: str) -> List[Tuple[List[float], int]]:
    samples: List[Tuple[List[float], int]] = []
    for label_name, label in (("benign", 0), ("malicious", 1)):
        sub = os.path.join(root, label_name)
        if not os.path.isdir(sub):
            print(f"[warn] 缺少目录 {sub}")
            continue
        count = 0
        for name in sorted(os.listdir(sub)):
            fpath = os.path.join(sub, name)
            if not os.path.isfile(fpath):
                continue
            try:
                with open(fpath, "rb") as fh:
                    data = fh.read()
            except OSError:
                continue
            samples.append((extract_features(data).values, label))
            count += 1
        print(f"[info] {label_name}: {count} 条")
    return samples


# ---------------------------------------------------------------- 纯 Python 逻辑回归

def _sigmoid(z: float) -> float:
    if z >= 0:
        return 1.0 / (1.0 + math.exp(-min(z, 60.0)))
    e = math.exp(max(z, -60.0))
    return e / (1.0 + e)


def standardize(rows: Sequence[Sequence[float]]) -> Tuple[List[float], List[float]]:
    n = len(rows)
    mean = [0.0] * FEATURE_COUNT
    for row in rows:
        for i, v in enumerate(row):
            mean[i] += v
    mean = [m / n for m in mean]

    var = [0.0] * FEATURE_COUNT
    for row in rows:
        for i, v in enumerate(row):
            var[i] += (v - mean[i]) ** 2
    std = [math.sqrt(v / n) or 1.0 for v in var]
    return mean, std


def train_logistic(
    rows: Sequence[Sequence[float]],
    labels: Sequence[int],
    epochs: int = 400,
    lr: float = 0.15,
    l2: float = 0.001,
) -> Dict[str, object]:
    mean, std = standardize(rows)
    x = [[(v - mean[i]) / std[i] for i, v in enumerate(row)] for row in rows]
    n = len(x)

    weights = [0.0] * FEATURE_COUNT
    bias = 0.0

    # 类别不平衡时给少数类加权，避免模型直接全判 0
    pos = sum(labels) or 1
    neg = n - sum(labels) or 1
    w_pos = n / (2.0 * pos)
    w_neg = n / (2.0 * neg)

    for epoch in range(epochs):
        grad_w = [0.0] * FEATURE_COUNT
        grad_b = 0.0
        loss = 0.0
        for row, y in zip(x, labels):
            z = bias + sum(w * v for w, v in zip(weights, row))
            p = _sigmoid(z)
            sample_w = w_pos if y == 1 else w_neg
            err = (p - y) * sample_w
            for i, v in enumerate(row):
                grad_w[i] += err * v
            grad_b += err
            eps = 1e-12
            loss -= sample_w * (y * math.log(p + eps) + (1 - y) * math.log(1 - p + eps))

        for i in range(FEATURE_COUNT):
            weights[i] -= lr * (grad_w[i] / n + l2 * weights[i])
        bias -= lr * (grad_b / n)

        if epoch % 100 == 0 or epoch == epochs - 1:
            print(f"  epoch {epoch:4d}  loss={loss / n:.4f}")

    return {
        "type": "logistic",
        "features": list(FEATURE_NAMES),
        "weights": weights,
        "bias": bias,
        "mean": mean,
        "std": std,
    }


# ---------------------------------------------------------------- sklearn 随机森林

def train_random_forest(
    rows: Sequence[Sequence[float]],
    labels: Sequence[int],
    n_estimators: int = 120,
    max_depth: Optional[int] = 12,
    seed: int = 42,
) -> Dict[str, object]:
    try:
        from sklearn.ensemble import RandomForestClassifier
    except ImportError:
        raise SystemExit(
            "未安装 sklearn，无法训练随机森林。\n"
            "  安装:  py -3.11 -m pip install scikit-learn\n"
            "  或改用: --model logistic （纯 Python，无需第三方库）"
        )

    clf = RandomForestClassifier(
        n_estimators=n_estimators,
        max_depth=max_depth,
        class_weight="balanced",
        random_state=seed,
        n_jobs=-1,
    )
    clf.fit(list(rows), list(labels))

    trees = []
    for est in clf.estimators_:
        t = est.tree_
        trees.append({
            "children_left": t.children_left.tolist(),
            "children_right": t.children_right.tolist(),
            "feature": t.feature.tolist(),
            "threshold": t.threshold.tolist(),
            # value 形状 (n_nodes, 1, n_classes) -> 压成 (n_nodes, n_classes)
            "value": [row[0].tolist() for row in t.value],
        })

    importances = sorted(
        zip(FEATURE_NAMES, clf.feature_importances_.tolist()),
        key=lambda p: p[1], reverse=True,
    )
    print("  特征重要度 Top8:")
    for name, imp in importances[:8]:
        print(f"    {name:26s} {imp:.4f}")

    return {
        "type": "random_forest",
        "features": list(FEATURE_NAMES),
        "trees": trees,
    }


# ---------------------------------------------------------------- 评估

def evaluate(model_dict: Dict[str, object],
             rows: Sequence[Sequence[float]],
             labels: Sequence[int],
             threshold: float = 0.5) -> Dict[str, float]:
    from core.ml_scorer import load_model_from_dict

    model = load_model_from_dict(model_dict, source="eval")
    tp = fp = tn = fn = 0
    for row, y in zip(rows, labels):
        p = model.predict_proba(row)
        pred = 1 if p >= threshold else 0
        if pred == 1 and y == 1:
            tp += 1
        elif pred == 1 and y == 0:
            fp += 1
        elif pred == 0 and y == 0:
            tn += 1
        else:
            fn += 1

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return {
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "accuracy": round((tp + tn) / max(len(labels), 1), 4),
    }


def split(samples: List[Tuple[List[float], int]], ratio: float, seed: int):
    rng = random.Random(seed)
    data = list(samples)
    rng.shuffle(data)
    cut = int(len(data) * ratio)
    return data[:cut], data[cut:]


# ---------------------------------------------------------------- 入口

def main() -> int:
    ap = argparse.ArgumentParser(
        description="训练载荷分类器并导出 core/ml_scorer.py 可加载的 JSON")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--jsonl", help="JSONL 标注文件")
    src.add_argument("--dir", help="含 benign/ 与 malicious/ 子目录的样本根目录")
    ap.add_argument("--out", default="data/ml/payload_clf.json", help="模型输出路径")
    ap.add_argument("--model", choices=["auto", "random_forest", "logistic"],
                    default="auto", help="auto = 有 sklearn 就用随机森林")
    ap.add_argument("--test-ratio", type=float, default=0.25)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--trees", type=int, default=120)
    ap.add_argument("--max-depth", type=int, default=12)
    ap.add_argument("--epochs", type=int, default=400)
    ap.add_argument("--report", action="store_true", help="打印训练/测试集指标")
    args = ap.parse_args()

    print(f"[1/4] 加载样本 ({FEATURE_COUNT} 维特征)")
    samples = load_jsonl(args.jsonl) if args.jsonl else load_dir(args.dir)
    if len(samples) < 20:
        print(f"[fatal] 只有 {len(samples)} 条样本，不足以训练。"
              f"至少准备几百条正负样本再来。")
        return 2

    pos = sum(1 for _, y in samples if y == 1)
    print(f"       共 {len(samples)} 条 (恶意 {pos} / 正常 {len(samples) - pos})")
    if pos == 0 or pos == len(samples):
        print("[fatal] 只有单一类别，无法训练")
        return 2

    test, train = split(samples, args.test_ratio, args.seed)
    train_rows = [r for r, _ in train]
    train_labels = [y for _, y in train]
    test_rows = [r for r, _ in test]
    test_labels = [y for _, y in test]
    print(f"       训练 {len(train)} / 测试 {len(test)}")

    backend = args.model
    if backend == "auto":
        try:
            import sklearn  # noqa: F401
            backend = "random_forest"
        except ImportError:
            backend = "logistic"
            print("[info] 未检测到 sklearn，改用纯 Python 逻辑回归")

    print(f"[2/4] 训练 ({backend})")
    if backend == "random_forest":
        model_dict = train_random_forest(
            train_rows, train_labels,
            n_estimators=args.trees, max_depth=args.max_depth, seed=args.seed)
    else:
        model_dict = train_logistic(train_rows, train_labels, epochs=args.epochs)

    print("[3/4] 评估")
    print(f"       train: {evaluate(model_dict, train_rows, train_labels)}")
    if test_rows:
        print(f"       test : {evaluate(model_dict, test_rows, test_labels)}")

    if args.report and test_rows:
        print("       阈值扫描 (test):")
        for thr in (0.3, 0.4, 0.5, 0.6, 0.7, 0.8):
            m = evaluate(model_dict, test_rows, test_labels, threshold=thr)
            print(f"         thr={thr:.1f}  P={m['precision']:.3f} "
                  f"R={m['recall']:.3f} F1={m['f1']:.3f}")

    out_path = os.path.abspath(args.out)
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(model_dict, fh, ensure_ascii=False)
    size_kb = os.path.getsize(out_path) / 1024
    print(f"[4/4] 已导出 {out_path} ({size_kb:.1f} KB)")
    print("      core/ml_scorer.py 下次启动会自动加载 data/ml/payload_clf.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
