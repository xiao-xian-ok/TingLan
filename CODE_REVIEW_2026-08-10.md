# 代码评审清单 — 2026-08-10

**读者：正在这个工作区里改代码的两个 AI。**

这份文档是对当前**未提交工作区**（`git diff` + `git diff --cached`）的第三方评审，不是需求文档。
基线：`py -3.11 -m pytest tests/ -q` = 183 passed —— 下面每一条都**不是测试能发现的**。

评审依据是本项目的头号设计不变量：

> 听澜是离线取证工具，不是 inline 网关。**任何攻击者可触发的上限 / 跳过都是安全洞。**
> 过滤器只决定「看的顺序和深度」，不决定「哪些永远不看」。
> 任何 SKIP 都必须是"看完之后可证明安全"，而不是"没看所以不知道"。
> 一旦截断必须留痕，不能让"少看了"看起来像"看完没事"。

行号基于 2026-08-10 02:2x 的工作区状态，改动后可能漂移，以符号名为准。

---

## 〇、先说别动的（已经改对了，不要回退）

这几处是本轮做得好的，如果后续重构碰到，请保留语义：

- `SuspiciousEncryptedHTTPDetector`：`params[:32]` 已删除，`MAX_BODY_PARSE` 64KB→8MB 且口径改成"只限 parse_qsl 建表规模"。两处 `params[:MAX_PARAMS]` 都清了。
- `ContextAnalyzer`：`_uri_path()` 只取 path（query/fragment 是攻击者随手改的，不能进白名单判据）；有强证据时不降权且留 `noise_rule_suppressed:` tag。
- `AttackDetector.detect()`：解码用 `sampled.combined_bytes`，`_extend_with_full_text()` 把原文接回来做全量字面量匹配，带 ceiling + 覆盖率审计 + warning + `coverage_truncated`。**兜底上限的处理方式是全库范本**，其他地方该照抄这个模式。
- `tshark_stream`：`first_data_timeout` 5s→120s，超时打 warning 不静默，且"还在吐行就重置计时"。
- `ProgressThrottler`：拆成"百分比钳制 + 消息照发"。
- `RequestLedger` 记在去重之前；`SessionTracker` / `RequestLedger` 每 worker 一份。
- `-c` 误用的识别与注释（`_run_webshell_ast_detection`、`get_packet_hex_dump`）。

---

## 一、P0 — 已证实的漏检 / 证据丢失

### P0-1 `search_full` 的分块边界丢弃规则会丢真命中（已实证）

**位置**：`core/attack_detector.py:146` `search_full()`，常量在 `:279`

**问题**：现在的两条丢弃规则是无条件的：

```python
if not is_last and match.end() == len(chunk):
    continue    # 贴着人为块尾，交给下一块
if not is_first and match.start() == 0:
    continue    # 贴着人为块首，上一块已经看过
```

注释里的保证是：

> 这类命中必然完整落在相邻块的重叠区里并在那一块被正常捕获，所以只是去重不是丢证据。

**这个保证只在「命中长度 ≤ overlap」时成立。** 命中长度 > overlap 且起点对齐到 `k·step` 时，
本块因 `start()==0` 被丢，上一块装不下（越过块尾）→ 两边都拿不到。

**`REGEX_CHUNK_OVERLAP = 8192` 的注释依据是错的。** 注释说"规则里最长的量词是 `{0,500}`"。
实际把 registry 里全部 **119 条**模式过了一遍，**有 2 条带无界量词，且都匹配攻击者完全可控的内容**：

```
[file_upload] content_disposition : Content-Disposition[^;]*filename\s*=\s*["']?([^"';\r\n]+)
[file_upload] multipart_boundary  : boundary=[-\w]+
```

**复现**（`py -3.11`，当前代码）：

```python
import re, sys; sys.path.insert(0, '.')
from core.attack_detector import search_full, ResourceLimits as RL
step = RL.MAX_REGEX_INPUT_LEN - RL.REGEX_CHUNK_OVERLAP      # 91808
pat  = re.compile(r'boundary=[-\w]+')                        # FileUpload 的真实规则
text = 'X'*step + 'boundary=' + 'A'*20000 + 'Z'*5000
print(bool(pat.search(text)))        # True
print(bool(search_full(pat, text)))  # False  ← 丢了
```

对照：命中长度 < overlap → True（安全）；起点错开 1 字节 → True（安全）。
起点偏移和 boundary 长度都在攻击者手里（body 全是他写的）。

**修法**（保留原本防 `^`/`$` 锚点假命中的意图，只在"确实能在邻块被重新完整捕获"时才丢）：

```python
if not is_last and match.end() == len(chunk) and match.start() >= step:
    continue
if not is_first and match.start() == 0 and match.end() <= overlap:
    continue
```

推导：
- 贴块尾的命中，要在下一块（起点 `+step`）被完整看到，需要 `match.start() >= step`。
- 贴块首的命中，要在上一块被完整看到，需要 `L <= limit - step = overlap`，即 `match.end() <= overlap`。

**还要做的（比修 bug 更重要）**：`search_full` 现在是全库唯一的长文本正则入口
（`safe_regex_match` 只是它的转发壳，`BaseDetector._search_full` 也走它）。
"overlap 必须大于任何规则的最长命中"这个不变量现在**只是注释里的一句口头承诺**——
以后任何人加一条带 `.*` 的规则都会静默破坏它。请加一条测试：遍历 registry 全部 pattern，
断言不存在无界量词；或者反过来，强制所有规则都用有上界的量词并把 overlap 定在其之上。

---

### P0-2 懒证据把 `response_sample` 一起省掉了，废掉成功研判维度 A

**位置**：`core/stream_worker.py:1343` `_attach_response_evidence()`

```python
lazy = bool(... detection.raw_result.get("evidence_lazy"))
if isinstance(detection.raw_result, dict):
    detection.raw_result["response_status"] = status_code
    if not lazy:
        detection.raw_result["response_sample"] = body_sample
        detection.raw_result["response_data"] = response_data
if not lazy:
    detection.response_sample = body_sample
    detection.response_data = response_data
```

**问题**：`success_adjudicator._response_text()`（`core/success_adjudicator.py:358`）读的就是
`response_sample` / `response_data` 这两个字段，维度 A（命令回显 `uid=0(root)`、`root:x:0:0:`、
`Windows IP Configuration`…）全靠它们。

**这笔账完全不划算**：`body_sample` 在 `stream_worker.py:1326` 已经被切到 **2000 字节**，
`response_data` 同样 `[:2000]`。省它们等于省 ~4KB；而懒加载真正要省的是请求体（上限 1MB）。
**花 4KB 的收益，换掉了整个"打成了没有"的主判据。**

**而且触发条件是攻击者可控的**：`FULL_EVIDENCE_DETECTIONS = 2000`，一次 dirb 就能灌满，
之后所有真攻击的研判从 CONFIRMED 掉到 UNKNOWN，分析员按研判排序时全部沉底。
这正是铁律要防的那类"攻击者填充即可触发的降级"。

**修法**：`lazy` 只作用于 `raw_request_*` 系列。`response_status` + `response_sample` 永远保留，
`response_data` 可以按 lazy 省（它是 headers+body 的拼接，信息量与 sample 重叠）。

---

### P0-3 会话加分之后没有重算 `threat_level`

**位置**：`core/stream_worker.py:1066` `_detect_packet()`

```python
if signal is not None and signal.triggered:
    detection['total_weight'] = detection.get('total_weight', 0) + signal.bonus
    detection['session_signals'] = signal.to_dict()
    detection['tags'] = list(detection.get('tags') or []) + signal.tags
    if detection['total_weight'] >= 40:
        detection['detected'] = True
```

改了 `total_weight` 和 `detected`，**没有改 `threat_level` / `confidence`**。

而 `DetectionResult.from_attack_result()`（`models/detection_result.py:427`）读的是
dict 里的 `threat_level` 字符串——那个值是 `AttackDetector._to_dict()` 在
`ThreatLevel.from_weight(result.weight)` 处算好的，**发生在会话加分之前**。

**后果**：`SessionTracker` 最多能加 80 分（upload_then_access +60 等）。
一条 30 分的请求被"上传 webshell → 随后回访"抬到 110，界面上仍然显示 LOW。
而"上传→回访"恰恰是最该置顶的那种链。按威胁等级排序 / 过滤全部失真，
还会被 `gui.UILimits.MAX_DISPLAY_ROWS = 5000` 挤出可视范围。

**修法**：加分后同步刷新：

```python
detection['threat_level'] = ThreatLevel.from_weight(detection['total_weight']).value
detection['confidence']   = detection['threat_level']
```

（参考 `_apply_ml_fusion` 里的做法——它是对的，加分后同步刷了 `result.confidence`。）

---

## 二、P1 — 应该改

### P1-1 `min(result.weight + verdict.adjustment, 100)`

**位置**：`core/attack_detector.py:2009`

写在一个标题是 **"ML 研判：只加分，不减分"** 的函数里，但它对任何 `weight > 100` 的检测是**减分**：
weight=300 的 CRITICAL 加 +10 之后变成 100。

目前撞不到，因为 `ml_scorer.fuse()` 只在灰区 30–70 生效（`core/ml_scorer.py:496-501`），
上限是 70+25=95。但这是潜伏地雷：`GRAY_HIGH` 一旦上调就立即生效，
而且它和函数自己的 docstring 直接矛盾。既然正在写这个函数，直接去掉 `min(..., 100)`。

### P1-2 懒证据回捞在 GUI 线程同步跑 tshark

**位置**：`gui/widgets/payload_viewer.py:888` `_ensureEvidenceLoaded()`
→ `controllers/analysis_controller.py:get_http_request_evidence()`（`subprocess.run(..., timeout=30)`）

**逻辑上自相矛盾**：懒加载只在**大文件**上触发（检测数 >2000），
而 `get_http_request_evidence` 用 `-c <帧号>` 读满 N 个包——帧号越大读得越多，
正好在大文件上最慢。用户点开第 3000 条 = 界面冻住最长 30 秒。

**而且失败不可重试**：`raw['_evidence_fetched'] = True` 在失败分支之前无条件设置，
超时一次之后再点永远显示"取证失败"。

**修法**：丢到 QThread + 显示 loading 态；失败时不要设 `_evidence_fetched`，允许重试。

### P1-3 `analyze_params` 去掉长度上限是对的，但缺留痕

**位置**：`core/webshell_detect.py:analyze_params()`

删掉 `MAX_PARAM_VALUE_LENGTH` 跳过是对的（长度是攻击者可控的，不能拿来跳过）。
但一个 50MB 参数会依次试 URL → 8 种前缀的 Base64 → Hex → 双层 Base64，
约 12 轮全量字符串拷贝，之后 `decoded` 还全量存进结果 dict。

**至少要像别处一样打点 / `_record_partial_coverage`**，否则现场遇到卡顿没法定位到是哪个参数。

### P1-4 MCP 路径仍保留着已从 GUI 删掉的 10000 条硬上限

**位置**：`mcp_server.py:386/390`（`_detect_webshell_ek`）、`:441/480`（`_detect_attacks_ek`）、`:2989/3036`

```python
limit = max_packets if max_packets > 0 else 10000
...
if len(attacks) >= limit: break        # 无任何告警
```

这正是当初从 `stream_worker` 里整个删掉的 `MAX_DETECTIONS`。
**铁律又一次只落实到 GUI 一侧。** MCP 是和 GUI 平级的入口（AI 客户端直接调），不是次要路径。

同一文件里还有一类问题：`_detect_webshell_ek` 整个函数一个 `except: return []`——
tshark 挂了、解析异常、内存不足，统统变成"没发现威胁"。取证工具最不能接受的失败模式。
至少 `logger.exception` + 返回结构里带 `partial: true` / `error` 字段。

### P1-5 `protocols_from_stats` 仍然零生产调用方

**位置**：`core/stream_worker.py:_run_deep_protocol_analysis()`（`deep_protocols = [p for p in ProtocolType if p not in SKIP]`）

现成的 `ProtocolAnalyzerManager.protocols_from_stats()`（`core/protocol_analyzer.py:5047`）没人用，
于是每个 pcap 都无条件跑 10 个深度分析器，每个各起一个 tshark 子进程全量读一遍文件。
一个纯 HTTP 的包也要为 RDP/Redis/SMB/SSH/USB/蓝牙/MMS 各扫一趟。预计可省 30–60% 总时长。

`protocol_counts` 在 5% 阶段已经拿到了，求个交集即可。
**不漏检的论证**：`io,phs` 统计的是 tshark 自己的协议树分层结果，某协议层帧数为 0
意味着 tshark 根本没解出这一层，对应分析器扫也扫不出东西。

**唯一的坑**：`_PROTOCOL_STAT_ALIASES` 里没登记别名的协议**必须默认跑**，
不能查表落空就跳过（否则又造出一个新的可绕过跳过）。CS 分析器映射到 HTTP，
USB/TLS/SMB 的别名要覆盖 `USBHID` / `SSL` / `SMB2`。

---

## 三、需要你们两个先对齐的（策略分叉，现在是矛盾的）

### 分叉 A：AST 超长到底走窗口还是走全量？

现在同一个操作有两套相反的策略：

| 位置 | 策略 |
|---|---|
| `core/ast_engine.py:1404` `analyze_windowed()` | >256KB 切 64KB 滑窗，返回 `windowed=True` 供留痕 |
| `core/webshell_detect.py` `_apply_ast_validation()` | 用 `analyze_windowed` |
| `core/fast_filter.py:24` 文件头注释 | 断言"AST 现在无条件跑全量，所以这里不需要再切窗口"，并删掉了整套 `ast_windows` / `_build_ast_windows` / `windowed_ast_threshold` |
| `core/attack_detector.py:2218` `_execute_shared_ast()` | 裸 `self._ast_engine.analyze(code)`，无长度门、无窗口、无超时 |

**这两条路径现在的行为不一致，注释也互相打脸。** 请先商定一个，再统一。

### 分叉 B（更急）：三处各自合理的改动组合成了"一个请求挂死分析"

1. `d144e93` 去掉 `MAX_AST_CODE_LEN` → AST 无长度门；
2. fast_filter 删掉窗口机制，前提是"AST 无条件跑全量"；
3. `attack_detector.py:1897` `_extend_with_full_text()` 把最多 **64MB**（`FULL_TEXT_CEILING`）
   原文接进 `context.decoded_text`，而 `_run_shared_ast_analysis` 在 `:1921` 被调用，
   吃的正是这个字段。

组合结果：body 里放一次 `eval(` 加 64MB 填充 →
fast_filter 不 SKIP → `SelectiveAnalyzer.needs_taint_analysis` 找到 sink →
**手写 PHP tokenizer 在 64MB 文本上跑，无窗口、无超时**。
（`ast_timeout_guard` 定义在 `core/attack_detector.py:309`，**全库零调用方**。）

每一处单看都说得通，组合起来是一条可构造的拒绝分析路径。
**这条涉及"时间/资源预算算不算可绕过上限"的原则问题，见下一节，先别自己拍板。**

### 分叉 C：`ek_bytes` 的"内存预算"方向要慎重

`core/tshark_stream.py:255` 新增的 `PacketData.ek_bytes`，注释说要给
`_run_webshell_ast_detection` 做内存预算，"而不是拍一个包数上限"（替代 `MAX_WEBSHELL_HTTP_PACKETS = 200_000`，`core/stream_worker.py:130`）。

**提醒：内存预算同样是攻击者可触发的，而且在取证语境下比包数上限更糟。**
包数上限至少是确定性、可复现的；内存预算下"分析到第几条为止"取决于攻击者塞了多少大包，
同一个 pcap 两次跑可能给出不同结论——取证结论不可复现是硬伤。

如果要做，建议触顶时**不要 `break`**，而是卸载已收集包的 `raw_ek_data` 继续收
（身份字段很轻，而 `pair_http_requests_responses` / 冰蝎密钥协商 / 哥斯拉会话扫描
这些跨包关联需要的是**完整序列**，断在中间正好毁掉"还原攻击路径"的能力），
或者干脆分两趟扫。

---

## 四、需要项目负责人拍板的，请勿自行决定

1. **时间 / 资源预算算不算"可绕过上限"？**
   现在所有长度门都拆了（方向正确），但没有任何 wall-clock 兜底，
   对抗性构造的 pcap 可以让分析实际上跑不完。铁律说"攻击者能触发的上限就是洞"，
   但"永远跑不完"对分析员来说和漏检等价。
   口径是「宁可跑一整夜也不设限」，还是「允许超时 → 降级 + 强制留痕 + 报告标注结论不完整」？

2. **AST 超长走窗口还是全量**（分叉 A/B 的最终裁决）。

3. **`_run_webshell_ast_detection` 的候选集依赖问题。**
   AST 候选主机来自「有非 failed 检测的来源 IP」，而那批检测全部来自 `attack_detector`。
   这把 webshell_detect 从一条**独立的召回路径**变成了 attack_detector 的**下游**。
   加密 webshell（冰蝎/哥斯拉正常交互，无任何明文特征）的召回现在完全押在
   `SuspiciousEncryptedHTTPDetector` 上——它一漏，那台主机的流量根本不会进 AST 阶段。
   本轮已经修掉了它的 `params[:32]` / `MAX_BODY_PARSE`，风险下降了，
   但这个「独立 → 依赖」的架构变化本身要不要保留，需要确认。

---

## 五、自查用的命令

```bash
py -3.11 -m pytest tests/ -q          # 基线 183 passed
```

改完 P0-1 后，建议把上面那段复现脚本固化成 `tests/test_regex_chunk_boundary.py`：
覆盖「命中长度 > overlap 且起点对齐」「命中长度 < overlap」「起点错开」三种情形，
再加一条"registry 里所有 pattern 都不含无界量词"的断言。
