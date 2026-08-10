# -*- coding: utf-8 -*-
"""界面响应性探针：量化分析期间主线程被占住的程度

用法:
    python tools/probe_ui_latency.py <pcap1> [pcap2 ...] <秒数>

起真实 MainWindow，按用户点"分析"的同一条路径跑，用 50ms 的 QTimer 量
事件循环延迟 —— 实际触发间隔减去 50ms 就是主线程被卡住的时间，也就是
用户感知到的"假死"。分析完成的模态框会挂死自动化，这里打桩计数。

这个探针是排查"两个文件并发分析时界面未响应"时写的，留着做回归：
改动分析流水线之后跑一遍，确认 max 没有回到秒级。
"""
import os, sys, time, threading
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import psutil
from PySide6.QtWidgets import QApplication, QDialog
from PySide6.QtCore import QTimer

FILES = sys.argv[1:-1]
BUDGET = float(sys.argv[-1])

modal = [0]
QDialog.exec = lambda self, *a, **k: modal.__setitem__(0, modal[0] + 1)

app = QApplication([])
from gui.main_window import MainWindow
win = MainWindow(); win.show(); app.processEvents()

P = psutil.Process()
lags, last, t0 = [], time.perf_counter(), time.perf_counter()
stalls, stage, done = [], {}, []

def tick():
    global last
    now = time.perf_counter()
    lag = (now - last - 0.05) * 1000.0
    lags.append(lag); last = now
    if lag > 400:
        stalls.append("  [%6.1fs] 卡顿 %8.1fms | RSS %6.1fMB | %s"
                      % (now - t0, lag, P.memory_info().rss/1048576, " || ".join(stage.values())))
    if now - t0 > BUDGET or len(done) >= len(FILES):
        report()

def report():
    win.analysis_controller.stopAnalysis()
    vals = sorted(l for l in lags if l > 0); n = len(vals)
    lines = ["===== 真 GUI 结果 ====="]
    lines.append("运行 %.1fs | 完成 %d/%d | 模态框弹出 %d 次 | RSS %.1fMB"
                 % (time.perf_counter()-t0, len(done), len(FILES), modal[0],
                    P.memory_info().rss/1048576))
    if n:
        lines.append("事件循环延迟 p50=%.1f p90=%.1f p99=%.1f max=%.1f ms"
                     % (vals[int(n*.5)], vals[int(n*.9)], vals[min(int(n*.99),n-1)], vals[-1]))
        for thr in (500,1000,2000,5000):
            c = sum(1 for v in vals if v > thr)
            lines.append("  卡顿 >%dms : %d 次" % (thr, c))
    lines.append("--- 卡顿现场 ---")
    lines.extend(stalls[:30] or ["  (无 >400ms 的卡顿)"])
    text = "\n".join(lines)
    print("\n" + text, flush=True)
    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "..", "output", "_lag_report.txt"), "w", encoding="utf-8") as fh:
        fh.write(text + "\n")
        fh.flush()
        os.fsync(fh.fileno())
    app.quit()

def hb():
    while not stop.wait(15.0):
        print("[%6.1fs] RSS %6.1fMB | 待处理检测 %d | %s" % (
            time.perf_counter()-t0, P.memory_info().rss/1048576,
            len(getattr(win, "_pending_detections", []) or []),
            " || ".join(stage.values())), flush=True)

_op = win._onAnalysisProgress
def prog(f, p, m):
    stage[os.path.basename(f)] = "%s %d%% %s" % (os.path.basename(f)[:9], p, m[:24])
    _op(f, p, m)
win._onAnalysisProgress = prog
win.analysis_controller.analysisProgress.disconnect(_op)
win.analysis_controller.analysisProgress.connect(prog)
win.analysis_controller.analysisFinished.connect(lambda s: done.append(s.file_path))
win.analysis_controller.analysisError.connect(lambda f,e: done.append(f))

stop = threading.Event(); threading.Thread(target=hb, daemon=True).start()
QTimer.singleShot(0, lambda: [win._onAnalyzeRequested(f) for f in FILES])
t = QTimer(); t.setInterval(50); t.timeout.connect(tick); t.start()
app.exec()
