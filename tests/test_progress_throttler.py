import time

from core.stream_worker import ProgressThrottler


def test_progress_throttler_emits_new_percentages_without_waiting() -> None:
    throttler = ProgressThrottler(interval_ms=10_000)

    assert throttler.next_percent(64) == 64
    assert throttler.next_percent(65) == 65


def test_progress_throttler_never_moves_backwards() -> None:
    """百分比对外只增不减 —— 进度条往回跳看着像出错"""
    throttler = ProgressThrottler(interval_ms=0)

    assert throttler.next_percent(65) == 65
    # _run_analysis 里 AST 发 44 之后响应扫描发 38，显示上要按 65 钳住
    assert throttler.next_percent(38) == 65


def test_same_percent_still_emits_after_interval() -> None:
    """百分比不变但消息在变时必须放行

    HTTP 阶段几十秒都停在同一个整数百分比上，只有消息文本
    ("已处理 N 请求")在动。旧实现整条丢弃，界面看上去就是卡死。
    """
    throttler = ProgressThrottler(interval_ms=20)

    assert throttler.next_percent(15) == 15
    assert throttler.next_percent(15) is None      # 太密，压掉
    time.sleep(0.03)
    assert throttler.next_percent(15) == 15        # 过了间隔，放行


def test_backwards_percent_still_emits_after_interval() -> None:
    """倒退的百分比也要能带着新阶段名发出去，只是显示值被钳住"""
    throttler = ProgressThrottler(interval_ms=20)

    assert throttler.next_percent(44) == 44
    assert throttler.next_percent(38) is None      # 间隔没到
    time.sleep(0.03)
    assert throttler.next_percent(38) == 44        # 放行，但显示 44 不倒退


def test_hundred_percent_always_delivered() -> None:
    """终态不能被节流吃掉，否则界面永远停在 99%"""
    throttler = ProgressThrottler(interval_ms=10_000)

    assert throttler.next_percent(40) == 40
    assert throttler.next_percent(41) == 41
    assert throttler.next_percent(100) == 100


def test_should_emit_compat_shim() -> None:
    throttler = ProgressThrottler(interval_ms=10_000)

    assert throttler.should_emit(10) is True
    assert throttler.should_emit(10) is False
