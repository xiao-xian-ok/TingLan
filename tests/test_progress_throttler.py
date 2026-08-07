from core.stream_worker import ProgressThrottler


def test_progress_throttler_emits_new_percentages_without_waiting() -> None:
    throttler = ProgressThrottler(interval_ms=10_000)

    assert throttler.should_emit(64) is True
    assert throttler.should_emit(65) is True


def test_progress_throttler_never_moves_backwards() -> None:
    throttler = ProgressThrottler(interval_ms=0)

    assert throttler.should_emit(65) is True
    assert throttler.should_emit(64) is False
