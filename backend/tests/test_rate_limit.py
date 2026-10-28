from app.core.rate_limit import SlidingWindowLimiter


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def test_sliding_window_blocks_then_recovers() -> None:
    clock = FakeClock()
    lim = SlidingWindowLimiter(clock)
    assert all(lim.hit("k", 3, 60) for _ in range(3))
    assert not lim.hit("k", 3, 60)
    assert lim.retry_after("k", 60) >= 1
    clock.now += 61
    assert lim.hit("k", 3, 60)


def test_keys_are_independent_and_reset_works() -> None:
    lim = SlidingWindowLimiter(FakeClock())
    assert lim.hit("a", 1, 60)
    assert not lim.hit("a", 1, 60)
    assert lim.hit("b", 1, 60)
    lim.reset("a")
    assert lim.hit("a", 1, 60)
    assert lim.count("b", 60) == 1
