from websockproxy import limiter
from websockproxy.limiter import RateLimitingState


def test_allows_burst_up_to_rate_then_throttles():
    state = RateLimitingState(1000.0, clientip='test', name='upstream')

    assert state.do_throttle(b'x' * 600)
    assert state.do_throttle(b'x' * 400)
    assert not state.do_throttle(b'x' * 10)


class FakeClock:
    """Wall clock and monotonic clock that can move independently."""

    def __init__(self):
        self.wall = 1_000_000.0
        self.mono = 100.0

    def time(self):
        return self.wall

    def monotonic(self):
        return self.mono


def test_wall_clock_jumping_backwards_does_not_throttle(monkeypatch):
    clock = FakeClock()
    monkeypatch.setattr(limiter, 'time', clock)
    state = RateLimitingState(1000.0, clientip='test', name='upstream')

    clock.wall -= 3600  # e.g. NTP correction
    clock.mono += 1

    assert state.do_throttle(b'x' * 100)


def test_zero_rate_disables_throttling():
    state = RateLimitingState(0, clientip='test', name='upstream')

    assert all(state.do_throttle(b'x' * 1_000_000) for _ in range(100))
