from websockproxy.limiter import RateLimitingState


def test_allows_burst_up_to_rate_then_throttles():
    state = RateLimitingState(1000.0, clientip='test', name='upstream')

    assert state.do_throttle(b'x' * 600)
    assert state.do_throttle(b'x' * 400)
    assert not state.do_throttle(b'x' * 10)
