import asyncio
from unittest import mock

import pytest

from prowler.providers.okta.lib.service.rate_limiter import (
    OktaRateLimiter,
    build_throttled_http_client,
)


class FakeClock:
    """Deterministic clock whose `sleep` advances time instead of waiting."""

    def __init__(self):
        self.now = 0.0
        self.sleeps = []

    def __call__(self):
        return self.now

    async def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds


def _limiter(rate, clock):
    return OktaRateLimiter(rate, clock=clock, sleep=clock.sleep)


class Test_OktaRateLimiter:
    def test_rejects_non_positive_rate(self):
        with pytest.raises(ValueError):
            OktaRateLimiter(0)
        with pytest.raises(ValueError):
            OktaRateLimiter(-1)

    def test_initial_burst_does_not_sleep(self):
        clock = FakeClock()
        # capacity == rate == 2, so the first two tokens are free.
        limiter = _limiter(2, clock)

        asyncio.run(limiter.acquire())
        asyncio.run(limiter.acquire())

        assert clock.sleeps == []

    def test_sleeps_to_maintain_rate_once_bucket_drained(self):
        clock = FakeClock()
        limiter = _limiter(2, clock)  # capacity 2, refill 2/s

        # Drain the burst, then the third call must wait one refill interval.
        asyncio.run(limiter.acquire())
        asyncio.run(limiter.acquire())
        asyncio.run(limiter.acquire())

        assert clock.sleeps == [pytest.approx(0.5)]
        assert clock.now == pytest.approx(0.5)

    def test_elapsed_time_refills_tokens_without_sleeping(self):
        clock = FakeClock()
        limiter = _limiter(2, clock)

        asyncio.run(limiter.acquire())
        asyncio.run(limiter.acquire())
        # Enough wall-clock passes to fully refill the bucket.
        clock.now += 1.0
        asyncio.run(limiter.acquire())

        assert clock.sleeps == []

    def test_rate_below_one_per_second(self):
        clock = FakeClock()
        limiter = _limiter(0.5, clock)  # capacity floored to 1.0

        asyncio.run(limiter.acquire())  # free initial token
        asyncio.run(limiter.acquire())  # must wait 1 / 0.5 = 2s

        assert clock.sleeps == [pytest.approx(2.0)]


class Test_build_throttled_http_client:
    def test_acquires_before_delegating_to_super(self):
        limiter = mock.MagicMock()
        limiter.acquire = mock.AsyncMock()

        throttled_cls = build_throttled_http_client(limiter)
        client = throttled_cls({"headers": {}})

        with mock.patch.object(
            throttled_cls.__bases__[0],
            "send_request",
            new=mock.AsyncMock(return_value="response"),
        ) as base_send:
            result = asyncio.run(client.send_request({"method": "GET"}))

        limiter.acquire.assert_awaited_once()
        base_send.assert_awaited_once_with({"method": "GET"})
        assert result == "response"
