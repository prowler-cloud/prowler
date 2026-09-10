"""Client-side request throttling for the Okta provider.

The Okta SDK already retries on HTTP 429 (see `service.py`), but retrying is
reactive: it only helps *after* a rate limit has been hit, and each backoff
waits out a full reset window. To avoid hitting Okta's limits in the first
place, this module paces outbound requests with a shared token bucket.

A single `OktaRateLimiter` instance lives on the provider and is shared by every
service's SDK client, so the cap applies to the *aggregate* request rate rather
than per client. The limiter is injected by wrapping the SDK's `HTTPClient`
(via the `httpClient` config key) and awaiting `acquire()` before each call.

Note: Okta enforces rate limits per endpoint, so a single requests-per-second
cap is a deliberately simple, blunt control. It keeps bursty pagination from
overrunning the limits without trying to model every per-endpoint budget.
"""

import asyncio
import threading
import time

from okta.http_client import HTTPClient

# Default aggregate request rate. Okta-managed orgs commonly throttle the
# busiest endpoints around a handful of requests per second, so we pace below
# that by default. Set `okta_requests_per_second` to 0 (or a negative value) to
# disable throttling entirely.
DEFAULT_REQUESTS_PER_SECOND = 4


class OktaRateLimiter:
    """Token-bucket limiter shared across a provider's Okta SDK clients.

    The bucket refills at `requests_per_second` tokens per second up to a small
    burst capacity. `acquire()` consumes one token, sleeping just long enough
    when the bucket is empty. Token accounting is wall-clock based
    (`time.monotonic`) so it stays correct across the separate event loops the
    services spin up with `asyncio.run`.
    """

    def __init__(
        self,
        requests_per_second: float,
        *,
        clock=time.monotonic,
        sleep=asyncio.sleep,
    ):
        if requests_per_second <= 0:
            raise ValueError("requests_per_second must be greater than 0")
        self._rate = float(requests_per_second)
        # Allow up to one second of requests to burst, then settle to the rate.
        self._capacity = max(1.0, self._rate)
        self._tokens = self._capacity
        self._clock = clock
        self._sleep = sleep
        self._last = clock()
        # Guards the token math only; never held across an await.
        self._lock = threading.Lock()

    async def acquire(self) -> None:
        """Block until a request token is available, then consume it."""
        while True:
            with self._lock:
                now = self._clock()
                self._tokens = min(
                    self._capacity, self._tokens + (now - self._last) * self._rate
                )
                self._last = now
                if self._tokens >= 1:
                    self._tokens -= 1
                    return
                wait = (1 - self._tokens) / self._rate
            await self._sleep(wait)


def build_throttled_http_client(limiter: OktaRateLimiter) -> type[HTTPClient]:
    """Return an `HTTPClient` subclass that paces requests through `limiter`.

    The Okta SDK instantiates `config["httpClient"]` with its HTTP config, so we
    return a class (not an instance) that closes over the shared limiter.

    Args:
        limiter: Shared token-bucket limiter that paces the aggregate request
            rate across every service client of the provider.

    Returns:
        An `HTTPClient` subclass that awaits the limiter before each request.
    """

    class ThrottledHTTPClient(HTTPClient):
        """`HTTPClient` that acquires a limiter token before each request."""

        async def send_request(self, request):
            """Acquire a rate-limit token, then delegate to the SDK client.

            Args:
                request: The request payload built by the Okta SDK.

            Returns:
                The result of the underlying `HTTPClient.send_request` call.
            """
            await limiter.acquire()
            return await super().send_request(request)

    return ThrottledHTTPClient
