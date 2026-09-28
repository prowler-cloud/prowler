"""Route registry and request recorder backed by ``httpx.MockTransport``.

Mocking at the transport boundary rather than stubbing ``client.request`` keeps
the parts of httpx the code under test actually relies on in play: base-URL
joining, query-parameter encoding, header assembly, ``raise_for_status()`` and
JSON decoding. A test that asserts on a recorded request is therefore asserting
on the bytes that would really have gone out.
"""

import json
from collections.abc import Callable
from typing import Any

import httpx

_UNSET = object()

ResponseFactory = Callable[[httpx.Request], httpx.Response]


class MockRouter:
    """Declare ``(METHOD, path) -> response`` and inspect what was requested.

    Responses registered for the same route are consumed in order and the last
    one repeats forever. That is what makes polling testable: register
    ``executing``, ``executing``, ``completed`` and the loop sees each in turn.

    An unregistered request raises instead of returning a default, so a test can
    never silently exercise a different endpoint than the one it set up.
    """

    def __init__(self) -> None:
        self._routes: dict[tuple[str, str], list[ResponseFactory]] = {}
        self.requests: list[httpx.Request] = []

    # --- registration -----------------------------------------------------

    def add(
        self,
        method: str,
        path: str,
        *,
        status: int = 200,
        json: Any = _UNSET,
        text: str | None = None,
        headers: dict[str, str] | None = None,
    ) -> "MockRouter":
        """Register a canned response for a route. Chainable."""
        kwargs: dict[str, Any] = {"headers": headers}
        if json is not _UNSET:
            kwargs["json"] = json
        if text is not None:
            kwargs["text"] = text
        return self.add_handler(
            method, path, lambda _request: httpx.Response(status, **kwargs)
        )

    def add_handler(
        self, method: str, path: str, handler: ResponseFactory
    ) -> "MockRouter":
        """Register a callable that builds the response from the request."""
        self._routes.setdefault((method.upper(), path), []).append(handler)
        return self

    # --- transport --------------------------------------------------------

    @property
    def transport(self) -> httpx.MockTransport:
        """A transport that serves this router. Works for sync and async clients."""
        return httpx.MockTransport(self._handle)

    def _handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        queue = self._routes.get((request.method.upper(), request.url.path))
        if not queue:
            registered = (
                ", ".join(f"{method} {path}" for method, path in sorted(self._routes))
                or "none"
            )
            raise AssertionError(
                f"Unregistered request {request.method} {request.url}. "
                f"Registered routes: {registered}"
            )
        # Keep the final response so a route can be polled repeatedly.
        factory = queue.pop(0) if len(queue) > 1 else queue[0]
        return factory(request)

    # --- inspection -------------------------------------------------------

    def request_for(self, method: str, path: str) -> httpx.Request:
        """Return the last recorded request for a route, failing if there is none."""
        matches = [
            request
            for request in self.requests
            if request.method.upper() == method.upper() and request.url.path == path
        ]
        if not matches:
            raise AssertionError(
                f"No {method.upper()} {path} request was made. Made: {self.paths()}"
            )
        return matches[-1]

    def query_params(self, method: str, path: str) -> dict[str, str]:
        """Return the decoded query parameters of the last request for a route."""
        return dict(self.request_for(method, path).url.params)

    def json_body(self, method: str, path: str) -> Any:
        """Return the decoded JSON body of the last request for a route.

        Write tools build a JSON:API document by hand, and the API silently
        ignores an attribute it does not recognise, so the body is the only place
        a misspelled key shows up.
        """
        return json.loads(self.request_for(method, path).content)

    def paths(self) -> list[str]:
        """Return every request made so far, as ``"METHOD /path"`` strings."""
        return [f"{request.method} {request.url.path}" for request in self.requests]
