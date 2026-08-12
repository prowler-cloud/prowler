"""What a Prowler MCP Server failure is, and the sentence it is described with.

MCP draws a line this server used to blur. A tool that *returns* `{"error": ...}`
produces a successful result (`isError: false`) whose failure is only discoverable by
guessing which key to look at; a tool that *raises* produces `isError: true`, which
every client and model already understands as "this call did not work". Moving the
server onto the second of those needs one vocabulary of failures and one way to render
them, which is what this module is; raising them is the sub-servers' job.

`render_tool_error` is the single place an exception becomes text a client reads, so
the same failure can never get described two different ways.

The exception types live here rather than next to the API client because the hub and the
documentation sub-servers must be able to raise and render them without taking a
dependency on `prowler_app`.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

import httpx

# Upstream bodies are not ours and may be large or HTML; enough to diagnose, not enough
# to flood the model's context.
_MAX_UPSTREAM_BODY = 500

# The one thing a status code does not say. Appended only when a request that could have
# changed something did not come back with a verdict, because an agent reads a failure as
# "nothing happened" and will happily send the write again.
_UNKNOWN_OUTCOME = (
    " It may have been carried out anyway, so check the current state before retrying."
)


@dataclass(frozen=True, slots=True)
class ApiErrorDetail:
    """One entry of a JSON:API `errors` array.

    The API answers a rejected write with one error *per invalid field*, each naming the
    field in `source`. Keeping the whole shape is what turns "the request was invalid"
    into "these two fields were invalid, and here is which".

    Field names are JSON:API's own. `source.pointer` and `source.parameter` are not two
    spellings of one thing: a pointer is a JSON Pointer into the request *document*
    (`/data/attributes/provider_id`, as `alerts/errors.py` and `tasks/beat.py` send),
    while a parameter is a *query parameter* name (`page[size]`, `lookback_days`, as
    `api/v1/views.py` sends). The spec has a third, `source.header`; the Prowler API
    never emits one, so there is nothing here to read it into.
    """

    detail: str | None = None
    title: str | None = None
    pointer: str | None = None
    """JSON:API `source.pointer`: a JSON Pointer into the request document."""
    parameter: str | None = None
    """JSON:API `source.parameter`: the query parameter that caused the error."""

    @classmethod
    def from_jsonapi(cls, error: dict[str, Any]) -> ApiErrorDetail:
        """Build from a single member of a JSON:API `errors` array.

        `source` is optional and most errors omit it, so it supplies the location only,
        never whether there is a detail worth reporting.
        """
        source = error.get("source", {})
        return cls(
            detail=error.get("detail"),
            title=error.get("title"),
            pointer=source.get("pointer"),
            parameter=source.get("parameter"),
        )

    def render(self) -> str:
        """The error text, and where the API said it is.

        A pointer is left as-is because a leading `/` already reads as a path into the
        body. A parameter is labelled, since `(page[size])` on its own would read like
        one.
        """
        text = self.detail or self.title or ""
        if not text:
            return ""
        if self.pointer:
            return f"{text} ({self.pointer})"
        if self.parameter:
            return f"{text} (parameter {self.parameter})"
        return text


def parse_jsonapi_errors(payload: Any) -> tuple[ApiErrorDetail, ...]:
    """Extract every error from a JSON:API error document.

    Tolerant on purpose: this runs while handling a failure, and a body that is not the
    document it should be must not turn a useful API error into a parsing traceback.
    """
    if not isinstance(payload, dict):
        return ()
    errors = payload.get("errors")
    if not isinstance(errors, list):
        return ()
    return tuple(
        ApiErrorDetail.from_jsonapi(error)
        for error in errors
        if isinstance(error, dict)
    )


class ProwlerAPIError(Exception):
    """An error response returned by the Prowler API.

    Raised only when the API answered with an error status, which tells a caller
    something no plain exception can: the request reached Prowler and was
    rejected, so it changed nothing. A timeout or a dropped connection stays a
    bare exception because the request may well have been processed.
    """

    def __init__(
        self,
        message: str,
        status_code: int,
        *,
        method: str | None = None,
        path: str | None = None,
        errors: tuple[ApiErrorDetail, ...] = (),
    ) -> None:
        super().__init__(message)
        self.status_code: int = status_code
        # Stored as plain strings so this module stays independent of the API client's
        # HTTPMethod enum; StrEnum members compare equal to their value either way.
        self.method: str | None = str(method) if method is not None else None
        self.path: str | None = path
        self.errors: tuple[ApiErrorDetail, ...] = tuple(errors)

    @property
    def rejected(self) -> bool:
        """The request reached Prowler and was refused, so it changed nothing."""
        return 400 <= self.status_code < 500


class ProwlerTaskError(Exception):
    """A background task this server was waiting on did not complete.

    Separate from `ProwlerAPIError` because the API already accepted the work: the
    task exists and may still be running, so the outcome is unknown rather than refused.
    """

    def __init__(self, message: str, *, task_id: str, state: str) -> None:
        super().__init__(message)
        self.task_id: str = task_id
        self.state: str = state
        """One of `timeout`, `failed` or `cancelled`."""


class ProwlerAuthError(ValueError):
    """The credentials are missing, malformed or expired.

    Subclasses `ValueError` so that the handlers which already treat an
    authentication failure as a refusal-before-send keep working. It is matched by name
    in `render_tool_error` rather than by that base class, so it is described as the
    credential problem it is instead of falling through to the bug branch.
    """


class ProwlerHubError(Exception):
    """The Prowler Hub answered with an error status.

    The Hub is a separate public service with its own client, so its failures cannot be
    `ProwlerAPIError`. Everything the Hub exposes is a read.
    """

    def __init__(
        self,
        message: str,
        *,
        status_code: int,
        path: str,
        body: str | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code: int = status_code
        self.path: str = path
        self.body: str | None = body


def _upstream_detail(body: str | None) -> str:
    """A readable line from an error body that is not JSON:API.

    The Prowler API answers with a JSON:API document, which is parsed into
    `ApiErrorDetail`. Every other host this server talks to has its own shape: the Hub
    answers `{"error": "Not found"}`, GitHub answers plain text, a proxy in between may
    answer HTML. Relaying any of those verbatim puts braces and markup in front of the
    model, so the message is pulled out when there is one and truncated when there is
    not.
    """
    if not body:
        return ""
    text = body.strip()
    try:
        parsed = json.loads(text)
    except ValueError:
        parsed = None
    if isinstance(parsed, dict):
        for key in ("error", "message", "detail"):
            value = parsed.get(key)
            if isinstance(value, str) and value:
                return value
    return f"{text[:_MAX_UPSTREAM_BODY]}..." if len(text) > _MAX_UPSTREAM_BODY else text


def render_tool_error(error: Exception, *, warn: bool = True) -> str:
    """Describe an exception in the plainest sentence that keeps every useful detail.

    Callers that surface a failure from anywhere other than a raised exception -- a
    message they write themselves, a field of a structured result -- go through here
    too, which is what keeps one failure from being described two different ways.

    Pass `warn=False` when the caller already states the outcome, which a structured
    result reporting `status="unknown"` does by definition. Otherwise the generic
    warning lands next to a more specific one saying the same thing.

    Ordered most specific first: `ProwlerAuthError` is a `ValueError` and
    `httpx.TimeoutException` is a `RequestError`, so the general branches come last.
    """
    unknown = _UNKNOWN_OUTCOME if warn else ""

    if isinstance(error, ProwlerAPIError):
        operation = (
            " ".join(p for p in (error.method, error.path) if p) or "The request"
        )
        details = "; ".join(text for text in (d.render() for d in error.errors) if text)
        message = f"{operation} failed with HTTP {error.status_code}."
        if details:
            message = f"{message} {details}"
        # A 4xx is a refusal, so it changed nothing and needs no warning.
        if error.rejected or error.method == "GET":
            return message
        return message + unknown

    if isinstance(error, ProwlerTaskError):
        # The API accepted the work before the wait failed, so the outcome is open
        # whichever way the task ended.
        return f"{error}{unknown}"

    if isinstance(error, ProwlerAuthError):
        return f"Prowler authentication failed: {error}"

    if isinstance(error, ProwlerHubError):
        # Same shape as the API branch, with the service named because the Hub can be
        # down while the API is fine. Everything the Hub exposes is a GET.
        message = f"Prowler Hub GET {error.path} failed with HTTP {error.status_code}."
        detail = _upstream_detail(error.body)
        return f"{message} {detail}" if detail else message

    if isinstance(error, httpx.HTTPStatusError):
        # An upstream that is not the Prowler API, such as the external-URL fetch.
        request = error.request
        message = (
            f"{request.method} {request.url} failed with HTTP "
            f"{error.response.status_code}."
        )
        detail = _upstream_detail(error.response.text)
        return f"{message} {detail}" if detail else message

    if isinstance(error, httpx.RequestError):
        # No answer at all: a timeout, a dropped connection, a DNS failure.
        try:
            operation = f"{error.request.method} {error.request.url}"
            method = error.request.method
        except RuntimeError:
            # httpx only attaches the request once it has one, and reading it before
            # then raises. Never let that hide the failure being reported.
            operation, method = "The request", None
        suffix = "" if method == "GET" else unknown
        return f"{operation} got no answer ({type(error).__name__}: {error}).{suffix}"

    # No `ValueError` branch, deliberately. A message written for the caller is raised
    # as a `ToolError`, which never reaches here. What is left -- a model factory
    # rejecting an API payload, a pydantic `ValidationError`, an `int()` on something
    # that is not a number -- is this server or the API breaking its own contract, and
    # saying so is the only useful thing to tell a caller who cannot fix it.
    return (
        f"The Prowler MCP Server hit an unexpected {type(error).__name__}: {error}. "
        "This is a bug in the server, not something you can fix by changing the "
        "arguments."
    )
