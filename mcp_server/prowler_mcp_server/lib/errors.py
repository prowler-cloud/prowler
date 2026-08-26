"""Shared failure classification for every tool in this server."""

import json
from typing import Any

import httpx
from fastmcp.exceptions import McpError, NotFoundError, ToolError
from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext
from pydantic import ValidationError

from prowler_mcp_server.lib.logger import logger

# ------------------------------------------------------------- failure types


class ProwlerAPIError(Exception):
    """An error response returned by the Prowler API.

    Attributes:
        status_code: HTTP status the API answered with
        detail: JSON:API `errors[0].detail`, None when there is none to trust
    """

    def __init__(
        self, message: str, status_code: int, *, detail: str | None = None
    ) -> None:
        super().__init__(message)
        self.status_code: int = status_code
        # Prowler's own JSON:API `errors[0].detail`, which our API writes for a
        # caller and we therefore trust. None when the body was not JSON:API --
        # a gateway HTML page or a debug traceback, which is exactly the case
        # that must never be repeated to a model -- and None for a 5xx, see
        # `jsonapi_detail`.
        self.detail: str | None = detail


class ProwlerAPIUnreachable(Exception):
    """The request never got an answer, so whether it was applied is unknown."""


class ProwlerAPIInvalidResponse(Exception):
    """The API answered, but with a body this server could not read as JSON."""


def jsonapi_detail(response: httpx.Response) -> str | None:
    """Return the API's own JSON:API error detail, when there is one to trust.

    Args:
        response: Error response returned by the Prowler API

    Returns:
        `errors[0].detail`, or None if the status is 5xx or the body is not
        JSON:API
    """
    if response.status_code >= 500:
        return None

    try:
        errors = response.json().get("errors")
    except Exception:
        return None

    if not isinstance(errors, list) or not errors:
        return None

    detail = errors[0].get("detail") if isinstance(errors[0], dict) else None
    return detail if isinstance(detail, str) and detail.strip() else None


class InvalidArgument(ValueError):
    """An argument this server rejected before any request went out."""


class CredentialError(Exception):
    """The credential the caller sent is missing, malformed or expired."""


# ------------------------------------------------------------------- messages


def _describe_prowler_api_error(exc: ProwlerAPIError) -> str:
    """Describe a request the Prowler API answered with an error status."""
    status = exc.status_code

    # The fallback: a status this server has nothing specific to say about.
    message = (
        f"Prowler rejected the request with status {status} and gave no reason. "
        "Check the arguments against the tool description."
    )

    if status == 401:
        message = (
            "Prowler rejected this server's credential: it is missing, malformed "
            "or expired. In HTTP mode the request needs an 'Authorization: Bearer "
            "<token>' header; in STDIO mode PROWLER_API_KEY must hold a valid key."
        )
    elif status == 403:
        message = (
            "The credential is valid but not allowed to do this. Use "
            "prowler_get_current_user to see which role it holds."
        )
    elif status == 429:
        message = (
            "Prowler is rate limiting this credential. Wait before retrying, and "
            "narrow the request with tighter filters or a smaller page_size."
        )
    elif status >= 500:
        message = (
            f"Prowler answered {status}: the request failed on Prowler's side, "
            "not because of anything in the call."
        )
    elif exc.detail:
        # Written by the Prowler API for a caller to read, so it is ours to relay.
        message = f"Prowler rejected the request ({status}): {exc.detail}"

    return message


def _describe_upstream_http_error(exc: httpx.HTTPError) -> str:
    """Describe a failure from an upstream this server reads directly."""
    # `.request` raises rather than returning None when it was never set, and
    # this runs inside an exception handler, so it is read defensively.
    request = getattr(exc, "_request", None)
    host = request.url.host if request is not None else "the upstream service"

    if not isinstance(exc, httpx.HTTPStatusError):
        return f"{host} could not be reached: {type(exc).__name__}."

    status = exc.response.status_code
    if status == 429:
        return f"{host} is rate limiting this server. Wait before retrying."
    if status >= 500:
        return (
            f"{host} answered {status}: the request failed on its side, not "
            "because of anything in the call."
        )
    return (
        f"{host} rejected the request with status {status}. Check the arguments "
        "against the tool description."
    )


def _describe_failure(exc: BaseException) -> str | None:
    """Describe a failure for a model to read, or return None to leave it masked."""
    # InvalidArgument first: it is the only ValueError here whose message this
    # server wrote. The ones below quote the input they rejected, so they are
    # matched by type and answered with a message of our own.
    if isinstance(exc, InvalidArgument):
        return str(exc)

    if isinstance(exc, ProwlerAPIError):
        return _describe_prowler_api_error(exc)

    if isinstance(exc, ProwlerAPIInvalidResponse):
        return (
            "Prowler answered with a body this server could not read, so the "
            "outcome of the call is unknown. If it changes anything, check the "
            "current state before sending it again."
        )

    if isinstance(exc, CredentialError):
        # Not an argument problem, so it is worth saying that plainly: the
        # answer is a credential the user has to fix, not another attempt.
        return (
            f"This request carried no usable credential: {exc}. Retrying or "
            "changing the arguments will not help -- the client has to send an "
            "'Authorization: Bearer <token>' header holding a valid Prowler API "
            "key or an unexpired JWT."
        )

    if isinstance(exc, ProwlerAPIUnreachable):
        # The only failure a model can turn into a duplicate write by repeating.
        return (
            f"Prowler could not be reached: {exc}. Whether the request was "
            "applied is unknown, so check the current state before sending it again."
        )

    if isinstance(exc, ValidationError):
        problems = [
            f"{'.'.join(str(part) for part in error['loc']) or '(argument)'}: {error['msg']}"
            for error in exc.errors(include_url=False)
        ]
        # Field and expectation only: pydantic quotes the rejected value back.
        return f"Invalid arguments -- {'; '.join(problems)}."

    if isinstance(exc, json.JSONDecodeError):
        return (
            "An argument that had to be a JSON object could not be parsed. Send "
            "it as a real object rather than as a quoted or escaped string."
        )

    # Only the Hub and documentation tools reach here: the Prowler API client
    # converts its own httpx failures into the two types matched above.
    if isinstance(exc, (httpx.HTTPStatusError, httpx.RequestError)):
        return _describe_upstream_http_error(exc)

    return None


# ----------------------------------------------------------------- middleware


class SharedFailureMiddleware(Middleware):
    """Replace the failures many tools share with a message a model can act on."""

    async def on_call_tool(
        self,
        context: MiddlewareContext[Any],
        call_next: CallNext[Any, Any],
    ) -> Any:
        """Replace a shared tool failure with the message that describes it.

        Args:
            context: Tool call being handled
            call_next: Rest of the middleware chain

        Returns:
            The tool result when the call succeeded

        Raises:
            ToolError: With the classified message when the failure is one this
                module recognises
        """
        try:
            return await call_next(context)
        except (NotFoundError, McpError):
            # Protocol-level, not a tool failure. Must stay exactly as it is.
            raise
        except Exception as exc:
            # FastMCP wraps whatever the tool raised and records it as __cause__.
            # An absent cause means the message is already the final word: a
            # ToolError raised deliberately without a `from` clause.
            original = exc.__cause__
            message = _describe_failure(original) if original is not None else None

            if message is None:
                if original is not None:
                    logger.warning(
                        "Tool %s failed with an unclassified error: %s: %s",
                        getattr(context.message, "name", "<unknown>"),
                        type(original).__name__,
                        original,
                    )
                raise

            logger.warning(
                "Tool %s failed: %s: %s",
                getattr(context.message, "name", "<unknown>"),
                type(original).__name__,
                original,
            )
            raise ToolError(message) from exc
