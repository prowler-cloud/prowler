import sentry_sdk
from config.env import env

IGNORED_EXCEPTIONS = [
    # Authentication Errors from AWS
    "InvalidToken",
    "AccessDeniedException",
    "AuthorizationErrorException",
    "UnrecognizedClientException",
    "UnauthorizedOperation",
    "AuthFailure",
    "InvalidClientTokenId",
    "AccessDenied",
    # Shodan Check
    "No Shodan API Key",
    # For now we don't want to log the RequestLimitExceeded errors
    "RequestLimitExceeded",
    "ThrottlingException",
    "Rate exceeded",
    # The following comes from urllib3
    # eu-west-1 -- HTTPClientError[126]: An HTTP Client raised an unhandled exception: AWSHTTPSConnectionPool(host='hostname.s3.eu-west-1.amazonaws.com', port=443): Pool is closed.
    "Pool is closed",
]


def before_send(event, hint):
    """
    before_send handles the Sentry events in order to sent them or not
    """
    # Ignore logs with the ignored_exceptions
    # https://docs.python.org/3/library/logging.html#logrecord-objects
    if "log_record" in hint:
        log_msg = hint["log_record"].msg
        log_lvl = hint["log_record"].levelno

        # Handle Error events and discard the rest
        if log_lvl == 40 and any(ignored in log_msg for ignored in IGNORED_EXCEPTIONS):
            return
    return event


sentry_sdk.init(
    dsn=env.str("DJANGO_SENTRY_DSN", ""),
    # Add data like request headers and IP for users,
    # see https://docs.sentry.io/platforms/python/data-management/data-collected/ for more info
    before_send=before_send,
    send_default_pii=True,
    _experiments={
        # Set continuous_profiling_auto_start to True
        # to automatically start the profiler on when
        # possible.
        "continuous_profiling_auto_start": True,
    },
)
