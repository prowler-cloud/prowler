from errno import errorcode

import sentry_sdk
from config.env import env

# How many links of the __cause__/__context__ chain are inspected when looking
# for the OSError that actually caused the event.
MAX_EXCEPTION_CHAIN_DEPTH = 10

IGNORED_EXCEPTIONS = [
    # Provider is not connected due to credentials errors
    "is not connected",
    "ProviderConnectionError",
    # Provider was deleted during a scan
    "ProviderDeletedException",
    "violates foreign key constraint",
    # Authentication Errors from AWS
    "InvalidToken",
    "AccessDeniedException",
    "AuthorizationErrorException",
    "UnrecognizedClientException",
    "UnauthorizedOperation",
    "AuthFailure",
    "InvalidClientTokenId",
    "AWSInvalidProviderIdError",
    "InternalServerErrorException",
    "AccessDenied",
    "No Shodan API Key",  # Shodan Check
    "RequestLimitExceeded",  # For now, we don't want to log the RequestLimitExceeded errors
    "ThrottlingException",
    "Rate exceeded",
    "SubscriptionRequiredException",
    "UnknownOperationException",
    "OptInRequired",
    "ReadTimeout",
    "LimitExceeded",
    "ConnectTimeoutError",
    "ExpiredToken",
    "IncompleteSignature",
    "RegionDisabledException",
    "TooManyRequestsException",
    "SignatureDoesNotMatch",
    "InvalidParameterValueException",
    "InvalidInputException",
    "ValidationException",
    "AWSSecretAccessKeyInvalidError",
    "InvalidAction",
    "InvalidRequestException",
    "RequestExpired",
    "ConnectionClosedError",
    "MaxRetryError",
    "AWSAccessKeyIDInvalidError",
    "AWSSessionTokenExpiredError",
    "EndpointConnectionError",  # AWS Service is not available in a region
    # The following comes from urllib3: eu-west-1 -- HTTPClientError[126]: An HTTP Client raised an
    # unhandled exception: AWSHTTPSConnectionPool(host='hostname.s3.eu-west-1.amazonaws.com', port=443): Pool is closed.
    "Pool is closed",
    # Authentication Errors from GCP
    "ClientAuthenticationError",
    "AuthorizationFailed",
    "Reauthentication is needed",
    "Permission denied to get service",
    "API has not been used in project",
    "HttpError 404 when requesting",
    "HttpError 403 when requesting",
    "HttpError 400 when requesting",
    "GCPNoAccesibleProjectsError",
    # Authentication Errors from Azure
    "ClientAuthenticationError",
    "AuthorizationFailed",
    "Subscription Not Registered",
    "AzureNotValidClientIdError",
    "AzureNotValidClientSecretError",
    "AzureNotValidTenantIdError",
    "AzureInvalidProviderIdError",
    "AzureTenantIdAndClientSecretNotBelongingToClientIdError",
    "AzureTenantIdAndClientIdNotBelongingToClientSecretError",
    "AzureClientIdAndClientSecretNotBelongingToTenantIdError",
    "AzureHTTPResponseError",
    "Error with credentials provided",
    # PowerShell Errors in User Authentication
    "Microsoft Teams User Auth connection failed: Please check your permissions and try again.",
    "Exchange Online User Auth connection failed: Please check your permissions and try again.",
    # ASGI: Client disconnected before the response finished (health-check probes on /health/live)
    "RequestAborted",
]


def errno_fingerprint(exception):
    """
    Return an errno-based fingerprint suffix for OSError-like exceptions.

    Filesystem failures such as ENOSPC (disk full), ENOENT (missing mount point)
    or EACCES (wrong permissions) are all OSError raised from the same call
    site, so Sentry's default grouping merges them into a single issue even
    when the exception is attached to the event. Appending the errno keeps the
    default grouping and splits the issue per failure cause.

    Returns None when no OSError with an errno is found in the exception chain.
    """
    seen = set()
    for _ in range(MAX_EXCEPTION_CHAIN_DEPTH):
        if exception is None or id(exception) in seen:
            break
        seen.add(id(exception))
        if isinstance(exception, OSError) and exception.errno is not None:
            return f"errno:{errorcode.get(exception.errno, exception.errno)}"
        exception = exception.__cause__ or exception.__context__
    return None


def before_send(event, hint):
    """
    before_send handles the Sentry events in order to send them or not
    """
    # Ignore logs with the ignored_exceptions
    # https://docs.python.org/3/library/logging.html#logrecord-objects
    if "log_record" in hint:
        log_record = hint["log_record"]
        log_msg = log_record.getMessage()
        log_lvl = log_record.levelno

        if (
            getattr(log_record, "name", "") == "cartography.graph.job"
            and "Neo.ClientError.Database.DatabaseNotFound" in log_msg
            and "db-tmp-scan-" in log_msg
        ):
            return None

        # The Neo4j driver logs transient connection errors (defunct
        # connections, resets) at ERROR level via the `neo4j.io` logger.
        # `RetryableSession` handles these with retries. If all retries
        # are exhausted, the exception propagates and Sentry captures
        # it as a normal exception event.
        if (
            getattr(log_record, "name", "").startswith("neo4j.io")
            and "defunct" in log_msg
        ):
            return None

        # Handle Error and Critical events and discard the rest
        if log_lvl <= 40 and any(ignored in log_msg for ignored in IGNORED_EXCEPTIONS):
            return None  # Explicitly return None to drop the event

    # Ignore exceptions with the ignored_exceptions
    if "exc_info" in hint and hint["exc_info"]:
        exception = hint["exc_info"][1]
        exc_value = str(exception)
        if any(ignored in exc_value for ignored in IGNORED_EXCEPTIONS):
            return None  # Explicitly return None to drop the event

        # Split OSError issues per errno instead of grouping every filesystem
        # failure raised from the same call site under a single issue.
        fingerprint_suffix = errno_fingerprint(exception)
        if fingerprint_suffix:
            event["fingerprint"] = ["{{ default }}", fingerprint_suffix]

    return event


def initialize_sentry():
    sentry_dsn = env.str("DJANGO_SENTRY_DSN", "")
    if not sentry_dsn:
        return

    sentry_sdk.init(
        dsn=sentry_dsn,
        # Add data like request headers and IP for users,
        # see https://docs.sentry.io/platforms/python/data-management/data-collected/ for more info
        before_send=before_send,
        send_default_pii=True,
        traces_sample_rate=env.float("DJANGO_SENTRY_TRACES_SAMPLE_RATE", default=0.02),
        _experiments={
            # Set continuous_profiling_auto_start to True
            # to automatically start the profiler on when
            # possible.
            "continuous_profiling_auto_start": True,
        },
        attach_stacktrace=True,
        ignore_errors=IGNORED_EXCEPTIONS,
    )


initialize_sentry()
