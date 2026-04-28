import sentry_sdk
from config.env import env

_SENTRY_TAG_FIELDS = {
    "prowler_provider": "provider",
    "prowler_region": "region",
    "prowler_service": "service",
    "prowler_tenant_id": "tenant_id",
    "prowler_scan_id": "scan_id",
    "prowler_provider_uid": "provider_uid",
}

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
]


def before_send(event, hint):
    """
    before_send handles the Sentry events in order to send them or not.

    It also promotes prowler context fields (injected by ProwlerContextFilter)
    from the LogRecord into Sentry event tags so they become searchable.
    """
    # Ignore logs with the ignored_exceptions
    # https://docs.python.org/3/library/logging.html#logrecord-objects
    if "log_record" in hint:
        log_record = hint["log_record"]
        log_msg = log_record.getMessage()
        log_lvl = log_record.levelno

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

        # Promote prowler context fields to Sentry tags
        for record_attr, tag_name in _SENTRY_TAG_FIELDS.items():
            value = getattr(log_record, record_attr, None)
            if value:
                event.setdefault("tags", {})
                if isinstance(event["tags"], dict):
                    event["tags"][tag_name] = str(value)
                elif isinstance(event["tags"], list):
                    event["tags"].append([tag_name, str(value)])

    # Ignore exceptions with the ignored_exceptions
    if "exc_info" in hint and hint["exc_info"]:
        exc_value = str(hint["exc_info"][1])
        if any(ignored in exc_value for ignored in IGNORED_EXCEPTIONS):
            return None  # Explicitly return None to drop the event

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
    attach_stacktrace=True,
    ignore_errors=IGNORED_EXCEPTIONS,
)
