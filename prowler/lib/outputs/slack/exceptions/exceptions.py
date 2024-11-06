from prowler.exceptions.exceptions import ProwlerException


# Exceptions codes from 8000 to 8999 are reserved for Slack exceptions
class SlackBaseException(ProwlerException):
    """Base class for Slack errors."""

    SLACK_ERROR_CODES = {
        (8000, "SlackClientError"): {
            "message": "Slack ClientError occurred",
            "remediation": "Check your Slack client configuration and permissions.",
        },
        (8001, "SlackNoCredentialsError"): {
            "message": "Invalid Slack credentials found",
            "remediation": "Some aspect of authentication cannot be validated. Either the provided token is invalid or the request originates from an IP address disallowed from making the request.",
        },
        (8002, "SlackChannelNotFound"): {
            "message": "Slack channel not found",
            "remediation": "Check the channel name and ensure it exists.",
        },
    }

    def __init__(self, code, file=None, original_exception=None, message=None):
        error_info = self.SLACK_ERROR_CODES.get((code, self.__class__.__name__))
        if message:
            error_info["message"] = message
        super().__init__(
            code,
            source="Slack",
            file=file,
            original_exception=original_exception,
            error_info=error_info,
        )


class SlackCredentialsError(SlackBaseException):
    """Base class for Slack credentials errors."""

    def __init__(self, code, file=None, original_exception=None, message=None):
        super().__init__(code, file, original_exception, message)


class SlackClientError(SlackCredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            8000, file=file, original_exception=original_exception, message=message
        )


class SlackNoCredentialsError(SlackCredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            8001, file=file, original_exception=original_exception, message=message
        )


class SlackChannelNotFound(SlackCredentialsError):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            8002, file=file, original_exception=original_exception, message=message
        )
