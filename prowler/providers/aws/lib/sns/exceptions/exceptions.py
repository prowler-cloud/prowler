from prowler.exceptions.exceptions import ProwlerException


class SNSException(ProwlerException):
    """Base class for SNS related exceptions."""

    AWS_SERVICE_NAME = "sns"

    def __init__(self, message: str, file=None, original_exception=None):
        """
        Initialize a SNSException.

        Args:
            message (str): The error message
            file (str): The file where the exception was raised
            original_exception (Exception): The original exception that was raised
        """
        super().__init__(
            source=SNSException.AWS_SERVICE_NAME,
            file=file,
            original_exception=original_exception,
            message=message,
        )


class SNSInvalidParameterError(SNSException):
    """Exception raised when an invalid parameter is provided."""

    def __init__(self, file=None, original_exception=None):
        message = "Invalid SNS parameters provided"
        super().__init__(message, file, original_exception)


class SNSAuthenticationError(SNSException):
    """Exception raised when authentication with SNS fails."""

    def __init__(self, file=None, original_exception=None):
        message = (
            "Failed to authenticate with Amazon SNS. Please check your credentials."
        )
        super().__init__(message, file, original_exception)


class SNSTopicNotFoundError(SNSException):
    """Exception raised when the specified SNS topic does not exist."""

    def __init__(self, topic_arn: str = None, file=None, original_exception=None):
        message = (
            f"SNS topic not found: {topic_arn}" if topic_arn else "SNS topic not found"
        )
        super().__init__(message, file, original_exception)


class SNSAccessDeniedError(SNSException):
    """Exception raised when access to SNS topic is denied."""

    def __init__(self, topic_arn: str = None, file=None, original_exception=None):
        message = (
            f"Access denied to SNS topic: {topic_arn}"
            if topic_arn
            else "Access denied to SNS topic"
        )
        super().__init__(message, file, original_exception)


class SNSPublishError(SNSException):
    """Exception raised when publishing to SNS topic fails."""

    def __init__(self, file=None, original_exception=None):
        message = "Failed to publish message to SNS topic"
        super().__init__(message, file, original_exception)


class SNSInvalidTopicARNError(SNSException):
    """Exception raised when an invalid SNS topic ARN is provided."""

    def __init__(self, topic_arn: str = None, file=None, original_exception=None):
        message = (
            f"Invalid SNS topic ARN: {topic_arn}"
            if topic_arn
            else "Invalid SNS topic ARN"
        )
        super().__init__(message, file, original_exception)


class SNSTestConnectionError(SNSException):
    """Exception raised when testing the SNS connection fails."""

    def __init__(self, file=None, original_exception=None):
        message = "Failed to test SNS connection"
        super().__init__(message, file, original_exception)


class SNSClientError(SNSException):
    """Exception raised for generic SNS client errors."""

    def __init__(self, file=None, original_exception=None):
        message = "SNS client error occurred"
        super().__init__(message, file, original_exception)
