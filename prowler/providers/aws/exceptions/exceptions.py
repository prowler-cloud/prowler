from prowler.exceptions.exceptions import ProwlerException


class AWSCredentialsError(ProwlerException):
    """Base class for AWS credentials errors."""

    def __init__(self, code, provider="AWS", file=None, original_exception=None):
        super().__init__(code, provider, file, original_exception)


class AWSClientError(AWSCredentialsError):
    def __init__(self, file=None, original_exception=None):
        super().__init__(
            1906, provider="AWS", file=file, original_exception=original_exception
        )


class AWSProfileNotFoundError(AWSCredentialsError):
    def __init__(self, file=None, original_exception=None):
        super().__init__(
            1907, provider="AWS", file=file, original_exception=original_exception
        )


class AWSNoCredentialsError(AWSCredentialsError):
    def __init__(self, file=None, original_exception=None):
        super().__init__(
            1908, provider="AWS", file=file, original_exception=original_exception
        )


class AWSArgumentTypeValidationError(ProwlerException):
    def __init__(self, file=None, original_exception=None):
        super().__init__(
            1909, provider="AWS", file=file, original_exception=original_exception
        )


class AWSSetUpSessionError(ProwlerException):
    def __init__(self, file=None, original_exception=None):
        super().__init__(
            1910, provider="AWS", file=file, original_exception=original_exception
        )
