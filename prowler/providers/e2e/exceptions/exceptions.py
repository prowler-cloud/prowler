class E2eCredentialsError(Exception):
    """Raised when E2E Cloud credentials are missing or invalid."""

    def __init__(self, message: str):
        self.message = message
        super().__init__(message)


class E2eSessionError(Exception):
    """Raised when the E2E Cloud session cannot be initialized."""

    def __init__(self, message: str, original_exception: Exception | None = None):
        self.message = message
        self.original_exception = original_exception
        super().__init__(message)


class E2eAPIError(Exception):
    """Raised when an E2E Cloud API request fails."""

    def __init__(self, message: str, original_exception: Exception | None = None):
        self.message = message
        self.original_exception = original_exception
        super().__init__(message)
