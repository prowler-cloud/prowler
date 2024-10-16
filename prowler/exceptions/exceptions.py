class ProwlerException(Exception):
    """Base exception for all Prowler SDK errors."""

    ERROR_CODES = {
        (1901, "UnexpectedError"): {
            "message": "Unexpected error occurred.",
            "remediation": "Please review the error message and try again.",
        }
    }

    def __init__(
        self, code, source=None, file=None, original_exception=None, error_info=None
    ):
        """
        Initialize the ProwlerException class.

        Args:
            code (int): The error code.
            source (str): The source name. This can be the provider name, module name, service name, etc.
            file (str): The file name.
            original_exception (Exception): The original exception.
            error_info (dict): The error information.

        Example:
            A ProwlerException is raised with the following parameters and format:
            >>> original_exception = Exception("Error occurred.")
            ProwlerException(1901, "AWS", "file.txt", original_exception)
            >>> [1901] Unexpected error occurred. - Exception: Error occurred.
        """
        self.code = code
        self.source = source
        self.file = file
        if error_info is None:
            error_info = self.ERROR_CODES.get((code, self.__class__.__name__))
        self.message = error_info.get("message")
        self.remediation = error_info.get("remediation")
        self.original_exception = original_exception
        # Format -> [code] message - original_exception
        if original_exception is None:
            super().__init__(f"[{self.code}] {self.message}")
        else:
            super().__init__(
                f"[{self.code}] {self.message} - {self.original_exception}"
            )

    def __str__(self):
        """Overriding the __str__ method"""
        default_str = f"{self.__class__.__name__}[{self.code}]: {self.message}"
        if self.original_exception:
            default_str += f" - {self.original_exception}"
        return default_str


class UnexpectedError(ProwlerException):
    def __init__(self, source, file, original_exception=None):
        super().__init__(1901, source, file, original_exception)
