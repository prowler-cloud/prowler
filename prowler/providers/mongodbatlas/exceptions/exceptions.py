from prowler.exceptions.exceptions import ProwlerException


# Exceptions codes from 8000 to 8999 are reserved for MongoDB Atlas exceptions
class MongoDBAtlasBaseException(ProwlerException):
    """Base class for MongoDB Atlas Errors."""

    MONGODBATLAS_ERROR_CODES = {
        (8000, "MongoDBAtlasCredentialsError"): {
            "message": "MongoDB Atlas credentials not found or invalid",
            "remediation": "Check the MongoDB Atlas API credentials and ensure they are properly set.",
        },
        (8001, "MongoDBAtlasAuthenticationError"): {
            "message": "MongoDB Atlas authentication failed",
            "remediation": "Check the MongoDB Atlas API credentials and ensure they are valid.",
        },
        (8002, "MongoDBAtlasSessionError"): {
            "message": "MongoDB Atlas session setup failed",
            "remediation": "Check the session setup and ensure it is properly configured.",
        },
        (8003, "MongoDBAtlasIdentityError"): {
            "message": "MongoDB Atlas identity setup failed",
            "remediation": "Check credentials and ensure they are properly set up for MongoDB Atlas.",
        },
        (8004, "MongoDBAtlasAPIError"): {
            "message": "MongoDB Atlas API call failed",
            "remediation": "Check the API request and ensure it is properly formatted.",
        },
        (8005, "MongoDBAtlasRateLimitError"): {
            "message": "MongoDB Atlas API rate limit exceeded",
            "remediation": "Reduce the number of API requests or wait before making more requests.",
        },
    }

    def __init__(self, code, file=None, original_exception=None, message=None):
        provider = "MongoDB Atlas"
        error_info = self.MONGODBATLAS_ERROR_CODES.get((code, self.__class__.__name__))
        if message:
            error_info["message"] = message
        super().__init__(
            code=code,
            source=provider,
            file=file,
            original_exception=original_exception,
            error_info=error_info,
        )


class MongoDBAtlasCredentialsError(MongoDBAtlasBaseException):
    """Exception for MongoDB Atlas credentials errors"""

    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            code=8000,
            file=file,
            original_exception=original_exception,
            message=message,
        )


class MongoDBAtlasAuthenticationError(MongoDBAtlasBaseException):
    """Exception for MongoDB Atlas authentication errors"""

    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            code=8001,
            file=file,
            original_exception=original_exception,
            message=message,
        )


class MongoDBAtlasSessionError(MongoDBAtlasBaseException):
    """Exception for MongoDB Atlas session setup errors"""

    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            code=8002,
            file=file,
            original_exception=original_exception,
            message=message,
        )


class MongoDBAtlasIdentityError(MongoDBAtlasBaseException):
    """Exception for MongoDB Atlas identity setup errors"""

    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            code=8003,
            file=file,
            original_exception=original_exception,
            message=message,
        )


class MongoDBAtlasAPIError(MongoDBAtlasBaseException):
    """Exception for MongoDB Atlas API errors"""

    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            code=8004,
            file=file,
            original_exception=original_exception,
            message=message,
        )


class MongoDBAtlasRateLimitError(MongoDBAtlasBaseException):
    """Exception for MongoDB Atlas rate limit errors"""

    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            code=8005,
            file=file,
            original_exception=original_exception,
            message=message,
        )
