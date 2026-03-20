from prowler.exceptions.exceptions import ProwlerException


class ElasticsearchBaseException(ProwlerException):
    """Base exception for Elasticsearch integration."""

    def __init__(self, code: int, message: str, original_exception: Exception = None):
        error_info = {
            "message": message,
            "remediation": "Please check your Elasticsearch configuration and try again.",
        }
        super().__init__(
            code=code,
            source="Elasticsearch",
            original_exception=original_exception,
            error_info=error_info,
        )


class ElasticsearchConnectionError(ElasticsearchBaseException):
    """Connection to Elasticsearch failed."""

    def __init__(self, url: str, message: str, original_exception: Exception = None):
        super().__init__(
            code=8000,
            message=f"Failed to connect to Elasticsearch at {url}: {message}",
            original_exception=original_exception,
        )


class ElasticsearchAuthenticationError(ElasticsearchBaseException):
    """Authentication to Elasticsearch failed."""

    def __init__(self, message: str, original_exception: Exception = None):
        super().__init__(
            code=8001,
            message=f"Elasticsearch authentication failed: {message}",
            original_exception=original_exception,
        )


class ElasticsearchIndexError(ElasticsearchBaseException):
    """Index operation failed."""

    def __init__(self, index: str, message: str, original_exception: Exception = None):
        super().__init__(
            code=8002,
            message=f"Elasticsearch index '{index}' error: {message}",
            original_exception=original_exception,
        )
