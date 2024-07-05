import json
import logging
from enum import StrEnum

from django_guid.log_filters import CorrelationId


class BackendLogger(StrEnum):
    DJANGO = "django"
    SECURITY = "django.security"
    DB = "django.db"
    API = "api"
    TASKS = "tasks"


# Formatters


class NDJSONFormatter(logging.Formatter):
    """NDJSON custom formatter for logging messages.

    If available, it will include all kind of API request metadata.
    """

    def format(self, record):
        log_record = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "message": record.getMessage(),
            "logger": record.name,
            "module": record.module,
            "pathname": record.pathname,
            "lineno": record.lineno,
            "funcName": record.funcName,
            "process": record.process,
            "thread": record.thread,
            "transaction_id": record.transaction_id
            if hasattr(record, "transaction_id")
            else "N/A",
        }

        # Add REST API extra fields
        if hasattr(record, "method"):
            log_record["method"] = record.method
        if hasattr(record, "path"):
            log_record["path"] = record.path
        if hasattr(record, "query_params"):
            log_record["query_params"] = record.query_params
        if hasattr(record, "duration"):
            log_record["duration"] = record.duration
        if hasattr(record, "status_code"):
            log_record["status_code"] = record.status_code

        if record.exc_info:
            log_record["exc_info"] = self.formatException(record.exc_info)

        return json.dumps(log_record)


# Filters


class TransactionIdFilter(CorrelationId):
    """Logging filter class.

    Used to override the `correlation_id_field` parameter in the parent class to use a different name.
    """

    CORRELATION_ID_FIELD = "transaction_id"

    def __init__(self):
        super().__init__(correlation_id_field=self.CORRELATION_ID_FIELD)


# Logging settings

LOGGING = {
    "version": 1,
    "disable_existing_loggers": True,
    "filters": {"transaction_id": {"()": TransactionIdFilter}},
    "formatters": {
        "ndjson": {
            "()": NDJSONFormatter,
            "datefmt": "%Y-%m-%d %H:%M:%S",
        },
        "django": {
            "format": "{asctime} [{name}] {levelname}: ({module}) {message}",
            "style": "{",
        },
        "api": {
            "format": '{asctime} [{name}] {levelname}: "{method} {path}" with parameters {query_params} done in '
            "{duration}s: {status_code}",
            "style": "{",
        },
        "db": {
            "format": "{asctime} [{name}] {levelname}: {message}",
            "style": "{",
        },
        "security": {
            "format": "{asctime} [{name}] {levelname}: {message}",
            "style": "{",
        },
        "tasks": {
            "format": "{asctime} [{name}] {levelname}: {message}",
            "style": "{",
        },
    },
    "handlers": {
        "django_console": {
            "level": "INFO",
            "class": "logging.StreamHandler",
            "formatter": "ndjson",
            "filters": ["transaction_id"],
        },
        "api_console": {
            "level": "INFO",
            "class": "logging.StreamHandler",
            "formatter": "ndjson",
            "filters": ["transaction_id"],
        },
        "db_console": {
            "level": "DEBUG",
            "class": "logging.StreamHandler",
            "formatter": "ndjson",
            "filters": ["transaction_id"],
        },
        "security_console": {
            "level": "INFO",
            "class": "logging.StreamHandler",
            "formatter": "ndjson",
            "filters": ["transaction_id"],
        },
        "tasks_console": {
            "level": "INFO",
            "class": "logging.StreamHandler",
            "formatter": "ndjson",
            "filters": ["transaction_id"],
        },
    },
    "loggers": {
        BackendLogger.DJANGO: {
            "handlers": ["django_console"],
            "level": "INFO",
            "propagate": True,
        },
        BackendLogger.DB: {
            "handlers": ["db_console"],
            "level": "DEBUG",
            "propagate": False,
        },
        BackendLogger.SECURITY: {
            "handlers": ["security_console"],
            "level": "INFO",
            "propagate": False,
        },
        BackendLogger.API: {
            "handlers": ["api_console"],
            "level": "INFO",
            "propagate": False,
        },
        BackendLogger.TASKS: {
            "handlers": ["tasks_console"],
            "level": "INFO",
            "propagate": False,
        },
    },
}
