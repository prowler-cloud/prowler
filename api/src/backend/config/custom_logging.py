import json
import logging
from enum import StrEnum

from django_guid.log_filters import CorrelationId

from config.env import env


class BackendLogger(StrEnum):
    GUNICORN = "gunicorn"
    GUNICORN_ACCESS = "gunicorn.access"
    GUNICORN_ERROR = "gunicorn.error"
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
            else None,
        }

        # Add REST API extra fields
        if hasattr(record, "user_id"):
            log_record["user_id"] = record.user_id
        if hasattr(record, "tenant_id"):
            log_record["tenant_id"] = record.tenant_id
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


class HumanReadableFormatter(logging.Formatter):
    """Human-readable custom formatter for logging messages.

    If available, it will include all kinds of API request metadata.
    """

    def format(self, record):
        log_components = [
            f"{self.formatTime(record, self.datefmt)}",
            f"[{record.name}]",
            f"{record.levelname}:",
            f"({record.module})",
            f"[module={record.module}",
            f"path={record.pathname}",
            f"line={record.lineno}",
            f"function={record.funcName}",
            f"process={record.process}",
            f"thread={record.thread}",
            f"transaction-id={record.transaction_id if hasattr(record, 'transaction_id') else None}]",
            f"{record.getMessage()}",
        ]

        # Add REST API extra fields
        if hasattr(record, "user_id"):
            log_components.append(f"({record.user_id})")
        if hasattr(record, "tenant_id"):
            log_components.append(f"[{record.tenant_id}]")
        if hasattr(record, "method"):
            log_components.append(f'"{record.method} {record.path}"')
        if hasattr(record, "query_params"):
            log_components.append(f"with parameters {record.query_params}")
        if hasattr(record, "duration"):
            log_components.append(f"done in {record.duration}s:")
        if hasattr(record, "status_code"):
            log_components.append(f"{record.status_code}")

        if record.exc_info:
            log_components.append(self.formatException(record.exc_info))

        return " ".join(log_components)


# Filters


class TransactionIdFilter(CorrelationId):
    """Logging filter class.

    Used to override the `correlation_id_field` parameter in the parent class to use a different name.
    """

    CORRELATION_ID_FIELD = "transaction_id"

    def __init__(self):
        super().__init__(correlation_id_field=self.CORRELATION_ID_FIELD)


# Logging settings

LEVEL = env("DJANGO_LOGGING_LEVEL", default="INFO")
FORMATTER = env("DJANGO_LOGGING_FORMATTER", default="ndjson")

LOGGING = {
    "version": 1,
    "disable_existing_loggers": True,
    "filters": {"transaction_id": {"()": TransactionIdFilter}},
    "formatters": {
        "ndjson": {
            "()": NDJSONFormatter,
            "datefmt": "%Y-%m-%d %H:%M:%S",
        },
        "human_readable": {
            "()": HumanReadableFormatter,
            "datefmt": "%Y-%m-%d %H:%M:%S",
        },
    },
    "handlers": {
        "gunicorn_console": {
            "level": LEVEL,
            "class": "logging.StreamHandler",
            "formatter": FORMATTER,
            "filters": ["transaction_id"],
        },
        "django_console": {
            "level": LEVEL,
            "class": "logging.StreamHandler",
            "formatter": FORMATTER,
            "filters": ["transaction_id"],
        },
        "api_console": {
            "level": LEVEL,
            "class": "logging.StreamHandler",
            "formatter": FORMATTER,
            "filters": ["transaction_id"],
        },
        "db_console": {
            "level": f"{'DEBUG' if LEVEL == 'DEBUG' else 'INFO'}",
            "class": "logging.StreamHandler",
            "formatter": FORMATTER,
            "filters": ["transaction_id"],
        },
        "security_console": {
            "level": LEVEL,
            "class": "logging.StreamHandler",
            "formatter": FORMATTER,
            "filters": ["transaction_id"],
        },
        "tasks_console": {
            "level": LEVEL,
            "class": "logging.StreamHandler",
            "formatter": FORMATTER,
            "filters": ["transaction_id"],
        },
    },
    "loggers": {
        BackendLogger.GUNICORN: {
            "handlers": ["gunicorn_console"],
            "level": LEVEL,
            "propagate": False,
        },
        BackendLogger.GUNICORN_ACCESS: {
            "handlers": ["gunicorn_console"],
            "level": "CRITICAL",
            "propagate": False,
        },
        BackendLogger.GUNICORN_ERROR: {
            "handlers": ["gunicorn_console"],
            "level": LEVEL,
            "propagate": False,
        },
        BackendLogger.DJANGO: {
            "handlers": ["django_console"],
            "level": "WARNING",
            "propagate": True,
        },
        BackendLogger.DB: {
            "handlers": ["db_console"],
            "level": LEVEL,
            "propagate": False,
        },
        BackendLogger.SECURITY: {
            "handlers": ["security_console"],
            "level": LEVEL,
            "propagate": False,
        },
        BackendLogger.API: {
            "handlers": ["api_console"],
            "level": LEVEL,
            "propagate": False,
        },
        BackendLogger.TASKS: {
            "handlers": ["tasks_console"],
            "level": LEVEL,
            "propagate": False,
        },
    },
    # Gunicorn required configuration
    "root": {
        "level": "ERROR",
        "handlers": ["gunicorn_console"],
    },
}
