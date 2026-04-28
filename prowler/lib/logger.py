import contextvars
import logging
from os import environ

# Core context — set by provider service base classes (Layer 1)
prowler_provider_var: contextvars.ContextVar[str] = contextvars.ContextVar(
    "prowler_provider", default=""
)
prowler_region_var: contextvars.ContextVar[str] = contextvars.ContextVar(
    "prowler_region", default=""
)
prowler_service_var: contextvars.ContextVar[str] = contextvars.ContextVar(
    "prowler_service", default=""
)

# App context — set by API layer only (Layer 2)
prowler_tenant_id_var: contextvars.ContextVar[str] = contextvars.ContextVar(
    "prowler_tenant_id", default=""
)
prowler_scan_id_var: contextvars.ContextVar[str] = contextvars.ContextVar(
    "prowler_scan_id", default=""
)
prowler_provider_uid_var: contextvars.ContextVar[str] = contextvars.ContextVar(
    "prowler_provider_uid", default=""
)

_PROWLER_CONTEXT_VARS = {
    "prowler_provider": prowler_provider_var,
    "prowler_region": prowler_region_var,
    "prowler_service": prowler_service_var,
    "prowler_tenant_id": prowler_tenant_id_var,
    "prowler_scan_id": prowler_scan_id_var,
    "prowler_provider_uid": prowler_provider_uid_var,
}


class ProwlerContextFilter(logging.Filter):
    """Injects prowler context from contextvars into every LogRecord."""

    def filter(self, record: logging.LogRecord) -> bool:
        for attr, var in _PROWLER_CONTEXT_VARS.items():
            if not hasattr(record, attr):
                value = var.get()
                if value:
                    setattr(record, attr, value)
        return True


# Logging levels
logging_levels = {
    "CRITICAL": logging.CRITICAL,
    "ERROR": logging.ERROR,
    "WARNING": logging.WARNING,
    "INFO": logging.INFO,
    "DEBUG": logging.DEBUG,
}


def set_logging_config(log_level: str, log_file: str = None, only_logs: bool = False):
    # Logs formatter
    stream_formatter = logging.Formatter(
        "\n%(asctime)s [File: %(filename)s:%(lineno)d] \t[Module: %(module)s]\t %(levelname)s: %(message)s"
    )
    log_file_formatter = logging.Formatter(
        '{"timestamp": "%(asctime)s", "filename": "%(filename)s:%(lineno)d", "level": "%(levelname)s", "module": "%(module)s", "message": "%(message)s"}'
    )

    # Where to put logs
    logging_handlers = []

    # Include stdout by default, if only_logs is set the log format is JSON
    stream_handler = logging.StreamHandler()
    if only_logs:
        stream_handler.setFormatter(log_file_formatter)
    else:
        stream_handler.setFormatter(stream_formatter)
    logging_handlers.append(stream_handler)

    # Log to file configuration
    if log_file:
        # Set log to file handler
        log_file_handler = logging.FileHandler(log_file)
        log_file_handler.setFormatter(log_file_formatter)
        # Append the log formatter
        logging_handlers.append(log_file_handler)

    # Set Log Level, environment takes precedence over the --log-level argument
    try:
        log_level = environ["LOG_LEVEL"]
    except KeyError:
        log_level = log_level

    # Configure Logger
    # Initialize you log configuration using the base class
    # https://docs.python.org/3/library/logging.html#logrecord-attributes
    logging.basicConfig(
        level=logging_levels.get(log_level),
        handlers=logging_handlers,
        datefmt="%m/%d/%Y %I:%M:%S %p",
    )

    logging.getLogger().addFilter(ProwlerContextFilter())


# Retrieve the logger instance
logger = logging.getLogger()
