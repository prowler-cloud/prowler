import logging

# Logging levels
logging_levels = {
    "CRITICAL": logging.CRITICAL,
    "ERROR": logging.ERROR,
    "WARNING": logging.WARNING,
    "INFO": logging.INFO,
    "DEBUG": logging.DEBUG,
}


def set_logging_config(log_file: str = None, log_level: str = "ERROR"):
    # Logs formatter
    stream_formatter = logging.Formatter(
        "%(asctime)s [File: %(filename)s:%(lineno)d] \t[Module: %(module)s]\t %(levelname)s: %(message)s"
    )
    log_file_formatter = logging.Formatter(
        '{"timestamp": "%(asctime)s", "filename": "%(filename)s:%(lineno)d", "level": "%(levelname)s", "module": "%(module)s", "message": "%(message)s"}'
    )

    # Where to put logs
    logging_handlers = []

    # Include stdout by default
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(stream_formatter)
    logging_handlers.append(stream_handler)

    # Log to file configuration
    if log_file:
        # Set log to file handler
        log_file_handler = logging.FileHandler(log_file)
        log_file_handler.setFormatter(log_file_formatter)
        # Append the log formatter
        logging_handlers.append(log_file_handler)

    # Configure Logger
    # Initialize you log configuration using the base class
    # https://docs.python.org/3/library/logging.html#logrecord-attributes
    logging.basicConfig(
        level=logging_levels.get(log_level),
        handlers=logging_handlers,
        datefmt="%m/%d/%Y %I:%M:%S %p",
    )


# Retrieve the logger instance
logger = logging.getLogger()
