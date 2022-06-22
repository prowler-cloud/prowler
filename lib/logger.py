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
    # Where to put logs
    logging_handlers = []
    # Include stdout by default
    logging_handlers.append(logging.StreamHandler())

    # When logging to file the log level is DEBUG to store every log
    if log_file:
        # Set log to file handler
        logging_handlers.append(logging.FileHandler(log_file))

    # Configure Logger
    # Initialize you log configuration using the base class
    # https://docs.python.org/3/library/logging.html#logrecord-attributes
    logging.basicConfig(
        level=logging_levels.get(log_level),
        handlers=logging_handlers,
        format="%(asctime)s [File: %(filename)s:%(lineno)d] \t[Module: %(module)s]\t %(levelname)s: %(message)s",
        datefmt="%m/%d/%Y %I:%M:%S %p",
    )


# Retrieve the logger instance
logger = logging.getLogger()
