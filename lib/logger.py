import logging
import sys

# Logging levels
logging_levels = {
    "CRITICAL": logging.CRITICAL,
    "ERROR": logging.ERROR,
    "WARNING": logging.WARNING,
    "INFO": logging.INFO,
    "DEBUG": logging.DEBUG,
}

# Initialize you log configuration using the base class
# https://docs.python.org/3/library/logging.html#logrecord-attributes
logging.basicConfig(
    stream=sys.stdout,
    format=f"%(asctime)s [File: %(filename)s:%(lineno)d] \t[Module: %(module)s]\t %(levelname)s: %(message)s",
    datefmt="%m/%d/%Y %I:%M:%S %p",
)

# Retrieve the logger instance
logger = logging.getLogger()
logger.setLevel(logging.ERROR)
