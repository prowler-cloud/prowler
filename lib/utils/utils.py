import json
from io import TextIOWrapper
from os.path import exists
from typing import Any

from lib.logger import logger


def open_file(input_file: str, mode: str = "r") -> TextIOWrapper:
    try:
        f = open(input_file, mode)
    except Exception as e:
        logger.critical(f"{input_file}: {e.__class__.__name__}")
        quit()
    else:
        return f


# Parse checks from file
def parse_json_file(input_file: TextIOWrapper) -> Any:
    # First recover the available groups in groups.json
    try:
        json_file = json.load(input_file)
    except Exception as e:
        logger.critical(f"{input_file.name}: {e.__class__.__name__}")
        quit()
    else:
        return json_file


# check if file exists
def file_exists(filename: str):
    try:
        exists_filename = exists(filename)
    except Exception as e:
        logger.critical(f"{exists_filename.name}: {e.__class__.__name__}")
        quit()
    else:
        return exists_filename
