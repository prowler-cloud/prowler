import json
from io import TextIOWrapper
from typing import Any

from lib.logger import logger


def open_file(input_file: str) -> TextIOWrapper:
    try:
        # First recover the available groups in groups.json
        f = open(input_file)
    except Exception as e:
        logger.critical(f"{input_file}: {e.__class__.__name__}")
        quit()
    else:
        return f


# Parse checks from file
def parse_json_file(input_file: TextIOWrapper) -> Any:
    try:
        json_file = json.load(input_file)
    except Exception as e:
        logger.critical(f"{input_file.name}: {e.__class__.__name__}")
        quit()
    else:
        return json_file
