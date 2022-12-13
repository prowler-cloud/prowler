import json
import sys
from hashlib import sha512
from io import TextIOWrapper
from os.path import exists
from typing import Any

from prowler.lib.logger import logger


def open_file(input_file: str, mode: str = "r") -> TextIOWrapper:
    try:
        f = open(input_file, mode)
    except Exception as e:
        logger.critical(
            f"{input_file}: {e.__class__.__name__}[{e.__traceback__.tb_lineno}]"
        )
        sys.exit()
    else:
        return f


# Parse checks from file
def parse_json_file(input_file: TextIOWrapper) -> Any:
    try:
        json_file = json.load(input_file)
    except Exception as e:
        logger.critical(
            f"{input_file.name}: {e.__class__.__name__}[{e.__traceback__.tb_lineno}]"
        )
        sys.exit()
    else:
        return json_file


# check if file exists
def file_exists(filename: str):
    try:
        exists_filename = exists(filename)
    except Exception as e:
        logger.critical(
            f"{exists_filename.name}: {e.__class__.__name__}[{e.__traceback__.tb_lineno}]"
        )
        sys.exit()
    else:
        return exists_filename


# create sha512 hash for string
def hash_sha512(string: str) -> str:
    return sha512(string.encode("utf-8")).hexdigest()[0:9]
