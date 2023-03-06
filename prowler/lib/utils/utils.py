import json
import os
import sys
import tempfile
from hashlib import sha512
from io import TextIOWrapper
from os.path import exists
from typing import Any

from detect_secrets import SecretsCollection
from detect_secrets.settings import default_settings

from prowler.lib.logger import logger


def open_file(input_file: str, mode: str = "r") -> TextIOWrapper:
    try:
        f = open(input_file, mode)
    except Exception as e:
        if e.__class__.__name__ == "OSError":
            logger.critical(
                "Ooops! You reached your user session maximum open files. To solve this issue, increase the shell session limit by running this command `ulimit -n 4096`. More info in https://docs.prowler.cloud/en/latest/troubleshooting/"
            )
        else:
            logger.critical(
                f"{input_file}: {e.__class__.__name__}[{e.__traceback__.tb_lineno}]"
            )
        sys.exit(1)
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
        sys.exit(1)
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
        sys.exit(1)
    else:
        return exists_filename


# create sha512 hash for string
def hash_sha512(string: str) -> str:
    return sha512(string.encode("utf-8")).hexdigest()[0:9]


def detect_secrets_scan(data):
    temp_data_file = tempfile.NamedTemporaryFile(delete=False)
    temp_data_file.write(bytes(data, encoding="raw_unicode_escape"))
    temp_data_file.close()

    secrets = SecretsCollection()
    with default_settings():
        secrets.scan_file(temp_data_file.name)
    os.remove(temp_data_file.name)

    detect_secrets_output = secrets.json()
    if detect_secrets_output:
        return detect_secrets_output[temp_data_file.name]
    else:
        return None
