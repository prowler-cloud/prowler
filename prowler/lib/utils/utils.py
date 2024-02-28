import grp
import json
import os
import pwd
import sys
import tempfile
from datetime import datetime
from hashlib import sha512
from io import TextIOWrapper
from ipaddress import ip_address
from os.path import exists
from time import mktime
from typing import Optional

from detect_secrets import SecretsCollection
from detect_secrets.settings import default_settings

from prowler.lib.logger import logger


def open_file(input_file: str, mode: str = "r") -> TextIOWrapper:
    """open_file returns a handler to the file using the specified mode."""
    try:
        f = open(input_file, mode)
    except OSError as os_error:
        if os_error.strerror == "Too many open files":
            logger.critical(
                "Ooops! You reached your user session maximum open files. To solve this issue, increase the shell session limit by running this command `ulimit -n 4096`. For more info visit https://docs.prowler.cloud/en/latest/troubleshooting/"
            )
        else:
            logger.critical(
                f"{input_file}: OSError[{os_error.errno}] {os_error.strerror}"
            )
        sys.exit(1)
    except Exception as e:
        logger.critical(
            f"{input_file}: {e.__class__.__name__}[{e.__traceback__.tb_lineno}]"
        )
        sys.exit(1)
    else:
        return f


def parse_json_file(input_file: TextIOWrapper) -> dict:
    """parse_json_file loads a JSON file and returns a dictionary with the JSON content."""
    try:
        json_file = json.load(input_file)
    except Exception as e:
        logger.critical(
            f"{input_file.name}: {e.__class__.__name__}[{e.__traceback__.tb_lineno}]"
        )
        sys.exit(1)
    else:
        return json_file


def file_exists(filename: str):
    """file_exists returns True if the given file exists, otherwise returns False."""
    try:
        exists_filename = exists(filename)
    except Exception as e:
        logger.critical(
            f"{filename}: {e.__class__.__name__}[{e.__traceback__.tb_lineno}]"
        )
        sys.exit(1)
    else:
        return exists_filename


def hash_sha512(string: str) -> str:
    """hash_sha512 returns the first 9 bytes of the SHA512 representation for the given string."""
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


def validate_ip_address(ip_string):
    """validate_ip_address return True if the IP is valid, otherwise returns False."""
    try:
        ip_address(ip_string)
        return True
    except ValueError:
        return False


def outputs_unix_timestamp(is_unix_timestamp: bool, timestamp: datetime):
    """outputs_unix_timestamp returns the epoch representation of the timestamp if the is_unix_timestamp is True, otherwise returns the ISO representation."""
    if is_unix_timestamp:
        timestamp = int(mktime(timestamp.timetuple()))
    else:
        timestamp = timestamp.isoformat()
    return timestamp


def get_file_permissions(file_path: str) -> Optional[str]:
    """
    Retrieves the permissions of a file.

    Args:
        file_path (str): The path to the file.

    Returns:
        Optional[str]: The file permissions in octal format, or None if an error occurs.
    """
    try:
        # Get file status
        file_stat = os.stat(file_path)

        # Extract permission bits using bitwise AND and formatting as octal
        permissions = oct(file_stat.st_mode & 0o777)
        return permissions
    except Exception as e:
        logger.error(
            f"{file_path}: {e.__class__.__name__}[{e.__traceback__.tb_lineno}]: {e}"
        )
        return None


def is_owned_by_root(file_path: str) -> bool:
    """
    Checks if a file is owned by the root user and group.

    Args:
        file_path (str): The path to the file.

    Returns:
        bool: True if owned by root, False otherwise or None if file does not exist.
    """
    try:
        # Get the file's status
        file_stat = os.stat(file_path)

        # Get the user and group names from their IDs
        user_name = pwd.getpwuid(file_stat.st_uid).pw_name
        group_name = grp.getgrgid(file_stat.st_gid).gr_name

        # Check if both user and group are 'root'
        return user_name == "root" and group_name == "root"

    except FileNotFoundError as e:
        logger.error(
            f"{file_path}: {e.__class__.__name__}[{e.__traceback__.tb_lineno}]: {e}"
        )
        return None
    except Exception as e:
        logger.error(
            f"{file_path}: {e.__class__.__name__}[{e.__traceback__.tb_lineno}]: {e}"
        )
        return False
