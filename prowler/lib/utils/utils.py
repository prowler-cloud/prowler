import json
import os
from operator import attrgetter

try:
    import grp
    import pwd
except ImportError:
    pass

import re
import sys
import tempfile
from datetime import datetime
from hashlib import sha512
from io import TextIOWrapper
from ipaddress import ip_address
from os.path import exists
from time import mktime
from typing import Any, Optional

from colorama import Style
from detect_secrets import SecretsCollection
from detect_secrets.settings import transient_settings

from prowler.config.config import encoding_format_utf_8
from prowler.lib.logger import logger


def open_file(input_file: str, mode: str = "r") -> TextIOWrapper:
    """open_file returns a handler to the file using the specified mode."""
    try:
        f = open(input_file, mode, encoding=encoding_format_utf_8)
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
    return sha512(string.encode(encoding_format_utf_8)).hexdigest()[0:9]


def detect_secrets_scan(
    data: str = None, file=None, excluded_secrets: list[str] = None
) -> list[dict[str, str]]:
    """detect_secrets_scan scans the data or file for secrets using the detect-secrets library.
    Args:
        data (str): The data to scan for secrets.
        file (str): The file to scan for secrets.
        excluded_secrets (list): A list of regex patterns to exclude from the scan.
    Returns:
        dict: The secrets found in the
    Raises:
        Exception: If an error occurs during the scan.
    Examples:
        >>> detect_secrets_scan(data="password=password")
        [{'filename': 'data', 'hashed_secret': 'f7c3bc1d808e04732adf679965ccc34ca7ae3441', 'is_verified': False, 'line_number': 1, 'type': 'Secret Keyword'}]
        >>> detect_secrets_scan(file="file.txt")
        {'file.txt': [{'filename': 'file.txt', 'hashed_secret': 'f7c3bc1d808e04732adf679965ccc34ca7ae3441', 'is_verified': False, 'line_number': 1, 'type': 'Secret Keyword'}]}
    """
    try:
        if not file:
            temp_data_file = tempfile.NamedTemporaryFile(delete=False)
            temp_data_file.write(bytes(data, encoding="raw_unicode_escape"))
            temp_data_file.close()

        secrets = SecretsCollection()

        settings = {
            "plugins_used": [
                {"name": "ArtifactoryDetector"},
                {"name": "AWSKeyDetector"},
                {"name": "AzureStorageKeyDetector"},
                {"name": "BasicAuthDetector"},
                {"name": "CloudantDetector"},
                {"name": "DiscordBotTokenDetector"},
                {"name": "GitHubTokenDetector"},
                {"name": "GitLabTokenDetector"},
                {"name": "Base64HighEntropyString", "limit": 6.0},
                {"name": "HexHighEntropyString", "limit": 3.0},
                {"name": "IbmCloudIamDetector"},
                {"name": "IbmCosHmacDetector"},
                # {"name": "IPPublicDetector"}, https://github.com/Yelp/detect-secrets/pull/885
                {"name": "JwtTokenDetector"},
                {"name": "KeywordDetector"},
                {"name": "MailchimpDetector"},
                {"name": "NpmDetector"},
                {"name": "OpenAIDetector"},
                {"name": "PrivateKeyDetector"},
                {"name": "PypiTokenDetector"},
                {"name": "SendGridDetector"},
                {"name": "SlackDetector"},
                {"name": "SoftlayerDetector"},
                {"name": "SquareOAuthDetector"},
                {"name": "StripeDetector"},
                # {"name": "TelegramBotTokenDetector"}, https://github.com/Yelp/detect-secrets/pull/878
                {"name": "TwilioKeyDetector"},
            ],
            "filters_used": [
                {"path": "detect_secrets.filters.common.is_invalid_file"},
                {"path": "detect_secrets.filters.common.is_known_false_positive"},
                {"path": "detect_secrets.filters.heuristic.is_likely_id_string"},
                {"path": "detect_secrets.filters.heuristic.is_potential_secret"},
            ],
        }
        if excluded_secrets and len(excluded_secrets) > 0:
            settings["filters_used"].append(
                {
                    "path": "detect_secrets.filters.regex.should_exclude_line",
                    "pattern": excluded_secrets,
                }
            )
        with transient_settings(settings):
            if file:
                secrets.scan_file(file)
            else:
                secrets.scan_file(temp_data_file.name)

        if not file:
            os.remove(temp_data_file.name)

        detect_secrets_output = secrets.json()

        if detect_secrets_output:
            if file:
                return detect_secrets_output[file]
            else:
                return detect_secrets_output[temp_data_file.name]
        else:
            return None
    except Exception as e:
        logger.error(f"Error scanning for secrets: {e}")
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


def strip_ansi_codes(s: str):
    """
    Strips ANSI escape codes from a string.
    Args:
        s (str): The string to strip.
    Returns:
        str: The string without ANSI escape codes.
    """
    ansi_escape = re.compile(r"(?:\x1B[@-_][0-?]*[ -/]*[@-~])")
    return ansi_escape.sub("", s)


def print_boxes(messages: list, report_title: str):
    """
    Prints a series of messages in a box format.
    Args:
        messages (list): A list of messages to print.
    """
    print(f"{Style.BRIGHT}-> {report_title}{Style.RESET_ALL}")
    for message in messages:
        print(
            f"{Style.BRIGHT}{Style.RESET_ALL}  · {message}{Style.BRIGHT}{Style.RESET_ALL}"
        )
    print()


def dict_to_lowercase(d):
    """
    Convert all keys in a dictionary to lowercase.
    This function takes a dictionary and returns a new dictionary
    with all the keys converted to lowercase. If a value in the
    dictionary is another dictionary, the function will recursively
    convert the keys of that dictionary to lowercase as well.
    Args:
        d (dict): The dictionary to convert.
    Returns:
        dict: A new dictionary with all keys in lowercase.
    """

    new_dict = {}
    for k, v in d.items():
        if isinstance(v, dict):
            v = dict_to_lowercase(v)
        new_dict[k.lower()] = v
    return new_dict


def get_nested_attribute(obj: Any, attr: str) -> Any:
    """
    Get a nested attribute from an object.
    Args:
        obj (Any): The object to get the attribute from.
        attr (str): The attribute to get.
    Returns:
        Any: The attribute value if present, otherwise "".
    """
    try:
        return attrgetter(attr)(obj)
    except AttributeError:
        return ""
    except Exception as error:
        logger.error(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )
        return ""
