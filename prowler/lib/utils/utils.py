import json
import os
from operator import attrgetter

try:
    import grp
    import pwd
except ImportError:
    pass

import re
import subprocess
import sys
import tempfile
from datetime import datetime
from functools import lru_cache
from hashlib import sha1, sha512
from io import TextIOWrapper
from ipaddress import ip_address
from os.path import exists
from time import mktime
from typing import Any, Optional

from colorama import Style

from prowler.config.config import encoding_format_utf_8
from prowler.lib.logger import logger

# Default minimum confidence level for reporting findings. "low" is required to
# enable Kingfisher's built-in generic rules (Generic Password / Secret / API
# Key), which preserve the keyword-based coverage Prowler had with
# detect-secrets' KeywordDetector; at "medium" those generic rules do not fire.
# Possible values: "low", "medium", "high".
default_secrets_confidence = "low"

# Kingfisher exit codes considered successful: 0 (no findings), 200 (findings),
# 205 (validated findings).
_kingfisher_success_exit_codes = (0, 200, 205)


@lru_cache(maxsize=1)
def get_kingfisher_binary() -> str:
    """Return the path to the bundled Kingfisher binary (cached)."""
    from kingfisher import get_binary_path

    return get_binary_path()


def open_file(input_file: str, mode: str = "r") -> TextIOWrapper:
    """open_file returns a handler to the file using the specified mode."""
    try:
        f = open(input_file, mode, encoding=encoding_format_utf_8)
    except OSError as os_error:
        if os_error.strerror == "Too many open files":
            logger.critical(
                "Ooops! You reached your user session maximum open files. To solve this issue, increase the shell session limit by running this command `ulimit -n 4096`. For more info visit https://docs.prowler.com/troubleshooting/"
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
    data: str = None,
    file=None,
    excluded_secrets: list[str] = None,
    detect_secrets_plugins: dict = None,
    confidence: str = default_secrets_confidence,
    validate: bool = False,
) -> list[dict[str, str]]:
    """detect_secrets_scan scans the data or file for secrets using Kingfisher.

    By default the scan runs fully offline (`--no-validate`, `--no-update-check`):
    no network calls are made, so the scanned data is never sent anywhere.
    Kingfisher's built-in ruleset is used at "low" confidence so its generic
    keyword rules fire (see ``default_secrets_confidence``).

    When ``validate`` is True, Kingfisher additionally checks whether each
    discovered secret is live by authenticating with it against the provider's
    API (the secret itself is used as the credential; no extra permissions are
    required). This makes outbound network calls and the discovered credential
    is exercised against the provider, so it must be explicitly opted in.

    Args:
        data (str): The data to scan for secrets.
        file (str): The file to scan for secrets.
        excluded_secrets (list): A list of regex patterns; any finding whose
            source line matches one of them is excluded from the results.
        detect_secrets_plugins (dict): Deprecated. Kept for backwards
            compatibility with existing call sites; ignored by Kingfisher.
        confidence (str): Minimum Kingfisher confidence to report ("low",
            "medium" or "high"). Defaults to ``default_secrets_confidence``.
        validate (bool): When True, validate discovered secrets against the
            provider APIs (live check). Makes outbound network calls. Defaults
            to False (fully offline).
    Returns:
        list[dict] | None: A list of findings, each with ``filename``,
            ``line_number``, ``type``, ``hashed_secret`` and ``is_verified``
            keys, or ``None`` when no secrets are found or an error occurs.
            ``is_verified`` is True only when ``validate`` is True and the
            secret was confirmed live.
    Examples:
        >>> detect_secrets_scan(data='password = "Tr0ub4dor&3xKq9vLmZ"')
        [{'filename': '/tmp/...', 'line_number': 1, 'type': 'Generic Password', 'hashed_secret': '...', 'is_verified': False}]
    """
    if detect_secrets_plugins is not None:
        logger.debug(
            "detect_secrets_plugins is deprecated and ignored when scanning with Kingfisher."
        )

    temp_data_file = None
    temp_output_file = None
    try:
        if file:
            scan_path = file
        else:
            # Ensure a trailing newline: Kingfisher does not scan the final line
            # of a file when it is not newline-terminated, and serialized payloads
            # (JSON dumps, joined log events, state-machine definitions) often are
            # not. Appending "\n" does not change line numbers or secret content.
            content = data if data.endswith("\n") else data + "\n"
            temp_data_file = tempfile.NamedTemporaryFile(delete=False, suffix=".txt")
            temp_data_file.write(bytes(content, encoding="raw_unicode_escape"))
            temp_data_file.close()
            scan_path = temp_data_file.name

        temp_output_file = tempfile.NamedTemporaryFile(delete=False, suffix=".json")
        temp_output_file.close()

        command = [
            get_kingfisher_binary(),
            "scan",
            scan_path,
            "--format",
            "json",
            "--output",
            temp_output_file.name,
            "--no-update-check",
            "--confidence",
            confidence,
        ]
        if validate:
            # Live-validate discovered secrets against provider APIs. Use
            # conservative defaults (short timeout, no retries) to limit the
            # blast radius of the outbound calls.
            command += [
                "--validation-timeout",
                "5",
                "--validation-retries",
                "0",
            ]
        else:
            command.append("--no-validate")
        process = subprocess.run(command, capture_output=True, text=True)
        if process.returncode not in _kingfisher_success_exit_codes:
            logger.error(
                f"Error scanning for secrets: Kingfisher exited with code "
                f"{process.returncode}: {process.stderr.strip()[:500]}"
            )
            return None

        with open(temp_output_file.name, encoding=encoding_format_utf_8) as f:
            output = f.read()
        kingfisher_output = json.loads(output) if output.strip() else {}

        # Read source lines once to apply excluded_secrets against the full line
        # (preserving detect-secrets' should_exclude_line semantics).
        source_lines = []
        if excluded_secrets:
            with open(scan_path, encoding=encoding_format_utf_8, errors="replace") as f:
                source_lines = f.read().splitlines()

        findings = []
        for entry in kingfisher_output.get("findings", []):
            rule = entry.get("rule", {})
            finding = entry.get("finding", {})
            line_number = finding.get("line")

            if excluded_secrets and line_number and line_number <= len(source_lines):
                line_text = source_lines[line_number - 1]
                if any(re.search(pattern, line_text) for pattern in excluded_secrets):
                    continue

            snippet = finding.get("snippet", "") or ""
            findings.append(
                {
                    "filename": finding.get("path", scan_path),
                    "line_number": line_number,
                    "type": rule.get("name"),
                    # Non-security identifier for the matched secret (matches
                    # the detect-secrets output shape); not used for security.
                    "hashed_secret": (
                        sha1(snippet.encode(), usedforsecurity=False).hexdigest()
                        if snippet
                        else None
                    ),
                    "is_verified": finding.get("validation", {}).get("status")
                    == "Active",
                }
            )

        return findings or None
    except Exception as e:
        logger.error(f"Error scanning for secrets: {e}")
        return None
    finally:
        for temp_file in (temp_data_file, temp_output_file):
            if temp_file and os.path.exists(temp_file.name):
                os.remove(temp_file.name)


def annotate_verified_secrets(report, secrets: list) -> None:
    """Escalate and annotate a finding when any of its secrets is confirmed live.

    When secret validation (``--scan-secrets-validate`` / ``secrets_validate``)
    confirms that a discovered secret is live, the finding is more severe than a
    potential secret: its severity is raised to critical and a note is appended
    to ``status_extended``. No-op when no secret was validated as live, so the
    default offline behavior (and existing finding messages) is unchanged.
    """
    if secrets and any(secret.get("is_verified") for secret in secrets):
        from prowler.lib.check.models import Severity

        report.check_metadata.Severity = Severity.critical
        report.status_extended += (
            " One or more of these secrets were confirmed to be live."
        )


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
