import json
import os
from operator import attrgetter

try:
    import grp
    import pwd
except ImportError:
    pass

import re
import shutil
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
from typing import Any, Iterable, Mapping, Optional, Union

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

# Number of payloads scanned per Kingfisher invocation in batch mode. Bounds
# peak temp-disk and memory while still amortizing the per-process spawn cost
# across many fragments (see detect_secrets_scan_batch).
default_secrets_batch_chunk_size = 500

# Wall-clock cap (seconds) for a single Kingfisher subprocess, so a hung binary
# cannot block the audit indefinitely.
default_secrets_scan_timeout = 300


class SecretsScanError(Exception):
    """The secret scanner could not produce a trustworthy result.

    Raised when Kingfisher exits with a non-success code, times out, cannot be
    located/executed, or returns output that cannot be parsed. This is distinct
    from "no secrets found": a security check must never treat a scanner failure
    as a clean result, so callers are expected to surface it as ``MANUAL``
    (manual review required) instead of ``PASS``.
    """


@lru_cache(maxsize=1)
def get_kingfisher_binary() -> str:
    """Return the path to the bundled Kingfisher binary (cached)."""
    from kingfisher import get_binary_path

    return get_binary_path()


def _build_kingfisher_command(
    scan_paths: list,
    output_path: str,
    confidence: str,
    validate: bool,
    no_dedup: bool = False,
) -> list:
    """Build the Kingfisher ``scan`` command shared by single and batch scans."""
    command = [
        get_kingfisher_binary(),
        "scan",
        *scan_paths,
        "--format",
        "json",
        "--output",
        output_path,
        "--no-update-check",
        "--confidence",
        confidence,
    ]
    if validate:
        # Live-validate discovered secrets against provider APIs. Use
        # conservative defaults (short timeout, no retries) to limit the blast
        # radius of the outbound calls.
        command += ["--validation-timeout", "5", "--validation-retries", "0"]
    else:
        command.append("--no-validate")
    if no_dedup:
        # Report every occurrence (one per file) so batched results match
        # scanning each payload individually.
        command.append("--no-dedup")
    return command


def _finding_to_dict(entry: dict, fallback_filename: str) -> dict:
    """Convert a Kingfisher finding entry into Prowler's finding dict shape."""
    rule = entry.get("rule", {})
    finding = entry.get("finding", {})
    snippet = finding.get("snippet", "") or ""
    return {
        "filename": finding.get("path", fallback_filename),
        "line_number": finding.get("line"),
        "type": rule.get("name"),
        # Non-security identifier for the matched secret (matches the
        # detect-secrets output shape); not used for security.
        "hashed_secret": (
            sha1(snippet.encode(), usedforsecurity=False).hexdigest()
            if snippet
            else None
        ),
        "is_verified": finding.get("validation", {}).get("status") == "Active",
    }


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


def _scan_batch_chunk(
    chunk: list,
    excluded_secrets: list,
    confidence: str,
    validate: bool,
    results: dict,
) -> None:
    """Scan one chunk of ``(key, data)`` payloads in a single Kingfisher call.

    Writes each payload to its own file in a temp directory, scans the whole
    directory once (``--no-dedup`` so per-file results match individual scans),
    maps findings back to their key by file path, and appends them to
    ``results``. The temp directory is always removed.
    """
    if not chunk:
        return
    tmp_dir = tempfile.mkdtemp()
    temp_output_file = None
    try:
        index_to_key = {}
        for index, (key, data) in enumerate(chunk):
            content = data if data.endswith("\n") else data + "\n"
            name = str(index)
            with open(os.path.join(tmp_dir, name), "wb") as fh:
                fh.write(bytes(content, encoding="raw_unicode_escape"))
            index_to_key[name] = key

        temp_output_file = tempfile.NamedTemporaryFile(delete=False, suffix=".json")
        temp_output_file.close()
        command = _build_kingfisher_command(
            [tmp_dir], temp_output_file.name, confidence, validate, no_dedup=True
        )
        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=default_secrets_scan_timeout,
        )
        if process.returncode not in _kingfisher_success_exit_codes:
            raise SecretsScanError(
                f"Kingfisher exited with code {process.returncode}: "
                f"{process.stderr.strip()[:500]}"
            )

        with open(temp_output_file.name, encoding=encoding_format_utf_8) as f:
            output = f.read()
        kingfisher_output = json.loads(output) if output.strip() else {}

        source_lines_cache = {}

        def source_lines(file_name: str) -> list:
            if file_name not in source_lines_cache:
                with open(
                    os.path.join(tmp_dir, file_name),
                    encoding=encoding_format_utf_8,
                    errors="replace",
                ) as f:
                    source_lines_cache[file_name] = f.read().splitlines()
            return source_lines_cache[file_name]

        for entry in kingfisher_output.get("findings", []):
            finding = entry.get("finding", {})
            name = os.path.basename(finding.get("path", ""))
            key = index_to_key.get(name)
            if key is None:
                continue
            # Validate the line index before any consumer trusts it. Checks use
            # ``line_number`` as a 1-based index into their own parallel data
            # (e.g. CloudWatch does ``events[line_number - 1]``), so a missing,
            # non-integer, or out-of-range line would crash the check or map the
            # secret to the wrong resource. Fail closed: surface a malformed
            # finding as a scan failure so callers report MANUAL instead of a
            # wrong PASS/FAIL. ``bool`` is rejected explicitly because it is a
            # subclass of ``int``.
            line_number = finding.get("line")
            lines = source_lines(name)
            if (
                isinstance(line_number, bool)
                or not isinstance(line_number, int)
                or not 1 <= line_number <= len(lines)
            ):
                raise SecretsScanError(
                    f"Kingfisher returned an invalid line number "
                    f"{line_number!r} for a finding in {name}"
                )
            if excluded_secrets and any(
                re.search(pattern, lines[line_number - 1])
                for pattern in excluded_secrets
            ):
                continue
            results.setdefault(key, []).append(_finding_to_dict(entry, name))
    except SecretsScanError:
        # Already a typed scan failure; propagate so callers report MANUAL.
        raise
    except subprocess.TimeoutExpired as error:
        raise SecretsScanError(
            f"Kingfisher timed out after {default_secrets_scan_timeout}s "
            "while scanning for secrets"
        ) from error
    except Exception as error:
        # Fail closed: a missing/unexecutable binary, unparseable JSON output or
        # any other runtime failure must NOT be silently treated as "no secrets
        # found". Surface it so callers can report MANUAL instead of PASS.
        raise SecretsScanError(f"Secret scan failed: {error}") from error
    finally:
        if temp_output_file and os.path.exists(temp_output_file.name):
            os.remove(temp_output_file.name)
        shutil.rmtree(tmp_dir, ignore_errors=True)


def detect_secrets_scan_batch(
    payloads: Union[Mapping[Any, str], Iterable[tuple[Any, str]]],
    excluded_secrets: Optional[list[str]] = None,
    confidence: str = default_secrets_confidence,
    validate: bool = False,
    chunk_size: int = default_secrets_batch_chunk_size,
) -> dict:
    """Scan many payloads with Kingfisher in chunked subprocess invocations.

    This is the scan entry point used by every secret check. Each payload is
    written to its own file and scanned with ``--no-dedup`` so per-payload
    results match scanning each payload on its own. Payloads are processed in
    chunks (writing each to disk and releasing it as it is consumed) to bound
    peak temp-disk and memory use while amortizing the per-process spawn cost
    across many fragments.

    By default the scan runs fully offline (``--no-validate``,
    ``--no-update-check``): no network calls are made, so the scanned data is
    never sent anywhere. When ``validate`` is True, Kingfisher additionally
    checks whether each discovered secret is live by authenticating with it
    against the provider's API (the secret itself is the credential; no extra
    permissions are required). That makes outbound network calls, so it must be
    explicitly opted in.

    Args:
        payloads: a mapping ``{key: data}`` or any iterable of ``(key, data)``
            pairs. ``key`` is any hashable the caller uses to map findings back
            to its source (e.g. a variable name or a ``(resource, stream)``).
        excluded_secrets (list): regex patterns; a finding whose source line
            matches one is excluded.
        confidence (str): minimum Kingfisher confidence ("low"/"medium"/"high").
        validate (bool): live-validate discovered secrets (outbound calls).
        chunk_size (int): payloads scanned per Kingfisher invocation.
    Returns:
        dict mapping each key that produced findings to its list of finding
        dicts, each with ``filename``, ``line_number``, ``type``,
        ``hashed_secret`` and ``is_verified`` keys. Keys with no findings are
        omitted.
    Raises:
        SecretsScanError: if the scanner fails for any chunk (non-success exit
            code, timeout, missing/unexecutable binary or unparseable output).
            An empty result is therefore always "no secrets found", never a
            silent scan failure; callers must report MANUAL on this error.
    """
    items = payloads.items() if hasattr(payloads, "items") else payloads
    results = {}
    chunk = []
    for key, data in items:
        chunk.append((key, data))
        if len(chunk) >= chunk_size:
            _scan_batch_chunk(chunk, excluded_secrets, confidence, validate, results)
            chunk = []
    _scan_batch_chunk(chunk, excluded_secrets, confidence, validate, results)
    return results


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
