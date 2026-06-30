import os
import subprocess
import tempfile
from datetime import datetime
from time import mktime

import pytest
from mock import patch

from prowler.lib.utils.utils import (
    SecretsScanError,
    detect_secrets_scan_batch,
    file_exists,
    get_file_permissions,
    hash_sha512,
    is_owned_by_root,
    open_file,
    outputs_unix_timestamp,
    parse_json_file,
    strip_ansi_codes,
    validate_ip_address,
)


def _fake_kingfisher_run(output_content=None, returncode=0, stderr=""):
    """Build a ``subprocess.run`` replacement that mimics a Kingfisher call.

    When ``output_content`` is given it is written to the ``--output`` path from
    the command (so the reader sees realistic file content); the call returns a
    CompletedProcess with the requested ``returncode``/``stderr``.
    """

    def _run(command, *_args, **_kwargs):
        if output_content is not None:
            output_path = command[command.index("--output") + 1]
            with open(output_path, "w") as output_file:
                output_file.write(output_content)
        return subprocess.CompletedProcess(
            command, returncode, stdout="", stderr=stderr
        )

    return _run


def _fake_kingfisher_run_with_findings(findings):
    """Build a ``subprocess.run`` replacement that emits crafted findings.

    Each entry in ``findings`` is a ``(payload_index, line)`` pair: the finding
    is mapped back to the temp file named ``str(payload_index)`` (the basename
    ``_scan_batch_chunk`` writes per payload) and given the requested ``line``
    value (omitted entirely when ``line`` is the sentinel ``_OMIT``). Returns a
    success exit code so only the finding shape is under test.
    """

    def _run(command, *_args, **_kwargs):
        output_path = command[command.index("--output") + 1]
        entries = []
        for payload_index, line in findings:
            finding = {"path": str(payload_index), "snippet": "secret"}
            if line is not _OMIT:
                finding["line"] = line
            entries.append({"finding": finding, "rule": {"name": "Generic Secret"}})
        import json as _json

        with open(output_path, "w") as output_file:
            output_file.write(_json.dumps({"findings": entries}))
        return subprocess.CompletedProcess(command, 200, stdout="", stderr="")

    return _run


_OMIT = object()


class Test_detect_secrets_scan_batch_invalid_line:
    """Kingfisher's ``line`` is consumed as a trusted 1-based index by checks
    (e.g. CloudWatch ``events[line_number - 1]``). A malformed line must fail
    closed as SecretsScanError, never return a finding with a bad index."""

    @pytest.mark.parametrize(
        "line",
        [_OMIT, None, "2", 0, -1, 5, True],
        ids=["missing", "none", "string", "zero", "negative", "out_of_range", "bool"],
    )
    def test_invalid_line_raises(self, line):
        # Payload "data" is a single line, so any line other than 1 is invalid.
        with patch(
            "prowler.lib.utils.utils.subprocess.run",
            side_effect=_fake_kingfisher_run_with_findings([(0, line)]),
        ):
            with pytest.raises(SecretsScanError) as exc:
                detect_secrets_scan_batch({"a": "data"})
        assert "invalid line number" in str(exc.value)

    def test_valid_line_is_returned(self):
        # A valid in-range line must still pass through to the caller.
        with patch(
            "prowler.lib.utils.utils.subprocess.run",
            side_effect=_fake_kingfisher_run_with_findings([(0, 1)]),
        ):
            results = detect_secrets_scan_batch({"a": "data"})
        assert results["a"][0]["line_number"] == 1

    def test_one_invalid_line_aborts_the_whole_scan(self):
        # Even mixed with a valid finding, a single invalid line fails closed.
        with patch(
            "prowler.lib.utils.utils.subprocess.run",
            side_effect=_fake_kingfisher_run_with_findings([(0, 1), (1, 0)]),
        ):
            with pytest.raises(SecretsScanError):
                detect_secrets_scan_batch({"a": "data", "b": "data"})


class Test_utils_open_file:
    def test_open_read_file(self):
        temp_data_file = tempfile.NamedTemporaryFile(delete=False)
        mode = "r"
        f = open_file(temp_data_file.name, mode)
        assert f.__class__.__name__ == "TextIOWrapper"
        os.remove(temp_data_file.name)

    def test_open_raise_too_many_open_files(self):
        temp_data_file = tempfile.NamedTemporaryFile(delete=False)
        mode = "r"
        with patch("prowler.lib.utils.utils.open") as mock_open:
            mock_open.side_effect = OSError(1, "Too many open files")
            with pytest.raises(SystemExit) as exception:
                open_file(temp_data_file.name, mode)
            assert exception.type == SystemExit
            assert exception.value.code == 1
            os.remove(temp_data_file.name)

    def test_open_raise_os_error(self):
        temp_data_file = tempfile.NamedTemporaryFile(delete=False)
        mode = "r"
        with patch("prowler.lib.utils.utils.open") as mock_open:
            mock_open.side_effect = OSError(1, "Another OS error")
            with pytest.raises(SystemExit) as exception:
                open_file(temp_data_file.name, mode)
            assert exception.type == SystemExit
            assert exception.value.code == 1
            os.remove(temp_data_file.name)

    def test_open_raise_exception(self):
        temp_data_file = tempfile.NamedTemporaryFile(delete=False)
        mode = "r"
        with patch("prowler.lib.utils.utils.open") as mock_open:
            mock_open.side_effect = Exception()
            with pytest.raises(SystemExit) as exception:
                open_file(temp_data_file.name, mode)
            assert exception.type == SystemExit
            assert exception.value.code == 1
            os.remove(temp_data_file.name)


class Test_parse_json_file:
    def test_parse_json_file_invalid(self):
        temp_data_file = tempfile.NamedTemporaryFile(delete=False)
        with pytest.raises(SystemExit) as exception:
            parse_json_file(temp_data_file)

        assert exception.type == SystemExit
        assert exception.value.code == 1
        os.remove(temp_data_file.name)

    def test_parse_json_file_valid(self):
        temp_data_file = tempfile.NamedTemporaryFile(delete=False)
        temp_data_file.write(b"{}")
        temp_data_file.seek(0)
        f = parse_json_file(temp_data_file)
        assert f == {}


class Test_file_exists:
    def test_file_exists_false(self):
        assert not file_exists("not_existing.txt")

    def test_file_exists(self):
        temp_data_file = tempfile.NamedTemporaryFile(delete=False)
        assert file_exists(temp_data_file.name)
        os.remove(temp_data_file.name)

    def test_file_exists_raised_exception(self):
        temp_data_file = tempfile.NamedTemporaryFile(delete=False)
        with patch("prowler.lib.utils.utils.exists") as mock_exists:
            mock_exists.side_effect = Exception()
            with pytest.raises(SystemExit) as exception:
                file_exists(temp_data_file.name)

        assert exception.type == SystemExit
        assert exception.value.code == 1

        os.remove(temp_data_file.name)


class Test_utils_validate_ip_address:
    def test_validate_ip_address(self):
        assert validate_ip_address("88.26.151.198")
        assert not validate_ip_address("Not an IP")


class Test_detect_secrets_scan_batch:
    def test_batch_returns_findings_per_key(self):
        results = detect_secrets_scan_batch(
            {
                "a": 'password = "Tr0ub4dor3xKq9vLmZ"',
                "b": "just a normal config = value",
            }
        )
        assert "a" in results
        assert results["a"][0]["type"] == "Generic Password"
        # keys without findings are omitted
        assert "b" not in results

    def test_batch_no_dedup_reports_identical_secret_in_each_key(self):
        # The same secret in two payloads must be reported for both (matches
        # scanning each payload individually).
        secret = "token = eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        results = detect_secrets_scan_batch({"a": secret, "b": secret})
        assert "a" in results
        assert "b" in results

    def test_batch_excluded_secrets_filters(self):
        results = detect_secrets_scan_batch(
            {"a": 'DB_ALLOW_EMPTY_PASSWORD = "Tr0ub4dor3xKq9vLmZ"'},
            excluded_secrets=[".*ALLOW_EMPTY_PASSWORD.*"],
        )
        assert results == {}

    def test_batch_chunking_maps_all_keys(self):
        payloads = {f"k{i}": f'password = "S3cr3tV4lu3xy{i}z"' for i in range(5)}
        results = detect_secrets_scan_batch(payloads, chunk_size=2)
        assert sorted(results.keys()) == ["k0", "k1", "k2", "k3", "k4"]

    def test_batch_empty_payloads(self):
        assert detect_secrets_scan_batch({}) == {}

    def test_batch_accepts_iterable_of_pairs(self):
        results = detect_secrets_scan_batch(
            iter([("x", 'password = "Tr0ub4dor3xKq9vLmZ"')])
        )
        assert "x" in results


class Test_detect_secrets_scan_batch_failures:
    """A scanner failure must surface as SecretsScanError, never as empty
    results (which a caller would read as 'no secrets found')."""

    def test_non_zero_exit_code_raises(self):
        with patch(
            "prowler.lib.utils.utils.subprocess.run",
            side_effect=_fake_kingfisher_run(returncode=1, stderr="boom"),
        ):
            with pytest.raises(SecretsScanError) as exc:
                detect_secrets_scan_batch({"a": "data"})
        assert "exited with code 1" in str(exc.value)
        assert "boom" in str(exc.value)

    def test_timeout_raises(self):
        with patch(
            "prowler.lib.utils.utils.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="kingfisher", timeout=300),
        ):
            with pytest.raises(SecretsScanError) as exc:
                detect_secrets_scan_batch({"a": "data"})
        assert "timed out" in str(exc.value)

    def test_malformed_json_output_raises(self):
        with patch(
            "prowler.lib.utils.utils.subprocess.run",
            side_effect=_fake_kingfisher_run(
                output_content="{not valid json", returncode=0
            ),
        ):
            with pytest.raises(SecretsScanError):
                detect_secrets_scan_batch({"a": "data"})

    def test_missing_binary_raises(self):
        with patch(
            "prowler.lib.utils.utils.subprocess.run",
            side_effect=FileNotFoundError("kingfisher binary not found"),
        ):
            with pytest.raises(SecretsScanError):
                detect_secrets_scan_batch({"a": "data"})

    def test_empty_output_is_not_a_failure(self):
        # Empty output means the scan ran and found nothing; it must NOT raise.
        with patch(
            "prowler.lib.utils.utils.subprocess.run",
            side_effect=_fake_kingfisher_run(output_content="", returncode=0),
        ):
            assert detect_secrets_scan_batch({"a": "data"}) == {}

    def test_failure_in_any_chunk_aborts_the_whole_scan(self):
        # A failure in any chunk must abort the whole scan, not silently return
        # partial results from the chunks that happened to succeed first.
        payloads = {f"k{i}": "data" for i in range(4)}
        with patch(
            "prowler.lib.utils.utils.subprocess.run",
            side_effect=_fake_kingfisher_run(returncode=2, stderr="boom"),
        ):
            with pytest.raises(SecretsScanError):
                detect_secrets_scan_batch(payloads, chunk_size=2)


class Test_hash_sha512:
    def test_hash_sha512(self):
        assert hash_sha512("test") == "ee26b0dd4"


class Test_outputs_unix_timestamp:
    def test_outputs_unix_timestamp_false(self):
        time = datetime.now()
        assert outputs_unix_timestamp(False, time) == time.isoformat()

    def test_outputs_unix_timestamp_true(self):
        time = datetime.now()
        assert outputs_unix_timestamp(True, time) == mktime(time.timetuple())


class TestFilePermissions:
    def test_get_file_permissions(self):
        # Create a temporary file with known permissions
        temp_file = tempfile.NamedTemporaryFile(delete=False)
        temp_file.close()
        os.chmod(temp_file.name, 0o644)  # Set permissions to 644 (-rw-r--r--)
        permissions = get_file_permissions(temp_file.name)
        assert permissions == "0o644"
        os.unlink(temp_file.name)
        assert not get_file_permissions("not_existing_file")

    def test_is_owned_by_root(self):
        # Create a temporary file with known permissions
        temp_file = tempfile.NamedTemporaryFile(delete=False)
        temp_file.close()
        os.chmod(temp_file.name, 0o644)  # Set permissions to 644 (-rw-r--r--)
        # Check ownership for the temporary file
        assert not is_owned_by_root(temp_file.name)
        os.unlink(temp_file.name)

        assert not is_owned_by_root("not_existing_file")
        # Not valid for darwin systems
        # assert is_owned_by_root("/etc/passwd")


class TestStripAnsiCodes:
    def test_strip_ansi_codes_no_alteration(self):
        input_string = "\x1b[31mHello\x1b[0m World"
        expected_output = "Hello World"

        actual_output = strip_ansi_codes(input_string)

        assert actual_output == expected_output

    def test_strip_ansi_codes_empty_string(self):
        input_string = ""
        expected_output = ""

        actual_output = strip_ansi_codes(input_string)

        assert actual_output == expected_output
