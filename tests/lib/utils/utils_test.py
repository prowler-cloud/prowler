import os
import tempfile
from datetime import datetime
from time import mktime

import pytest
from mock import Mock, patch

from prowler.lib.utils.utils import (
    detect_secrets_scan,
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


class Test_detect_secrets_scan:
    def test_detect_secrets_scan_data(self):
        data = 'password = "Tr0ub4dor3xKq9vLmZ"'
        secrets_detected = detect_secrets_scan(data=data, excluded_secrets=[])
        assert type(secrets_detected) is list
        assert len(secrets_detected) == 1
        assert "filename" in secrets_detected[0]
        assert "hashed_secret" in secrets_detected[0]
        assert "is_verified" in secrets_detected[0]
        assert secrets_detected[0]["line_number"] == 1
        assert secrets_detected[0]["type"] == "Generic Password"

    def test_detect_secrets_scan_no_secrets_data(self):
        data = ""
        assert detect_secrets_scan(data=data) is None

    def test_detect_secrets_scan_file_with_secrets(self):
        temp_data_file = tempfile.NamedTemporaryFile(delete=False, suffix=".txt")
        temp_data_file.write(b'password = "Tr0ub4dor3xKq9vLmZ"\n')
        temp_data_file.seek(0)
        secrets_detected = detect_secrets_scan(
            file=temp_data_file.name, excluded_secrets=[]
        )
        assert type(secrets_detected) is list
        assert len(secrets_detected) == 1
        assert "filename" in secrets_detected[0]
        assert "hashed_secret" in secrets_detected[0]
        assert "is_verified" in secrets_detected[0]
        assert secrets_detected[0]["line_number"] == 1
        assert secrets_detected[0]["type"] == "Generic Password"
        os.remove(temp_data_file.name)

    def test_detect_secrets_scan_file_no_secrets(self):
        temp_data_file = tempfile.NamedTemporaryFile(delete=False)
        temp_data_file.write(b"no secrets")
        temp_data_file.seek(0)
        assert detect_secrets_scan(file=temp_data_file.name) is None
        os.remove(temp_data_file.name)

    def test_detect_secrets_using_regex(self):
        data = "MYSQL_ALLOW_EMPTY_PASSWORD=password"
        secrets_detected = detect_secrets_scan(
            data=data, excluded_secrets=[".*password"]
        )
        assert secrets_detected is None

    def test_detect_secrets_using_regex_file(self):
        temp_data_file = tempfile.NamedTemporaryFile(delete=False)
        temp_data_file.write(b"MYSQL_ALLOW_EMPTY_PASSWORD=password")
        temp_data_file.seek(0)
        secrets_detected = detect_secrets_scan(
            file=temp_data_file.name, excluded_secrets=[".*password"]
        )
        assert secrets_detected is None
        os.remove(temp_data_file.name)

    def test_detect_secrets_secrets_using_regex(self):
        # Two secrets on separate lines; exclude the line with the
        # ALLOW_EMPTY_PASSWORD key, leaving only the MYSQL_PASSWORD secret.
        data = (
            'MYSQL_ALLOW_EMPTY_PASSWORD="Tr0ub4dor3xKq9vLmZ"\n'
            'MYSQL_PASSWORD="Xy9zPq2wKmRtVbN4Lm"'
        )
        secrets_detected = detect_secrets_scan(
            data=data, excluded_secrets=[".*ALLOW_EMPTY_PASSWORD.*"]
        )
        assert type(secrets_detected) is list
        assert len(secrets_detected) == 1
        assert "filename" in secrets_detected[0]
        assert "hashed_secret" in secrets_detected[0]
        assert "is_verified" in secrets_detected[0]
        assert secrets_detected[0]["line_number"] == 2
        assert secrets_detected[0]["type"] == "Generic Password"

    def test_detect_secrets_scan_offline_by_default(self):
        # By default the scan is fully offline: --no-validate is passed and no
        # validation flags are added.
        with (
            patch(
                "prowler.lib.utils.utils.get_kingfisher_binary",
                return_value="kingfisher",
            ),
            patch("prowler.lib.utils.utils.subprocess.run") as mock_run,
        ):
            mock_run.return_value = Mock(returncode=0, stdout="", stderr="")
            detect_secrets_scan(data="password = 'value'")
            command = mock_run.call_args[0][0]
            assert "--no-validate" in command
            assert "--validation-timeout" not in command

    def test_detect_secrets_scan_validate_enabled(self):
        # With validate=True, --no-validate is dropped and conservative
        # validation flags are added.
        with (
            patch(
                "prowler.lib.utils.utils.get_kingfisher_binary",
                return_value="kingfisher",
            ),
            patch("prowler.lib.utils.utils.subprocess.run") as mock_run,
        ):
            mock_run.return_value = Mock(returncode=0, stdout="", stderr="")
            detect_secrets_scan(data="password = 'value'", validate=True)
            command = mock_run.call_args[0][0]
            assert "--no-validate" not in command
            assert "--validation-timeout" in command
            assert "--validation-retries" in command


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
