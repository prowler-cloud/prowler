import os
import tempfile
from datetime import datetime
from time import mktime

import pytest
from mock import patch

from prowler.lib.utils.utils import (
    detect_secrets_scan,
    file_exists,
    hash_sha512,
    open_file,
    outputs_unix_timestamp,
    parse_json_file,
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
    def test_detect_secrets_scan(self):
        data = "password=password"
        secrets_detected = detect_secrets_scan(data)
        assert type(secrets_detected) is list
        assert len(secrets_detected) == 1
        assert "filename" in secrets_detected[0]
        assert "hashed_secret" in secrets_detected[0]
        assert "is_verified" in secrets_detected[0]
        assert secrets_detected[0]["line_number"] == 1
        assert secrets_detected[0]["type"] == "Secret Keyword"

    def test_detect_secrets_scan_no_secrets(self):
        data = ""
        assert detect_secrets_scan(data) is None


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
