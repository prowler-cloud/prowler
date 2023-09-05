from datetime import datetime
from time import mktime

from prowler.lib.utils.utils import outputs_unix_timestamp, validate_ip_address


class Test_utils:
    def test_validate_ip_address(self):
        assert validate_ip_address("88.26.151.198")
        assert not validate_ip_address("Not an IP")

    def test_outputs_unix_timestamp_false(self):
        time = datetime.now()
        assert outputs_unix_timestamp(False, time) == time.isoformat()

    def test_outputs_unix_timestamp_true(self):
        time = datetime.now()
        assert outputs_unix_timestamp(True, time) == mktime(time.timetuple())
