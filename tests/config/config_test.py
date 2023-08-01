from unittest import mock

from requests import Response

from prowler.config.config import check_current_version
from prowler.providers.aws.aws_provider import get_aws_available_regions

MOCK_PROWLER_VERSION = "3.3.0"
MOCK_OLD_PROWLER_VERSION = "0.0.0"


def mock_prowler_get_latest_release(_):
    """Mock requests.get() to get the Prowler latest release"""
    response = Response()
    response._content = b'[{"name":"3.3.0"}]'
    return response


class Test_Config:
    def test_get_aws_available_regions(self):
        assert len(get_aws_available_regions()) == 32

    @mock.patch(
        "prowler.config.config.requests.get", new=mock_prowler_get_latest_release
    )
    @mock.patch("prowler.config.config.prowler_version", new=MOCK_PROWLER_VERSION)
    def test_check_current_version_with_latest(self):
        assert (
            check_current_version()
            == f"Prowler {MOCK_PROWLER_VERSION} (it is the latest version, yay!)"
        )

    @mock.patch(
        "prowler.config.config.requests.get", new=mock_prowler_get_latest_release
    )
    @mock.patch("prowler.config.config.prowler_version", new=MOCK_OLD_PROWLER_VERSION)
    def test_check_current_version_with_old(self):
        assert (
            check_current_version()
            == f"Prowler {MOCK_OLD_PROWLER_VERSION} (latest is {MOCK_PROWLER_VERSION}, upgrade for the latest features)"
        )
