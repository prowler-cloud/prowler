from prowler.config.config import check_current_version, prowler_version
from prowler.providers.aws.aws_provider import get_aws_available_regions


class Test_Config:
    def test_get_aws_available_regions(self):
        assert len(get_aws_available_regions()) == 31

    def test_check_current_version(self):
        assert (
            check_current_version(prowler_version) == "(it is the latest version, yay!)"
        )
        assert (
            check_current_version("0.0.0")
            == f"(latest is {prowler_version}, upgrade for the latest features)"
        )
