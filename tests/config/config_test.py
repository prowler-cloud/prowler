from prowler.config.config import get_aws_available_regions


class Test_Config:
    def test_get_aws_available_regions(self):
        assert len(get_aws_available_regions()) == 29
