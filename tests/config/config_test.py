from prowler.providers.aws.aws_provider import get_aws_available_regions


class Test_Config:
    def test_get_aws_available_regions(self):
        assert len(get_aws_available_regions()) == 31
