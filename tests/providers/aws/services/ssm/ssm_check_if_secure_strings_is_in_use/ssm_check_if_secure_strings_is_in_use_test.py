from unittest import mock

# Mock Test Region
AWS_REGION = "eu-west-1"


class Test_ssm_check_if_secure_strings_is_in_use:
    def test_no_secure_string(self):
        ssm_client = mock.MagicMock
        ssm_client.parameters = []
        with mock.patch(
            "prowler.providers.aws.services.ssm.ssm_service.SSM",
            new=ssm_client,
        ):
            # Test Check
            from prowler.providers.aws.services.ssm.ssm_check_if_secure_strings_is_in_use.ssm_check_if_secure_strings_is_in_use import (
                ssm_check_if_secure_strings_is_in_use,
            )

            check = ssm_check_if_secure_strings_is_in_use()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended == "SSm secure strings is not in use."

    def test_one_secure_string(self):
        ssm_client = mock.MagicMock
        ssm_client.parameters = [{"Type": "SecureString"}]
        with mock.patch(
            "prowler.providers.aws.services.ssm.ssm_service.SSM",
            new=ssm_client,
        ):
            # Test Check
            from prowler.providers.aws.services.ssm.ssm_check_if_secure_strings_is_in_use.ssm_check_if_secure_strings_is_in_use import (
                ssm_check_if_secure_strings_is_in_use,
            )

            check = ssm_check_if_secure_strings_is_in_use()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].status_extended == "SSM secure strings is in use."
