from unittest import mock

from prowler.providers.aws.services.trustedadvisor.trustedadvisor_service import (
    Check,
    PremiumSupport,
)
from tests.providers.aws.utils import (
    AWS_ACCOUNT_ARN,
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
)

CHECK_NAME = "test-check"
CHECK_ARN = "arn:aws:trusted-advisor:::check/test-check"


class Test_trustedadvisor_errors_and_warnings:
    def test_no_detectors_premium_support_disabled(self):
        trustedadvisor_client = mock.MagicMock
        trustedadvisor_client.checks = []
        trustedadvisor_client.premium_support = PremiumSupport(enabled=False)
        trustedadvisor_client.audited_account = AWS_ACCOUNT_NUMBER
        trustedadvisor_client.audited_account_arn = AWS_ACCOUNT_ARN
        trustedadvisor_client.audited_partition = "aws"
        trustedadvisor_client.region = AWS_REGION_US_EAST_1
        trustedadvisor_client.account_arn_template = f"arn:{trustedadvisor_client.audited_partition}:trusted-advisor:{trustedadvisor_client.region}:{trustedadvisor_client.audited_account}:account"
        trustedadvisor_client.__get_account_arn_template__ = mock.MagicMock(
            return_value=trustedadvisor_client.account_arn_template
        )
        with mock.patch(
            "prowler.providers.aws.services.trustedadvisor.trustedadvisor_service.TrustedAdvisor",
            trustedadvisor_client,
        ):
            from prowler.providers.aws.services.trustedadvisor.trustedadvisor_errors_and_warnings.trustedadvisor_errors_and_warnings import (
                trustedadvisor_errors_and_warnings,
            )

            check = trustedadvisor_errors_and_warnings()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert (
                result[0].status_extended
                == "Amazon Web Services Premium Support Subscription is required to use this service."
            )
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_id == AWS_ACCOUNT_NUMBER
            assert (
                result[0].resource_arn
                == f"arn:aws:trusted-advisor:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:account"
            )

    def test_trustedadvisor_all_passed_checks(self):
        trustedadvisor_client = mock.MagicMock
        trustedadvisor_client.checks = []
        trustedadvisor_client.premium_support = PremiumSupport(enabled=True)
        trustedadvisor_client.audited_account = AWS_ACCOUNT_NUMBER
        trustedadvisor_client.audited_account_arn = AWS_ACCOUNT_ARN
        trustedadvisor_client.checks.append(
            Check(
                id=CHECK_NAME,
                name=CHECK_NAME,
                arn=CHECK_ARN,
                region=AWS_REGION_US_EAST_1,
                status="ok",
            )
        )
        with mock.patch(
            "prowler.providers.aws.services.trustedadvisor.trustedadvisor_service.TrustedAdvisor",
            trustedadvisor_client,
        ):
            from prowler.providers.aws.services.trustedadvisor.trustedadvisor_errors_and_warnings.trustedadvisor_errors_and_warnings import (
                trustedadvisor_errors_and_warnings,
            )

            check = trustedadvisor_errors_and_warnings()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Trusted Advisor check {CHECK_NAME} is in state ok."
            )
            assert result[0].resource_id == CHECK_NAME
            assert result[0].region == AWS_REGION_US_EAST_1

    def test_trustedadvisor_error_check(self):
        trustedadvisor_client = mock.MagicMock
        trustedadvisor_client.checks = []
        trustedadvisor_client.premium_support = PremiumSupport(enabled=True)
        trustedadvisor_client.audited_account = AWS_ACCOUNT_NUMBER
        trustedadvisor_client.audited_account_arn = AWS_ACCOUNT_ARN
        trustedadvisor_client.checks.append(
            Check(
                id=CHECK_NAME,
                name=CHECK_NAME,
                arn=CHECK_ARN,
                region=AWS_REGION_US_EAST_1,
                status="error",
            )
        )
        with mock.patch(
            "prowler.providers.aws.services.trustedadvisor.trustedadvisor_service.TrustedAdvisor",
            trustedadvisor_client,
        ):
            from prowler.providers.aws.services.trustedadvisor.trustedadvisor_errors_and_warnings.trustedadvisor_errors_and_warnings import (
                trustedadvisor_errors_and_warnings,
            )

            check = trustedadvisor_errors_and_warnings()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Trusted Advisor check {CHECK_NAME} is in state error."
            )
            assert result[0].resource_id == CHECK_NAME
            assert result[0].region == AWS_REGION_US_EAST_1

    def test_trustedadvisor_not_available_check(self):
        trustedadvisor_client = mock.MagicMock
        trustedadvisor_client.checks = []
        trustedadvisor_client.premium_support = PremiumSupport(enabled=True)
        trustedadvisor_client.audited_account = AWS_ACCOUNT_NUMBER
        trustedadvisor_client.audited_account_arn = AWS_ACCOUNT_ARN
        trustedadvisor_client.checks.append(
            Check(
                id=CHECK_NAME,
                name=CHECK_NAME,
                arn=CHECK_ARN,
                region=AWS_REGION_US_EAST_1,
                status="not_available",
            )
        )
        with mock.patch(
            "prowler.providers.aws.services.trustedadvisor.trustedadvisor_service.TrustedAdvisor",
            trustedadvisor_client,
        ):
            from prowler.providers.aws.services.trustedadvisor.trustedadvisor_errors_and_warnings.trustedadvisor_errors_and_warnings import (
                trustedadvisor_errors_and_warnings,
            )

            check = trustedadvisor_errors_and_warnings()
            result = check.execute()
            assert len(result) == 0
