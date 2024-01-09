from unittest import mock

from prowler.providers.aws.services.trustedadvisor.trustedadvisor_service import (
    Check,
    PremiumSupport,
)

AWS_REGION = "eu-west-1"
AWS_ACCOUNT_NUMBER = "123456789012"
AWS_ACCOUNT_ARN = f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"

CHECK_NAME = "test-check"


class Test_trustedadvisor_errors_and_warnings:
    def test_no_detectors_premium_support_disabled(self):
        trustedadvisor_client = mock.MagicMock
        trustedadvisor_client.checks = []
        trustedadvisor_client.premium_support = PremiumSupport(enabled=False)
        trustedadvisor_client.audited_account = AWS_ACCOUNT_NUMBER
        trustedadvisor_client.audited_account_arn = AWS_ACCOUNT_ARN
        trustedadvisor_client.region = AWS_REGION
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
            assert result[0].region == AWS_REGION
            assert result[0].resource_id == AWS_ACCOUNT_NUMBER
            assert result[0].resource_arn == AWS_ACCOUNT_ARN

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
                region=AWS_REGION,
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
            assert result[0].region == AWS_REGION

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
                region=AWS_REGION,
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
            assert result[0].region == AWS_REGION

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
                region=AWS_REGION,
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
