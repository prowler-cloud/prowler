from unittest import mock

from prowler.providers.aws.services.trustedadvisor.trustedadvisor_service import (
    PremiumSupport,
)
from tests.providers.aws.utils import (
    AWS_ACCOUNT_ARN,
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
)


class Test_trustedadvisor_premium_support_plan_subscribed:
    def test_premium_support_not_susbcribed(self):
        trustedadvisor_client = mock.MagicMock
        trustedadvisor_client.checks = []
        trustedadvisor_client.premium_support = PremiumSupport(enabled=False)
        trustedadvisor_client.audited_account = AWS_ACCOUNT_NUMBER
        trustedadvisor_client.audited_account_arn = AWS_ACCOUNT_ARN
        trustedadvisor_client.audited_partition = "aws"
        trustedadvisor_client.region = AWS_REGION_US_EAST_1

        # Set verify_premium_support_plans config
        trustedadvisor_client.audit_config = {"verify_premium_support_plans": True}
        trustedadvisor_client.account_arn_template = f"arn:{trustedadvisor_client.audited_partition}:trusted-advisor:{trustedadvisor_client.region}:{trustedadvisor_client.audited_account}:account"
        trustedadvisor_client.__get_account_arn_template__ = mock.MagicMock(
            return_value=trustedadvisor_client.account_arn_template
        )
        with mock.patch(
            "prowler.providers.aws.services.trustedadvisor.trustedadvisor_service.TrustedAdvisor",
            trustedadvisor_client,
        ):
            from prowler.providers.aws.services.trustedadvisor.trustedadvisor_premium_support_plan_subscribed.trustedadvisor_premium_support_plan_subscribed import (
                trustedadvisor_premium_support_plan_subscribed,
            )

            check = trustedadvisor_premium_support_plan_subscribed()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Amazon Web Services Premium Support Plan isn't subscribed."
            )
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_id == AWS_ACCOUNT_NUMBER
            assert (
                result[0].resource_arn
                == f"arn:aws:trusted-advisor:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:account"
            )

    def test_premium_support_susbcribed(self):
        trustedadvisor_client = mock.MagicMock
        trustedadvisor_client.checks = []
        trustedadvisor_client.premium_support = PremiumSupport(enabled=True)
        trustedadvisor_client.audited_account = AWS_ACCOUNT_NUMBER
        trustedadvisor_client.audited_account_arn = AWS_ACCOUNT_ARN
        trustedadvisor_client.audited_partition = "aws"
        trustedadvisor_client.region = AWS_REGION_US_EAST_1

        # Set verify_premium_support_plans config
        trustedadvisor_client.audit_config = {"verify_premium_support_plans": True}
        trustedadvisor_client.account_arn_template = f"arn:{trustedadvisor_client.audited_partition}:trusted-advisor:{trustedadvisor_client.region}:{trustedadvisor_client.audited_account}:account"
        trustedadvisor_client.__get_account_arn_template__ = mock.MagicMock(
            return_value=trustedadvisor_client.account_arn_template
        )
        with mock.patch(
            "prowler.providers.aws.services.trustedadvisor.trustedadvisor_service.TrustedAdvisor",
            trustedadvisor_client,
        ):
            from prowler.providers.aws.services.trustedadvisor.trustedadvisor_premium_support_plan_subscribed.trustedadvisor_premium_support_plan_subscribed import (
                trustedadvisor_premium_support_plan_subscribed,
            )

            check = trustedadvisor_premium_support_plan_subscribed()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Amazon Web Services Premium Support Plan is subscribed."
            )
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_id == AWS_ACCOUNT_NUMBER
            assert (
                result[0].resource_arn
                == f"arn:aws:trusted-advisor:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:account"
            )
