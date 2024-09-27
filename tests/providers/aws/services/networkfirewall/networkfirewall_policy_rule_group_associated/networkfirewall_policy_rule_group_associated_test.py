from unittest import mock

from prowler.providers.aws.services.networkfirewall.networkfirewall_service import (
    Firewall,
)
from tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider

FIREWALL_ARN = "arn:aws:network-firewall:us-east-1:123456789012:firewall/my-firewall"
FIREWALL_NAME = "my-firewall"
VPC_ID_PROTECTED = "vpc-12345678901234567"
VPC_ID_UNPROTECTED = "vpc-12345678901234568"
POLICY_ARN = "arn:aws:network-firewall:us-east-1:123456789012:firewall-policy/my-policy"


class Test_networkfirewall_policy_rule_group_associated:
    def test_no_networkfirewall(self):
        networkfirewall_client = mock.MagicMock
        networkfirewall_client.provider = set_mocked_aws_provider(
            [AWS_REGION_US_EAST_1]
        )
        networkfirewall_client.region = AWS_REGION_US_EAST_1
        networkfirewall_client.network_firewalls = {}

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.networkfirewall.networkfirewall_policy_rule_group_associated.networkfirewall_policy_rule_group_associated.networkfirewall_client",
                new=networkfirewall_client,
            ):
                # Test Check
                from prowler.providers.aws.services.networkfirewall.networkfirewall_policy_rule_group_associated.networkfirewall_policy_rule_group_associated import (
                    networkfirewall_policy_rule_group_associated,
                )

                check = networkfirewall_policy_rule_group_associated()
                result = check.execute()

                assert len(result) == 0

    def test_networkfirewall_policy_stateless_rule_group_associated(self):
        networkfirewall_client = mock.MagicMock
        networkfirewall_client.provider = set_mocked_aws_provider(
            [AWS_REGION_US_EAST_1]
        )
        networkfirewall_client.region = AWS_REGION_US_EAST_1
        networkfirewall_client.network_firewalls = {
            FIREWALL_ARN: Firewall(
                arn=FIREWALL_ARN,
                name=FIREWALL_NAME,
                region=AWS_REGION_US_EAST_1,
                policy_arn=POLICY_ARN,
                vpc_id=VPC_ID_PROTECTED,
                tags=[],
                encryption_type="CUSTOMER_KMS",
                deletion_protection=False,
                stateless_rule_groups=[
                    "arn:aws:network-firewall:us-east-1:123456789012:stateful-rule-group/my-stateless-rule-group"
                ],
            )
        }
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.networkfirewall.networkfirewall_policy_rule_group_associated.networkfirewall_policy_rule_group_associated.networkfirewall_client",
                new=networkfirewall_client,
            ):
                # Test Check
                from prowler.providers.aws.services.networkfirewall.networkfirewall_policy_rule_group_associated.networkfirewall_policy_rule_group_associated import (
                    networkfirewall_policy_rule_group_associated,
                )

                check = networkfirewall_policy_rule_group_associated()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == f"Network Firewall {FIREWALL_NAME} policy has at least one rule group associated."
                )
                assert result[0].region == AWS_REGION_US_EAST_1
                assert result[0].resource_id == FIREWALL_NAME
                assert result[0].resource_tags == []
                assert result[0].resource_arn == FIREWALL_ARN

    def test_networkfirewall_policy_stateful_rule_group_associated(self):
        networkfirewall_client = mock.MagicMock
        networkfirewall_client.provider = set_mocked_aws_provider(
            [AWS_REGION_US_EAST_1]
        )
        networkfirewall_client.region = AWS_REGION_US_EAST_1
        networkfirewall_client.network_firewalls = {
            FIREWALL_ARN: Firewall(
                arn=FIREWALL_ARN,
                name=FIREWALL_NAME,
                region=AWS_REGION_US_EAST_1,
                policy_arn=POLICY_ARN,
                vpc_id=VPC_ID_PROTECTED,
                tags=[],
                encryption_type="CUSTOMER_KMS",
                deletion_protection=False,
                stateful_rule_groups=[
                    "arn:aws:network-firewall:us-east-1:123456789012:stateful-rule-group/my-stateful-rule-group"
                ],
            )
        }
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.networkfirewall.networkfirewall_policy_rule_group_associated.networkfirewall_policy_rule_group_associated.networkfirewall_client",
                new=networkfirewall_client,
            ):
                # Test Check
                from prowler.providers.aws.services.networkfirewall.networkfirewall_policy_rule_group_associated.networkfirewall_policy_rule_group_associated import (
                    networkfirewall_policy_rule_group_associated,
                )

                check = networkfirewall_policy_rule_group_associated()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == f"Network Firewall {FIREWALL_NAME} policy has at least one rule group associated."
                )
                assert result[0].region == AWS_REGION_US_EAST_1
                assert result[0].resource_id == FIREWALL_NAME
                assert result[0].resource_tags == []
                assert result[0].resource_arn == FIREWALL_ARN

    def test_networkfirewall_policy_both_rule_groups_associated(self):
        networkfirewall_client = mock.MagicMock
        networkfirewall_client.provider = set_mocked_aws_provider(
            [AWS_REGION_US_EAST_1]
        )
        networkfirewall_client.region = AWS_REGION_US_EAST_1
        networkfirewall_client.network_firewalls = {
            FIREWALL_ARN: Firewall(
                arn=FIREWALL_ARN,
                name=FIREWALL_NAME,
                region=AWS_REGION_US_EAST_1,
                policy_arn=POLICY_ARN,
                vpc_id=VPC_ID_PROTECTED,
                tags=[],
                encryption_type="CUSTOMER_KMS",
                deletion_protection=True,
                stateless_rule_groups=[
                    "arn:aws:network-firewall:us-east-1:123456789012:stateful-rule-group/my-stateless-rule-group"
                ],
                stateful_rule_groups=[
                    "arn:aws:network-firewall:us-east-1:123456789012:stateful-rule-group/my-stateful-rule-group"
                ],
            )
        }

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.networkfirewall.networkfirewall_policy_rule_group_associated.networkfirewall_policy_rule_group_associated.networkfirewall_client",
                new=networkfirewall_client,
            ):
                # Test Check
                from prowler.providers.aws.services.networkfirewall.networkfirewall_policy_rule_group_associated.networkfirewall_policy_rule_group_associated import (
                    networkfirewall_policy_rule_group_associated,
                )

                check = networkfirewall_policy_rule_group_associated()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == f"Network Firewall {FIREWALL_NAME} policy has at least one rule group associated."
                )
                assert result[0].region == AWS_REGION_US_EAST_1
                assert result[0].resource_id == FIREWALL_NAME
                assert result[0].resource_tags == []
                assert result[0].resource_arn == FIREWALL_ARN

    def test_networkfirewall_policy_no_rule_groups_associated(self):
        networkfirewall_client = mock.MagicMock
        networkfirewall_client.provider = set_mocked_aws_provider(
            [AWS_REGION_US_EAST_1]
        )
        networkfirewall_client.region = AWS_REGION_US_EAST_1
        networkfirewall_client.network_firewalls = {
            FIREWALL_ARN: Firewall(
                arn=FIREWALL_ARN,
                name=FIREWALL_NAME,
                region=AWS_REGION_US_EAST_1,
                policy_arn=POLICY_ARN,
                vpc_id=VPC_ID_PROTECTED,
                tags=[],
                encryption_type="CUSTOMER_KMS",
                deletion_protection=True,
            )
        }

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.networkfirewall.networkfirewall_policy_rule_group_associated.networkfirewall_policy_rule_group_associated.networkfirewall_client",
                new=networkfirewall_client,
            ):
                # Test Check
                from prowler.providers.aws.services.networkfirewall.networkfirewall_policy_rule_group_associated.networkfirewall_policy_rule_group_associated import (
                    networkfirewall_policy_rule_group_associated,
                )

                check = networkfirewall_policy_rule_group_associated()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == f"Network Firewall {FIREWALL_NAME} policy does not have rule groups associated."
                )
                assert result[0].region == AWS_REGION_US_EAST_1
                assert result[0].resource_id == FIREWALL_NAME
                assert result[0].resource_tags == []
                assert result[0].resource_arn == FIREWALL_ARN
