from unittest import mock

from boto3 import client
from moto import mock_aws

from prowler.providers.aws.services.organizations.organizations_service import (
    Organizations,
)
from tests.providers.aws.utils import (
    AWS_REGION_EU_CENTRAL_1,
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_provider,
)


def scp_restrict_regions_with_deny():
    return '{"Version":"2012-10-17","Statement":{"Effect":"Deny","NotAction":"s3:*","Resource":"*","Condition":{"StringNotEquals":{"aws:RequestedRegion":["eu-central-1","eu-west-1"]}}}}'


class Test_organizations_scp_check_deny_regions:
    @mock_aws
    def test_no_organization(self):
        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1], create_default_organization=False
        )
        aws_provider._audit_config = {
            "organizations_enabled_regions": [AWS_REGION_EU_WEST_1]
        }
        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.organizations.organizations_scp_check_deny_regions.organizations_scp_check_deny_regions.organizations_client",
                new=Organizations(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.organizations.organizations_scp_check_deny_regions.organizations_scp_check_deny_regions import (
                    organizations_scp_check_deny_regions,
                )

                check = organizations_scp_check_deny_regions()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == "AWS Organizations is not in-use for this AWS Account."
                )
                assert result[0].resource_id == "unknown"
                assert (
                    result[0].resource_arn
                    == "arn:aws:organizations::123456789012:unknown"
                )
                assert result[0].region == AWS_REGION_EU_WEST_1

    @mock_aws
    def test_organization_without_scp_deny_regions(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        aws_provider._audit_config = {
            "organizations_enabled_regions": [AWS_REGION_EU_WEST_1]
        }

        # Create Organization
        conn = client("organizations", region_name=AWS_REGION_EU_WEST_1)
        response = conn.create_organization()
        org_id = response["Organization"]["Id"]

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.organizations.organizations_scp_check_deny_regions.organizations_scp_check_deny_regions.organizations_client",
                new=Organizations(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.organizations.organizations_scp_check_deny_regions.organizations_scp_check_deny_regions import (
                    organizations_scp_check_deny_regions,
                )

                check = organizations_scp_check_deny_regions()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert result[0].resource_id == response["Organization"]["Id"]
                # Using this because there is no way to get the ARN of the organization
                assert (
                    "arn:aws:organizations::123456789012:organization/o-"
                    in result[0].resource_arn
                )
                assert (
                    result[0].status_extended
                    == f"AWS Organization {org_id} has SCP policies but don't restrict AWS Regions."
                )
                assert result[0].region == AWS_REGION_EU_WEST_1

    @mock_aws
    def test_organization_with_scp_deny_regions_valid(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        # Create Organization
        conn = client("organizations", region_name=AWS_REGION_EU_WEST_1)
        response = conn.create_organization()
        # Create Policy
        response_policy = conn.create_policy(
            Content=scp_restrict_regions_with_deny(),
            Description="Test",
            Name="Test",
            Type="SERVICE_CONTROL_POLICY",
        )
        org_id = response["Organization"]["Id"]
        policy_id = response_policy["Policy"]["PolicySummary"]["Id"]

        # Set config variable
        aws_provider._audit_config = {"organizations_enabled_regions": ["eu-central-1"]}

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.organizations.organizations_scp_check_deny_regions.organizations_scp_check_deny_regions.organizations_client",
                new=Organizations(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.organizations.organizations_scp_check_deny_regions.organizations_scp_check_deny_regions import (
                    organizations_scp_check_deny_regions,
                )

                check = organizations_scp_check_deny_regions()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert result[0].resource_id == response["Organization"]["Id"]
                assert result[0].resource_arn == response["Organization"]["Arn"]
                assert (
                    result[0].status_extended
                    == f"AWS Organization {org_id} has SCP policy {policy_id} restricting all configured regions found."
                )
                assert result[0].region == AWS_REGION_EU_WEST_1

    @mock_aws
    def test_organization_with_scp_deny_regions_not_valid(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        # Create Organization
        conn = client("organizations", region_name=AWS_REGION_EU_WEST_1)
        response = conn.create_organization()
        # Create Policy
        response_policy = conn.create_policy(
            Content=scp_restrict_regions_with_deny(),
            Description="Test",
            Name="Test",
            Type="SERVICE_CONTROL_POLICY",
        )
        org_id = response["Organization"]["Id"]
        policy_id = response_policy["Policy"]["PolicySummary"]["Id"]

        # Set config variable
        aws_provider._audit_config = {"organizations_enabled_regions": ["us-east-1"]}

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.organizations.organizations_scp_check_deny_regions.organizations_scp_check_deny_regions.organizations_client",
                new=Organizations(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.organizations.organizations_scp_check_deny_regions.organizations_scp_check_deny_regions import (
                    organizations_scp_check_deny_regions,
                )

                check = organizations_scp_check_deny_regions()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert result[0].resource_id == response["Organization"]["Id"]
                assert (
                    "arn:aws:organizations::123456789012:organization/o-"
                    in result[0].resource_arn
                )
                assert (
                    result[0].status_extended
                    == f"AWS Organization {org_id} has SCP policies {policy_id} restricting some AWS Regions, but not all the configured ones, please check config."
                )
                assert result[0].region == AWS_REGION_EU_WEST_1

    @mock_aws
    def test_organization_with_scp_deny_all_regions_valid(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        aws_provider._audit_config = {
            "organizations_enabled_regions": [
                AWS_REGION_EU_WEST_1,
                AWS_REGION_EU_CENTRAL_1,
            ]
        }
        # Create Organization
        conn = client("organizations", region_name=AWS_REGION_EU_WEST_1)
        response = conn.create_organization()
        # Create Policy
        response_policy = conn.create_policy(
            Content=scp_restrict_regions_with_deny(),
            Description="Test",
            Name="Test",
            Type="SERVICE_CONTROL_POLICY",
        )
        org_id = response["Organization"]["Id"]
        policy_id = response_policy["Policy"]["PolicySummary"]["Id"]

        # Set config variable
        aws_provider._audit_config = {"organizations_enabled_regions": ["eu-central-1"]}

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.organizations.organizations_scp_check_deny_regions.organizations_scp_check_deny_regions.organizations_client",
                new=Organizations(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.organizations.organizations_scp_check_deny_regions.organizations_scp_check_deny_regions import (
                    organizations_scp_check_deny_regions,
                )

                check = organizations_scp_check_deny_regions()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert result[0].resource_id == response["Organization"]["Id"]
                assert result[0].resource_arn == response["Organization"]["Arn"]
                assert (
                    result[0].status_extended
                    == f"AWS Organization {org_id} has SCP policy {policy_id} restricting all configured regions found."
                )
                assert result[0].region == AWS_REGION_EU_WEST_1

    @mock_aws
    def test_access_denied(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        aws_provider._audit_config = {
            "organizations_enabled_regions": [
                AWS_REGION_EU_WEST_1,
                AWS_REGION_EU_CENTRAL_1,
            ]
        }

        # Create Organization
        conn = client("organizations", region_name=AWS_REGION_EU_WEST_1)
        response = conn.create_organization()
        response["Organization"]["Arn"]

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.organizations.organizations_scp_check_deny_regions.organizations_scp_check_deny_regions.organizations_client",
                new=Organizations(aws_provider),
            ) as organizations_client:
                # Test Check
                from prowler.providers.aws.services.organizations.organizations_scp_check_deny_regions.organizations_scp_check_deny_regions import (
                    organizations_scp_check_deny_regions,
                )

                organizations_client.organization.policies = None

                check = organizations_scp_check_deny_regions()
                result = check.execute()

                assert len(result) == 0
