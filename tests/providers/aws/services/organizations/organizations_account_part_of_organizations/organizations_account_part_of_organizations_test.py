from unittest import mock

from boto3 import client
from moto import mock_aws

from prowler.providers.aws.services.organizations.organizations_service import (
    Organizations,
)
from tests.providers.aws.utils import AWS_REGION_EU_WEST_1, set_mocked_aws_provider


class Test_organizations_account_part_of_organizations:
    @mock_aws
    def test_no_organization(self):
        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1], create_default_organization=False
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.organizations.organizations_account_part_of_organizations.organizations_account_part_of_organizations.organizations_client",
                new=Organizations(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.organizations.organizations_account_part_of_organizations.organizations_account_part_of_organizations import (
                    organizations_account_part_of_organizations,
                )

                check = organizations_account_part_of_organizations()
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
    def test_organization(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        # Create Organization
        conn = client("organizations")
        response = conn.create_organization()
        org_id = response["Organization"]["Id"]

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.organizations.organizations_account_part_of_organizations.organizations_account_part_of_organizations.organizations_client",
                new=Organizations(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.organizations.organizations_account_part_of_organizations.organizations_account_part_of_organizations import (
                    organizations_account_part_of_organizations,
                )

                check = organizations_account_part_of_organizations()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == f"AWS Organization {org_id} contains this AWS account."
                )
                assert result[0].resource_id == response["Organization"]["Id"]
                assert result[0].resource_arn == response["Organization"]["Arn"]
                assert result[0].region == AWS_REGION_EU_WEST_1
