from unittest import mock

from boto3 import client
from moto import mock_aws

from prowler.providers.aws.services.organizations.organizations_service import (
    Organizations,
    Policy,
)
from tests.providers.aws.utils import (
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_provider,
)


def mock_rcp_full_aws_access():
    """Mock RCPFullAWSAccess policy content"""
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*"
            }
        ]
    }


def mock_restrictive_rcp():
    """Mock a restrictive RCP that enforces encryption"""
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "RequireS3Encryption",
                "Effect": "Deny",
                "Action": ["s3:PutObject"],
                "Resource": "*",
                "Condition": {
                    "Null": {
                        "s3:x-amz-server-side-encryption": "true"
                    }
                }
            }
        ]
    }


class Test_organizations_resource_control_policies_enabled:
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
                "prowler.providers.aws.services.organizations.organizations_resource_control_policies_enabled.organizations_resource_control_policies_enabled.organizations_client",
                new=Organizations(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.organizations.organizations_resource_control_policies_enabled.organizations_resource_control_policies_enabled import (
                    organizations_resource_control_policies_enabled,
                )

                check = organizations_resource_control_policies_enabled()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == "AWS Organizations is not in-use for this AWS Account."
                )
                assert result[0].resource_id == "unknown"
                assert result[0].region == AWS_REGION_EU_WEST_1

    @mock_aws
    def test_organization_without_rcps(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        aws_provider._audit_config = {
            "organizations_enabled_regions": [AWS_REGION_EU_WEST_1]
        }

        # Create Organization
        conn = client("organizations", region_name=AWS_REGION_EU_WEST_1)
        response = conn.describe_organization()
        org_id = response["Organization"]["Id"]

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.organizations.organizations_resource_control_policies_enabled.organizations_resource_control_policies_enabled.organizations_client",
                new=Organizations(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.organizations.organizations_resource_control_policies_enabled.organizations_resource_control_policies_enabled import (
                    organizations_resource_control_policies_enabled,
                )

                check = organizations_resource_control_policies_enabled()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert result[0].resource_id == org_id
                # The test might fail with a different message if moto adds default policies
                assert "Resource Control Policies" in result[0].status_extended

    @mock_aws
    def test_organization_with_only_rcp_full_aws_access(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        aws_provider._audit_config = {
            "organizations_enabled_regions": [AWS_REGION_EU_WEST_1]
        }

        # Create Organization
        conn = client("organizations", region_name=AWS_REGION_EU_WEST_1)
        response = conn.describe_organization()
        org_id = response["Organization"]["Id"]

        # Mock organization with RCPFullAWSAccess
        mocked_org = Organizations(aws_provider)
        mocked_org.organization.policies = {
            "RESOURCE_CONTROL_POLICY": [
                Policy(
                    arn="arn:aws:organizations::123456789012:policy/o-test/resource_control_policy/p-FullAWSAccess",
                    id="p-FullAWSAccess",
                    type="RESOURCE_CONTROL_POLICY",
                    aws_managed=True,
                    content=mock_rcp_full_aws_access(),
                    targets=["r-root"],
                )
            ]
        }

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.organizations.organizations_resource_control_policies_enabled.organizations_resource_control_policies_enabled.organizations_client",
                new=mocked_org,
            ):
                # Test Check
                from prowler.providers.aws.services.organizations.organizations_resource_control_policies_enabled.organizations_resource_control_policies_enabled import (
                    organizations_resource_control_policies_enabled,
                )

                check = organizations_resource_control_policies_enabled()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert result[0].resource_id == org_id
                assert "only RCPFullAWSAccess is attached" in result[0].status_extended
                assert "provides no security value" in result[0].status_extended

    @mock_aws
    def test_organization_with_restrictive_rcps(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        aws_provider._audit_config = {
            "organizations_enabled_regions": [AWS_REGION_EU_WEST_1]
        }

        # Create Organization
        conn = client("organizations", region_name=AWS_REGION_EU_WEST_1)
        response = conn.describe_organization()
        org_id = response["Organization"]["Id"]

        # Mock organization with restrictive RCPs
        mocked_org = Organizations(aws_provider)
        mocked_org.organization.policies = {
            "RESOURCE_CONTROL_POLICY": [
                Policy(
                    arn="arn:aws:organizations::123456789012:policy/o-test/resource_control_policy/p-FullAWSAccess",
                    id="p-FullAWSAccess",
                    type="RESOURCE_CONTROL_POLICY",
                    aws_managed=True,
                    content=mock_rcp_full_aws_access(),
                    targets=["r-root"],
                ),
                Policy(
                    arn="arn:aws:organizations::123456789012:policy/o-test/resource_control_policy/p-encryption",
                    id="p-encryption",
                    type="RESOURCE_CONTROL_POLICY",
                    aws_managed=False,
                    content=mock_restrictive_rcp(),
                    targets=["r-root"],
                ),
            ]
        }

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.organizations.organizations_resource_control_policies_enabled.organizations_resource_control_policies_enabled.organizations_client",
                new=mocked_org,
            ):
                # Test Check
                from prowler.providers.aws.services.organizations.organizations_resource_control_policies_enabled.organizations_resource_control_policies_enabled import (
                    organizations_resource_control_policies_enabled,
                )

                check = organizations_resource_control_policies_enabled()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert result[0].resource_id == org_id
                assert "1 restrictive Resource Control Policies" in result[0].status_extended

    @mock_aws
    def test_organization_with_rcps_not_attached(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        aws_provider._audit_config = {
            "organizations_enabled_regions": [AWS_REGION_EU_WEST_1]
        }

        # Create Organization
        conn = client("organizations", region_name=AWS_REGION_EU_WEST_1)
        response = conn.describe_organization()
        org_id = response["Organization"]["Id"]

        # Mock organization with RCPs but not attached
        mocked_org = Organizations(aws_provider)
        mocked_org.organization.policies = {
            "RESOURCE_CONTROL_POLICY": [
                Policy(
                    arn="arn:aws:organizations::123456789012:policy/o-test/resource_control_policy/p-encryption",
                    id="p-encryption",
                    type="RESOURCE_CONTROL_POLICY",
                    aws_managed=False,
                    content=mock_restrictive_rcp(),
                    targets=[],  # No targets
                )
            ]
        }

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.organizations.organizations_resource_control_policies_enabled.organizations_resource_control_policies_enabled.organizations_client",
                new=mocked_org,
            ):
                # Test Check
                from prowler.providers.aws.services.organizations.organizations_resource_control_policies_enabled.organizations_resource_control_policies_enabled import (
                    organizations_resource_control_policies_enabled,
                )

                check = organizations_resource_control_policies_enabled()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert result[0].resource_id == org_id
                assert "none are attached to targets" in result[0].status_extended