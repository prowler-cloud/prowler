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


def mock_rcp_with_network_security():
    """Mock RCP that enforces network security"""
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "RequireSecureTransport",
                "Effect": "Deny",
                "Action": "*",
                "Resource": "*",
                "Condition": {
                    "Bool": {
                        "aws:SecureTransport": "false"
                    }
                }
            }
        ]
    }


class Test_organizations_rcps_enforce_network_security:
    @mock_aws
    def test_organization_without_rcps(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        aws_provider._audit_config = {
            "organizations_enabled_regions": [AWS_REGION_EU_WEST_1]
        }

        conn = client("organizations", region_name=AWS_REGION_EU_WEST_1)
        response = conn.describe_organization()
        org_id = response["Organization"]["Id"]

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.organizations.organizations_rcps_enforce_network_security.organizations_rcps_enforce_network_security.organizations_client",
                new=Organizations(aws_provider),
            ):
                from prowler.providers.aws.services.organizations.organizations_rcps_enforce_network_security.organizations_rcps_enforce_network_security import (
                    organizations_rcps_enforce_network_security,
                )

                check = organizations_rcps_enforce_network_security()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert result[0].resource_id == org_id
                assert "does not have Resource Control Policies enforcing network security" in result[0].status_extended

    @mock_aws
    def test_organization_with_network_security_rcps(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        aws_provider._audit_config = {
            "organizations_enabled_regions": [AWS_REGION_EU_WEST_1]
        }

        conn = client("organizations", region_name=AWS_REGION_EU_WEST_1)
        response = conn.describe_organization()
        org_id = response["Organization"]["Id"]

        mocked_org = Organizations(aws_provider)
        mocked_org.organization.policies = {
            "RESOURCE_CONTROL_POLICY": [
                Policy(
                    arn="arn:aws:organizations::123456789012:policy/o-test/resource_control_policy/p-network",
                    id="p-network",
                    
                    type="RESOURCE_CONTROL_POLICY",
                    aws_managed=False,
                    content=mock_rcp_with_network_security(),
                    targets=["r-root"],
                ),
            ]
        }

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.organizations.organizations_rcps_enforce_network_security.organizations_rcps_enforce_network_security.organizations_client",
                new=mocked_org,
            ):
                from prowler.providers.aws.services.organizations.organizations_rcps_enforce_network_security.organizations_rcps_enforce_network_security import (
                    organizations_rcps_enforce_network_security,
                )

                check = organizations_rcps_enforce_network_security()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert result[0].resource_id == org_id
                assert "Resource Control Policies enforcing network security" in result[0].status_extended