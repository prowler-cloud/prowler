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


def mock_rcp_with_encryption():
    """Mock RCP that enforces encryption"""
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
            },
            {
                "Sid": "RequireEBSEncryption",
                "Effect": "Deny",
                "Action": ["ec2:CreateVolume"],
                "Resource": "*",
                "Condition": {
                    "Bool": {
                        "ec2:Encrypted": "false"
                    }
                }
            }
        ]
    }


def mock_rcp_without_encryption():
    """Mock RCP that doesn't enforce encryption"""
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "RestrictRegions",
                "Effect": "Deny",
                "Action": "*",
                "Resource": "*",
                "Condition": {
                    "StringNotEquals": {
                        "aws:RequestedRegion": ["us-east-1", "eu-west-1"]
                    }
                }
            }
        ]
    }


class Test_organizations_rcps_enforce_encryption:
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
                "prowler.providers.aws.services.organizations.organizations_rcps_enforce_encryption.organizations_rcps_enforce_encryption.organizations_client",
                new=Organizations(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.organizations.organizations_rcps_enforce_encryption.organizations_rcps_enforce_encryption import (
                    organizations_rcps_enforce_encryption,
                )

                check = organizations_rcps_enforce_encryption()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == "AWS Organizations is not in-use for this AWS Account."
                )
                assert result[0].resource_id == "unknown"

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
                "prowler.providers.aws.services.organizations.organizations_rcps_enforce_encryption.organizations_rcps_enforce_encryption.organizations_client",
                new=Organizations(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.organizations.organizations_rcps_enforce_encryption.organizations_rcps_enforce_encryption import (
                    organizations_rcps_enforce_encryption,
                )

                check = organizations_rcps_enforce_encryption()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert result[0].resource_id == org_id
                assert "does not have Resource Control Policies enforcing encryption" in result[0].status_extended

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

        # Mock organization with only RCPFullAWSAccess
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
                "prowler.providers.aws.services.organizations.organizations_rcps_enforce_encryption.organizations_rcps_enforce_encryption.organizations_client",
                new=mocked_org,
            ):
                # Test Check
                from prowler.providers.aws.services.organizations.organizations_rcps_enforce_encryption.organizations_rcps_enforce_encryption import (
                    organizations_rcps_enforce_encryption,
                )

                check = organizations_rcps_enforce_encryption()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert result[0].resource_id == org_id
                assert "does not have Resource Control Policies enforcing encryption" in result[0].status_extended

    @mock_aws
    def test_organization_with_encryption_rcps(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        aws_provider._audit_config = {
            "organizations_enabled_regions": [AWS_REGION_EU_WEST_1]
        }

        # Create Organization
        conn = client("organizations", region_name=AWS_REGION_EU_WEST_1)
        response = conn.describe_organization()
        org_id = response["Organization"]["Id"]

        # Mock organization with encryption RCPs
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
                    content=mock_rcp_with_encryption(),
                    targets=["r-root"],
                ),
            ]
        }

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.organizations.organizations_rcps_enforce_encryption.organizations_rcps_enforce_encryption.organizations_client",
                new=mocked_org,
            ):
                # Test Check
                from prowler.providers.aws.services.organizations.organizations_rcps_enforce_encryption.organizations_rcps_enforce_encryption import (
                    organizations_rcps_enforce_encryption,
                )

                check = organizations_rcps_enforce_encryption()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert result[0].resource_id == org_id
                assert "1 Resource Control Policies enforcing encryption" in result[0].status_extended

    @mock_aws
    def test_organization_with_non_encryption_rcps(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        aws_provider._audit_config = {
            "organizations_enabled_regions": [AWS_REGION_EU_WEST_1]
        }

        # Create Organization
        conn = client("organizations", region_name=AWS_REGION_EU_WEST_1)
        response = conn.describe_organization()
        org_id = response["Organization"]["Id"]

        # Mock organization with non-encryption RCPs
        mocked_org = Organizations(aws_provider)
        mocked_org.organization.policies = {
            "RESOURCE_CONTROL_POLICY": [
                Policy(
                    arn="arn:aws:organizations::123456789012:policy/o-test/resource_control_policy/p-region",
                    id="p-region",
                    type="RESOURCE_CONTROL_POLICY",
                    aws_managed=False,
                    content=mock_rcp_without_encryption(),
                    targets=["r-root"],
                ),
            ]
        }

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.organizations.organizations_rcps_enforce_encryption.organizations_rcps_enforce_encryption.organizations_client",
                new=mocked_org,
            ):
                # Test Check
                from prowler.providers.aws.services.organizations.organizations_rcps_enforce_encryption.organizations_rcps_enforce_encryption import (
                    organizations_rcps_enforce_encryption,
                )

                check = organizations_rcps_enforce_encryption()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert result[0].resource_id == org_id
                assert "does not have Resource Control Policies enforcing encryption" in result[0].status_extended

    @mock_aws
    def test_encryption_detection_with_kms_conditions(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        aws_provider._audit_config = {
            "organizations_enabled_regions": [AWS_REGION_EU_WEST_1]
        }

        # Create Organization
        conn = client("organizations", region_name=AWS_REGION_EU_WEST_1)
        response = conn.describe_organization()
        org_id = response["Organization"]["Id"]

        # Mock organization with KMS encryption RCP
        mocked_org = Organizations(aws_provider)
        mocked_org.organization.policies = {
            "RESOURCE_CONTROL_POLICY": [
                Policy(
                    arn="arn:aws:organizations::123456789012:policy/o-test/resource_control_policy/p-kms",
                    id="p-kms",
                    
                    type="RESOURCE_CONTROL_POLICY",
                    aws_managed=False,
                    content={
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Deny",
                                "Action": "*",
                                "Resource": "*",
                                "Condition": {
                                    "StringNotLike": {
                                        "kms:EncryptionContext:aws:s3:arn": "*"
                                    }
                                }
                            }
                        ]
                    },
                    targets=["r-root"],
                ),
            ]
        }

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.organizations.organizations_rcps_enforce_encryption.organizations_rcps_enforce_encryption.organizations_client",
                new=mocked_org,
            ):
                # Test Check
                from prowler.providers.aws.services.organizations.organizations_rcps_enforce_encryption.organizations_rcps_enforce_encryption import (
                    organizations_rcps_enforce_encryption,
                )

                check = organizations_rcps_enforce_encryption()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert result[0].resource_id == org_id
                assert "Resource Control Policies enforcing encryption" in result[0].status_extended