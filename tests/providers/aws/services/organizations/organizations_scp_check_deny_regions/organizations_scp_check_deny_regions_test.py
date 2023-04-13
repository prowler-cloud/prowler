from re import search
from unittest import mock

from boto3 import client, session
from moto import mock_organizations

from prowler.providers.aws.lib.audit_info.audit_info import AWS_Audit_Info
from prowler.providers.aws.services.organizations.organizations_service import (
    Organizations,
)

AWS_REGION = "us-east-1"


def scp_restrict_regions_with_deny():
    return '{"Version":"2012-10-17","Statement":{"Effect":"Deny","NotAction":"s3:*","Resource":"*","Condition":{"StringNotEquals":{"aws:RequestedRegion":["eu-central-1"]}}}}'


class Test_organizations_scp_check_deny_regions:
    # Mocked Audit Info
    def set_mocked_audit_info(self):
        audit_info = AWS_Audit_Info(
            session_config=None,
            original_session=None,
            audit_session=session.Session(
                profile_name=None,
                botocore_session=None,
            ),
            audited_account=None,
            audited_user_id=None,
            audited_partition="aws",
            audited_identity_arn=None,
            profile=None,
            profile_region=None,
            credentials=None,
            assumed_role_info=None,
            audited_regions=[AWS_REGION],
            organizations_metadata=None,
            audit_resources=None,
        )
        return audit_info

    @mock_organizations
    def test_no_organization(self):
        audit_info = self.set_mocked_audit_info()

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.organizations.organizations_scp_check_deny_regions.organizations_scp_check_deny_regions.organizations_client",
                new=Organizations(audit_info),
            ):
                # Test Check
                from prowler.providers.aws.services.organizations.organizations_scp_check_deny_regions.organizations_scp_check_deny_regions import (
                    organizations_scp_check_deny_regions,
                )

                check = organizations_scp_check_deny_regions()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert search(
                    "AWS Organizations is not in-use for this AWS Account",
                    result[0].status_extended,
                )
                assert result[0].resource_id == "AWS Organization"
                assert result[0].resource_arn == ""
                assert result[0].region == AWS_REGION

    @mock_organizations
    def test_organization_without_scp_deny_regions(self):
        audit_info = self.set_mocked_audit_info()

        # Create Organization
        conn = client("organizations", region_name=AWS_REGION)
        response = conn.create_organization()

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.organizations.organizations_scp_check_deny_regions.organizations_scp_check_deny_regions.organizations_client",
                new=Organizations(audit_info),
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
                assert result[0].resource_arn == response["Organization"]["Arn"]
                assert search(
                    "level but don't restrict AWS Regions",
                    result[0].status_extended,
                )
                assert result[0].region == AWS_REGION

    @mock_organizations
    def test_organization_with_scp_deny_regions_valid(self):
        audit_info = self.set_mocked_audit_info()

        # Create Organization
        conn = client("organizations", region_name=AWS_REGION)
        response = conn.create_organization()
        # Create Policy
        conn.create_policy(
            Content=scp_restrict_regions_with_deny(),
            Description="Test",
            Name="Test",
            Type="SERVICE_CONTROL_POLICY",
        )

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.organizations.organizations_scp_check_deny_regions.organizations_scp_check_deny_regions.organizations_client",
                new=Organizations(audit_info),
            ):
                with mock.patch(
                    "prowler.providers.aws.services.organizations.organizations_scp_check_deny_regions.organizations_scp_check_deny_regions.get_config_var",
                    return_value=["eu-central-1"],
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
                    assert search(
                        "restricting all configured regions found",
                        result[0].status_extended,
                    )
                    assert result[0].region == AWS_REGION

    @mock_organizations
    def test_organization_with_scp_deny_regions_not_valid(self):
        audit_info = self.set_mocked_audit_info()

        # Create Organization
        conn = client("organizations", region_name=AWS_REGION)
        response = conn.create_organization()
        # Create Policy
        conn.create_policy(
            Content=scp_restrict_regions_with_deny(),
            Description="Test",
            Name="Test",
            Type="SERVICE_CONTROL_POLICY",
        )

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.organizations.organizations_scp_check_deny_regions.organizations_scp_check_deny_regions.organizations_client",
                new=Organizations(audit_info),
            ):
                with mock.patch(
                    "prowler.providers.aws.services.organizations.organizations_scp_check_deny_regions.organizations_scp_check_deny_regions.get_config_var",
                    return_value=["us-east-1"],
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
                    assert result[0].resource_arn == response["Organization"]["Arn"]
                    assert search(
                        "restricting some AWS Regions, but not all the configured ones, please check config...",
                        result[0].status_extended,
                    )
                    assert result[0].region == AWS_REGION
