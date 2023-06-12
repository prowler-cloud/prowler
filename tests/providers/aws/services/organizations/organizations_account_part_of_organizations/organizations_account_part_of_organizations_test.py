from re import search
from unittest import mock

from boto3 import client, session
from moto import mock_organizations

from prowler.providers.aws.lib.audit_info.audit_info import AWS_Audit_Info
from prowler.providers.aws.services.organizations.organizations_service import (
    Organizations,
)

AWS_REGION = "us-east-1"


class Test_organizations_account_part_of_organizations:
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
            audited_account_arn=None,
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
                "prowler.providers.aws.services.organizations.organizations_account_part_of_organizations.organizations_account_part_of_organizations.organizations_client",
                new=Organizations(audit_info),
            ):
                # Test Check
                from prowler.providers.aws.services.organizations.organizations_account_part_of_organizations.organizations_account_part_of_organizations import (
                    organizations_account_part_of_organizations,
                )

                check = organizations_account_part_of_organizations()
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
    def test_organization(self):
        audit_info = self.set_mocked_audit_info()

        # Create Organization
        conn = client("organizations")
        response = conn.create_organization()

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.organizations.organizations_account_part_of_organizations.organizations_account_part_of_organizations.organizations_client",
                new=Organizations(audit_info),
            ):
                # Test Check
                from prowler.providers.aws.services.organizations.organizations_account_part_of_organizations.organizations_account_part_of_organizations import (
                    organizations_account_part_of_organizations,
                )

                check = organizations_account_part_of_organizations()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert search(
                    "Account is part of AWS Organization",
                    result[0].status_extended,
                )
                assert result[0].resource_id == response["Organization"]["Id"]
                assert result[0].resource_arn == response["Organization"]["Arn"]
                assert result[0].region == AWS_REGION
