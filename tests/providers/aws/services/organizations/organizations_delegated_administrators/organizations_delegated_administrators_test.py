from re import search
from unittest import mock

from boto3 import client, session
from moto import mock_organizations

from prowler.providers.aws.lib.audit_info.audit_info import AWS_Audit_Info
from prowler.providers.aws.services.organizations.organizations_service import (
    Organizations,
)

AWS_REGION = "us-east-1"


class Test_organizations_delegated_administrators:
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
                "prowler.providers.aws.services.organizations.organizations_delegated_administrators.organizations_delegated_administrators.organizations_client",
                new=Organizations(audit_info),
            ):
                # Test Check
                from prowler.providers.aws.services.organizations.organizations_delegated_administrators.organizations_delegated_administrators import (
                    organizations_delegated_administrators,
                )

                check = organizations_delegated_administrators()
                result = check.execute()

                assert len(result) == 0

    @mock_organizations
    def test_organization_no_delegations(self):
        audit_info = self.set_mocked_audit_info()

        # Create Organization
        conn = client("organizations", region_name=AWS_REGION)
        response = conn.create_organization()

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.organizations.organizations_delegated_administrators.organizations_delegated_administrators.organizations_client",
                new=Organizations(audit_info),
            ):
                # Test Check
                from prowler.providers.aws.services.organizations.organizations_delegated_administrators.organizations_delegated_administrators import (
                    organizations_delegated_administrators,
                )

                check = organizations_delegated_administrators()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert result[0].resource_id == response["Organization"]["Id"]
                assert result[0].resource_arn == response["Organization"]["Arn"]
                assert search(
                    "No Delegated Administrators",
                    result[0].status_extended,
                )
                assert result[0].region == AWS_REGION

    @mock_organizations
    def test_organization_trusted_delegated(self):
        audit_info = self.set_mocked_audit_info()

        # Create Organization
        conn = client("organizations", region_name=AWS_REGION)
        response = conn.create_organization()
        # Create Dummy Account
        account = conn.create_account(
            Email="test@test.com",
            AccountName="test",
        )
        # Delegate Administrator
        conn.register_delegated_administrator(
            AccountId=account["CreateAccountStatus"]["AccountId"],
            ServicePrincipal="config-multiaccountsetup.amazonaws.com",
        )

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.organizations.organizations_delegated_administrators.organizations_delegated_administrators.organizations_client",
                new=Organizations(audit_info),
            ):
                with mock.patch(
                    "prowler.providers.aws.services.organizations.organizations_delegated_administrators.organizations_delegated_administrators.get_config_var",
                    return_value=[account["CreateAccountStatus"]["AccountId"]],
                ):
                    # Test Check
                    from prowler.providers.aws.services.organizations.organizations_delegated_administrators.organizations_delegated_administrators import (
                        organizations_delegated_administrators,
                    )

                    check = organizations_delegated_administrators()
                    result = check.execute()

                    assert len(result) == 1
                    assert result[0].status == "PASS"
                    assert result[0].resource_id == response["Organization"]["Id"]
                    assert result[0].resource_arn == response["Organization"]["Arn"]
                    assert search(
                        "Trusted Delegated Administrator",
                        result[0].status_extended,
                    )
                    assert result[0].region == AWS_REGION

    @mock_organizations
    def test_organization_untrusted_delegated(self):
        audit_info = self.set_mocked_audit_info()

        # Create Organization
        conn = client("organizations", region_name=AWS_REGION)
        response = conn.create_organization()
        # Create Dummy Account
        account = conn.create_account(
            Email="test@test.com",
            AccountName="test",
        )
        # Delegate Administrator
        conn.register_delegated_administrator(
            AccountId=account["CreateAccountStatus"]["AccountId"],
            ServicePrincipal="config-multiaccountsetup.amazonaws.com",
        )

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.organizations.organizations_delegated_administrators.organizations_delegated_administrators.organizations_client",
                new=Organizations(audit_info),
            ):
                # Test Check
                from prowler.providers.aws.services.organizations.organizations_delegated_administrators.organizations_delegated_administrators import (
                    organizations_delegated_administrators,
                )

                check = organizations_delegated_administrators()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert result[0].resource_id == response["Organization"]["Id"]
                assert result[0].resource_arn == response["Organization"]["Arn"]
                assert search(
                    "Untrusted Delegated Administrator",
                    result[0].status_extended,
                )
                assert result[0].region == AWS_REGION
