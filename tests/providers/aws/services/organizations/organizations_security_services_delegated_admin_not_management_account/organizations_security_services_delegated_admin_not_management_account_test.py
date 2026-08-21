from unittest import mock

from boto3 import client
from moto import mock_aws

from prowler.providers.aws.services.organizations.organizations_service import (
    DelegatedAdministrator,
    Organizations,
)
from tests.providers.aws.utils import AWS_REGION_EU_WEST_1, set_mocked_aws_provider

CHECK_MODULE = "prowler.providers.aws.services.organizations.organizations_security_services_delegated_admin_not_management_account.organizations_security_services_delegated_admin_not_management_account"
DELEGATED_ADMIN_ACCOUNT_ID = "222222222222"
SECOND_DELEGATED_ADMIN_ACCOUNT_ID = "333333333333"


def delegated_administrator(account_id: str) -> DelegatedAdministrator:
    return DelegatedAdministrator(
        arn=f"arn:aws:organizations::123456789012:account/o-abcde12345/{account_id}",
        id=account_id,
        name=f"account-{account_id}",
        email=f"{account_id}@example.com",
        status="ACTIVE",
        joinedmethod="CREATED",
    )


def organizations_with(
    aws_provider,
    enabled_service_principals,
    delegated_service_principals,
    delegated_administrators=None,
):
    """Build the Organizations client with a given delegation configuration.

    The organization itself comes from moto, so the management account ID under test
    is the one the API reports rather than a constant this test invented.
    """
    organizations = Organizations(aws_provider)
    organizations.organization.enabled_service_principals = enabled_service_principals
    organizations.organization.delegated_service_principals = (
        delegated_service_principals
    )
    if delegated_administrators is None and delegated_service_principals:
        delegated_administrators = [
            delegated_administrator(account_id)
            for account_id in delegated_service_principals
        ]
    organizations.organization.delegated_administrators = delegated_administrators or []
    return organizations


class Test_organizations_security_services_delegated_admin_not_management_account:
    @mock_aws
    def test_no_organization(self):
        """AWSOrganizationsNotInUseException reaches no verdict rather than a PASS."""
        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1], create_default_organization=False
        )
        organizations = Organizations(aws_provider)
        assert organizations.organization.status == "NOT_AVAILABLE"

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                f"{CHECK_MODULE}.organizations_client",
                new=organizations,
            ):
                from prowler.providers.aws.services.organizations.organizations_security_services_delegated_admin_not_management_account.organizations_security_services_delegated_admin_not_management_account import (
                    organizations_security_services_delegated_admin_not_management_account,
                )

                check = (
                    organizations_security_services_delegated_admin_not_management_account()
                )
                result = check.execute()

                assert len(result) == 0

    @mock_aws
    def test_organization_unknown(self):
        """No verdict when DescribeOrganization did not yield an organization."""
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        organizations = Organizations(aws_provider)
        organizations.organization = None

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(f"{CHECK_MODULE}.organizations_client", new=organizations):
                from prowler.providers.aws.services.organizations.organizations_security_services_delegated_admin_not_management_account.organizations_security_services_delegated_admin_not_management_account import (
                    organizations_security_services_delegated_admin_not_management_account,
                )

                check = (
                    organizations_security_services_delegated_admin_not_management_account()
                )
                result = check.execute()

                assert len(result) == 0

    @mock_aws
    def test_delegated_administrators_unreadable(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        conn = client("organizations", region_name=AWS_REGION_EU_WEST_1)
        organization = conn.describe_organization()["Organization"]
        organizations = organizations_with(
            aws_provider,
            enabled_service_principals=["guardduty.amazonaws.com"],
            delegated_service_principals={},
            delegated_administrators=None,
        )
        organizations.organization.delegated_administrators = None

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(f"{CHECK_MODULE}.organizations_client", new=organizations):
                from prowler.providers.aws.services.organizations.organizations_security_services_delegated_admin_not_management_account.organizations_security_services_delegated_admin_not_management_account import (
                    organizations_security_services_delegated_admin_not_management_account,
                )

                check = (
                    organizations_security_services_delegated_admin_not_management_account()
                )
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "MANUAL"
                assert result[0].resource_id == organization["Id"]
                assert result[0].resource_arn == organization["Arn"]
                assert result[0].region == AWS_REGION_EU_WEST_1
                assert result[0].status_extended == (
                    f"AWS Organization {organization['Id']} delegated administration "
                    f"of the security services could not be determined; run this "
                    f"check from the organization management account."
                )

    @mock_aws
    def test_enabled_service_principals_unreadable(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        conn = client("organizations", region_name=AWS_REGION_EU_WEST_1)
        organization = conn.describe_organization()["Organization"]
        organizations = organizations_with(
            aws_provider,
            enabled_service_principals=None,
            delegated_service_principals={
                DELEGATED_ADMIN_ACCOUNT_ID: ["guardduty.amazonaws.com"]
            },
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(f"{CHECK_MODULE}.organizations_client", new=organizations):
                from prowler.providers.aws.services.organizations.organizations_security_services_delegated_admin_not_management_account.organizations_security_services_delegated_admin_not_management_account import (
                    organizations_security_services_delegated_admin_not_management_account,
                )

                check = (
                    organizations_security_services_delegated_admin_not_management_account()
                )
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "MANUAL"
                assert result[0].status_extended == (
                    f"AWS Organization {organization['Id']} delegated administration "
                    f"of the security services could not be determined; run this "
                    f"check from the organization management account."
                )

    @mock_aws
    def test_delegated_services_unreadable_for_one_administrator(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        conn = client("organizations", region_name=AWS_REGION_EU_WEST_1)
        organization = conn.describe_organization()["Organization"]
        organizations = organizations_with(
            aws_provider,
            enabled_service_principals=["guardduty.amazonaws.com"],
            delegated_service_principals={
                DELEGATED_ADMIN_ACCOUNT_ID: ["guardduty.amazonaws.com"],
                SECOND_DELEGATED_ADMIN_ACCOUNT_ID: None,
            },
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(f"{CHECK_MODULE}.organizations_client", new=organizations):
                from prowler.providers.aws.services.organizations.organizations_security_services_delegated_admin_not_management_account.organizations_security_services_delegated_admin_not_management_account import (
                    organizations_security_services_delegated_admin_not_management_account,
                )

                check = (
                    organizations_security_services_delegated_admin_not_management_account()
                )
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "MANUAL"
                assert result[0].status_extended == (
                    f"AWS Organization {organization['Id']} delegated administration "
                    f"of the security services could not be determined; run this "
                    f"check from the organization management account."
                )

    @mock_aws
    def test_no_security_service_integrated(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        conn = client("organizations", region_name=AWS_REGION_EU_WEST_1)
        organization = conn.describe_organization()["Organization"]
        organizations = organizations_with(
            aws_provider,
            enabled_service_principals=["sso.amazonaws.com", "ram.amazonaws.com"],
            delegated_service_principals={
                DELEGATED_ADMIN_ACCOUNT_ID: ["sso.amazonaws.com"]
            },
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(f"{CHECK_MODULE}.organizations_client", new=organizations):
                from prowler.providers.aws.services.organizations.organizations_security_services_delegated_admin_not_management_account.organizations_security_services_delegated_admin_not_management_account import (
                    organizations_security_services_delegated_admin_not_management_account,
                )

                check = (
                    organizations_security_services_delegated_admin_not_management_account()
                )
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "MANUAL"
                assert result[0].status_extended == (
                    f"AWS Organization {organization['Id']} has no security service "
                    f"integrated with the organization, so no security service is "
                    f"administered organization-wide."
                )

    @mock_aws
    def test_service_principal_field_missing_from_response(self):
        """A renamed ServicePrincipal member must not read as a compliant organization."""
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        conn = client("organizations", region_name=AWS_REGION_EU_WEST_1)
        organization = conn.describe_organization()["Organization"]
        organizations = organizations_with(
            aws_provider,
            enabled_service_principals=[None],
            delegated_service_principals={DELEGATED_ADMIN_ACCOUNT_ID: [None]},
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(f"{CHECK_MODULE}.organizations_client", new=organizations):
                from prowler.providers.aws.services.organizations.organizations_security_services_delegated_admin_not_management_account.organizations_security_services_delegated_admin_not_management_account import (
                    organizations_security_services_delegated_admin_not_management_account,
                )

                check = (
                    organizations_security_services_delegated_admin_not_management_account()
                )
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "MANUAL"
                assert result[0].status_extended == (
                    f"AWS Organization {organization['Id']} has no security service "
                    f"integrated with the organization, so no security service is "
                    f"administered organization-wide."
                )

    @mock_aws
    def test_security_service_without_delegated_administrator(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        conn = client("organizations", region_name=AWS_REGION_EU_WEST_1)
        organization = conn.describe_organization()["Organization"]
        organizations = organizations_with(
            aws_provider,
            enabled_service_principals=["guardduty.amazonaws.com"],
            delegated_service_principals={},
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(f"{CHECK_MODULE}.organizations_client", new=organizations):
                from prowler.providers.aws.services.organizations.organizations_security_services_delegated_admin_not_management_account.organizations_security_services_delegated_admin_not_management_account import (
                    organizations_security_services_delegated_admin_not_management_account,
                )

                check = (
                    organizations_security_services_delegated_admin_not_management_account()
                )
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert result[0].resource_id == organization["Id"]
                assert result[0].resource_arn == organization["Arn"]
                assert result[0].region == AWS_REGION_EU_WEST_1
                assert result[0].status_extended == (
                    f"AWS Organization {organization['Id']} administers "
                    f"guardduty.amazonaws.com from the management account "
                    f"{organization['MasterAccountId']} instead of a delegated "
                    f"administrator account."
                )

    @mock_aws
    def test_management_account_is_the_delegated_administrator(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        conn = client("organizations", region_name=AWS_REGION_EU_WEST_1)
        organization = conn.describe_organization()["Organization"]
        organizations = organizations_with(
            aws_provider,
            enabled_service_principals=["securityhub.amazonaws.com"],
            delegated_service_principals={
                organization["MasterAccountId"]: ["securityhub.amazonaws.com"]
            },
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(f"{CHECK_MODULE}.organizations_client", new=organizations):
                from prowler.providers.aws.services.organizations.organizations_security_services_delegated_admin_not_management_account.organizations_security_services_delegated_admin_not_management_account import (
                    organizations_security_services_delegated_admin_not_management_account,
                )

                check = (
                    organizations_security_services_delegated_admin_not_management_account()
                )
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert result[0].status_extended == (
                    f"AWS Organization {organization['Id']} administers "
                    f"securityhub.amazonaws.com from the management account "
                    f"{organization['MasterAccountId']} instead of a delegated "
                    f"administrator account."
                )

    @mock_aws
    def test_only_some_security_services_delegated(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        conn = client("organizations", region_name=AWS_REGION_EU_WEST_1)
        organization = conn.describe_organization()["Organization"]
        organizations = organizations_with(
            aws_provider,
            enabled_service_principals=[
                "guardduty.amazonaws.com",
                "securityhub.amazonaws.com",
                "macie.amazonaws.com",
                "sso.amazonaws.com",
            ],
            delegated_service_principals={
                DELEGATED_ADMIN_ACCOUNT_ID: [
                    "guardduty.amazonaws.com",
                    "sso.amazonaws.com",
                ]
            },
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(f"{CHECK_MODULE}.organizations_client", new=organizations):
                from prowler.providers.aws.services.organizations.organizations_security_services_delegated_admin_not_management_account.organizations_security_services_delegated_admin_not_management_account import (
                    organizations_security_services_delegated_admin_not_management_account,
                )

                check = (
                    organizations_security_services_delegated_admin_not_management_account()
                )
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert result[0].status_extended == (
                    f"AWS Organization {organization['Id']} administers "
                    f"macie.amazonaws.com, securityhub.amazonaws.com from the "
                    f"management account {organization['MasterAccountId']} instead of "
                    f"a delegated administrator account."
                )

    @mock_aws
    def test_all_integrated_security_services_delegated(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        conn = client("organizations", region_name=AWS_REGION_EU_WEST_1)
        organization = conn.describe_organization()["Organization"]
        organizations = organizations_with(
            aws_provider,
            enabled_service_principals=[
                "guardduty.amazonaws.com",
                "securityhub.amazonaws.com",
                "sso.amazonaws.com",
            ],
            delegated_service_principals={
                DELEGATED_ADMIN_ACCOUNT_ID: ["guardduty.amazonaws.com"],
                SECOND_DELEGATED_ADMIN_ACCOUNT_ID: ["securityhub.amazonaws.com"],
            },
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(f"{CHECK_MODULE}.organizations_client", new=organizations):
                from prowler.providers.aws.services.organizations.organizations_security_services_delegated_admin_not_management_account.organizations_security_services_delegated_admin_not_management_account import (
                    organizations_security_services_delegated_admin_not_management_account,
                )

                check = (
                    organizations_security_services_delegated_admin_not_management_account()
                )
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert result[0].resource_id == organization["Id"]
                assert result[0].resource_arn == organization["Arn"]
                assert result[0].region == AWS_REGION_EU_WEST_1
                assert result[0].status_extended == (
                    f"AWS Organization {organization['Id']} administers "
                    f"guardduty.amazonaws.com, securityhub.amazonaws.com from "
                    f"delegated administrator accounts other than the management "
                    f"account {organization['MasterAccountId']}."
                )
