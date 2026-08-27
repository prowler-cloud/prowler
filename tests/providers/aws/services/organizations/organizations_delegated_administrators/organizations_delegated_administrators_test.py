from unittest import mock

import botocore
from boto3 import client
from moto import mock_aws

from prowler.providers.aws.services.organizations.organizations_service import (
    DelegatedAdministrator,
    Organizations,
)
from tests.providers.aws.utils import AWS_REGION_EU_WEST_1, set_mocked_aws_provider

TRUSTED_ACCOUNT_ID = "222222222222"
SECOND_TRUSTED_ACCOUNT_ID = "333333333333"
UNTRUSTED_ACCOUNT_ID = "999999999999"
SECOND_UNTRUSTED_ACCOUNT_ID = "888888888888"


def delegated_administrator(account_id: str) -> DelegatedAdministrator:
    """Build a delegated administrator for a given account.

    Args:
        account_id: The account ID to register as a delegated administrator.

    Returns:
        The delegated administrator the Organizations collector would have built.
    """
    return DelegatedAdministrator(
        arn=f"arn:aws:organizations::123456789012:account/o-abcde12345/{account_id}",
        id=account_id,
        name=f"account-{account_id}",
        email=f"{account_id}@example.com",
        status="ACTIVE",
        joinedmethod="CREATED",
    )


def organizations_with_administrators(aws_provider, account_ids: list[str]):
    """Build the Organizations client with delegated administrators in a fixed order.

    ListDelegatedAdministrators documents no ordering, so the order is set explicitly
    here rather than left to whatever the API or the mock happens to return.
    """
    organizations = Organizations(aws_provider)
    organizations.organization.delegated_administrators = [
        delegated_administrator(account_id) for account_id in account_ids
    ]
    return organizations


def client_error(code: str) -> botocore.exceptions.ClientError:
    """Build the ClientError botocore raises for a `ListDelegatedAdministrators` code.

    Args:
        code: The error code the API answered with.

    Returns:
        The modeled error the collector receives.
    """
    return botocore.exceptions.ClientError(
        {"Error": {"Code": code, "Message": f"simulated {code}"}},
        "ListDelegatedAdministrators",
    )


def organizations_with_unreadable_administrators(aws_provider, error: Exception):
    """Build the Organizations client with the administrator lookup failing on `error`.

    The real collector is driven rather than the sentinel being set by hand, so the whole
    chain from the raised failure to the verdict is covered.

    Args:
        aws_provider: The mocked provider the collector builds its client from.
        error: The failure `ListDelegatedAdministrators` raises.

    Returns:
        The Organizations client whose delegated administrator lookup failed.
    """
    real_make_api_call = botocore.client.BaseClient._make_api_call

    def fail_list_delegated_administrators(self, operation_name, kwarg):
        """Raise `error` from ListDelegatedAdministrators only."""
        if operation_name == "ListDelegatedAdministrators":
            raise error
        return real_make_api_call(self, operation_name, kwarg)

    with mock.patch(
        "botocore.client.BaseClient._make_api_call",
        new=fail_list_delegated_administrators,
    ):
        return Organizations(aws_provider)


class Test_organizations_delegated_administrators:
    @mock_aws
    def test_no_organization(self):
        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1], create_default_organization=False
        )
        aws_provider._audit_config = {
            "organizations_trusted_delegated_administrators": []
        }
        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.organizations.organizations_delegated_administrators.organizations_delegated_administrators.organizations_client",
                new=Organizations(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.organizations.organizations_delegated_administrators.organizations_delegated_administrators import (
                    organizations_delegated_administrators,
                )

                check = organizations_delegated_administrators()
                result = check.execute()

                assert len(result) == 0

    @mock_aws
    def test_organization_no_delegations(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        aws_provider._audit_config = {
            "organizations_trusted_delegated_administrators": []
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
                "prowler.providers.aws.services.organizations.organizations_delegated_administrators.organizations_delegated_administrators.organizations_client",
                new=Organizations(aws_provider),
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
                assert (
                    result[0].status_extended
                    == f"AWS Organization {org_id} has no Delegated Administrators."
                )
                assert result[0].region == AWS_REGION_EU_WEST_1

    @mock_aws
    def test_organization_trusted_delegated(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        # Create Organization
        conn = client("organizations", region_name=AWS_REGION_EU_WEST_1)
        response = conn.describe_organization()
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
        org_id = response["Organization"]["Id"]
        account_id = account["CreateAccountStatus"]["AccountId"]

        # Set config variable
        aws_provider._audit_config = {
            "organizations_trusted_delegated_administrators": [
                account["CreateAccountStatus"]["AccountId"]
            ]
        }

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.organizations.organizations_delegated_administrators.organizations_delegated_administrators.organizations_client",
                new=Organizations(aws_provider),
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
                assert (
                    result[0].status_extended
                    == f"AWS Organization {org_id} has a trusted Delegated Administrator: {account_id}."
                )
                assert result[0].region == AWS_REGION_EU_WEST_1

    @mock_aws
    def test_organization_untrusted_delegated(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        # Create Organization
        conn = client("organizations", region_name=AWS_REGION_EU_WEST_1)
        response = conn.describe_organization()
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
        org_id = response["Organization"]["Id"]
        account_id = account["CreateAccountStatus"]["AccountId"]

        # Set config variable
        aws_provider._audit_config = {
            "organizations_trusted_delegated_administrators": []
        }

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.organizations.organizations_delegated_administrators.organizations_delegated_administrators.organizations_client",
                new=Organizations(aws_provider),
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
                assert (
                    result[0].status_extended
                    == f"AWS Organization {org_id} has an untrusted Delegated Administrator: {account_id}."
                )
                assert result[0].region == AWS_REGION_EU_WEST_1

    @mock_aws
    def test_organization_untrusted_delegated_before_trusted(self):
        """An untrusted administrator is reported even when a trusted one follows it."""
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        conn = client("organizations", region_name=AWS_REGION_EU_WEST_1)
        org_id = conn.describe_organization()["Organization"]["Id"]
        aws_provider._audit_config = {
            "organizations_trusted_delegated_administrators": [TRUSTED_ACCOUNT_ID]
        }
        organizations = organizations_with_administrators(
            aws_provider, [UNTRUSTED_ACCOUNT_ID, TRUSTED_ACCOUNT_ID]
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.organizations.organizations_delegated_administrators.organizations_delegated_administrators.organizations_client",
                new=organizations,
            ):
                # Test Check
                from prowler.providers.aws.services.organizations.organizations_delegated_administrators.organizations_delegated_administrators import (
                    organizations_delegated_administrators,
                )

                check = organizations_delegated_administrators()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == f"AWS Organization {org_id} has an untrusted Delegated Administrator: {UNTRUSTED_ACCOUNT_ID}."
                )

    @mock_aws
    def test_organization_trusted_delegated_before_untrusted(self):
        """The same verdict as the reverse order, so it cannot depend on API ordering."""
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        conn = client("organizations", region_name=AWS_REGION_EU_WEST_1)
        org_id = conn.describe_organization()["Organization"]["Id"]
        aws_provider._audit_config = {
            "organizations_trusted_delegated_administrators": [TRUSTED_ACCOUNT_ID]
        }
        organizations = organizations_with_administrators(
            aws_provider, [TRUSTED_ACCOUNT_ID, UNTRUSTED_ACCOUNT_ID]
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.organizations.organizations_delegated_administrators.organizations_delegated_administrators.organizations_client",
                new=organizations,
            ):
                # Test Check
                from prowler.providers.aws.services.organizations.organizations_delegated_administrators.organizations_delegated_administrators import (
                    organizations_delegated_administrators,
                )

                check = organizations_delegated_administrators()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == f"AWS Organization {org_id} has an untrusted Delegated Administrator: {UNTRUSTED_ACCOUNT_ID}."
                )

    @mock_aws
    def test_organization_multiple_untrusted_delegated(self):
        """Every untrusted administrator is named, not only the last one seen."""
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        conn = client("organizations", region_name=AWS_REGION_EU_WEST_1)
        org_id = conn.describe_organization()["Organization"]["Id"]
        aws_provider._audit_config = {
            "organizations_trusted_delegated_administrators": [TRUSTED_ACCOUNT_ID]
        }
        organizations = organizations_with_administrators(
            aws_provider,
            [UNTRUSTED_ACCOUNT_ID, TRUSTED_ACCOUNT_ID, SECOND_UNTRUSTED_ACCOUNT_ID],
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.organizations.organizations_delegated_administrators.organizations_delegated_administrators.organizations_client",
                new=organizations,
            ):
                # Test Check
                from prowler.providers.aws.services.organizations.organizations_delegated_administrators.organizations_delegated_administrators import (
                    organizations_delegated_administrators,
                )

                check = organizations_delegated_administrators()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == f"AWS Organization {org_id} has an untrusted Delegated Administrator: {UNTRUSTED_ACCOUNT_ID}, {SECOND_UNTRUSTED_ACCOUNT_ID}."
                )

    @mock_aws
    def test_organization_multiple_trusted_delegated(self):
        """Every trusted administrator is named on the PASS side too."""
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        conn = client("organizations", region_name=AWS_REGION_EU_WEST_1)
        org_id = conn.describe_organization()["Organization"]["Id"]
        aws_provider._audit_config = {
            "organizations_trusted_delegated_administrators": [
                TRUSTED_ACCOUNT_ID,
                SECOND_TRUSTED_ACCOUNT_ID,
            ]
        }
        organizations = organizations_with_administrators(
            aws_provider, [TRUSTED_ACCOUNT_ID, SECOND_TRUSTED_ACCOUNT_ID]
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.organizations.organizations_delegated_administrators.organizations_delegated_administrators.organizations_client",
                new=organizations,
            ):
                # Test Check
                from prowler.providers.aws.services.organizations.organizations_delegated_administrators.organizations_delegated_administrators import (
                    organizations_delegated_administrators,
                )

                check = organizations_delegated_administrators()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == f"AWS Organization {org_id} has a trusted Delegated Administrator: {TRUSTED_ACCOUNT_ID}, {SECOND_TRUSTED_ACCOUNT_ID}."
                )

    @mock_aws
    def test_organization_trusted_list_set_to_null(self):
        """A null trusted list means nothing is trusted, and must not raise.

        `audit_config.get` returns None for a key that is present but null in the
        configuration file, and every membership test against None raises TypeError,
        which the framework swallows into a check that reports nothing at all.

        The administrator is deliberately the account the trusted constant names: the
        FAIL below is then attributable to the null configuration alone, rather than to
        having picked an account that no trusted list in this file ever contains.
        """
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        conn = client("organizations", region_name=AWS_REGION_EU_WEST_1)
        org_id = conn.describe_organization()["Organization"]["Id"]
        aws_provider._audit_config = {
            "organizations_trusted_delegated_administrators": None
        }
        organizations = organizations_with_administrators(
            aws_provider, [TRUSTED_ACCOUNT_ID]
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.organizations.organizations_delegated_administrators.organizations_delegated_administrators.organizations_client",
                new=organizations,
            ):
                # Test Check
                from prowler.providers.aws.services.organizations.organizations_delegated_administrators.organizations_delegated_administrators import (
                    organizations_delegated_administrators,
                )

                check = organizations_delegated_administrators()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == f"AWS Organization {org_id} has an untrusted Delegated Administrator: {TRUSTED_ACCOUNT_ID}."
                )

    @mock_aws
    def test_organization_delegated_administrators_access_denied(self):
        """Access denied reports MANUAL, and reports where to run the scan from.

        A member account cannot list delegated administrators, which previously left the
        check silent for every such account instead of saying it could not evaluate. It is
        the only collection failure the audited account can answer by running the scan
        somewhere else, so it is the only one that says so.
        """
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        conn = client("organizations", region_name=AWS_REGION_EU_WEST_1)
        org_id = conn.describe_organization()["Organization"]["Id"]
        aws_provider._audit_config = {
            "organizations_trusted_delegated_administrators": []
        }
        organizations = organizations_with_unreadable_administrators(
            aws_provider, client_error("AccessDeniedException")
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.organizations.organizations_delegated_administrators.organizations_delegated_administrators.organizations_client",
                new=organizations,
            ):
                # Test Check
                from prowler.providers.aws.services.organizations.organizations_delegated_administrators.organizations_delegated_administrators import (
                    organizations_delegated_administrators,
                )

                check = organizations_delegated_administrators()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "MANUAL"
                assert (
                    result[0].status_extended
                    == f"AWS Organization {org_id} delegated administrators could not be determined; run this check from the organization management account."
                )

    @mock_aws
    def test_organization_delegated_administrators_throttled(self):
        """A throttle is named, so it is not read as an access denial.

        Every collection failure leaves the same sentinel, so the reported text is the
        only thing that tells an operator a retry will resolve this one, rather than
        moving the scan to the management account as an access denial asks for.
        """
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        conn = client("organizations", region_name=AWS_REGION_EU_WEST_1)
        org_id = conn.describe_organization()["Organization"]["Id"]
        aws_provider._audit_config = {
            "organizations_trusted_delegated_administrators": []
        }
        organizations = organizations_with_unreadable_administrators(
            aws_provider, client_error("TooManyRequestsException")
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.organizations.organizations_delegated_administrators.organizations_delegated_administrators.organizations_client",
                new=organizations,
            ):
                # Test Check
                from prowler.providers.aws.services.organizations.organizations_delegated_administrators.organizations_delegated_administrators import (
                    organizations_delegated_administrators,
                )

                check = organizations_delegated_administrators()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "MANUAL"
                assert (
                    result[0].status_extended
                    == f"AWS Organization {org_id} delegated administrators could not be determined: TooManyRequestsException."
                )

    @mock_aws
    def test_organization_delegated_administrators_validation_error(self):
        """A validation error is named rather than reported as an access denial.

        A request the service rejects is a defect in the call, not a permission the
        audited account is missing, so the remediation for an access denial would send an
        operator to an account where the call fails the same way.
        """
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        conn = client("organizations", region_name=AWS_REGION_EU_WEST_1)
        org_id = conn.describe_organization()["Organization"]["Id"]
        aws_provider._audit_config = {
            "organizations_trusted_delegated_administrators": []
        }
        organizations = organizations_with_unreadable_administrators(
            aws_provider, client_error("ValidationException")
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.organizations.organizations_delegated_administrators.organizations_delegated_administrators.organizations_client",
                new=organizations,
            ):
                # Test Check
                from prowler.providers.aws.services.organizations.organizations_delegated_administrators.organizations_delegated_administrators import (
                    organizations_delegated_administrators,
                )

                check = organizations_delegated_administrators()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "MANUAL"
                assert (
                    result[0].status_extended
                    == f"AWS Organization {org_id} delegated administrators could not be determined: ValidationException."
                )

    @mock_aws
    def test_organization_delegated_administrators_organization_not_in_use(self):
        """An organization that DescribeOrganization served and this call denies is named.

        This code is grouped with access denial elsewhere, but not here: the organization
        is already known ACTIVE from DescribeOrganization, so the same account being told
        the organization is not in use is a contradiction rather than a missing
        permission, and naming the code says so instead of blaming the caller's account.
        """
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        conn = client("organizations", region_name=AWS_REGION_EU_WEST_1)
        org_id = conn.describe_organization()["Organization"]["Id"]
        aws_provider._audit_config = {
            "organizations_trusted_delegated_administrators": []
        }
        organizations = organizations_with_unreadable_administrators(
            aws_provider, client_error("AWSOrganizationsNotInUseException")
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.organizations.organizations_delegated_administrators.organizations_delegated_administrators.organizations_client",
                new=organizations,
            ):
                # Test Check
                from prowler.providers.aws.services.organizations.organizations_delegated_administrators.organizations_delegated_administrators import (
                    organizations_delegated_administrators,
                )

                check = organizations_delegated_administrators()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "MANUAL"
                assert (
                    result[0].status_extended
                    == f"AWS Organization {org_id} delegated administrators could not be determined: AWSOrganizationsNotInUseException."
                )

    @mock_aws
    def test_organization_delegated_administrators_transport_failure(self):
        """A failure that never reached the service is named by its exception class.

        There is no AWS error code to report for a connection that dropped, so the class
        stands in for one. Without it this failure would carry the text of an access
        denial, which is the one collection failure it is certainly not.
        """
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        conn = client("organizations", region_name=AWS_REGION_EU_WEST_1)
        org_id = conn.describe_organization()["Organization"]["Id"]
        aws_provider._audit_config = {
            "organizations_trusted_delegated_administrators": []
        }
        organizations = organizations_with_unreadable_administrators(
            aws_provider, ConnectionResetError("Connection reset by peer")
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.organizations.organizations_delegated_administrators.organizations_delegated_administrators.organizations_client",
                new=organizations,
            ):
                # Test Check
                from prowler.providers.aws.services.organizations.organizations_delegated_administrators.organizations_delegated_administrators import (
                    organizations_delegated_administrators,
                )

                check = organizations_delegated_administrators()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "MANUAL"
                assert (
                    result[0].status_extended
                    == f"AWS Organization {org_id} delegated administrators could not be determined: ConnectionResetError."
                )
