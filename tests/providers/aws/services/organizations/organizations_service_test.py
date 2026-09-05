import json
from unittest.mock import patch

import botocore
from boto3 import client
from moto import mock_aws

from prowler.providers.aws.services.organizations.organizations_service import (
    Organizations,
)
from tests.providers.aws.utils import (
    AWS_REGION_EU_WEST_1,
    mocked_api_response,
    set_mocked_aws_provider,
)

MANAGEMENT_ACCOUNT_ID = "111111111111"
DELEGATED_ADMIN_ACCOUNT_ID = "222222222222"
SECOND_DELEGATED_ADMIN_ACCOUNT_ID = "333333333333"
ORGANIZATION_ID = "o-abcde12345"
ORGANIZATION_ARN = (
    f"arn:aws:organizations::{MANAGEMENT_ACCOUNT_ID}:organization/{ORGANIZATION_ID}"
)


def scp_restrict_regions_with_deny():
    return '{"Version":"2012-10-17","Statement":{"Effect":"Deny","NotAction":"s3:*","Resource":"*","Condition":{"StringNotEquals":{"aws:RequestedRegion":["eu-central-1"]}}}}'


def delegated_administrator(account_id: str) -> dict:
    """Build one `ListDelegatedAdministrators` entry.

    Args:
        account_id: The account ID the entry describes.

    Returns:
        The entry as the API models it, keyed the way the collector reads it.
    """
    return {
        "Id": account_id,
        "Arn": f"arn:aws:organizations::{MANAGEMENT_ACCOUNT_ID}:account/{ORGANIZATION_ID}/{account_id}",
        "Email": f"{account_id}@example.com",
        "Name": f"account-{account_id}",
        "Status": "ACTIVE",
        "JoinedMethod": "CREATED",
    }


def build_mock_make_api_call(
    delegated_administrators_pages: list[list[dict]] = None,
    enabled_service_principals_pages: list[list[str]] = None,
    delegated_services_pages: dict[str, list[list[str]]] = None,
    describe_organization: dict = None,
    errors: dict[str, str] = None,
):
    """Build a `_make_api_call` replacement serving multi-page Organizations responses.

    Each `*_pages` argument is a list of pages: the mock hands out page N and a
    `NextToken` whenever another page follows, so a collector that stops after the
    first page returns less than the mock offered.

    Args:
        delegated_administrators_pages: Pages of `ListDelegatedAdministrators` entries.
        enabled_service_principals_pages: Pages of service principal strings for
            `ListAWSServiceAccessForOrganization`.
        delegated_services_pages: Pages of service principal strings keyed by the
            account ID passed to `ListDelegatedServicesForAccount`.
        describe_organization: Override for the `DescribeOrganization` organization.
        errors: Error codes to raise, keyed by operation name.

    Returns:
        A callable suitable for patching `botocore.client.BaseClient._make_api_call`.
    """
    delegated_administrators_pages = delegated_administrators_pages or [[]]
    enabled_service_principals_pages = enabled_service_principals_pages or [[]]
    delegated_services_pages = delegated_services_pages or {}
    errors = errors or {}
    # Captured per builder call rather than at module scope: the builder runs while
    # constructing the patch, so this is the unpatched method even if the module was
    # imported while some other patch was in force.
    make_api_call = botocore.client.BaseClient._make_api_call

    def page_for(pages: list, next_token: str):
        """Resolve one page and the token that follows it.

        Args:
            pages: The pages to serve, in order.
            next_token: The token the caller sent, or None for the first page.

        Returns:
            A dict carrying the page under `page`, plus `NextToken` when another follows.
        """
        index = int(next_token) if next_token else 0
        response = {"page": pages[index]}
        if index + 1 < len(pages):
            response["NextToken"] = str(index + 1)
        return response

    def mock_make_api_call(self, operation_name, kwarg):
        """Serve the configured Organizations responses and defer anything else.

        Every response is validated against the API model, so a page this mock builds
        with a key the service does not define fails here rather than in the collector.
        """
        if operation_name in errors:
            raise botocore.exceptions.ClientError(
                {"Error": {"Code": errors[operation_name], "Message": "denied"}},
                operation_name,
            )

        if operation_name == "DescribeOrganization":
            organization = describe_organization
            if organization is None:
                organization = {
                    "Id": ORGANIZATION_ID,
                    "Arn": ORGANIZATION_ARN,
                    "FeatureSet": "ALL",
                    "MasterAccountId": MANAGEMENT_ACCOUNT_ID,
                }
            return mocked_api_response(
                "organizations", operation_name, {"Organization": organization}
            )

        if operation_name == "ListPolicies":
            return mocked_api_response(
                "organizations", operation_name, {"Policies": []}
            )

        if operation_name == "ListDelegatedAdministrators":
            page = page_for(delegated_administrators_pages, kwarg.get("NextToken"))
            response = {"DelegatedAdministrators": page["page"]}
            if "NextToken" in page:
                response["NextToken"] = page["NextToken"]
            return mocked_api_response("organizations", operation_name, response)

        if operation_name == "ListAWSServiceAccessForOrganization":
            page = page_for(enabled_service_principals_pages, kwarg.get("NextToken"))
            response = {
                "EnabledServicePrincipals": [
                    {"ServicePrincipal": service_principal}
                    for service_principal in page["page"]
                ]
            }
            if "NextToken" in page:
                response["NextToken"] = page["NextToken"]
            return mocked_api_response("organizations", operation_name, response)

        if operation_name == "ListDelegatedServicesForAccount":
            page = page_for(
                delegated_services_pages.get(kwarg["AccountId"], [[]]),
                kwarg.get("NextToken"),
            )
            response = {
                "DelegatedServices": [
                    {"ServicePrincipal": service_principal}
                    for service_principal in page["page"]
                ]
            }
            if "NextToken" in page:
                response["NextToken"] = page["NextToken"]
            return mocked_api_response("organizations", operation_name, response)

        return make_api_call(self, operation_name, kwarg)

    return mock_make_api_call


class Test_Organizations_Service:
    @mock_aws
    def test_service(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        organizations = Organizations(aws_provider)
        assert organizations.service == "organizations"

    @mock_aws
    def test_describe_organization(self):
        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1],
        )
        conn = client("organizations", region_name=AWS_REGION_EU_WEST_1)
        response = conn.describe_organization()
        organizations = Organizations(aws_provider)
        assert organizations.organization.arn == response["Organization"]["Arn"]
        assert organizations.organization.id == response["Organization"]["Id"]
        assert (
            organizations.organization.master_id
            == response["Organization"]["MasterAccountId"]
        )
        assert organizations.organization.status == "ACTIVE"
        assert organizations.organization.delegated_administrators == []

    @mock_aws
    def test_list_policies(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        conn = client("organizations", region_name=AWS_REGION_EU_WEST_1)
        response = conn.create_policy(
            Content=scp_restrict_regions_with_deny(),
            Description="Test",
            Name="Test",
            Type="SERVICE_CONTROL_POLICY",
        )
        organizations = Organizations(aws_provider)
        for policy in organizations.policies:
            if policy.arn == response["Policy"]["PolicySummary"]["Arn"]:
                assert policy.type == "SERVICE_CONTROL_POLICY"
                assert policy.aws_managed is False
                assert policy.content == json.loads(response["Policy"]["Content"])
                assert policy.targets == []

    @mock_aws
    def test_describe_policy(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        conn = client("organizations", region_name=AWS_REGION_EU_WEST_1)
        response = conn.create_policy(
            Content=scp_restrict_regions_with_deny(),
            Description="Test",
            Name="Test",
            Type="SERVICE_CONTROL_POLICY",
        )
        organizations = Organizations(aws_provider)
        policy = organizations._describe_policy(
            response["Policy"]["PolicySummary"]["Id"]
        )
        assert policy == json.loads(response["Policy"]["Content"])

    def test_list_delegated_administrators_reads_every_page(self):
        """The collector follows NextToken, so an administrator on page two is not lost.

        An administrator dropped with the second page would be an untrusted account this
        service never reports, so the fields of that second entry are asserted too.
        """
        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1], create_default_organization=False
        )
        with patch(
            "botocore.client.BaseClient._make_api_call",
            new=build_mock_make_api_call(
                delegated_administrators_pages=[
                    [delegated_administrator(DELEGATED_ADMIN_ACCOUNT_ID)],
                    [delegated_administrator(SECOND_DELEGATED_ADMIN_ACCOUNT_ID)],
                ],
            ),
        ):
            organizations = Organizations(aws_provider)

        administrators = organizations.organization.delegated_administrators
        assert [administrator.id for administrator in administrators] == [
            DELEGATED_ADMIN_ACCOUNT_ID,
            SECOND_DELEGATED_ADMIN_ACCOUNT_ID,
        ]
        assert administrators[1].name == f"account-{SECOND_DELEGATED_ADMIN_ACCOUNT_ID}"
        assert (
            administrators[1].email
            == f"{SECOND_DELEGATED_ADMIN_ACCOUNT_ID}@example.com"
        )
        assert administrators[1].status == "ACTIVE"
        assert administrators[1].joinedmethod == "CREATED"

    def test_list_aws_service_access_for_organization_reads_every_page(self):
        """Trusted access is read across pages, in the order the API returned it."""
        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1], create_default_organization=False
        )
        with patch(
            "botocore.client.BaseClient._make_api_call",
            new=build_mock_make_api_call(
                enabled_service_principals_pages=[
                    ["guardduty.amazonaws.com"],
                    ["securityhub.amazonaws.com", "macie.amazonaws.com"],
                ],
            ),
        ):
            organizations = Organizations(aws_provider)

        assert organizations.organization.enabled_service_principals == [
            "guardduty.amazonaws.com",
            "securityhub.amazonaws.com",
            "macie.amazonaws.com",
        ]

    def test_list_delegated_services_for_account_reads_every_page(self):
        """Per-account delegations are read across pages.

        A delegation dropped with the second page would make its service look
        administered from the management account.
        """
        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1], create_default_organization=False
        )
        with patch(
            "botocore.client.BaseClient._make_api_call",
            new=build_mock_make_api_call(
                delegated_administrators_pages=[
                    [delegated_administrator(DELEGATED_ADMIN_ACCOUNT_ID)]
                ],
                delegated_services_pages={
                    DELEGATED_ADMIN_ACCOUNT_ID: [
                        ["guardduty.amazonaws.com"],
                        ["securityhub.amazonaws.com"],
                    ]
                },
            ),
        ):
            organizations = Organizations(aws_provider)

        assert organizations.organization.delegated_service_principals == {
            DELEGATED_ADMIN_ACCOUNT_ID: [
                "guardduty.amazonaws.com",
                "securityhub.amazonaws.com",
            ]
        }

    def test_list_delegated_services_for_account_is_called_per_administrator(self):
        """Every administrator is queried, not only the first one listed.

        ListDelegatedServicesForAccount takes one account at a time, so a loop that
        stopped early would leave later administrators looking as if they held no
        delegation.
        """
        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1], create_default_organization=False
        )
        with patch(
            "botocore.client.BaseClient._make_api_call",
            new=build_mock_make_api_call(
                delegated_administrators_pages=[
                    [
                        delegated_administrator(DELEGATED_ADMIN_ACCOUNT_ID),
                        delegated_administrator(SECOND_DELEGATED_ADMIN_ACCOUNT_ID),
                    ]
                ],
                delegated_services_pages={
                    DELEGATED_ADMIN_ACCOUNT_ID: [["guardduty.amazonaws.com"]],
                    SECOND_DELEGATED_ADMIN_ACCOUNT_ID: [["macie.amazonaws.com"]],
                },
            ),
        ):
            organizations = Organizations(aws_provider)

        assert organizations.organization.delegated_service_principals == {
            DELEGATED_ADMIN_ACCOUNT_ID: ["guardduty.amazonaws.com"],
            SECOND_DELEGATED_ADMIN_ACCOUNT_ID: ["macie.amazonaws.com"],
        }

    def test_list_aws_service_access_for_organization_access_denied(self):
        """A denied trusted access read is the sentinel, not the page the mock offered.

        The mock is given a service principal so that the empty list cannot be mistaken
        for the collector having simply read nothing.
        """
        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1], create_default_organization=False
        )
        with patch(
            "botocore.client.BaseClient._make_api_call",
            new=build_mock_make_api_call(
                enabled_service_principals_pages=[["guardduty.amazonaws.com"]],
                errors={"ListAWSServiceAccessForOrganization": "AccessDeniedException"},
            ),
        ):
            organizations = Organizations(aws_provider)

        assert organizations.organization.enabled_service_principals is None

    def test_list_delegated_services_for_account_access_denied(self):
        """A denied per-account read leaves that account keyed to the sentinel.

        The administrator stays in the map so a caller can tell an account whose
        delegations are unknown from an account that is not an administrator at all.
        """
        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1], create_default_organization=False
        )
        with patch(
            "botocore.client.BaseClient._make_api_call",
            new=build_mock_make_api_call(
                delegated_administrators_pages=[
                    [delegated_administrator(DELEGATED_ADMIN_ACCOUNT_ID)]
                ],
                delegated_services_pages={
                    DELEGATED_ADMIN_ACCOUNT_ID: [["guardduty.amazonaws.com"]]
                },
                errors={"ListDelegatedServicesForAccount": "AccessDeniedException"},
            ),
        ):
            organizations = Organizations(aws_provider)

        assert organizations.organization.delegated_service_principals == {
            DELEGATED_ADMIN_ACCOUNT_ID: None
        }

    def test_list_delegated_administrators_access_denied(self):
        """Unknown administrators means no per-account read is attempted at all.

        The delegation map stays empty rather than being keyed to accounts the collector
        never established, which is what the `or []` in the loop over administrators is
        for.
        """
        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1], create_default_organization=False
        )
        with patch(
            "botocore.client.BaseClient._make_api_call",
            new=build_mock_make_api_call(
                delegated_administrators_pages=[
                    [delegated_administrator(DELEGATED_ADMIN_ACCOUNT_ID)]
                ],
                errors={"ListDelegatedAdministrators": "AccessDeniedException"},
            ),
        ):
            organizations = Organizations(aws_provider)

        assert organizations.organization.delegated_administrators is None
        assert (
            organizations.organization.delegated_administrators_error_code
            == "AccessDeniedException"
        )
        assert organizations.organization.delegated_service_principals == {}

    def test_list_delegated_administrators_throttled(self):
        """A throttle is unreadable, not an organization without administrators.

        Only AccessDeniedException used to set the sentinel, so every other modeled
        error left the empty list in place and read as a determined answer. The code is
        recorded alongside the sentinel because the sentinel alone cannot tell this
        apart from the access denial that asks the operator to move the scan.
        """
        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1], create_default_organization=False
        )
        with patch(
            "botocore.client.BaseClient._make_api_call",
            new=build_mock_make_api_call(
                delegated_administrators_pages=[
                    [delegated_administrator(DELEGATED_ADMIN_ACCOUNT_ID)]
                ],
                errors={"ListDelegatedAdministrators": "TooManyRequestsException"},
            ),
        ):
            organizations = Organizations(aws_provider)

        assert organizations.organization.delegated_administrators is None
        assert (
            organizations.organization.delegated_administrators_error_code
            == "TooManyRequestsException"
        )

    def test_list_delegated_administrators_renamed_result_key(self):
        """A renamed result key reads as unknown, not as no administrators.

        The collector indexes page["DelegatedAdministrators"], so a rename raises
        KeyError rather than ClientError, reaching the generic handler. That handler
        must set the sentinel too, or the empty list survives and reports a determined
        answer from an inventory that was never read.
        """
        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1], create_default_organization=False
        )
        mock_make_api_call = build_mock_make_api_call()

        def mock_renamed_result_key(self, operation_name, kwarg):
            """Return ListDelegatedAdministrators under a key the collector does not read."""
            if operation_name == "ListDelegatedAdministrators":
                # Deliberately not validated against the API model: this simulates the
                # result key being renamed out from under the collector.
                return {"Administrators": []}
            return mock_make_api_call(self, operation_name, kwarg)

        with patch(
            "botocore.client.BaseClient._make_api_call", new=mock_renamed_result_key
        ):
            organizations = Organizations(aws_provider)

        assert organizations.organization.delegated_administrators is None
        # A failure that carries no AWS error code records its exception class, so the
        # generic handler is still distinguishable from an access denial.
        assert (
            organizations.organization.delegated_administrators_error_code == "KeyError"
        )

    def test_describe_organization_without_master_account_id(self):
        """An organization without MasterAccountId is left unset, not defaulted.

        `master_id` is a required field, so a DescribeOrganization response that stops
        carrying it makes the whole organization unknown instead of silently becoming
        an empty account ID that every comparison against it would match.
        """
        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1], create_default_organization=False
        )
        with patch(
            "botocore.client.BaseClient._make_api_call",
            new=build_mock_make_api_call(
                describe_organization={
                    "Id": ORGANIZATION_ID,
                    "Arn": ORGANIZATION_ARN,
                    "FeatureSet": "ALL",
                },
            ),
        ):
            organizations = Organizations(aws_provider)

        assert organizations.organization is None

    def test_list_aws_service_access_for_organization_unexpected_response_shape(self):
        """A renamed result key reads as unknown, not as an organization with no integration.

        The collector indexes page["EnabledServicePrincipals"], so a rename raises
        KeyError rather than ClientError and only the generic handler can turn it into the
        sentinel.
        """
        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1], create_default_organization=False
        )
        mock_make_api_call = build_mock_make_api_call()

        def mock_renamed_result_key(self, operation_name, kwarg):
            """Return the trusted access list under a key the collector does not read."""
            if operation_name == "ListAWSServiceAccessForOrganization":
                # Deliberately not validated against the API model: this simulates the
                # response key being renamed out from under the collector.
                return {
                    "ServicePrincipals": [
                        {"ServicePrincipal": "guardduty.amazonaws.com"}
                    ]
                }
            return mock_make_api_call(self, operation_name, kwarg)

        with patch(
            "botocore.client.BaseClient._make_api_call", new=mock_renamed_result_key
        ):
            organizations = Organizations(aws_provider)

        assert organizations.organization.enabled_service_principals is None

    def test_list_delegated_services_for_account_unexpected_response_shape(self):
        """A renamed result key reads as unknown, not as an account with no delegation.

        Reported per administrator, so the account stays in the map keyed to the sentinel
        rather than dropping out of it.
        """
        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1], create_default_organization=False
        )
        mock_make_api_call = build_mock_make_api_call(
            delegated_administrators_pages=[
                [delegated_administrator(DELEGATED_ADMIN_ACCOUNT_ID)]
            ],
        )

        def mock_renamed_result_key(self, operation_name, kwarg):
            """Return the per-account delegations under a key the collector does not read."""
            if operation_name == "ListDelegatedServicesForAccount":
                # Deliberately not validated against the API model: this simulates the
                # response key being renamed out from under the collector.
                return {"Services": [{"ServicePrincipal": "guardduty.amazonaws.com"}]}
            return mock_make_api_call(self, operation_name, kwarg)

        with patch(
            "botocore.client.BaseClient._make_api_call", new=mock_renamed_result_key
        ):
            organizations = Organizations(aws_provider)

        assert organizations.organization.delegated_service_principals == {
            DELEGATED_ADMIN_ACCOUNT_ID: None
        }

    def test_list_aws_service_access_for_organization_renamed_member_key(self):
        """A renamed ServicePrincipal member reads as unknown, not as an empty scope."""
        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1], create_default_organization=False
        )
        mock_make_api_call = build_mock_make_api_call()

        def mock_renamed_member_key(self, operation_name, kwarg):
            """Keep the trusted access result key but rename the member inside it."""
            if operation_name == "ListAWSServiceAccessForOrganization":
                # Deliberately not validated against the API model: this simulates the
                # member key being renamed out from under the collector.
                return {"EnabledServicePrincipals": [{"Principal": "guardduty"}]}
            return mock_make_api_call(self, operation_name, kwarg)

        with patch(
            "botocore.client.BaseClient._make_api_call", new=mock_renamed_member_key
        ):
            organizations = Organizations(aws_provider)

        assert organizations.organization.enabled_service_principals is None

    def test_list_delegated_services_for_account_renamed_member_key(self):
        """A renamed ServicePrincipal member reads as unknown, not as no delegations."""
        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1], create_default_organization=False
        )
        mock_make_api_call = build_mock_make_api_call(
            delegated_administrators_pages=[
                [delegated_administrator(DELEGATED_ADMIN_ACCOUNT_ID)]
            ],
        )

        def mock_renamed_member_key(self, operation_name, kwarg):
            """Keep the per-account delegation result key but rename the member inside it."""
            if operation_name == "ListDelegatedServicesForAccount":
                # Deliberately not validated against the API model: this simulates the
                # member key being renamed out from under the collector.
                return {"DelegatedServices": [{"Principal": "guardduty"}]}
            return mock_make_api_call(self, operation_name, kwarg)

        with patch(
            "botocore.client.BaseClient._make_api_call", new=mock_renamed_member_key
        ):
            organizations = Organizations(aws_provider)

        assert organizations.organization.delegated_service_principals == {
            DELEGATED_ADMIN_ACCOUNT_ID: None
        }
