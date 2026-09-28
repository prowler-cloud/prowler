from unittest.mock import patch

import botocore

from prowler.providers.aws.services.securityhub.securityhub_service import SecurityHub
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    mocked_api_response,
    set_mocked_aws_provider,
)

# Mocking Access Analyzer Calls
make_api_call = botocore.client.BaseClient._make_api_call


def mock_make_api_call(self, operation_name, kwarg):
    """
    We have to mock every AWS API call using Boto3

    As you can see the operation_name has the snake_case
    Rationale -> https://github.com/boto/botocore/blob/develop/botocore/client.py#L810:L816
    """
    if operation_name == "GetEnabledStandards":
        return {
            "StandardsSubscriptions": [
                {
                    "StandardsArn": "arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0",
                    "StandardsSubscriptionArn": "arn:aws:securityhub:us-east-1:0123456789012:subscription/cis-aws-foundations-benchmark/v/1.2.0",
                    "StandardsInput": {"string": "string"},
                    "StandardsStatus": "READY",
                },
            ]
        }
    if operation_name == "ListEnabledProductsForImport":
        return {
            "ProductSubscriptions": [
                "arn:aws:securityhub:us-east-1:0123456789012:product-subscription/prowler/prowler",
            ]
        }
    if operation_name == "DescribeHub":
        return {
            "HubArn": "arn:aws:securityhub:us-east-1:0123456789012:hub/default",
        }
    if operation_name == "ListTagsForResource":
        return {
            "Tags": {"test_key": "test_value"},
        }
    if operation_name == "ListOrganizationAdminAccounts":
        # Security Hub returns AccountId/Status, unlike GuardDuty's
        # AdminAccountId/AdminStatus for the same operation name.
        return mocked_api_response(
            "securityhub",
            operation_name,
            {"AdminAccounts": [{"AccountId": AWS_ACCOUNT_NUMBER, "Status": "ENABLED"}]},
        )

    return make_api_call(self, operation_name, kwarg)


def mock_make_api_call_admin_account_missing_fields(self, operation_name, kwarg):
    """Return an admin account entry without the documented fields."""
    if operation_name == "ListOrganizationAdminAccounts":
        # Deliberately not validated against the API model: this simulates the
        # response drifting away from what botocore currently describes.
        return {"AdminAccounts": [{"SomethingElse": "unexpected"}]}

    return mock_make_api_call(self, operation_name, kwarg)


def mock_make_api_call_admin_account_access_denied(self, operation_name, kwarg):
    """Deny ListOrganizationAdminAccounts, as AWS does outside the management account."""
    if operation_name == "ListOrganizationAdminAccounts":
        raise botocore.exceptions.ClientError(
            {
                "Error": {
                    "Code": "AccessDeniedException",
                    "Message": "User is not authorized to perform: securityhub:ListOrganizationAdminAccounts",
                }
            },
            operation_name,
        )

    return mock_make_api_call(self, operation_name, kwarg)


# Mock generate_regional_clients()
def mock_generate_regional_clients(provider, service):
    regional_client = provider._session.current_session.client(
        service, region_name=AWS_REGION_EU_WEST_1
    )
    regional_client.region = AWS_REGION_EU_WEST_1
    return {AWS_REGION_EU_WEST_1: regional_client}


# Patch every AWS call using Boto3 and generate_regional_clients to have 1 client
@patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
@patch(
    "prowler.providers.aws.aws_provider.AwsProvider.generate_regional_clients",
    new=mock_generate_regional_clients,
)
class Test_SecurityHub_Service:
    # Test SecurityHub Client
    def test_get_client(self):
        security_hub = SecurityHub(set_mocked_aws_provider([AWS_REGION_EU_WEST_1]))
        assert (
            security_hub.regional_clients[AWS_REGION_EU_WEST_1].__class__.__name__
            == "SecurityHub"
        )

    # Test SecurityHub Session
    def test__get_session__(self):
        security_hub = SecurityHub(set_mocked_aws_provider([AWS_REGION_EU_WEST_1]))
        assert security_hub.session.__class__.__name__ == "Session"

    def test_describe_hub(self):
        # Set partition for the service
        securityhub = SecurityHub(set_mocked_aws_provider([AWS_REGION_EU_WEST_1]))
        assert len(securityhub.securityhubs) == 1
        assert (
            securityhub.securityhubs[0].arn
            == "arn:aws:securityhub:us-east-1:0123456789012:hub/default"
        )
        assert securityhub.securityhubs[0].id == "default"
        assert securityhub.securityhubs[0].standards == "cis-aws-foundations-benchmark "
        assert securityhub.securityhubs[0].integrations == "prowler "

    def test_list_tags(self):
        # Set partition for the service
        securityhub = SecurityHub(set_mocked_aws_provider([AWS_REGION_EU_WEST_1]))
        assert len(securityhub.securityhubs) == 1
        assert securityhub.securityhubs[0].tags == [{"test_key": "test_value"}]

    def test_list_organization_admin_accounts(self):
        """Security Hub returns AccountId/Status, not GuardDuty's AdminAccountId/AdminStatus."""
        securityhub = SecurityHub(set_mocked_aws_provider([AWS_REGION_EU_WEST_1]))

        assert securityhub.organization_admin_lookup_failed_regions == set()
        assert len(securityhub.organization_admin_accounts) == 1
        assert (
            securityhub.organization_admin_accounts[0].admin_account_id
            == AWS_ACCOUNT_NUMBER
        )
        assert securityhub.organization_admin_accounts[0].admin_status == "ENABLED"
        assert securityhub.organization_admin_accounts[0].region == AWS_REGION_EU_WEST_1

    def test_list_organization_admin_accounts_missing_fields(self):
        """An unparseable entry marks the region as unknown instead of raising."""
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with patch(
            "botocore.client.BaseClient._make_api_call",
            new=mock_make_api_call_admin_account_missing_fields,
        ):
            securityhub = SecurityHub(aws_provider)

        assert securityhub.organization_admin_accounts == []
        assert securityhub.organization_admin_lookup_failed_regions == {
            AWS_REGION_EU_WEST_1
        }

    def test_list_organization_admin_accounts_access_denied(self):
        """A denied lookup only marks its own region as unknown."""
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with patch(
            "botocore.client.BaseClient._make_api_call",
            new=mock_make_api_call_admin_account_access_denied,
        ):
            securityhub = SecurityHub(aws_provider)

        assert securityhub.organization_admin_accounts == []
        assert securityhub.organization_admin_lookup_failed_regions == {
            AWS_REGION_EU_WEST_1
        }
