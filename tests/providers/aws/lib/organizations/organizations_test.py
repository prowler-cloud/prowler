from unittest.mock import MagicMock

import boto3
from botocore.exceptions import ClientError
from moto import mock_aws

from prowler.providers.aws.config import BOTO3_USER_AGENT_EXTRA
from prowler.providers.aws.lib.organizations.organizations import (
    _get_ou_metadata,
    get_organizations_metadata,
    parse_organizations_metadata,
)
from prowler.providers.aws.models import AWSOrganizationsInfo
from tests.providers.aws.utils import AWS_ACCOUNT_NUMBER, AWS_REGION_US_EAST_1


class Test_AWS_Organizations:
    @mock_aws
    def test_organizations(self):
        client = boto3.client("organizations", region_name=AWS_REGION_US_EAST_1)

        mockname = "mock-account"
        mockdomain = "moto-example.org"
        mockemail = "@".join([mockname, mockdomain])

        org_id = client.create_organization(FeatureSet="ALL")["Organization"]["Id"]
        account_id = client.create_account(AccountName=mockname, Email=mockemail)[
            "CreateAccountStatus"
        ]["AccountId"]

        client.tag_resource(
            ResourceId=account_id, Tags=[{"Key": "key", "Value": "value"}]
        )

        metadata, tags, ou_metadata = get_organizations_metadata(
            account_id, boto3.Session()
        )
        org = parse_organizations_metadata(metadata, tags, ou_metadata)

        assert isinstance(org, AWSOrganizationsInfo)
        assert org.account_email == mockemail
        assert org.account_name == mockname
        assert (
            org.organization_account_arn
            == f"arn:aws:organizations::{AWS_ACCOUNT_NUMBER}:account/{org_id}/{account_id}"
        )
        assert (
            org.organization_arn
            == f"arn:aws:organizations::{AWS_ACCOUNT_NUMBER}:organization/{org_id}"
        )
        assert org.organization_id == org_id
        assert org.account_tags == {"key": "value"}
        assert org.account_ou_id == ""
        assert org.account_ou_name == ""

    def test_parse_organizations_metadata(self):
        tags = {"Tags": [{"Key": "test-key", "Value": "test-value"}]}
        name = "mock-account"
        email = "mock-account@moto-example.org"
        organization_name = "o-v4bzbxm7ib"
        arn = f"arn:aws:organizations::{AWS_ACCOUNT_NUMBER}:organization/{organization_name}"
        metadata = {
            "Account": {
                "Id": AWS_ACCOUNT_NUMBER,
                "Arn": f"arn:aws:organizations::123456789012:account/o-v4bzbxm7ib/{AWS_ACCOUNT_NUMBER}",
                "Email": "mock-account@moto-example.org",
                "Name": "mock-account",
                "Status": "ACTIVE",
            }
        }

        org = parse_organizations_metadata(metadata, tags)

        assert isinstance(org, AWSOrganizationsInfo)
        assert org.account_email == email
        assert org.account_name == name
        assert (
            org.organization_account_arn
            == f"arn:aws:organizations::{AWS_ACCOUNT_NUMBER}:account/{organization_name}/{AWS_ACCOUNT_NUMBER}"
        )
        assert org.organization_arn == arn
        assert org.account_tags == {"test-key": "test-value"}
        assert org.account_ou_id == ""
        assert org.account_ou_name == ""

    @mock_aws
    def test_organizations_with_ou(self):
        client = boto3.client("organizations", region_name=AWS_REGION_US_EAST_1)

        client.create_organization(FeatureSet="ALL")
        account_id = client.create_account(
            AccountName="ou-account", Email="ou@example.org"
        )["CreateAccountStatus"]["AccountId"]

        root_id = client.list_roots()["Roots"][0]["Id"]
        ou = client.create_organizational_unit(ParentId=root_id, Name="SecurityOU")[
            "OrganizationalUnit"
        ]

        client.move_account(
            AccountId=account_id,
            SourceParentId=root_id,
            DestinationParentId=ou["Id"],
        )

        metadata, tags, ou_metadata = get_organizations_metadata(
            account_id, boto3.Session()
        )
        org = parse_organizations_metadata(metadata, tags, ou_metadata)

        assert org.account_ou_id == ou["Id"]
        assert org.account_ou_name == "SecurityOU"

    @mock_aws
    def test_organizations_with_nested_ou(self):
        client = boto3.client("organizations", region_name=AWS_REGION_US_EAST_1)

        client.create_organization(FeatureSet="ALL")
        account_id = client.create_account(
            AccountName="nested-account", Email="nested@example.org"
        )["CreateAccountStatus"]["AccountId"]

        root_id = client.list_roots()["Roots"][0]["Id"]
        parent_ou = client.create_organizational_unit(
            ParentId=root_id, Name="Infrastructure"
        )["OrganizationalUnit"]
        child_ou = client.create_organizational_unit(
            ParentId=parent_ou["Id"], Name="Security"
        )["OrganizationalUnit"]

        client.move_account(
            AccountId=account_id,
            SourceParentId=root_id,
            DestinationParentId=child_ou["Id"],
        )

        metadata, tags, ou_metadata = get_organizations_metadata(
            account_id, boto3.Session()
        )
        org = parse_organizations_metadata(metadata, tags, ou_metadata)

        assert org.account_ou_id == child_ou["Id"]
        assert org.account_ou_name == "Infrastructure/Security"

    def test_parse_organizations_metadata_with_ou(self):
        tags = {"Tags": []}
        metadata = {
            "Account": {
                "Id": AWS_ACCOUNT_NUMBER,
                "Arn": f"arn:aws:organizations::123456789012:account/o-abc123/{AWS_ACCOUNT_NUMBER}",
                "Email": "test@example.org",
                "Name": "test-account",
                "Status": "ACTIVE",
            }
        }
        ou_metadata = {"ou_id": "ou-xxxx-12345678", "ou_path": "Infra/Security"}

        org = parse_organizations_metadata(metadata, tags, ou_metadata)

        assert org.account_ou_id == "ou-xxxx-12345678"
        assert org.account_ou_name == "Infra/Security"

    def test_get_ou_metadata_api_error_returns_empty_dict(self):
        client = MagicMock()
        client.list_parents.side_effect = ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "Access denied"}},
            "ListParents",
        )

        result = _get_ou_metadata(client, "123456789012")

        assert result == {}

    def test_get_ou_metadata_describe_ou_error_returns_empty_dict(self):
        client = MagicMock()
        client.list_parents.return_value = {
            "Parents": [{"Id": "ou-xxxx-12345678", "Type": "ORGANIZATIONAL_UNIT"}]
        }
        client.describe_organizational_unit.side_effect = ClientError(
            {
                "Error": {
                    "Code": "OrganizationalUnitNotFoundException",
                    "Message": "OU not found",
                }
            },
            "DescribeOrganizationalUnit",
        )

        result = _get_ou_metadata(client, "123456789012")

        assert result == {}

    def test_get_ou_metadata_deeply_nested_three_levels(self):
        client = MagicMock()
        # First call: account's parent is child OU
        # Second call: child OU's parent is mid OU
        # Third call: mid OU's parent is top OU
        # Fourth call: top OU's parent is ROOT
        client.list_parents.side_effect = [
            {"Parents": [{"Id": "ou-child", "Type": "ORGANIZATIONAL_UNIT"}]},
            {"Parents": [{"Id": "ou-mid", "Type": "ORGANIZATIONAL_UNIT"}]},
            {"Parents": [{"Id": "ou-top", "Type": "ORGANIZATIONAL_UNIT"}]},
            {"Parents": [{"Id": "r-root", "Type": "ROOT"}]},
        ]
        client.describe_organizational_unit.side_effect = [
            {"OrganizationalUnit": {"Id": "ou-child", "Name": "NonProd"}},
            {"OrganizationalUnit": {"Id": "ou-mid", "Name": "Workloads"}},
            {"OrganizationalUnit": {"Id": "ou-top", "Name": "Root"}},
        ]

        result = _get_ou_metadata(client, "123456789012")

        assert result == {"ou_id": "ou-child", "ou_path": "Root/Workloads/NonProd"}

    @mock_aws
    def test_get_organizations_metadata_api_failure_returns_empty_tuples(self):
        # Use a non-existent account ID without creating an organization
        metadata, tags, ou_metadata = get_organizations_metadata(
            "999999999999", boto3.Session()
        )

        assert metadata == {}
        assert tags == {}
        assert ou_metadata == {}

    def test_get_organizations_metadata_uses_user_agent_extra(self):
        session = MagicMock()

        get_organizations_metadata("123456789012", session)

        _, kwargs = session.client.call_args
        config = kwargs.get("config")
        assert config is not None
        assert BOTO3_USER_AGENT_EXTRA in config.user_agent_extra

    def test_parse_organizations_metadata_with_empty_ou_metadata(self):
        tags = {"Tags": []}
        metadata = {
            "Account": {
                "Id": AWS_ACCOUNT_NUMBER,
                "Arn": f"arn:aws:organizations::123456789012:account/o-abc123/{AWS_ACCOUNT_NUMBER}",
                "Email": "test@example.org",
                "Name": "test-account",
                "Status": "ACTIVE",
            }
        }
        # Simulates the error path where _get_ou_metadata returns {}
        ou_metadata = {}

        org = parse_organizations_metadata(metadata, tags, ou_metadata)

        assert org.account_ou_id == ""
        assert org.account_ou_name == ""

    def test_parse_organizations_metadata_with_none_ou_metadata(self):
        tags = {"Tags": []}
        metadata = {
            "Account": {
                "Id": AWS_ACCOUNT_NUMBER,
                "Arn": f"arn:aws:organizations::123456789012:account/o-abc123/{AWS_ACCOUNT_NUMBER}",
                "Email": "test@example.org",
                "Name": "test-account",
                "Status": "ACTIVE",
            }
        }

        org = parse_organizations_metadata(metadata, tags, None)

        assert org.account_ou_id == ""
        assert org.account_ou_name == ""

    @mock_aws
    def test_end_to_end_ou_metadata_flows_to_organizations_info(self):
        """Integration test: exercises get_organizations_metadata →
        parse_organizations_metadata with a nested OU, verifying the full
        data flow that AwsProvider.get_organizations_info relies on."""
        client = boto3.client("organizations", region_name=AWS_REGION_US_EAST_1)

        client.create_organization(FeatureSet="ALL")
        account_id = client.create_account(
            AccountName="e2e-account", Email="e2e@example.org"
        )["CreateAccountStatus"]["AccountId"]

        root_id = client.list_roots()["Roots"][0]["Id"]
        top_ou = client.create_organizational_unit(ParentId=root_id, Name="Workloads")[
            "OrganizationalUnit"
        ]
        child_ou = client.create_organizational_unit(
            ParentId=top_ou["Id"], Name="NonProd"
        )["OrganizationalUnit"]

        client.move_account(
            AccountId=account_id,
            SourceParentId=root_id,
            DestinationParentId=child_ou["Id"],
        )
        client.tag_resource(
            ResourceId=account_id,
            Tags=[{"Key": "Environment", "Value": "dev"}],
        )

        # Full flow: get → parse → AWSOrganizationsInfo
        metadata, tags, ou_metadata = get_organizations_metadata(
            account_id, boto3.Session()
        )
        org = parse_organizations_metadata(metadata, tags, ou_metadata)

        assert isinstance(org, AWSOrganizationsInfo)
        assert org.account_name == "e2e-account"
        assert org.account_email == "e2e@example.org"
        assert org.account_tags == {"Environment": "dev"}
        assert org.account_ou_id == child_ou["Id"]
        assert org.account_ou_name == "Workloads/NonProd"

    @mock_aws
    def test_end_to_end_account_under_root_has_empty_ou(self):
        """Integration test: account directly under Root should produce
        empty OU fields, not errors."""
        client = boto3.client("organizations", region_name=AWS_REGION_US_EAST_1)

        client.create_organization(FeatureSet="ALL")
        account_id = client.create_account(
            AccountName="root-account", Email="root@example.org"
        )["CreateAccountStatus"]["AccountId"]

        metadata, tags, ou_metadata = get_organizations_metadata(
            account_id, boto3.Session()
        )
        org = parse_organizations_metadata(metadata, tags, ou_metadata)

        assert isinstance(org, AWSOrganizationsInfo)
        assert org.account_ou_id == ""
        assert org.account_ou_name == ""
