import boto3
from moto import mock_aws

from prowler.providers.aws.lib.organizations.organizations import (
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
