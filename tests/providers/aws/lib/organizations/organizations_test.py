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

        metadata, tags = get_organizations_metadata(account_id, boto3.Session())
        org = parse_organizations_metadata(metadata, tags)

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
