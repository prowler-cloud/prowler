import yaml
from boto3 import resource, session
from moto import mock_dynamodb, mock_s3

from providers.aws.lib.allowlist.allowlist import is_allowlisted, parse_allowlist_file
from providers.aws.lib.audit_info.models import AWS_Audit_Info

AWS_ACCOUNT_NUMBER = 123456789012
AWS_REGION = "us-east-1"


class Test_Allowlist:

    # Mocked Audit Info
    def set_mocked_audit_info(self):
        audit_info = AWS_Audit_Info(
            original_session=None,
            audit_session=session.Session(
                profile_name=None,
                botocore_session=None,
            ),
            audited_account=AWS_ACCOUNT_NUMBER,
            audited_user_id=None,
            audited_partition="aws",
            audited_identity_arn=None,
            profile=None,
            profile_region=None,
            credentials=None,
            assumed_role_info=None,
            audited_regions=None,
            organizations_metadata=None,
        )
        return audit_info

    # Test S3 allowlist
    @mock_s3
    def test_s3_allowlist(self):
        audit_info = self.set_mocked_audit_info()
        # Create bucket and upload allowlist yaml
        s3_resource = resource("s3", region_name=AWS_REGION)
        s3_resource.create_bucket(Bucket="test-allowlist")
        s3_resource.Object("test-allowlist", "allowlist.yaml").put(
            Body=open(
                "providers/aws/lib/allowlist/fixtures/allowlist.yaml",
                "rb",
            )
        )

        with open("providers/aws/lib/allowlist/fixtures/allowlist.yaml") as f:
            assert yaml.safe_load(f)["Allowlist"] == parse_allowlist_file(
                audit_info, "s3://test-allowlist/allowlist.yaml"
            )

    # Test S3 allowlist
    @mock_dynamodb
    def test_dynamo_allowlist(self):
        audit_info = self.set_mocked_audit_info()
        # Create table and put item
        dynamodb_resource = resource("dynamodb", region_name=AWS_REGION)
        table_name = "test-allowlist"
        params = {
            "TableName": table_name,
            "KeySchema": [
                {"AttributeName": "Accounts", "KeyType": "HASH"},
                {"AttributeName": "Checks", "KeyType": "RANGE"},
            ],
            "AttributeDefinitions": [
                {"AttributeName": "Accounts", "AttributeType": "S"},
                {"AttributeName": "Checks", "AttributeType": "S"},
            ],
            "ProvisionedThroughput": {
                "ReadCapacityUnits": 10,
                "WriteCapacityUnits": 10,
            },
        }
        table = dynamodb_resource.create_table(**params)
        table.put_item(
            Item={
                "Accounts": "*",
                "Checks": "iam_user_hardware_mfa_enabled",
                "Regions": ["eu-west-1", "us-east-1"],
                "Resources": ["keyword"],
            }
        )

        assert (
            "keyword"
            in parse_allowlist_file(
                audit_info,
                "arn:aws:dynamodb:"
                + AWS_REGION
                + ":"
                + str(AWS_ACCOUNT_NUMBER)
                + ":table/"
                + table_name,
            )["Accounts"]["*"]["Checks"]["iam_user_hardware_mfa_enabled"]["Resources"]
        )

    # Allowlist checks
    def test_is_allowlisted(self):

        # Allowlist example
        allowlist = {
            "Accounts": {
                "*": {
                    "Checks": {
                        "check_test": {
                            "Regions": ["us-east-1", "eu-west-1"],
                            "Resources": ["prowler", "^test"],
                        }
                    }
                }
            }
        }

        assert (
            is_allowlisted(
                allowlist, AWS_ACCOUNT_NUMBER, "check_test", AWS_REGION, "prowler"
            )
            == True
        )

        assert (
            is_allowlisted(
                allowlist, AWS_ACCOUNT_NUMBER, "check_test", AWS_REGION, "prowler-test"
            )
            == True
        )

        assert (
            is_allowlisted(
                allowlist, AWS_ACCOUNT_NUMBER, "check_test", AWS_REGION, "test-prowler"
            )
            == True
        )

        assert (
            is_allowlisted(
                allowlist, AWS_ACCOUNT_NUMBER, "check_test", "us-east-2", "test"
            )
            == False
        )
