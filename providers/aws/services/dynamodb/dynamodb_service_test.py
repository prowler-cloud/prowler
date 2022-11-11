from boto3 import session
from moto import mock_dynamodb

from providers.aws.lib.audit_info.models import AWS_Audit_Info
from providers.aws.services.dynamodb.dynamodb_service import Dynamo

AWS_ACCOUNT_NUMBER = 123456789012
AWS_REGION = "us-east-1"


class Test_Dynamo_Service:
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

    # Test Dynamo Service
    @mock_dynamodb
    def test_service(self):
        # Dynamo client for this test class
        audit_info = self.set_mocked_audit_info()
        dynamodb = Dynamo(audit_info)
        assert dynamodb.service == "dynamodb"

    # Test Dynamo Client
    @mock_dynamodb
    def test_client(self):
        # Dynamo client for this test class
        audit_info = self.set_mocked_audit_info()
        dynamodb = Dynamo(audit_info)
        for client in dynamodb.regional_clients.values():
            assert client.__class__.__name__ == "DynamoDB"

    # Test Dynamo Session
    @mock_dynamodb
    def test__get_session__(self):
        # Dynamo client for this test class
        audit_info = self.set_mocked_audit_info()
        dynamodb = Dynamo(audit_info)
        assert dynamodb.session.__class__.__name__ == "Session"

    # Test Dynamo Session
    @mock_dynamodb
    def test_audited_account(self):
        # Dynamo client for this test class
        audit_info = self.set_mocked_audit_info()
        dynamodb = Dynamo(audit_info)
        assert dynamodb.audited_account == AWS_ACCOUNT_NUMBER
