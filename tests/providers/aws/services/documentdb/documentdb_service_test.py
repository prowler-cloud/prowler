import botocore
from boto3 import session
from mock import patch

from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info
from prowler.providers.aws.services.documentdb.documentdb_service import (
    DocumentDB,
    Instance,
)
from prowler.providers.common.models import Audit_Metadata

AWS_ACCOUNT_NUMBER = "123456789012"
AWS_ACCOUNT_ARN = f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"
AWS_REGION = "us-east-1"

DOC_DB_CLUSTER_ID = "test-cluster"
DOC_DB_INSTANCE_NAME = "test-db"
DOC_DB_INSTANCE_ARN = (
    f"arn:aws:rds:{AWS_REGION}:{AWS_ACCOUNT_NUMBER}:db:{DOC_DB_INSTANCE_NAME}"
)
DOC_DB_ENGINE_VERSION = "5.0.0"

# Mocking Access Analyzer Calls
make_api_call = botocore.client.BaseClient._make_api_call


def mock_make_api_call(self, operation_name, kwargs):
    """
    As you can see the operation_name has the list_analyzers snake_case form but
    we are using the ListAnalyzers form.
    Rationale -> https://github.com/boto/botocore/blob/develop/botocore/client.py#L810:L816

    We have to mock every AWS API call using Boto3
    """
    if operation_name == "DescribeDBInstances":
        return {
            "DBInstances": [
                {
                    "DBInstanceIdentifier": DOC_DB_INSTANCE_NAME,
                    "DBInstanceClass": "string",
                    "Engine": "docdb",
                    "DBInstanceStatus": "available",
                    "BackupRetentionPeriod": 1,
                    "EngineVersion": "5.0.0",
                    "AutoMinorVersionUpgrade": False,
                    "PubliclyAccessible": False,
                    "DBClusterIdentifier": DOC_DB_CLUSTER_ID,
                    "StorageEncrypted": False,
                    "DbiResourceId": "string",
                    "CACertificateIdentifier": "string",
                    "CopyTagsToSnapshot": True | False,
                    "PromotionTier": 123,
                    "DBInstanceArn": DOC_DB_INSTANCE_ARN,
                },
            ]
        }
    if operation_name == "ListTagsForResource":
        return {"TagList": [{"Key": "environment", "Value": "test"}]}

    return make_api_call(self, operation_name, kwargs)


def mock_generate_regional_clients(service, audit_info, _):
    regional_client = audit_info.audit_session.client(service, region_name=AWS_REGION)
    regional_client.region = AWS_REGION
    return {AWS_REGION: regional_client}


@patch(
    "prowler.providers.aws.lib.service.service.generate_regional_clients",
    new=mock_generate_regional_clients,
)
# Patch every AWS call using Boto3
@patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
class Test_DocumentDB_Service:
    # Mocked Audit Info
    def set_mocked_audit_info(self):
        audit_info = AWS_Audit_Info(
            session_config=None,
            original_session=None,
            audit_session=session.Session(
                profile_name=None,
                botocore_session=None,
            ),
            audited_account=AWS_ACCOUNT_NUMBER,
            audited_account_arn=AWS_ACCOUNT_ARN,
            audited_user_id=None,
            audited_partition="aws",
            audited_identity_arn=None,
            profile=None,
            profile_region=None,
            credentials=None,
            assumed_role_info=None,
            audited_regions=None,
            organizations_metadata=None,
            audit_resources=None,
            mfa_enabled=False,
            audit_metadata=Audit_Metadata(
                services_scanned=0,
                expected_checks=[],
                completed_checks=0,
                audit_progress=0,
            ),
        )
        return audit_info

    # Test DocumentDB Service
    def test_service(self):
        audit_info = self.set_mocked_audit_info()
        docdb = DocumentDB(audit_info)
        assert docdb.service == "docdb"

    # Test DocumentDB Client
    def test_client(self):
        audit_info = self.set_mocked_audit_info()
        docdb = DocumentDB(audit_info)
        assert docdb.client.__class__.__name__ == "DocDB"

    # Test DocumentDB Session
    def test__get_session__(self):
        audit_info = self.set_mocked_audit_info()
        docdb = DocumentDB(audit_info)
        assert docdb.session.__class__.__name__ == "Session"

    # Test DocumentDB Session
    def test_audited_account(self):
        audit_info = self.set_mocked_audit_info()
        docdb = DocumentDB(audit_info)
        assert docdb.audited_account == AWS_ACCOUNT_NUMBER

    # Test DocumentDB Get DocumentDB Contacts
    def test_describe_db_instances(self):
        audit_info = self.set_mocked_audit_info()
        docdb = DocumentDB(audit_info)
        assert docdb.db_instances == {
            DOC_DB_INSTANCE_ARN: Instance(
                id=DOC_DB_INSTANCE_NAME,
                arn=DOC_DB_INSTANCE_ARN,
                engine="docdb",
                engine_version="5.0.0",
                status="available",
                public=False,
                encrypted=False,
                cluster_id=DOC_DB_CLUSTER_ID,
                region=AWS_REGION,
                tags=[{"Key": "environment", "Value": "test"}],
            )
        }
