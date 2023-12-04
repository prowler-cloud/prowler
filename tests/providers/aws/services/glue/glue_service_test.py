from unittest.mock import patch

import botocore
from boto3 import session
from moto import mock_glue

from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info
from prowler.providers.aws.services.glue.glue_service import Glue
from prowler.providers.common.models import Audit_Metadata
from tests.providers.aws.audit_info_utils import (
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_audit_info,
)

AWS_ACCOUNT_NUMBER = "123456789012"
AWS_REGION = "us-east-1"

# Mocking Access Analyzer Calls
make_api_call = botocore.client.BaseClient._make_api_call


def mock_make_api_call(self, operation_name, kwarg):
    """
    We have to mock every AWS API call using Boto3

    As you can see the operation_name has the list_analyzers snake_case form but
    we are using the ListAnalyzers form.
    Rationale -> https://github.com/boto/botocore/blob/develop/botocore/client.py#L810:L816
    """
    if operation_name == "GetJobs":
        return {
            "Jobs": [
                {
                    "Name": "job",
                    "SecurityConfiguration": "security_config",
                    "DefaultArguments": {
                        "--encryption-type": "sse-s3",
                        "--enable-job-insights": "false",
                    },
                }
            ]
        }
    elif operation_name == "GetConnections":
        return {
            "ConnectionList": [
                {
                    "Name": "connection",
                    "ConnectionType": "JDBC",
                    "ConnectionProperties": {
                        "CONNECTOR_TYPE": "Jdbc",
                        "JDBC_CONNECTION_URL": '[["default=test"],":"]',
                        "CONNECTOR_URL": "s3://bck-dev",
                        "CONNECTOR_CLASS_NAME": "test",
                        "JDBC_ENFORCE_SSL": "true",
                    },
                }
            ]
        }
    elif operation_name == "SearchTables":
        return {
            "TableList": [
                {"Name": "table", "DatabaseName": "database", "CatalogId": "catalog"}
            ]
        }
    elif operation_name == "GetDevEndpoints":
        return {
            "DevEndpoints": [
                {
                    "EndpointName": "endpoint",
                    "SecurityConfiguration": "security_config",
                }
            ]
        }
    elif operation_name == "GetDataCatalogEncryptionSettings":
        return {
            "DataCatalogEncryptionSettings": {
                "EncryptionAtRest": {
                    "CatalogEncryptionMode": "SSE-KMS",
                    "SseAwsKmsKeyId": "kms_key",
                },
                "ConnectionPasswordEncryption": {
                    "ReturnConnectionPasswordEncrypted": True,
                    "AwsKmsKeyId": "password_key",
                },
            }
        }
    elif operation_name == "GetSecurityConfigurations":
        return {
            "SecurityConfigurations": [
                {
                    "Name": "test",
                    "EncryptionConfiguration": {
                        "S3Encryption": [
                            {
                                "S3EncryptionMode": "DISABLED",
                            },
                        ],
                        "CloudWatchEncryption": {
                            "CloudWatchEncryptionMode": "DISABLED",
                        },
                        "JobBookmarksEncryption": {
                            "JobBookmarksEncryptionMode": "DISABLED",
                        },
                    },
                },
            ],
        }
    return make_api_call(self, operation_name, kwarg)


# Mock generate_regional_clients()
def mock_generate_regional_clients(service, audit_info, _):
    regional_client = audit_info.audit_session.client(service, region_name=AWS_REGION)
    regional_client.region = AWS_REGION
    return {AWS_REGION: regional_client}


# Patch every AWS call using Boto3 and generate_regional_clients to have 1 client
@patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
@patch(
    "prowler.providers.aws.lib.service.service.generate_regional_clients",
    new=mock_generate_regional_clients,
)
class Test_Glue_Service:
    def set_mocked_audit_info(self):
        audit_info = AWS_Audit_Info(
            session_config=None,
            original_session=None,
            audit_session=session.Session(
                profile_name=None,
                botocore_session=None,
            ),
            audited_account=AWS_ACCOUNT_NUMBER,
            audited_account_arn=f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root",
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

    # Test Glue Service
    @mock_glue
    def test_service(self):
        # Glue client for this test class
        audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])
        glue = Glue(audit_info)
        assert glue.service == "glue"

    # Test Glue Client
    @mock_glue
    def test_client(self):
        # Glue client for this test class
        audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])
        glue = Glue(audit_info)
        for regional_client in glue.regional_clients.values():
            assert regional_client.__class__.__name__ == "Glue"

    # Test Glue Session
    @mock_glue
    def test__get_session__(self):
        # Glue client for this test class
        audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])
        glue = Glue(audit_info)
        assert glue.session.__class__.__name__ == "Session"

    # Test Glue Session
    @mock_glue
    def test_audited_account(self):
        # Glue client for this test class
        audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])
        glue = Glue(audit_info)
        assert glue.audited_account == AWS_ACCOUNT_NUMBER

    # Test Glue Search Tables
    @mock_glue
    def test__search_tables__(self):
        audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])
        glue = Glue(audit_info)
        assert len(glue.tables) == 1
        assert glue.tables[0].name == "table"
        assert glue.tables[0].database == "database"
        assert glue.tables[0].catalog == "catalog"
        assert glue.tables[0].region == AWS_REGION

    # Test Glue Get Connections
    @mock_glue
    def test__get_connections__(self):
        audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])
        glue = Glue(audit_info)
        assert len(glue.connections) == 1
        assert glue.connections[0].name == "connection"
        assert glue.connections[0].type == "JDBC"
        assert glue.connections[0].properties == {
            "CONNECTOR_TYPE": "Jdbc",
            "JDBC_CONNECTION_URL": '[["default=test"],":"]',
            "CONNECTOR_URL": "s3://bck-dev",
            "CONNECTOR_CLASS_NAME": "test",
            "JDBC_ENFORCE_SSL": "true",
        }
        assert glue.connections[0].region == AWS_REGION

    # Test Glue Get Catalog Encryption
    @mock_glue
    def test__get_data_catalog_encryption_settings__(self):
        audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])
        glue = Glue(audit_info)
        assert len(glue.catalog_encryption_settings) == 1
        assert glue.catalog_encryption_settings[0].mode == "SSE-KMS"
        assert glue.catalog_encryption_settings[0].kms_id == "kms_key"
        assert glue.catalog_encryption_settings[0].password_encryption
        assert glue.catalog_encryption_settings[0].password_kms_id == "password_key"
        assert glue.catalog_encryption_settings[0].region == AWS_REGION

    # Test Glue Get Dev Endpoints
    @mock_glue
    def test__get_dev_endpoints__(self):
        audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])
        glue = Glue(audit_info)
        assert len(glue.dev_endpoints) == 1
        assert glue.dev_endpoints[0].name == "endpoint"
        assert glue.dev_endpoints[0].security == "security_config"
        assert glue.dev_endpoints[0].region == AWS_REGION

    # Test Glue Get Security Configs
    @mock_glue
    def test__get_security_configurations__(self):
        audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])
        glue = Glue(audit_info)
        assert len(glue.security_configs) == 1
        assert glue.security_configs[0].name == "test"
        assert glue.security_configs[0].s3_encryption == "DISABLED"
        assert glue.security_configs[0].cw_encryption == "DISABLED"
        assert glue.security_configs[0].jb_encryption == "DISABLED"
        assert glue.security_configs[0].region == AWS_REGION

    # Test Glue Get Security Configs
    @mock_glue
    def test__get_jobs__(self):
        audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])
        glue = Glue(audit_info)
        assert len(glue.jobs) == 1
        assert glue.jobs[0].name == "job"
        assert glue.jobs[0].security == "security_config"
        assert glue.jobs[0].arguments == {
            "--encryption-type": "sse-s3",
            "--enable-job-insights": "false",
        }
        assert glue.jobs[0].region == AWS_REGION
