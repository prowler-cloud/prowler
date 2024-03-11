from unittest.mock import patch

import botocore
from moto import mock_aws

from prowler.providers.aws.services.glue.glue_service import Glue
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

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
def mock_generate_regional_clients(provider, service):
    regional_client = provider._session.current_session.client(
        service, region_name=AWS_REGION_US_EAST_1
    )
    regional_client.region = AWS_REGION_US_EAST_1
    return {AWS_REGION_US_EAST_1: regional_client}


# Patch every AWS call using Boto3 and generate_regional_clients to have 1 client
@patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
@patch(
    "prowler.providers.aws.aws_provider.AwsProvider.generate_regional_clients",
    new=mock_generate_regional_clients,
)
class Test_Glue_Service:
    # Test Glue Service
    @mock_aws
    def test_service(self):
        # Glue client for this test class
        aws_provider = set_mocked_aws_provider()
        glue = Glue(aws_provider)
        assert glue.service == "glue"

    # Test Glue Client
    @mock_aws
    def test_client(self):
        # Glue client for this test class
        aws_provider = set_mocked_aws_provider()
        glue = Glue(aws_provider)
        for regional_client in glue.regional_clients.values():
            assert regional_client.__class__.__name__ == "Glue"

    # Test Glue Session
    @mock_aws
    def test__get_session__(self):
        # Glue client for this test class
        aws_provider = set_mocked_aws_provider()
        glue = Glue(aws_provider)
        assert glue.session.__class__.__name__ == "Session"

    # Test Glue Session
    @mock_aws
    def test_audited_account(self):
        # Glue client for this test class
        aws_provider = set_mocked_aws_provider()
        glue = Glue(aws_provider)
        assert glue.audited_account == AWS_ACCOUNT_NUMBER

    # Test Glue Search Tables
    @mock_aws
    def test__search_tables__(self):
        aws_provider = set_mocked_aws_provider()
        glue = Glue(aws_provider)
        assert len(glue.tables) == 1
        assert glue.tables[0].name == "table"
        assert glue.tables[0].database == "database"
        assert glue.tables[0].catalog == "catalog"
        assert glue.tables[0].region == AWS_REGION_US_EAST_1

    # Test Glue Get Connections
    @mock_aws
    def test__get_connections__(self):
        aws_provider = set_mocked_aws_provider()
        glue = Glue(aws_provider)
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
        assert glue.connections[0].region == AWS_REGION_US_EAST_1

    # Test Glue Get Catalog Encryption
    @mock_aws
    def test__get_data_catalog_encryption_settings__(self):
        aws_provider = set_mocked_aws_provider()
        glue = Glue(aws_provider)
        assert len(glue.catalog_encryption_settings) == 1
        assert glue.catalog_encryption_settings[0].mode == "SSE-KMS"
        assert glue.catalog_encryption_settings[0].kms_id == "kms_key"
        assert glue.catalog_encryption_settings[0].password_encryption
        assert glue.catalog_encryption_settings[0].password_kms_id == "password_key"
        assert glue.catalog_encryption_settings[0].region == AWS_REGION_US_EAST_1

    # Test Glue Get Dev Endpoints
    @mock_aws
    def test__get_dev_endpoints__(self):
        aws_provider = set_mocked_aws_provider()
        glue = Glue(aws_provider)
        assert len(glue.dev_endpoints) == 1
        assert glue.dev_endpoints[0].name == "endpoint"
        assert glue.dev_endpoints[0].security == "security_config"
        assert glue.dev_endpoints[0].region == AWS_REGION_US_EAST_1

    # Test Glue Get Security Configs
    @mock_aws
    def test__get_security_configurations__(self):
        aws_provider = set_mocked_aws_provider()
        glue = Glue(aws_provider)
        assert len(glue.security_configs) == 1
        assert glue.security_configs[0].name == "test"
        assert glue.security_configs[0].s3_encryption == "DISABLED"
        assert glue.security_configs[0].cw_encryption == "DISABLED"
        assert glue.security_configs[0].jb_encryption == "DISABLED"
        assert glue.security_configs[0].region == AWS_REGION_US_EAST_1

    # Test Glue Get Security Configs
    @mock_aws
    def test__get_jobs__(self):
        aws_provider = set_mocked_aws_provider()
        glue = Glue(aws_provider)
        assert len(glue.jobs) == 1
        assert glue.jobs[0].name == "job"
        assert glue.jobs[0].security == "security_config"
        assert glue.jobs[0].arguments == {
            "--encryption-type": "sse-s3",
            "--enable-job-insights": "false",
        }
        assert glue.jobs[0].region == AWS_REGION_US_EAST_1
