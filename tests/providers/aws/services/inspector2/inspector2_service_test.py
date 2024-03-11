from datetime import datetime
from unittest.mock import patch

import botocore

from prowler.providers.aws.services.inspector2.inspector2_service import Inspector2
from tests.providers.aws.audit_info_utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_provider,
)

FINDING_ARN = (
    "arn:aws:inspector2:us-east-1:123456789012:finding/0e436649379db5f327e3cf5bb4421d76"
)

# Mocking Calls
make_api_call = botocore.client.BaseClient._make_api_call


def mock_make_api_call(self, operation_name, kwargs):
    """We have to mock every AWS API call using Boto3"""
    if operation_name == "BatchGetAccountStatus":
        return {
            "accounts": [
                {
                    "accountId": AWS_ACCOUNT_NUMBER,
                    "resourceState": {
                        "ec2": {
                            "errorCode": "ALREADY_ENABLED",
                            "errorMessage": "string",
                            "status": "ENABLED",
                        },
                        "ecr": {
                            "errorCode": "ALREADY_ENABLED",
                            "errorMessage": "string",
                            "status": "ENABLED",
                        },
                        "lambda": {
                            "errorCode": "ALREADY_ENABLED",
                            "errorMessage": "string",
                            "status": "ENABLED",
                        },
                    },
                    "state": {
                        "errorCode": "ALREADY_ENABLED",
                        "errorMessage": "string",
                        "status": "ENABLED",
                    },
                }
            ]
        }
    if operation_name == "ListFindings":
        return {
            "findings": [
                {
                    "awsAccountId": AWS_ACCOUNT_NUMBER,
                    "findingArn": FINDING_ARN,
                    "description": "Finding Description",
                    "severity": "MEDIUM",
                    "status": "ACTIVE",
                    "title": "CVE-2022-40897 - setuptools",
                    "type": "PACKAGE_VULNERABILITY",
                    "updatedAt": datetime(2024, 1, 1),
                }
            ]
        }

    return make_api_call(self, operation_name, kwargs)


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
class Test_Inspector2_Service:
    def test__get_client__(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        inspector2 = Inspector2(aws_provider)
        assert (
            inspector2.regional_clients[AWS_REGION_EU_WEST_1].__class__.__name__
            == "Inspector2"
        )

    def test__get_service__(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        inspector2 = Inspector2(aws_provider)
        assert inspector2.service == "inspector2"

    def test__batch_get_account_status__(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        inspector2 = Inspector2(aws_provider)
        assert len(inspector2.inspectors) == 1
        assert inspector2.inspectors[0].id == "Inspector2"
        assert inspector2.inspectors[0].region == AWS_REGION_EU_WEST_1
        assert inspector2.inspectors[0].status == "ENABLED"

    def test__list_findings__(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        inspector2 = Inspector2(aws_provider)
        assert len(inspector2.inspectors[0].findings) == 1
        assert inspector2.inspectors[0].findings[0].arn == FINDING_ARN
        assert inspector2.inspectors[0].findings[0].region == AWS_REGION_EU_WEST_1
        assert inspector2.inspectors[0].findings[0].severity == "MEDIUM"
        assert inspector2.inspectors[0].findings[0].status == "ACTIVE"
        assert (
            inspector2.inspectors[0].findings[0].title == "CVE-2022-40897 - setuptools"
        )
