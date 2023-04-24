from datetime import datetime
from unittest.mock import patch

import botocore
from boto3 import session

from prowler.providers.aws.lib.audit_info.audit_info import AWS_Audit_Info
from prowler.providers.aws.services.inspector2.inspector2_service import Inspector2

AWS_REGION = "us-east-1"
AWS_ACCOUNT_ID = "123456789012"
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
                        "accountId": "string",
                        "resourceState": { 
                            "ec2": { 
                            "errorCode": "ALREADY_ENABLED",
                            "errorMessage": "string",
                            "status": "ENABLED"
                            },
                            "ecr": { 
                            "errorCode": "ALREADY_ENABLED",
                            "errorMessage": "string",
                            "status": "ENABLED"
                            },
                            "lambda": { 
                            "errorCode": "ALREADY_ENABLED",
                            "errorMessage": "string",
                            "status": "ENABLED"
                            }
                        },
                        "state": { 
                            "errorCode": "ALREADY_ENABLED",
                            "errorMessage": "string",
                            "status": "ENABLED"
                        }
                    }
                ]
                }
    if operation_name == "ListFindings":
        return {
            "findings": [
                {
                    "awsAccountId": AWS_ACCOUNT_ID,
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


def mock_generate_regional_clients(service, audit_info):
    regional_client = audit_info.audit_session.client(service, region_name=AWS_REGION)
    regional_client.region = AWS_REGION
    return {AWS_REGION: regional_client}


# Patch every AWS call using Boto3 and generate_regional_clients to have 1 client
@patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
@patch(
    "prowler.providers.aws.services.inspector2.inspector2_service.generate_regional_clients",
    new=mock_generate_regional_clients,
)
class Test_Inspector2_Service:

    # Mocked Audit Info
    def set_mocked_audit_info(self):
        audit_info = AWS_Audit_Info(
            session_config=None,
            original_session=None,
            audit_session=session.Session(
                profile_name=None,
                botocore_session=None,
            ),
            audited_account=None,
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
        )
        return audit_info

    def test__get_client__(self):
        audit_info = self.set_mocked_audit_info()
        ssmincidents = Inspector2(audit_info)
        assert (
            ssmincidents.regional_clients[AWS_REGION].__class__.__name__ == "Inspector2"
        )

    def test__get_service__(self):
        audit_info = self.set_mocked_audit_info()
        ssmincidents = Inspector2(audit_info)
        assert ssmincidents.service == "inspector2"

    def test__batch_get_account_status__(self):
        audit_info = self.set_mocked_audit_info()
        ssmincidents = Inspector2(audit_info)
        assert len(ssmincidents.inspectors) == 1
        assert ssmincidents.inspectors[0].id == "Inspector2"
        assert ssmincidents.inspectors[0].region == AWS_REGION
        assert ssmincidents.inspectors[0].status == "ENABLED"

    def test__list_findings__(self):
        audit_info = self.set_mocked_audit_info()
        ssmincidents = Inspector2(audit_info)
        assert len(ssmincidents.inspectors[0].findings) == 1
        assert ssmincidents.inspectors[0].findings[0].arn == FINDING_ARN
        assert ssmincidents.inspectors[0].findings[0].region == AWS_REGION
        assert ssmincidents.inspectors[0].findings[0].severity == "MEDIUM"
        assert ssmincidents.inspectors[0].findings[0].status == "ACTIVE"
        assert (
            ssmincidents.inspectors[0].findings[0].title
            == "CVE-2022-40897 - setuptools"
        )
