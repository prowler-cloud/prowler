from datetime import datetime
from unittest.mock import patch

import botocore

from prowler.providers.aws.services.ssmincidents.ssmincidents_service import (
    SSMIncidents,
)
from tests.providers.aws.audit_info_utils import (
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

REPLICATION_SET_ARN = "arn:aws:ssm-incidents::111122223333:replication-set/40bd98f0-4110-2dee-b35e-b87006f9e172"
RESPONSE_PLAN_ARN = "arn:aws:ssm-incidents::111122223333:response-plan/example-response"

# Mocking Calls
make_api_call = botocore.client.BaseClient._make_api_call


def mock_make_api_call(self, operation_name, kwargs):
    """We have to mock every AWS API call using Boto3"""
    if operation_name == "ListReplicationSets":
        return {"replicationSetArns": [REPLICATION_SET_ARN]}
    if operation_name == "GetReplicationSet":
        return {
            "replicationSet": {
                "arn": REPLICATION_SET_ARN,
                "createdBy": "Prowler",
                "createdTime": datetime(2024, 1, 1),
                "deletionProtected": False,
                "lastModifiedBy": datetime(2024, 1, 1),
                "lastModifiedTime": datetime(2024, 1, 1),
                "regionMap": {
                    AWS_REGION_US_EAST_1: {
                        "sseKmsKeyId": "DefaultKey",
                        "status": "ACTIVE",
                        "statusMessage": "Test",
                        "statusUpdateDateTime": datetime(2024, 1, 1),
                    }
                },
                "status": "ACTIVE",
            }
        }
    if operation_name == "ListResponsePlans":
        return {
            "responsePlanSummaries": [
                {"Arn": RESPONSE_PLAN_ARN, "displayName": "test", "Name": "test"}
            ]
        }
    if operation_name == "ListTagsForResource":
        return {"tags": {"tag_test": "tag_value"}}

    return make_api_call(self, operation_name, kwargs)


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
class Test_SSMIncidents_Service:
    def test__get_client__(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        ssmincidents = SSMIncidents(aws_provider)
        assert (
            ssmincidents.regional_clients[AWS_REGION_US_EAST_1].__class__.__name__
            == "SSMIncidents"
        )

    def test__get_service__(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        ssmincidents = SSMIncidents(aws_provider)
        assert ssmincidents.service == "ssm-incidents"

    def test__list_replication_sets__(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        ssmincidents = SSMIncidents(aws_provider)
        assert len(ssmincidents.replication_set) == 1

    def test__get_replication_set__(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        ssmincidents = SSMIncidents(aws_provider)
        assert ssmincidents.replication_set[0].arn == REPLICATION_SET_ARN
        assert ssmincidents.replication_set[0].status == "ACTIVE"
        for region in ssmincidents.replication_set[0].region_map:
            assert region.region == AWS_REGION_US_EAST_1
            assert region.status == "ACTIVE"
            assert region.sse_kms_id == "DefaultKey"

    def test__list_response_plans__(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        ssmincidents = SSMIncidents(aws_provider)
        assert len(ssmincidents.response_plans) == 1
        assert ssmincidents.response_plans[0].arn == RESPONSE_PLAN_ARN
        assert ssmincidents.response_plans[0].name == "test"
        assert ssmincidents.response_plans[0].region == AWS_REGION_US_EAST_1
        assert ssmincidents.response_plans[0].tags == {"tag_test": "tag_value"}

    def test__list_tags_for_resource__(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        ssmincidents = SSMIncidents(aws_provider)
        assert len(ssmincidents.response_plans) == 1
        assert ssmincidents.response_plans[0].tags == {"tag_test": "tag_value"}
