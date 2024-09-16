from unittest.mock import patch
from uuid import uuid4

import botocore

from prowler.providers.aws.services.wellarchitected.wellarchitected_service import (
    WellArchitected,
)
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_provider,
)

workload_id = str(uuid4())

make_api_call = botocore.client.BaseClient._make_api_call


def mock_make_api_call(self, operation_name, kwarg):
    if operation_name == "ListWorkloads":
        return {
            "WorkloadSummaries": [
                {
                    "WorkloadId": workload_id,
                    "WorkloadArn": f"arn:aws:wellarchitected:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:workload/{workload_id}",
                    "WorkloadName": "test",
                    "Owner": AWS_ACCOUNT_NUMBER,
                    "UpdatedAt": "2023-06-07T15:40:24+02:00",
                    "Lenses": ["wellarchitected", "serverless", "softwareasaservice"],
                    "RiskCounts": {"UNANSWERED": 56, "NOT_APPLICABLE": 4, "HIGH": 10},
                    "ImprovementStatus": "NOT_APPLICABLE",
                },
            ]
        }
    if operation_name == "ListTagsForResource":
        return {
            "Tags": {"Key": "test", "Value": "test"},
        }
    return make_api_call(self, operation_name, kwarg)


def mock_generate_regional_clients(provider, service):
    regional_client = provider._session.current_session.client(
        service, region_name=AWS_REGION_EU_WEST_1
    )
    regional_client.region = AWS_REGION_EU_WEST_1
    return {AWS_REGION_EU_WEST_1: regional_client}


@patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
@patch(
    "prowler.providers.aws.aws_provider.AwsProvider.generate_regional_clients",
    new=mock_generate_regional_clients,
)
class Test_WellArchitected_Service:
    # Test WellArchitected Service
    def test_service(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        wellarchitected = WellArchitected(aws_provider)
        assert wellarchitected.service == "wellarchitected"

    # Test WellArchitected client
    def test_client(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        wellarchitected = WellArchitected(aws_provider)
        for reg_client in wellarchitected.regional_clients.values():
            assert reg_client.__class__.__name__ == "WellArchitected"

    # Test WellArchitected session
    def test__get_session__(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        wellarchitected = WellArchitected(aws_provider)
        assert wellarchitected.session.__class__.__name__ == "Session"

    # Test WellArchitected list workloads
    def test_list_workloads(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        wellarchitected = WellArchitected(aws_provider)
        assert len(wellarchitected.workloads) == 1
        assert wellarchitected.workloads[0].id == workload_id
        assert (
            wellarchitected.workloads[0].arn
            == f"arn:aws:wellarchitected:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:workload/{workload_id}"
        )
        assert wellarchitected.workloads[0].name == "test"
        assert wellarchitected.workloads[0].region == AWS_REGION_EU_WEST_1
        assert wellarchitected.workloads[0].tags == [
            {"Key": "test", "Value": "test"},
        ]
        assert wellarchitected.workloads[0].lenses == [
            "wellarchitected",
            "serverless",
            "softwareasaservice",
        ]
        assert wellarchitected.workloads[0].improvement_status == "NOT_APPLICABLE"
        assert wellarchitected.workloads[0].risks == {
            "UNANSWERED": 56,
            "NOT_APPLICABLE": 4,
            "HIGH": 10,
        }
