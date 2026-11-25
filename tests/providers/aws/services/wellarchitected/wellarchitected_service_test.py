from unittest.mock import patch
from uuid import uuid4

import botocore
import pytest

from prowler.providers.aws.services.wellarchitected.wellarchitected_service import (
    WellArchitected,
)
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    mocked_api_response,
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


@pytest.fixture
def paginated_workloads():
    first_id = "1" * 32
    second_id = "2" * 32
    first = {
        "WorkloadId": first_id,
        "WorkloadArn": f"arn:aws:wellarchitected:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:workload/{first_id}",
        "WorkloadName": "first-page",
        "Owner": AWS_ACCOUNT_NUMBER,
        "UpdatedAt": "2026-11-25T12:00:00+00:00",
        "Lenses": ["wellarchitected"],
        "RiskCounts": {},
        "ImprovementStatus": "IN_PROGRESS",
    }
    second = {
        **first,
        "WorkloadId": second_id,
        "WorkloadArn": f"arn:aws:wellarchitected:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:workload/{second_id}",
        "WorkloadName": "later-page",
        "Lenses": ["wellarchitected", "serverless"],
        "RiskCounts": {"HIGH": 4, "MEDIUM": 2},
    }
    pages = {
        None: {"WorkloadSummaries": [first], "NextToken": "second-page"},
        "second-page": {"WorkloadSummaries": [second]},
    }
    requested_tokens = set()

    def mock_paginated_api_call(client, operation_name, params):
        if client.meta.service_model.service_name != "wellarchitected":
            return make_api_call(client, operation_name, params)
        if operation_name == "ListWorkloads":
            token = params.get("NextToken")
            request = (client, token)
            assert request not in requested_tokens, "Pagination requested a page twice"
            requested_tokens.add(request)
            response = pages[token]
            if isinstance(response, Exception):
                raise response
            return mocked_api_response("wellarchitected", operation_name, response)
        if operation_name == "ListTagsForResource":
            page = "second" if params["WorkloadArn"].endswith(second_id) else "first"
            return mocked_api_response(
                "wellarchitected", operation_name, {"Tags": {"page": page}}
            )
        return mock_make_api_call(client, operation_name, params)

    with patch(
        "botocore.client.BaseClient._make_api_call", new=mock_paginated_api_call
    ):
        yield pages


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


@patch(
    "prowler.providers.aws.aws_provider.AwsProvider.generate_regional_clients",
    new=mock_generate_regional_clients,
)
class Test_WellArchitected_Pagination:
    def test_list_workloads_multiple_pages(self, paginated_workloads):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        wellarchitected = WellArchitected(aws_provider)

        assert [workload.id for workload in wellarchitected.workloads] == [
            "1" * 32,
            "2" * 32,
        ]
        workload = wellarchitected.workloads[1]
        assert workload.arn == (
            f"arn:aws:wellarchitected:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:workload/"
            + "2" * 32
        )
        assert workload.name == "later-page"
        assert workload.region == AWS_REGION_EU_WEST_1
        assert workload.lenses == ["wellarchitected", "serverless"]
        assert workload.improvement_status == "IN_PROGRESS"
        assert workload.risks == {"HIGH": 4, "MEDIUM": 2}
        assert workload.tags == [{"page": "second"}]

    @pytest.mark.parametrize("first_page_empty", [False, True])
    def test_list_workloads_filtered_later_page(
        self, paginated_workloads, first_page_empty
    ):
        if first_page_empty:
            paginated_workloads[None]["WorkloadSummaries"] = []
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        aws_provider._audit_resources = [
            f"arn:aws:wellarchitected:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:workload/"
            + "2" * 32
        ]

        wellarchitected = WellArchitected(aws_provider)

        assert [workload.id for workload in wellarchitected.workloads] == ["2" * 32]
        assert wellarchitected.workloads[0].tags == [{"page": "second"}]

    def test_list_workloads_empty(self, paginated_workloads):
        paginated_workloads[None] = {"WorkloadSummaries": []}
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        wellarchitected = WellArchitected(aws_provider)

        assert wellarchitected.workloads == []

    def test_list_workloads_later_page_error(self, paginated_workloads, caplog):
        paginated_workloads["second-page"] = botocore.exceptions.ClientError(
            {
                "Error": {
                    "Code": "AccessDeniedException",
                    "Message": "Synthetic later-page failure",
                }
            },
            "ListWorkloads",
        )
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        wellarchitected = WellArchitected(aws_provider)

        assert [workload.id for workload in wellarchitected.workloads] == ["1" * 32]
        assert wellarchitected.workloads[0].tags == [{"page": "first"}]
        assert "Synthetic later-page failure" in caplog.text

    def test_later_page_workload_risks_are_reported(self, paginated_workloads):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        wellarchitected = WellArchitected(aws_provider)
        # Restore any client/check modules first imported by this test.
        with (
            patch.dict("sys.modules"),
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            patch(
                "prowler.providers.aws.services.wellarchitected.wellarchitected_workload_no_high_or_medium_risks.wellarchitected_workload_no_high_or_medium_risks.wellarchitected_client",
                new=wellarchitected,
            ),
        ):
            from prowler.providers.aws.services.wellarchitected.wellarchitected_workload_no_high_or_medium_risks.wellarchitected_workload_no_high_or_medium_risks import (
                wellarchitected_workload_no_high_or_medium_risks,
            )

            findings = wellarchitected_workload_no_high_or_medium_risks().execute()

        assert [(finding.resource_id, finding.status) for finding in findings] == [
            ("1" * 32, "PASS"),
            ("2" * 32, "FAIL"),
        ]
        assert findings[1].region == AWS_REGION_EU_WEST_1
        assert findings[1].status_extended == (
            "Well Architected workload later-page contains 4 high and 2 medium risks."
        )
