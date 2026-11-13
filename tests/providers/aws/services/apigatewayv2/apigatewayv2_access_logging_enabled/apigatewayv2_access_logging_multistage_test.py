"""Regression coverage for independent access-logging findings per stage."""

from unittest import mock

import botocore
import pytest
from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider


@pytest.fixture
def run_stages():
    """Run the real collector and check with controlled GetStages responses."""

    def run(stage_names):
        with mock_aws():
            aws_client = client("apigatewayv2", region_name=AWS_REGION_US_EAST_1)
            api_id = aws_client.create_api(Name="test-api", ProtocolType="HTTP")[
                "ApiId"
            ]
            original_call = botocore.client.BaseClient._make_api_call

            def api_call(self, operation_name, params):
                if self.meta.service_model.service_name == "apigatewayv2":
                    if operation_name == "GetAuthorizers":
                        return {"Items": []}
                    if operation_name == "GetStages":
                        assert params["ApiId"] == api_id
                        return {
                            "Items": [
                                {
                                    "StageName": name,
                                    **(
                                        {
                                            "AccessLogSettings": {
                                                "DestinationArn": "arn:aws:logs:us-east-1:123456789012:log-group:access-logs",
                                                "Format": "$context.requestId",
                                            }
                                        }
                                        if name == "stage-b"
                                        else {}
                                    ),
                                }
                                for name in stage_names
                            ]
                        }
                return original_call(self, operation_name, params)

            from prowler.providers.aws.services.apigatewayv2.apigatewayv2_service import (
                ApiGatewayV2,
            )

            aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
            with mock.patch("botocore.client.BaseClient._make_api_call", new=api_call):
                service = ApiGatewayV2(aws_provider)
                assert len(service.apis) == 1
                assert [(s.name, s.logging) for s in service.apis[0].stages] == [
                    (name, name == "stage-b") for name in stage_names
                ]
                with (
                    mock.patch(
                        "prowler.providers.common.provider.Provider.get_global_provider",
                        return_value=aws_provider,
                    ),
                    mock.patch(
                        "prowler.providers.aws.services.apigatewayv2.apigatewayv2_api_access_logging_enabled.apigatewayv2_api_access_logging_enabled.apigatewayv2_client",
                        new=service,
                    ),
                ):
                    from prowler.providers.aws.services.apigatewayv2.apigatewayv2_api_access_logging_enabled.apigatewayv2_api_access_logging_enabled import (
                        apigatewayv2_api_access_logging_enabled,
                    )

                    findings = apigatewayv2_api_access_logging_enabled().execute()
            assert len(findings) == len(stage_names)
            return api_id, findings

    return run


@pytest.mark.parametrize(
    "stage_names",
    [("stage-a", "stage-b"), ("stage-b", "stage-a")],
    ids=["off-on", "on-off"],
)
class Test_apigatewayv2_multistage_findings:
    """Verify access logging findings for both stage orders."""

    def test_status_per_stage(self, run_stages, stage_names):
        """Verify the status and description of each stage."""
        api_id, findings = run_stages(stage_names)
        assert [f.status for f in findings] == [
            "PASS" if name == "stage-b" else "FAIL" for name in stage_names
        ]
        assert [f.status_extended for f in findings] == [
            f"API Gateway V2 test-api ID {api_id} in stage {name} has access logging "
            f"{'enabled' if name == 'stage-b' else 'disabled'}."
            for name in stage_names
        ]

    def test_resource_id_per_stage(self, run_stages, stage_names):
        """Verify the resource ID identifies the corresponding stage."""
        _, findings = run_stages(stage_names)
        assert [f.resource_id for f in findings] == [
            f"test-api-{name}" for name in stage_names
        ]

    def test_finding_objects_are_independent(self, run_stages, stage_names):
        """Verify each stage has a separate finding object."""
        _, findings = run_stages(stage_names)
        assert findings[0] is not findings[1]


@pytest.mark.parametrize(
    "stage_name,expected", [("stage-a", "FAIL"), ("stage-b", "PASS")]
)
def test_single_stage_control(run_stages, stage_name, expected):
    """Verify the status and resource ID when the API has one stage."""
    _, (finding,) = run_stages((stage_name,))
    assert finding.status == expected
    assert finding.resource_id == f"test-api-{stage_name}"
