from datetime import datetime
from unittest.mock import patch

import botocore
from boto3 import client
from moto import mock_aws

from prowler.providers.aws.services.ecr.ecr_service import ECR, ScanningRule
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_provider,
)

repo_arn = f"arn:aws:ecr:eu-west-1:{AWS_ACCOUNT_NUMBER}:repository/test-repo"
repo_name = "test-repo"

# Mocking Access Analyzer Calls
make_api_call = botocore.client.BaseClient._make_api_call


def mock_make_api_call(self, operation_name, kwarg):
    if operation_name == "DescribeImages":
        return {
            "imageDetails": [
                {
                    "imageDigest": "sha256:d8868e50ac4c7104d2200d42f432b661b2da8c1e417ccfae217e6a1e04bb9295",
                    "imageTags": [
                        "test-tag1",
                    ],
                    "imagePushedAt": datetime(2023, 1, 1),
                    "imageScanStatus": {
                        "status": "COMPLETE",
                    },
                    "imageScanFindingsSummary": {
                        "findingSeverityCounts": {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 3}
                    },
                },
                {
                    "imageDigest": "sha256:83251ac64627fc331584f6c498b3aba5badc01574e2c70b2499af3af16630eed",
                    "imageTags": [
                        "test-tag2",
                    ],
                    "imagePushedAt": datetime(2023, 1, 2),
                    "imageScanStatus": {
                        "status": "COMPLETE",
                    },
                    "imageScanFindingsSummary": {
                        "findingSeverityCounts": {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 3}
                    },
                },
            ],
        }
    if operation_name == "GetRepositoryPolicy":
        return {
            "registryId": "string",
            "repositoryName": "string",
            "policyText": '{\n  "Version" : "2012-10-17",\n  "Statement" : [ {\n    "Sid" : "Allow Describe Images",\n    "Effect" : "Allow",\n    "Principal" : {\n      "AWS" : [ "arn:aws:iam::123456789012:root" ]\n    },\n    "Action" : [ "ecr:DescribeImages", "ecr:DescribeRepositories" ]\n  } ]\n}',
        }
    if operation_name == "GetLifecyclePolicy":
        return {
            "registryId": "string",
            "repositoryName": "string",
            "lifecyclePolicyText": "test-policy",
        }
    if operation_name == "GetRegistryScanningConfiguration":
        return {
            "registryId": AWS_ACCOUNT_NUMBER,
            "scanningConfiguration": {
                "scanType": "BASIC",
                "rules": [
                    {
                        "scanFrequency": "SCAN_ON_PUSH",
                        "repositoryFilters": [
                            {"filter": "*", "filterType": "WILDCARD"},
                        ],
                    },
                ],
            },
        }

    return make_api_call(self, operation_name, kwarg)


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
class Test_ECR_Service:
    # Test ECR Service
    def test_service(self):
        aws_provider = set_mocked_aws_provider()
        ecr = ECR(aws_provider)
        assert ecr.service == "ecr"

    # Test ECR client
    def test_client(self):
        aws_provider = set_mocked_aws_provider()
        ecr = ECR(aws_provider)
        for regional_client in ecr.regional_clients.values():
            assert regional_client.__class__.__name__ == "ECR"

    # Test ECR session
    def test__get_session__(self):
        aws_provider = set_mocked_aws_provider()
        ecr = ECR(aws_provider)
        assert ecr.session.__class__.__name__ == "Session"

    # Test describe ECR repositories
    @mock_aws
    def test__describe_registries_and_repositories__(self):
        ecr_client = client("ecr", region_name=AWS_REGION_EU_WEST_1)
        ecr_client.create_repository(
            repositoryName=repo_name,
            imageScanningConfiguration={"scanOnPush": True},
            tags=[
                {"Key": "test", "Value": "test"},
            ],
        )
        aws_provider = set_mocked_aws_provider()
        ecr = ECR(aws_provider)

        assert len(ecr.registries) == 1
        assert ecr.registries[AWS_REGION_EU_WEST_1].id == AWS_ACCOUNT_NUMBER
        assert ecr.registries[AWS_REGION_EU_WEST_1].region == AWS_REGION_EU_WEST_1
        assert len(ecr.registries[AWS_REGION_EU_WEST_1].repositories) == 1

        assert ecr.registries[AWS_REGION_EU_WEST_1].repositories[0].name == repo_name
        assert ecr.registries[AWS_REGION_EU_WEST_1].repositories[0].arn == repo_arn
        assert ecr.registries[AWS_REGION_EU_WEST_1].repositories[0].scan_on_push
        assert ecr.registries[AWS_REGION_EU_WEST_1].repositories[0].tags == [
            {"Key": "test", "Value": "test"},
        ]

    # Test describe ECR repository policies
    @mock_aws
    def test__describe_repository_policies__(self):
        ecr_client = client("ecr", region_name=AWS_REGION_EU_WEST_1)
        ecr_client.create_repository(
            repositoryName=repo_name,
            imageScanningConfiguration={"scanOnPush": True},
        )
        aws_provider = set_mocked_aws_provider()
        ecr = ECR(aws_provider)
        assert len(ecr.registries) == 1
        assert len(ecr.registries[AWS_REGION_EU_WEST_1].repositories) == 1
        assert ecr.registries[AWS_REGION_EU_WEST_1].repositories[0].name == repo_name
        assert ecr.registries[AWS_REGION_EU_WEST_1].repositories[0].arn == repo_arn
        assert ecr.registries[AWS_REGION_EU_WEST_1].repositories[0].scan_on_push
        assert (
            ecr.registries[AWS_REGION_EU_WEST_1]
            .repositories[0]
            .policy["Statement"][0]["Sid"]
            == "Allow Describe Images"
        )
        assert (
            ecr.registries[AWS_REGION_EU_WEST_1]
            .repositories[0]
            .policy["Statement"][0]["Effect"]
            == "Allow"
        )
        assert (
            ecr.registries[AWS_REGION_EU_WEST_1]
            .repositories[0]
            .policy["Statement"][0]["Principal"]["AWS"][0]
            == f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"
        )
        assert (
            ecr.registries[AWS_REGION_EU_WEST_1]
            .repositories[0]
            .policy["Statement"][0]["Action"][0]
            == "ecr:DescribeImages"
        )
        assert (
            ecr.registries[AWS_REGION_EU_WEST_1]
            .repositories[0]
            .policy["Statement"][0]["Action"][1]
            == "ecr:DescribeRepositories"
        )

    # Test describe ECR repository lifecycle policies
    @mock_aws
    def test__get_lifecycle_policies__(self):
        ecr_client = client("ecr", region_name=AWS_REGION_EU_WEST_1)
        ecr_client.create_repository(
            repositoryName=repo_name,
            imageScanningConfiguration={"scanOnPush": True},
        )
        aws_provider = set_mocked_aws_provider()
        ecr = ECR(aws_provider)
        assert len(ecr.registries) == 1
        assert len(ecr.registries[AWS_REGION_EU_WEST_1].repositories) == 1
        assert ecr.registries[AWS_REGION_EU_WEST_1].repositories[0].name == repo_name
        assert ecr.registries[AWS_REGION_EU_WEST_1].repositories[0].arn == repo_arn
        assert ecr.registries[AWS_REGION_EU_WEST_1].repositories[0].scan_on_push
        assert ecr.registries[AWS_REGION_EU_WEST_1].repositories[0].lifecycle_policy

    # Test get image details
    @mock_aws
    def test__get_image_details__(self):
        ecr_client = client("ecr", region_name=AWS_REGION_EU_WEST_1)
        ecr_client.create_repository(
            repositoryName=repo_name,
            imageScanningConfiguration={"scanOnPush": True},
        )
        aws_provider = set_mocked_aws_provider()
        ecr = ECR(aws_provider)
        assert len(ecr.registries) == 1
        assert len(ecr.registries[AWS_REGION_EU_WEST_1].repositories) == 1
        assert ecr.registries[AWS_REGION_EU_WEST_1].repositories[0].name == repo_name
        assert ecr.registries[AWS_REGION_EU_WEST_1].repositories[0].arn == repo_arn
        assert ecr.registries[AWS_REGION_EU_WEST_1].repositories[0].scan_on_push
        assert (
            len(ecr.registries[AWS_REGION_EU_WEST_1].repositories[0].images_details)
            == 2
        )
        # First image pushed
        assert ecr.registries[AWS_REGION_EU_WEST_1].repositories[0].images_details[
            0
        ].image_pushed_at == datetime(2023, 1, 1)
        assert (
            ecr.registries[AWS_REGION_EU_WEST_1]
            .repositories[0]
            .images_details[0]
            .latest_tag
            == "test-tag1"
        )
        assert (
            ecr.registries[AWS_REGION_EU_WEST_1]
            .repositories[0]
            .images_details[0]
            .latest_digest
            == "sha256:d8868e50ac4c7104d2200d42f432b661b2da8c1e417ccfae217e6a1e04bb9295"
        )
        assert (
            ecr.registries[AWS_REGION_EU_WEST_1]
            .repositories[0]
            .images_details[0]
            .scan_findings_status
            == "COMPLETE"
        )
        assert (
            ecr.registries[AWS_REGION_EU_WEST_1]
            .repositories[0]
            .images_details[0]
            .scan_findings_severity_count.critical
            == 1
        )
        assert (
            ecr.registries[AWS_REGION_EU_WEST_1]
            .repositories[0]
            .images_details[0]
            .scan_findings_severity_count.high
            == 2
        )
        assert (
            ecr.registries[AWS_REGION_EU_WEST_1]
            .repositories[0]
            .images_details[0]
            .scan_findings_severity_count.medium
            == 3
        )

        # Second image pushed
        assert ecr.registries[AWS_REGION_EU_WEST_1].repositories[0].images_details[
            1
        ].image_pushed_at == datetime(2023, 1, 2)
        assert (
            ecr.registries[AWS_REGION_EU_WEST_1]
            .repositories[0]
            .images_details[1]
            .latest_tag
            == "test-tag2"
        )
        assert (
            ecr.registries[AWS_REGION_EU_WEST_1]
            .repositories[0]
            .images_details[1]
            .latest_digest
            == "sha256:83251ac64627fc331584f6c498b3aba5badc01574e2c70b2499af3af16630eed"
        )
        assert (
            ecr.registries[AWS_REGION_EU_WEST_1]
            .repositories[0]
            .images_details[1]
            .scan_findings_status
            == "COMPLETE"
        )
        assert (
            ecr.registries[AWS_REGION_EU_WEST_1]
            .repositories[0]
            .images_details[1]
            .scan_findings_severity_count.critical
            == 1
        )
        assert (
            ecr.registries[AWS_REGION_EU_WEST_1]
            .repositories[0]
            .images_details[1]
            .scan_findings_severity_count.high
            == 2
        )
        assert (
            ecr.registries[AWS_REGION_EU_WEST_1]
            .repositories[0]
            .images_details[1]
            .scan_findings_severity_count.medium
            == 3
        )

    # Test get ECR Registries Scanning Configuration
    @mock_aws
    def test__get_registry_scanning_configuration__(self):
        aws_provider = set_mocked_aws_provider()
        ecr = ECR(aws_provider)
        assert len(ecr.registries) == 1
        assert ecr.registries[AWS_REGION_EU_WEST_1].id == AWS_ACCOUNT_NUMBER
        assert ecr.registries[AWS_REGION_EU_WEST_1].scan_type == "BASIC"
        assert ecr.registries[AWS_REGION_EU_WEST_1].rules == [
            ScanningRule(
                scan_frequency="SCAN_ON_PUSH",
                scan_filters=[{"filter": "*", "filterType": "WILDCARD"}],
            )
        ]
