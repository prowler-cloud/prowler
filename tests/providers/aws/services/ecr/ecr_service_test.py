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
                # Scannable image #1
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
                    "artifactMediaType": "application/vnd.docker.container.image.v1+json",
                },
                # Scannable image #2
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
                    "artifactMediaType": "application/vnd.docker.container.image.v1+json",
                },
                # Not scannable image
                {
                    "imageDigest": "sha256:83251ac64627fc331584f6c498b3aba5badc01574e2c70b2499af3af16630eed",
                    "imageTags": [
                        "sha256-abcdefg123456.sig",
                    ],
                    "imagePushedAt": datetime(2023, 1, 2),
                    "artifactMediaType": "application/vnd.docker.container.image.v1+json",
                },
                # Scannable image #3
                {
                    "imageDigest": "sha256:33251ac64627fc331584f6c498b3aba5badc01574e2c70b2499af3af16630eed",
                    "imageTags": [
                        "test-tag3",
                    ],
                    "imagePushedAt": datetime(2023, 1, 2),
                    "imageScanFindings": {
                        "findingSeverityCounts": {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 3}
                    },
                    "artifactMediaType": "application/vnd.docker.container.image.v1+json",
                },
                # Not scannable image
                {
                    "imageDigest": "sha256:83251ac64627fc331584f6c498b3aba5badc01574e2c70b2499af3af16630eed",
                    "imageTags": [
                        "sha256-83251ac64627fc331584f6c498b3aba5badc01574e2c70b2499af3af16630eed.sig",
                    ],
                    "imagePushedAt": datetime(2023, 1, 2),
                    "imageScanStatus": {
                        "status": "FAILED",
                    },
                    "artifactMediaType": "application/vnd.oci.image.config.v1+json",
                },
                # Not scannable image
                {
                    "imageDigest": "sha256:83251ac64627fc331584f6c498b3aba5badc01574e2c70b2499af3af16630eed",
                    "imageTags": [
                        "test-tag2",
                    ],
                    "imagePushedAt": datetime(2023, 1, 2),
                    "imageScanStatus": {
                        "status": "FAILED",
                    },
                    "artifactMediaType": "application/vnd.cncf.notary.v2.signature",
                },
                # Scannable image #4
                {
                    "imageDigest": "sha256:43251ac64627fc331584f6c498b3aba5badc01574e2c70b2499af3af16630eed",
                    "imageTags": [
                        "test-tag4",
                    ],
                    "imagePushedAt": datetime(2023, 1, 2),
                    "imageScanStatus": {
                        "status": "FAILED",
                    },
                    "artifactMediaType": "application/vnd.docker.container.image.v1+json",
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

    if operation_name == "DescribeImageScanFindings":
        return {
            "imageScanStatus": {
                "status": "COMPLETE",
            },
            "imageScanFindings": {
                "findingSeverityCounts": {"CRITICAL": 3, "HIGH": 4, "MEDIUM": 5}
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
    def test_get_session(self):
        aws_provider = set_mocked_aws_provider()
        ecr = ECR(aws_provider)
        assert ecr.session.__class__.__name__ == "Session"

    # Test describe ECR repositories
    @mock_aws
    def test_describe_registries_and_repositories(self):
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
        assert (
            ecr.registries[AWS_REGION_EU_WEST_1].arn
            == f"arn:aws:ecr:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:registry/{AWS_ACCOUNT_NUMBER}"
        )
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
    def test_describe_repository_policies(self):
        ecr_client = client("ecr", region_name=AWS_REGION_EU_WEST_1)
        ecr_client.create_repository(
            repositoryName=repo_name,
            imageScanningConfiguration={"scanOnPush": True},
            imageTagMutability="IMMUTABLE",
        )
        aws_provider = set_mocked_aws_provider()
        ecr = ECR(aws_provider)
        assert len(ecr.registries) == 1
        assert len(ecr.registries[AWS_REGION_EU_WEST_1].repositories) == 1

        repository = ecr.registries[AWS_REGION_EU_WEST_1].repositories[0]
        assert repository.name == repo_name
        assert repository.arn == repo_arn
        assert repository.scan_on_push
        assert repository.policy["Statement"][0]["Sid"] == "Allow Describe Images"
        assert repository.policy["Statement"][0]["Effect"] == "Allow"
        assert (
            repository.policy["Statement"][0]["Principal"]["AWS"][0]
            == f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"
        )
        assert repository.policy["Statement"][0]["Action"][0] == "ecr:DescribeImages"
        assert (
            repository.policy["Statement"][0]["Action"][1] == "ecr:DescribeRepositories"
        )

    # Test describe ECR repository lifecycle policies
    @mock_aws
    def test_get_lifecycle_policies(self):
        ecr_client = client("ecr", region_name=AWS_REGION_EU_WEST_1)
        ecr_client.create_repository(
            repositoryName=repo_name,
            imageScanningConfiguration={"scanOnPush": True},
            imageTagMutability="IMMUTABLE",
        )
        aws_provider = set_mocked_aws_provider()
        ecr = ECR(aws_provider)
        assert len(ecr.registries) == 1
        assert len(ecr.registries[AWS_REGION_EU_WEST_1].repositories) == 1
        assert ecr.registries[AWS_REGION_EU_WEST_1].repositories[0].name == repo_name
        assert ecr.registries[AWS_REGION_EU_WEST_1].repositories[0].arn == repo_arn
        assert ecr.registries[AWS_REGION_EU_WEST_1].repositories[0].scan_on_push
        assert ecr.registries[AWS_REGION_EU_WEST_1].repositories[0].lifecycle_policy
        assert ecr.registries[AWS_REGION_EU_WEST_1].repositories[0].immutability

    # Test get image details
    @mock_aws
    def test_get_image_details(self):
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
            == 4
        )
        # First image pushed
        first_image = (
            ecr.registries[AWS_REGION_EU_WEST_1].repositories[0].images_details[0]
        )
        assert first_image.image_pushed_at == datetime(2023, 1, 1)
        assert first_image.latest_tag == "test-tag1"
        assert (
            ecr.registries[AWS_REGION_EU_WEST_1]
            .repositories[0]
            .images_details[0]
            .latest_digest
            == "sha256:d8868e50ac4c7104d2200d42f432b661b2da8c1e417ccfae217e6a1e04bb9295"
        )
        assert first_image.scan_findings_status == "COMPLETE"
        assert first_image.scan_findings_severity_count.critical == 1
        assert first_image.scan_findings_severity_count.high == 2
        assert first_image.scan_findings_severity_count.medium == 3
        assert (
            first_image.artifact_media_type
            == "application/vnd.docker.container.image.v1+json"
        )

        # Second image pushed
        second_image = (
            ecr.registries[AWS_REGION_EU_WEST_1].repositories[0].images_details[1]
        )
        assert second_image.image_pushed_at == datetime(2023, 1, 2)
        assert second_image.latest_tag == "test-tag2"
        assert (
            second_image.latest_digest
            == "sha256:83251ac64627fc331584f6c498b3aba5badc01574e2c70b2499af3af16630eed"
        )
        assert second_image.scan_findings_status == "COMPLETE"
        assert second_image.scan_findings_severity_count.critical == 1
        assert second_image.scan_findings_severity_count.high == 2
        assert second_image.scan_findings_severity_count.medium == 3
        assert (
            second_image.artifact_media_type
            == "application/vnd.docker.container.image.v1+json"
        )

        # Third image pushed
        third_image = (
            ecr.registries[AWS_REGION_EU_WEST_1].repositories[0].images_details[2]
        )
        assert third_image.image_pushed_at == datetime(2023, 1, 2)
        assert third_image.latest_tag == "test-tag3"
        assert (
            third_image.latest_digest
            == "sha256:33251ac64627fc331584f6c498b3aba5badc01574e2c70b2499af3af16630eed"
        )
        assert third_image.scan_findings_status == "COMPLETE"
        assert third_image.scan_findings_severity_count.critical == 3
        assert third_image.scan_findings_severity_count.high == 4
        assert third_image.scan_findings_severity_count.medium == 5
        assert (
            third_image.artifact_media_type
            == "application/vnd.docker.container.image.v1+json"
        )

        # Fourth image pushed
        fourth_image = (
            ecr.registries[AWS_REGION_EU_WEST_1].repositories[0].images_details[3]
        )
        assert fourth_image.image_pushed_at == datetime(2023, 1, 2)
        assert fourth_image.latest_tag == "test-tag4"
        assert (
            fourth_image.latest_digest
            == "sha256:43251ac64627fc331584f6c498b3aba5badc01574e2c70b2499af3af16630eed"
        )

        assert fourth_image.scan_findings_status == "FAILED"
        assert fourth_image.scan_findings_severity_count is None
        assert (
            fourth_image.artifact_media_type
            == "application/vnd.docker.container.image.v1+json"
        )

    # Test get ECR Registries Scanning Configuration
    @mock_aws
    def test_get_registry_scanning_configuration(self):
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

    def test_is_artifact_scannable_docker(self):
        assert ECR._is_artifact_scannable(
            "application/vnd.docker.container.image.v1+json"
        )

    def test_is_artifact_scannable_layer_tar(self):
        assert ECR._is_artifact_scannable(
            "application/vnd.docker.image.rootfs.diff.tar"
        )

    def test_is_artifact_scannable_layer_gzip(self):
        assert ECR._is_artifact_scannable(
            "application/vnd.docker.image.rootfs.diff.tar.gzip"
        )

    def test_is_artifact_scannable_oci(self):
        assert ECR._is_artifact_scannable("application/vnd.oci.image.config.v1+json")

    def test_is_artifact_scannable_oci_tar(self):
        assert ECR._is_artifact_scannable("application/vnd.oci.image.layer.v1.tar")

    def test_is_artifact_scannable_oci_compressed(self):
        assert ECR._is_artifact_scannable("application/vnd.oci.image.layer.v1.tar+gzip")

    def test_is_artifact_scannable_none(self):
        assert not ECR._is_artifact_scannable(None)

    def test_is_artifact_scannable_empty(self):
        assert not ECR._is_artifact_scannable("")

    def test_is_artifact_scannable_non_scannable_tags(self):
        assert not ECR._is_artifact_scannable("", ["sha256-abcdefg123456.sig"])

    def test_is_artifact_scannable_scannable_tags(self):
        assert ECR._is_artifact_scannable(
            "application/vnd.docker.container.image.v1+json", ["abcdefg123456"]
        )
