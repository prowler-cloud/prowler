import json
from concurrent.futures import Future
from datetime import datetime
from unittest.mock import MagicMock, patch

import botocore
import pytest
from boto3 import client
from moto import mock_aws

from prowler.providers.aws.services.ecr.ecr_service import (
    ECR,
    ScanningRule,
)
from tests.providers.aws.services.ecr.image_scan_fixtures import (
    MANIFESTS_BY_DIGEST,
    reset_image_fixtures,
)
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_provider,
)

repo_arn = f"arn:aws:ecr:eu-west-1:{AWS_ACCOUNT_NUMBER}:repository/test-repo"
repo_name = "test-repo"

# Mocking Access Analyzer Calls
make_api_call = botocore.client.BaseClient._make_api_call

# BatchGetImage / GetDownloadUrlForLayer fixtures (which moto does not
# implement) live in image_scan_fixtures and are served by mock_make_api_call.


@pytest.fixture(autouse=True)
def _reset_image_fixtures():
    """Isolate the BatchGetImage/GetDownloadUrlForLayer fixtures per test."""
    reset_image_fixtures()
    yield
    reset_image_fixtures()


def mock_make_api_call(self, operation_name, kwarg):
    """Fake botocore responses for the ECR operations this suite exercises."""
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

    if operation_name == "BatchGetImage":
        digest = kwarg["imageIds"][0]["imageDigest"]
        manifest = MANIFESTS_BY_DIGEST.get(digest)
        if manifest is None:
            return {
                "images": [],
                "failures": [
                    {
                        "imageId": {"imageDigest": digest},
                        "failureCode": "ImageNotFound",
                    }
                ],
            }
        return {
            "images": [
                {
                    "imageManifest": json.dumps(manifest),
                    "imageManifestMediaType": manifest.get("mediaType", ""),
                }
            ]
        }

    if operation_name == "GetDownloadUrlForLayer":
        digest = kwarg["layerDigest"]
        return {"downloadUrl": f"https://layers.example.com/{digest}"}

    return make_api_call(self, operation_name, kwarg)


def mock_generate_regional_clients(provider, service):
    """Return a single regional client for every requested region."""
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
    """Tests for the ECR service."""

    def test_service(self):
        """The service name is set correctly."""
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        ecr = ECR(aws_provider)
        assert ecr.service == "ecr"

    # Test ECR client
    def test_client(self):
        """Each regional client is an ECR client."""
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        ecr = ECR(aws_provider)
        for regional_client in ecr.regional_clients.values():
            assert regional_client.__class__.__name__ == "ECR"

    # Test ECR session
    def test_get_session(self):
        """The session is set correctly."""
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        ecr = ECR(aws_provider)
        assert ecr.session.__class__.__name__ == "Session"

    # Test describe ECR repositories
    @mock_aws
    def test_describe_registries_and_repositories(self):
        """Registries and repositories are discovered."""
        ecr_client = client("ecr", region_name=AWS_REGION_EU_WEST_1)
        ecr_client.create_repository(
            repositoryName=repo_name,
            imageScanningConfiguration={"scanOnPush": True},
            tags=[
                {"Key": "test", "Value": "test"},
            ],
        )
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
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
        """Repository policies are fetched and parsed."""
        ecr_client = client("ecr", region_name=AWS_REGION_EU_WEST_1)
        ecr_client.create_repository(
            repositoryName=repo_name,
            imageScanningConfiguration={"scanOnPush": True},
            imageTagMutability="IMMUTABLE",
        )
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
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
        """Repository lifecycle policies are fetched."""
        ecr_client = client("ecr", region_name=AWS_REGION_EU_WEST_1)
        ecr_client.create_repository(
            repositoryName=repo_name,
            imageScanningConfiguration={"scanOnPush": True},
            imageTagMutability="IMMUTABLE",
        )
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
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
        """Scannable, tagged images are collected and sorted by push date."""
        ecr_client = client("ecr", region_name=AWS_REGION_EU_WEST_1)
        ecr_client.create_repository(
            repositoryName=repo_name,
            imageScanningConfiguration={"scanOnPush": True},
        )
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
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
        """The registry's scanning configuration is fetched."""
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
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
        """A Docker image config is scannable."""
        assert ECR._is_artifact_scannable(
            "application/vnd.docker.container.image.v1+json"
        )

    def test_is_artifact_scannable_layer_tar(self):
        """An uncompressed Docker layer is scannable."""
        assert ECR._is_artifact_scannable(
            "application/vnd.docker.image.rootfs.diff.tar"
        )

    def test_is_artifact_scannable_layer_gzip(self):
        """A gzip-compressed Docker layer is scannable."""
        assert ECR._is_artifact_scannable(
            "application/vnd.docker.image.rootfs.diff.tar.gzip"
        )

    def test_is_artifact_scannable_oci(self):
        """An OCI image config is scannable."""
        assert ECR._is_artifact_scannable("application/vnd.oci.image.config.v1+json")

    def test_is_artifact_scannable_oci_tar(self):
        """An uncompressed OCI layer is scannable."""
        assert ECR._is_artifact_scannable("application/vnd.oci.image.layer.v1.tar")

    def test_is_artifact_scannable_oci_compressed(self):
        """A gzip-compressed OCI layer is scannable."""
        assert ECR._is_artifact_scannable("application/vnd.oci.image.layer.v1.tar+gzip")

    def test_is_artifact_scannable_none(self):
        """A missing media type is not scannable."""
        assert not ECR._is_artifact_scannable(None)

    def test_is_artifact_scannable_empty(self):
        """An empty media type is not scannable."""
        assert not ECR._is_artifact_scannable("")

    def test_is_artifact_scannable_non_scannable_tags(self):
        """A signature-tagged artifact is not scannable."""
        assert not ECR._is_artifact_scannable("", ["sha256-abcdefg123456.sig"])

    def test_is_artifact_scannable_scannable_tags(self):
        """A normally-tagged artifact is scannable."""
        assert ECR._is_artifact_scannable(
            "application/vnd.docker.container.image.v1+json", ["abcdefg123456"]
        )

    @mock_aws
    def test_get_image_scan_data_selects_only_latest_image_per_repository(self):
        """Only the latest image per repository is selected for scanning."""
        ecr_client_boto = client("ecr", region_name=AWS_REGION_EU_WEST_1)
        ecr_client_boto.create_repository(
            repositoryName=repo_name,
            imageScanningConfiguration={"scanOnPush": True},
        )
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        ecr = ECR(aws_provider)

        repository = ecr.registries[AWS_REGION_EU_WEST_1].repositories[0]
        # Sanity check: this repository has several scannable tagged images.
        assert len(repository.images_details) == 4

        results = list(ecr._get_image_scan_data())

        # Only the most recently pushed image is selected, not all four.
        assert len(results) == 1
        fetched_repository, fetched_image, _ = results[0]
        assert fetched_repository.name == repo_name
        assert fetched_image.latest_tag == "test-tag4"
        assert (
            fetched_image.latest_digest
            == "sha256:43251ac64627fc331584f6c498b3aba5badc01574e2c70b2499af3af16630eed"
        )

    @mock_aws
    def test_get_image_scan_data_covers_scan_on_push_disabled_repository(self):
        """A scan-on-push-disabled repo (empty images_details) is still scanned."""
        ecr_client_boto = client("ecr", region_name=AWS_REGION_EU_WEST_1)
        ecr_client_boto.create_repository(
            repositoryName=repo_name,
            imageScanningConfiguration={"scanOnPush": False},
        )
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        ecr = ECR(aws_provider)

        repository = ecr.registries[AWS_REGION_EU_WEST_1].repositories[0]
        # Scan-on-push disabled: the metadata pass leaves images_details empty...
        assert repository.scan_on_push is False
        assert repository.images_details == []

        # ...yet the secret-scan path resolves the latest image via a dedicated
        # describe_images lookup, so the repository is not silently skipped.
        results = list(ecr._get_image_scan_data())

        assert len(results) == 1
        fetched_repository, fetched_image, _ = results[0]
        assert fetched_repository.name == repo_name
        assert fetched_image.latest_tag == "test-tag4"
        # The dedicated lookup must NOT mutate the shared images_details, or
        # other checks would treat this repo as having a scanned image.
        assert repository.images_details == []

    @mock_aws
    def test_get_image_scan_data_bounds_submitted_futures(self):
        """Image fetches are submitted only as earlier results are consumed."""
        ecr_client_boto = client("ecr", region_name=AWS_REGION_EU_WEST_1)
        for index in range(10):
            ecr_client_boto.create_repository(
                repositoryName=f"{repo_name}-{index}",
                imageScanningConfiguration={"scanOnPush": True},
            )
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        ecr = ECR(aws_provider)
        repositories = ecr.registries[AWS_REGION_EU_WEST_1].repositories

        executor = MagicMock()
        executor.__enter__.return_value = executor
        futures = []

        def submit(*_args):
            future = Future()
            futures.append(future)
            if len(futures) == 1:
                future.set_result(None)
            return future

        executor.submit.side_effect = submit
        with patch(
            "prowler.providers.aws.services.ecr.ecr_service.ThreadPoolExecutor",
            return_value=executor,
        ):
            results = ecr._get_image_scan_data()
            first_result = next(results)

        assert first_result[0] == repositories[0]
        assert (
            first_result[1].latest_digest
            == repositories[0].images_details[-1].latest_digest
        )
        assert executor.submit.call_count == 4

    @mock_aws
    def test_get_scan_target_image_ignores_stale_scanned_image(self):
        """Secret scanning selects a newer image absent from scan findings."""
        ecr_client_boto = client("ecr", region_name=AWS_REGION_EU_WEST_1)
        ecr_client_boto.create_repository(
            repositoryName=repo_name,
            imageScanningConfiguration={"scanOnPush": True},
        )
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        ecr = ECR(aws_provider)
        repository = ecr.registries[AWS_REGION_EU_WEST_1].repositories[0]
        older_scanned_image = repository.images_details[0]
        repository.images_details = [older_scanned_image]

        target = ecr._get_scan_target_image(repository)

        assert target.latest_tag == "test-tag4"
        assert target.image_pushed_at > older_scanned_image.image_pushed_at

    @mock_aws
    def test_get_scan_target_image_lookup_failure_rejects_stale_image(self):
        """A failed authoritative lookup does not select cached scan metadata."""
        ecr_client_boto = client("ecr", region_name=AWS_REGION_EU_WEST_1)
        ecr_client_boto.create_repository(
            repositoryName=repo_name,
            imageScanningConfiguration={"scanOnPush": True},
        )
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        ecr = ECR(aws_provider)
        repository = ecr.registries[AWS_REGION_EU_WEST_1].repositories[0]
        repository.images_details = [repository.images_details[0]]

        with patch.object(
            ecr.regional_clients[AWS_REGION_EU_WEST_1],
            "get_paginator",
            side_effect=RuntimeError("authoritative lookup failed"),
        ):
            target = ecr._get_scan_target_image(repository)
            scan_results = list(ecr._get_image_scan_data())

        assert isinstance(target, RuntimeError)
        assert len(scan_results) == 1
        _, result_image, result_error = scan_results[0]
        assert result_image is None and isinstance(result_error, RuntimeError)
