from datetime import datetime
from unittest import mock

from prowler.providers.aws.services.ecr.ecr_service import (
    FindingSeverityCounts,
    ImageDetails,
    Registry,
    Repository,
)
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_provider,
)

repository_name = "test_repo"
repository_arn = (
    f"arn:aws:ecr:eu-west-1:{AWS_ACCOUNT_NUMBER}:repository/{repository_name}"
)
latest_tag = "test-tag"
latest_digest = "test-digest"
docker_container_image_artifact_media_type = (
    "application/vnd.docker.container.image.v1+json"
)
oci_media_type = "application/vnd.oci.artifact.v1+json"
repo_policy_public = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "ECRRepositoryPolicy",
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:user/username"},
            "Action": ["ecr:DescribeImages", "ecr:DescribeRepositories"],
        }
    ],
}


class Test_ecr_repositories_scan_vulnerabilities_in_latest_image:
    def test_no_registries(self):
        ecr_client = mock.MagicMock
        ecr_client.registries = {}
        ecr_client.audit_config = {}

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider(),
        ), mock.patch(
            "prowler.providers.aws.services.ecr.ecr_repositories_scan_vulnerabilities_in_latest_image.ecr_repositories_scan_vulnerabilities_in_latest_image.ecr_client",
            ecr_client,
        ):
            from prowler.providers.aws.services.ecr.ecr_repositories_scan_vulnerabilities_in_latest_image.ecr_repositories_scan_vulnerabilities_in_latest_image import (
                ecr_repositories_scan_vulnerabilities_in_latest_image,
            )

            check = ecr_repositories_scan_vulnerabilities_in_latest_image()
            result = check.execute()
            assert len(result) == 0

    def test_registry_no_repositories(self):
        ecr_client = mock.MagicMock
        ecr_client.registries = {}
        ecr_client.registries[AWS_REGION_EU_WEST_1] = Registry(
            id=AWS_ACCOUNT_NUMBER,
            arn=f"arn:aws:ecr:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:registry/{AWS_ACCOUNT_NUMBER}",
            region=AWS_REGION_EU_WEST_1,
            scan_type="BASIC",
            repositories=[],
            rules=[],
        )
        ecr_client.audit_config = {}

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider(),
        ), mock.patch(
            "prowler.providers.aws.services.ecr.ecr_repositories_scan_vulnerabilities_in_latest_image.ecr_repositories_scan_vulnerabilities_in_latest_image.ecr_client",
            ecr_client,
        ):
            from prowler.providers.aws.services.ecr.ecr_repositories_scan_vulnerabilities_in_latest_image.ecr_repositories_scan_vulnerabilities_in_latest_image import (
                ecr_repositories_scan_vulnerabilities_in_latest_image,
            )

            check = ecr_repositories_scan_vulnerabilities_in_latest_image()
            result = check.execute()
            assert len(result) == 0

    def test_empty_repository(self):
        ecr_client = mock.MagicMock
        ecr_client.registries = {}
        ecr_client.registries[AWS_REGION_EU_WEST_1] = Registry(
            id=AWS_ACCOUNT_NUMBER,
            arn=f"arn:aws:ecr:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:registry/{AWS_ACCOUNT_NUMBER}",
            region=AWS_REGION_EU_WEST_1,
            scan_type="BASIC",
            repositories=[
                Repository(
                    name=repository_name,
                    arn=repository_arn,
                    region=AWS_REGION_EU_WEST_1,
                    scan_on_push=True,
                    policy=repo_policy_public,
                    images_details=[],
                    lifecycle_policy=None,
                )
            ],
            rules=[],
        )
        ecr_client.audit_config = {}

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider(),
        ), mock.patch(
            "prowler.providers.aws.services.ecr.ecr_repositories_scan_vulnerabilities_in_latest_image.ecr_repositories_scan_vulnerabilities_in_latest_image.ecr_client",
            ecr_client,
        ):
            from prowler.providers.aws.services.ecr.ecr_repositories_scan_vulnerabilities_in_latest_image.ecr_repositories_scan_vulnerabilities_in_latest_image import (
                ecr_repositories_scan_vulnerabilities_in_latest_image,
            )

            check = ecr_repositories_scan_vulnerabilities_in_latest_image()
            result = check.execute()
            assert len(result) == 0

    def test_docker_image_scaned_without_findings(self):
        ecr_client = mock.MagicMock
        ecr_client.registries = {}
        ecr_client.registries[AWS_REGION_EU_WEST_1] = Registry(
            id=AWS_ACCOUNT_NUMBER,
            arn=f"arn:aws:ecr:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:registry/{AWS_ACCOUNT_NUMBER}",
            region=AWS_REGION_EU_WEST_1,
            scan_type="BASIC",
            repositories=[
                Repository(
                    name=repository_name,
                    arn=repository_arn,
                    region=AWS_REGION_EU_WEST_1,
                    scan_on_push=True,
                    policy=repo_policy_public,
                    images_details=[
                        ImageDetails(
                            latest_tag=latest_tag,
                            latest_digest=latest_digest,
                            image_pushed_at=datetime(2023, 1, 1),
                            scan_findings_status="COMPLETE",
                            scan_findings_severity_count=FindingSeverityCounts(
                                critical=0, high=0, medium=0
                            ),
                            artifact_media_type=docker_container_image_artifact_media_type,
                            type="Docker",
                        ),
                    ],
                    lifecycle_policy=None,
                )
            ],
            rules=[],
        )
        ecr_client.audit_config = {}

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider(),
        ), mock.patch(
            "prowler.providers.aws.services.ecr.ecr_repositories_scan_vulnerabilities_in_latest_image.ecr_repositories_scan_vulnerabilities_in_latest_image.ecr_client",
            ecr_client,
        ):
            from prowler.providers.aws.services.ecr.ecr_repositories_scan_vulnerabilities_in_latest_image.ecr_repositories_scan_vulnerabilities_in_latest_image import (
                ecr_repositories_scan_vulnerabilities_in_latest_image,
            )

            check = ecr_repositories_scan_vulnerabilities_in_latest_image()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"ECR repository '{repository_name}' has scanned the Docker container image with digest '{latest_digest}' and tag '{latest_tag}' without findings."
            )
            assert result[0].resource_id == repository_name
            assert result[0].resource_arn == repository_arn
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource_tags == []

    def test_oci_image_scaned_without_findings(self):
        ecr_client = mock.MagicMock
        ecr_client.registries = {}
        ecr_client.registries[AWS_REGION_EU_WEST_1] = Registry(
            id=AWS_ACCOUNT_NUMBER,
            arn=f"arn:aws:ecr:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:registry/{AWS_ACCOUNT_NUMBER}",
            region=AWS_REGION_EU_WEST_1,
            scan_type="BASIC",
            repositories=[
                Repository(
                    name=repository_name,
                    arn=repository_arn,
                    region=AWS_REGION_EU_WEST_1,
                    scan_on_push=True,
                    policy=repo_policy_public,
                    images_details=[
                        ImageDetails(
                            latest_tag=latest_tag,
                            latest_digest=latest_digest,
                            image_pushed_at=datetime(2023, 1, 1),
                            scan_findings_status="COMPLETE",
                            scan_findings_severity_count=FindingSeverityCounts(
                                critical=0, high=0, medium=0
                            ),
                            artifact_media_type=docker_container_image_artifact_media_type,
                            type="OCI",
                        ),
                    ],
                    lifecycle_policy=None,
                )
            ],
            rules=[],
        )
        ecr_client.audit_config = {}

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider(),
        ), mock.patch(
            "prowler.providers.aws.services.ecr.ecr_repositories_scan_vulnerabilities_in_latest_image.ecr_repositories_scan_vulnerabilities_in_latest_image.ecr_client",
            ecr_client,
        ):
            from prowler.providers.aws.services.ecr.ecr_repositories_scan_vulnerabilities_in_latest_image.ecr_repositories_scan_vulnerabilities_in_latest_image import (
                ecr_repositories_scan_vulnerabilities_in_latest_image,
            )

            check = ecr_repositories_scan_vulnerabilities_in_latest_image()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"ECR repository '{repository_name}' has scanned the OCI container image with digest '{latest_digest}' and tag '{latest_tag}' without findings."
            )
            assert result[0].resource_id == repository_name
            assert result[0].resource_arn == repository_arn
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource_tags == []

    def test_image_scanned_with_findings_default_severity_MEDIUM(self):
        ecr_client = mock.MagicMock
        ecr_client.registries = {}
        ecr_client.registries[AWS_REGION_EU_WEST_1] = Registry(
            id=AWS_ACCOUNT_NUMBER,
            arn=f"arn:aws:ecr:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:registry/{AWS_ACCOUNT_NUMBER}",
            region=AWS_REGION_EU_WEST_1,
            scan_type="BASIC",
            repositories=[
                Repository(
                    name=repository_name,
                    arn=repository_arn,
                    region=AWS_REGION_EU_WEST_1,
                    scan_on_push=True,
                    policy=repo_policy_public,
                    images_details=[
                        ImageDetails(
                            latest_tag=latest_tag,
                            latest_digest=latest_digest,
                            image_pushed_at=datetime(2023, 1, 1),
                            scan_findings_status="COMPLETE",
                            scan_findings_severity_count=FindingSeverityCounts(
                                critical=12, high=34, medium=7
                            ),
                            artifact_media_type=docker_container_image_artifact_media_type,
                            type="Docker",
                        )
                    ],
                    lifecycle_policy=None,
                )
            ],
            rules=[],
        )

        # Set audit_config
        ecr_client.audit_config = {
            "ecr_repository_vulnerability_minimum_severity": "MEDIUM"
        }

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider(),
        ), mock.patch(
            "prowler.providers.aws.services.ecr.ecr_repositories_scan_vulnerabilities_in_latest_image.ecr_repositories_scan_vulnerabilities_in_latest_image.ecr_client",
            ecr_client,
        ):
            from prowler.providers.aws.services.ecr.ecr_repositories_scan_vulnerabilities_in_latest_image.ecr_repositories_scan_vulnerabilities_in_latest_image import (
                ecr_repositories_scan_vulnerabilities_in_latest_image,
            )

            check = ecr_repositories_scan_vulnerabilities_in_latest_image()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"ECR repository '{repository_name}' has scanned the Docker container image with digest '{latest_digest}' and tag '{latest_tag}' with findings: CRITICAL->{12}, HIGH->{34}, MEDIUM->{7}."
            )
            assert result[0].resource_id == repository_name
            assert result[0].resource_arn == repository_arn
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource_tags == []

    def test_image_scanned_with_findings_default_severity_HIGH(self):
        ecr_client = mock.MagicMock
        ecr_client.registries = {}
        ecr_client.registries[AWS_REGION_EU_WEST_1] = Registry(
            id=AWS_ACCOUNT_NUMBER,
            arn=f"arn:aws:ecr:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:registry/{AWS_ACCOUNT_NUMBER}",
            region=AWS_REGION_EU_WEST_1,
            scan_type="BASIC",
            repositories=[
                Repository(
                    name=repository_name,
                    arn=repository_arn,
                    region=AWS_REGION_EU_WEST_1,
                    scan_on_push=True,
                    policy=repo_policy_public,
                    images_details=[
                        ImageDetails(
                            latest_tag=latest_tag,
                            latest_digest=latest_digest,
                            image_pushed_at=datetime(2023, 1, 1),
                            scan_findings_status="COMPLETE",
                            scan_findings_severity_count=FindingSeverityCounts(
                                critical=12, high=34, medium=7
                            ),
                            artifact_media_type=docker_container_image_artifact_media_type,
                            type="Docker",
                        )
                    ],
                    lifecycle_policy=None,
                )
            ],
            rules=[],
        )

        # Set audit_config
        ecr_client.audit_config = {
            "ecr_repository_vulnerability_minimum_severity": "HIGH"
        }

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider(),
        ), mock.patch(
            "prowler.providers.aws.services.ecr.ecr_repositories_scan_vulnerabilities_in_latest_image.ecr_repositories_scan_vulnerabilities_in_latest_image.ecr_client",
            ecr_client,
        ):
            from prowler.providers.aws.services.ecr.ecr_repositories_scan_vulnerabilities_in_latest_image.ecr_repositories_scan_vulnerabilities_in_latest_image import (
                ecr_repositories_scan_vulnerabilities_in_latest_image,
            )

            check = ecr_repositories_scan_vulnerabilities_in_latest_image()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"ECR repository '{repository_name}' has scanned the Docker container image with digest '{latest_digest}' and tag '{latest_tag}' with findings: CRITICAL->{12}, HIGH->{34}."
            )
            assert result[0].resource_id == repository_name
            assert result[0].resource_arn == repository_arn
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource_tags == []

    def test_image_scanned_with_findings_default_severity_CRITICAL(self):
        ecr_client = mock.MagicMock
        ecr_client.registries = {}
        ecr_client.registries[AWS_REGION_EU_WEST_1] = Registry(
            id=AWS_ACCOUNT_NUMBER,
            arn=f"arn:aws:ecr:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:registry/{AWS_ACCOUNT_NUMBER}",
            region=AWS_REGION_EU_WEST_1,
            scan_type="BASIC",
            repositories=[
                Repository(
                    name=repository_name,
                    arn=repository_arn,
                    region=AWS_REGION_EU_WEST_1,
                    scan_on_push=True,
                    policy=repo_policy_public,
                    images_details=[
                        ImageDetails(
                            latest_tag=latest_tag,
                            latest_digest=latest_digest,
                            image_pushed_at=datetime(2023, 1, 1),
                            scan_findings_status="COMPLETE",
                            scan_findings_severity_count=FindingSeverityCounts(
                                critical=12, high=34, medium=7
                            ),
                            artifact_media_type=docker_container_image_artifact_media_type,
                            type="Docker",
                        )
                    ],
                    lifecycle_policy=None,
                )
            ],
            rules=[],
        )

        # Set audit_config
        ecr_client.audit_config = {
            "ecr_repository_vulnerability_minimum_severity": "CRITICAL"
        }

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider(),
        ), mock.patch(
            "prowler.providers.aws.services.ecr.ecr_repositories_scan_vulnerabilities_in_latest_image.ecr_repositories_scan_vulnerabilities_in_latest_image.ecr_client",
            ecr_client,
        ):
            from prowler.providers.aws.services.ecr.ecr_repositories_scan_vulnerabilities_in_latest_image.ecr_repositories_scan_vulnerabilities_in_latest_image import (
                ecr_repositories_scan_vulnerabilities_in_latest_image,
            )

            check = ecr_repositories_scan_vulnerabilities_in_latest_image()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"ECR repository '{repository_name}' has scanned the Docker container image with digest '{latest_digest}' and tag '{latest_tag}' with findings: CRITICAL->{12}."
            )
            assert result[0].resource_id == repository_name
            assert result[0].resource_arn == repository_arn
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource_tags == []

    def test_image_scanned_without_CRITICAL_findings_default_severity_CRITICAL(self):
        ecr_client = mock.MagicMock
        ecr_client.registries = {}
        ecr_client.registries[AWS_REGION_EU_WEST_1] = Registry(
            id=AWS_ACCOUNT_NUMBER,
            arn=f"arn:aws:ecr:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:registry/{AWS_ACCOUNT_NUMBER}",
            region=AWS_REGION_EU_WEST_1,
            scan_type="BASIC",
            repositories=[
                Repository(
                    name=repository_name,
                    arn=repository_arn,
                    region=AWS_REGION_EU_WEST_1,
                    scan_on_push=True,
                    policy=repo_policy_public,
                    images_details=[
                        ImageDetails(
                            latest_tag=latest_tag,
                            latest_digest=latest_digest,
                            image_pushed_at=datetime(2023, 1, 1),
                            scan_findings_status="COMPLETE",
                            scan_findings_severity_count=FindingSeverityCounts(
                                critical=0, high=34, medium=7
                            ),
                            artifact_media_type=docker_container_image_artifact_media_type,
                            type="Docker",
                        )
                    ],
                    lifecycle_policy=None,
                )
            ],
            rules=[],
        )

        # Set audit_config
        ecr_client.audit_config = {
            "ecr_repository_vulnerability_minimum_severity": "CRITICAL"
        }

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider(),
        ), mock.patch(
            "prowler.providers.aws.services.ecr.ecr_repositories_scan_vulnerabilities_in_latest_image.ecr_repositories_scan_vulnerabilities_in_latest_image.ecr_client",
            ecr_client,
        ):
            from prowler.providers.aws.services.ecr.ecr_repositories_scan_vulnerabilities_in_latest_image.ecr_repositories_scan_vulnerabilities_in_latest_image import (
                ecr_repositories_scan_vulnerabilities_in_latest_image,
            )

            check = ecr_repositories_scan_vulnerabilities_in_latest_image()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"ECR repository '{repository_name}' has scanned the Docker container image with digest '{latest_digest}' and tag '{latest_tag}' without findings."
            )
            assert result[0].resource_id == repository_name
            assert result[0].resource_arn == repository_arn

    def test_image_scanned_without_CRITICAL_and_HIGH_findings_default_severity_HIGH(
        self,
    ):
        ecr_client = mock.MagicMock
        ecr_client.registries = {}
        ecr_client.registries[AWS_REGION_EU_WEST_1] = Registry(
            id=AWS_ACCOUNT_NUMBER,
            arn=f"arn:aws:ecr:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:registry/{AWS_ACCOUNT_NUMBER}",
            region=AWS_REGION_EU_WEST_1,
            scan_type="BASIC",
            repositories=[
                Repository(
                    name=repository_name,
                    arn=repository_arn,
                    region=AWS_REGION_EU_WEST_1,
                    scan_on_push=True,
                    policy=repo_policy_public,
                    images_details=[
                        ImageDetails(
                            latest_tag=latest_tag,
                            latest_digest=latest_digest,
                            image_pushed_at=datetime(2023, 1, 1),
                            scan_findings_status="COMPLETE",
                            scan_findings_severity_count=FindingSeverityCounts(
                                critical=0, high=0, medium=7
                            ),
                            artifact_media_type=docker_container_image_artifact_media_type,
                            type="Docker",
                        )
                    ],
                    lifecycle_policy=None,
                )
            ],
            rules=[],
        )

        # Set audit_config
        ecr_client.audit_config = {
            "ecr_repository_vulnerability_minimum_severity": "HIGH"
        }

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider(),
        ), mock.patch(
            "prowler.providers.aws.services.ecr.ecr_repositories_scan_vulnerabilities_in_latest_image.ecr_repositories_scan_vulnerabilities_in_latest_image.ecr_client",
            ecr_client,
        ):
            from prowler.providers.aws.services.ecr.ecr_repositories_scan_vulnerabilities_in_latest_image.ecr_repositories_scan_vulnerabilities_in_latest_image import (
                ecr_repositories_scan_vulnerabilities_in_latest_image,
            )

            check = ecr_repositories_scan_vulnerabilities_in_latest_image()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"ECR repository '{repository_name}' has scanned the Docker container image with digest '{latest_digest}' and tag '{latest_tag}' without findings."
            )
            assert result[0].resource_id == repository_name
            assert result[0].resource_arn == repository_arn
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource_tags == []

    def test_image_scanned_fail_scan(self):
        ecr_client = mock.MagicMock
        ecr_client.registries = {}
        ecr_client.registries[AWS_REGION_EU_WEST_1] = Registry(
            id=AWS_ACCOUNT_NUMBER,
            arn=f"arn:aws:ecr:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:registry/{AWS_ACCOUNT_NUMBER}",
            region=AWS_REGION_EU_WEST_1,
            scan_type="BASIC",
            repositories=[
                Repository(
                    name=repository_name,
                    arn=repository_arn,
                    region=AWS_REGION_EU_WEST_1,
                    scan_on_push=True,
                    policy=repo_policy_public,
                    images_details=[
                        ImageDetails(
                            latest_tag=latest_tag,
                            latest_digest=latest_digest,
                            image_pushed_at=datetime(2023, 1, 1),
                            scan_findings_status="FAILED",
                            scan_findings_severity_count=FindingSeverityCounts(
                                critical=0, high=0, medium=0
                            ),
                            artifact_media_type=docker_container_image_artifact_media_type,
                            type="Docker",
                        )
                    ],
                    lifecycle_policy=None,
                )
            ],
            rules=[],
        )
        ecr_client.audit_config = {}

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider(),
        ), mock.patch(
            "prowler.providers.aws.services.ecr.ecr_repositories_scan_vulnerabilities_in_latest_image.ecr_repositories_scan_vulnerabilities_in_latest_image.ecr_client",
            ecr_client,
        ):
            from prowler.providers.aws.services.ecr.ecr_repositories_scan_vulnerabilities_in_latest_image.ecr_repositories_scan_vulnerabilities_in_latest_image import (
                ecr_repositories_scan_vulnerabilities_in_latest_image,
            )

            check = ecr_repositories_scan_vulnerabilities_in_latest_image()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"ECR repository '{repository_name}' has scanned the Docker container image with digest '{latest_digest}' and tag '{latest_tag}' with scan status FAILED."
            )
            assert result[0].resource_id == repository_name
            assert result[0].resource_arn == repository_arn
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource_tags == []

    def test_image_not_scanned(self):
        ecr_client = mock.MagicMock
        ecr_client.registries = {}
        ecr_client.registries[AWS_REGION_EU_WEST_1] = Registry(
            id=AWS_ACCOUNT_NUMBER,
            arn=f"arn:aws:ecr:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:registry/{AWS_ACCOUNT_NUMBER}",
            region=AWS_REGION_EU_WEST_1,
            scan_type="BASIC",
            repositories=[
                Repository(
                    name=repository_name,
                    arn=repository_arn,
                    region=AWS_REGION_EU_WEST_1,
                    scan_on_push=True,
                    policy=repo_policy_public,
                    images_details=[
                        ImageDetails(
                            latest_tag=latest_tag,
                            latest_digest=latest_digest,
                            image_pushed_at=datetime(2023, 1, 1),
                            scan_findings_status="",
                            scan_findings_severity_count=FindingSeverityCounts(
                                critical=0, high=0, medium=0
                            ),
                            artifact_media_type=docker_container_image_artifact_media_type,
                            type="Docker",
                        )
                    ],
                    lifecycle_policy=None,
                )
            ],
            rules=[],
        )
        ecr_client.audit_config = {}

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider(),
        ), mock.patch(
            "prowler.providers.aws.services.ecr.ecr_repositories_scan_vulnerabilities_in_latest_image.ecr_repositories_scan_vulnerabilities_in_latest_image.ecr_client",
            ecr_client,
        ):
            from prowler.providers.aws.services.ecr.ecr_repositories_scan_vulnerabilities_in_latest_image.ecr_repositories_scan_vulnerabilities_in_latest_image import (
                ecr_repositories_scan_vulnerabilities_in_latest_image,
            )

            check = ecr_repositories_scan_vulnerabilities_in_latest_image()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"ECR repository '{repository_name}' has scanned the Docker container image with digest '{latest_digest}' and tag '{latest_tag}' without a scan."
            )
            assert result[0].resource_id == repository_name
            assert result[0].resource_arn == repository_arn
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource_tags == []
