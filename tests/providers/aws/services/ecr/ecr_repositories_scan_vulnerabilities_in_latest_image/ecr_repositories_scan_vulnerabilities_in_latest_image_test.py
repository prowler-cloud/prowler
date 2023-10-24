from datetime import datetime
from unittest import mock

from boto3 import session

from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info
from prowler.providers.aws.services.ecr.ecr_service import (
    FindingSeverityCounts,
    ImageDetails,
    Registry,
    Repository,
)
from prowler.providers.common.models import Audit_Metadata

# Mock Test Region
AWS_REGION = "eu-west-1"
AWS_ACCOUNT_NUMBER = "123456789012"
repository_name = "test_repo"
repository_arn = (
    f"arn:aws:ecr:eu-west-1:{AWS_ACCOUNT_NUMBER}:repository/{repository_name}"
)
latest_tag = "test-tag"
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
            audited_account_arn=None,
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
            mfa_enabled=False,
            audit_metadata=Audit_Metadata(
                services_scanned=0,
                expected_checks=[],
                completed_checks=0,
                audit_progress=0,
            ),
        )
        return audit_info

    def test_no_registries(self):
        ecr_client = mock.MagicMock
        ecr_client.registries = {}
        ecr_client.audit_config = {}

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            self.set_mocked_audit_info(),
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
        ecr_client.registries[AWS_REGION] = Registry(
            id=AWS_ACCOUNT_NUMBER,
            region=AWS_REGION,
            scan_type="BASIC",
            repositories=[],
            rules=[],
        )
        ecr_client.audit_config = {}

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            self.set_mocked_audit_info(),
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
        ecr_client.registries[AWS_REGION] = Registry(
            id=AWS_ACCOUNT_NUMBER,
            region=AWS_REGION,
            scan_type="BASIC",
            repositories=[
                Repository(
                    name=repository_name,
                    arn=repository_arn,
                    region=AWS_REGION,
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
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            self.set_mocked_audit_info(),
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

    def test_image_scaned_without_findings(self):
        ecr_client = mock.MagicMock
        ecr_client.registries = {}
        ecr_client.registries[AWS_REGION] = Registry(
            id=AWS_ACCOUNT_NUMBER,
            region=AWS_REGION,
            scan_type="BASIC",
            repositories=[
                Repository(
                    name=repository_name,
                    arn=repository_arn,
                    region=AWS_REGION,
                    scan_on_push=True,
                    policy=repo_policy_public,
                    images_details=[
                        ImageDetails(
                            latest_tag=latest_tag,
                            latest_digest="test-digest",
                            image_pushed_at=datetime(2023, 1, 1),
                            scan_findings_status="COMPLETE",
                            scan_findings_severity_count=FindingSeverityCounts(
                                critical=0, high=0, medium=0
                            ),
                        ),
                    ],
                    lifecycle_policy=None,
                )
            ],
            rules=[],
        )
        ecr_client.audit_config = {}

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            self.set_mocked_audit_info(),
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
                == f"ECR repository {repository_name} has imageTag {latest_tag} scanned without findings."
            )
            assert result[0].resource_id == repository_name
            assert result[0].resource_arn == repository_arn

    def test_image_scanned_with_findings_default_severity_MEDIUM(self):
        ecr_client = mock.MagicMock
        ecr_client.registries = {}
        ecr_client.registries[AWS_REGION] = Registry(
            id=AWS_ACCOUNT_NUMBER,
            region=AWS_REGION,
            scan_type="BASIC",
            repositories=[
                Repository(
                    name=repository_name,
                    arn=repository_arn,
                    region=AWS_REGION,
                    scan_on_push=True,
                    policy=repo_policy_public,
                    images_details=[
                        ImageDetails(
                            latest_tag=latest_tag,
                            latest_digest="test-digest",
                            image_pushed_at=datetime(2023, 1, 1),
                            scan_findings_status="COMPLETE",
                            scan_findings_severity_count=FindingSeverityCounts(
                                critical=12, high=34, medium=7
                            ),
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
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            self.set_mocked_audit_info(),
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
                == f"ECR repository {repository_name} has imageTag {latest_tag} scanned with findings: CRITICAL->{12}, HIGH->{34}, MEDIUM->{7}."
            )
            assert result[0].resource_id == repository_name
            assert result[0].resource_arn == repository_arn

    def test_image_scanned_with_findings_default_severity_HIGH(self):
        ecr_client = mock.MagicMock
        ecr_client.registries = {}
        ecr_client.registries[AWS_REGION] = Registry(
            id=AWS_ACCOUNT_NUMBER,
            region=AWS_REGION,
            scan_type="BASIC",
            repositories=[
                Repository(
                    name=repository_name,
                    arn=repository_arn,
                    region=AWS_REGION,
                    scan_on_push=True,
                    policy=repo_policy_public,
                    images_details=[
                        ImageDetails(
                            latest_tag=latest_tag,
                            latest_digest="test-digest",
                            image_pushed_at=datetime(2023, 1, 1),
                            scan_findings_status="COMPLETE",
                            scan_findings_severity_count=FindingSeverityCounts(
                                critical=12, high=34, medium=7
                            ),
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
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            self.set_mocked_audit_info(),
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
                == f"ECR repository {repository_name} has imageTag {latest_tag} scanned with findings: CRITICAL->{12}, HIGH->{34}."
            )
            assert result[0].resource_id == repository_name
            assert result[0].resource_arn == repository_arn

    def test_image_scanned_with_findings_default_severity_CRITICAL(self):
        ecr_client = mock.MagicMock
        ecr_client.registries = {}
        ecr_client.registries[AWS_REGION] = Registry(
            id=AWS_ACCOUNT_NUMBER,
            region=AWS_REGION,
            scan_type="BASIC",
            repositories=[
                Repository(
                    name=repository_name,
                    arn=repository_arn,
                    region=AWS_REGION,
                    scan_on_push=True,
                    policy=repo_policy_public,
                    images_details=[
                        ImageDetails(
                            latest_tag=latest_tag,
                            latest_digest="test-digest",
                            image_pushed_at=datetime(2023, 1, 1),
                            scan_findings_status="COMPLETE",
                            scan_findings_severity_count=FindingSeverityCounts(
                                critical=12, high=34, medium=7
                            ),
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
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            self.set_mocked_audit_info(),
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
                == f"ECR repository {repository_name} has imageTag {latest_tag} scanned with findings: CRITICAL->{12}."
            )
            assert result[0].resource_id == repository_name
            assert result[0].resource_arn == repository_arn

    def test_image_scanned_without_CRITICAL_findings_default_severity_CRITICAL(self):
        ecr_client = mock.MagicMock
        ecr_client.registries = {}
        ecr_client.registries[AWS_REGION] = Registry(
            id=AWS_ACCOUNT_NUMBER,
            region=AWS_REGION,
            scan_type="BASIC",
            repositories=[
                Repository(
                    name=repository_name,
                    arn=repository_arn,
                    region=AWS_REGION,
                    scan_on_push=True,
                    policy=repo_policy_public,
                    images_details=[
                        ImageDetails(
                            latest_tag=latest_tag,
                            latest_digest="test-digest",
                            image_pushed_at=datetime(2023, 1, 1),
                            scan_findings_status="COMPLETE",
                            scan_findings_severity_count=FindingSeverityCounts(
                                critical=0, high=34, medium=7
                            ),
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
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            self.set_mocked_audit_info(),
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
                == f"ECR repository {repository_name} has imageTag {latest_tag} scanned without findings."
            )
            assert result[0].resource_id == repository_name
            assert result[0].resource_arn == repository_arn

    def test_image_scanned_without_CRITICAL_and_HIGH_findings_default_severity_HIGH(
        self,
    ):
        ecr_client = mock.MagicMock
        ecr_client.registries = {}
        ecr_client.registries[AWS_REGION] = Registry(
            id=AWS_ACCOUNT_NUMBER,
            region=AWS_REGION,
            scan_type="BASIC",
            repositories=[
                Repository(
                    name=repository_name,
                    arn=repository_arn,
                    region=AWS_REGION,
                    scan_on_push=True,
                    policy=repo_policy_public,
                    images_details=[
                        ImageDetails(
                            latest_tag=latest_tag,
                            latest_digest="test-digest",
                            image_pushed_at=datetime(2023, 1, 1),
                            scan_findings_status="COMPLETE",
                            scan_findings_severity_count=FindingSeverityCounts(
                                critical=0, high=0, medium=7
                            ),
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
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            self.set_mocked_audit_info(),
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
                == f"ECR repository {repository_name} has imageTag {latest_tag} scanned without findings."
            )
            assert result[0].resource_id == repository_name
            assert result[0].resource_arn == repository_arn

    def test_image_scanned_fail_scan(self):
        ecr_client = mock.MagicMock
        ecr_client.registries = {}
        ecr_client.registries[AWS_REGION] = Registry(
            id=AWS_ACCOUNT_NUMBER,
            region=AWS_REGION,
            scan_type="BASIC",
            repositories=[
                Repository(
                    name=repository_name,
                    arn=repository_arn,
                    region=AWS_REGION,
                    scan_on_push=True,
                    policy=repo_policy_public,
                    images_details=[
                        ImageDetails(
                            latest_tag=latest_tag,
                            latest_digest="test-digest",
                            image_pushed_at=datetime(2023, 1, 1),
                            scan_findings_status="FAILED",
                            scan_findings_severity_count=FindingSeverityCounts(
                                critical=0, high=0, medium=0
                            ),
                        )
                    ],
                    lifecycle_policy=None,
                )
            ],
            rules=[],
        )
        ecr_client.audit_config = {}

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            self.set_mocked_audit_info(),
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
                == f"ECR repository {repository_name} with scan status FAILED."
            )
            assert result[0].resource_id == repository_name
            assert result[0].resource_arn == repository_arn

    def test_image_not_scanned(self):
        ecr_client = mock.MagicMock
        ecr_client.registries = {}
        ecr_client.registries[AWS_REGION] = Registry(
            id=AWS_ACCOUNT_NUMBER,
            region=AWS_REGION,
            scan_type="BASIC",
            repositories=[
                Repository(
                    name=repository_name,
                    arn=repository_arn,
                    region=AWS_REGION,
                    scan_on_push=True,
                    policy=repo_policy_public,
                    images_details=[
                        ImageDetails(
                            latest_tag=latest_tag,
                            latest_digest="test-digest",
                            image_pushed_at=datetime(2023, 1, 1),
                            scan_findings_status="",
                            scan_findings_severity_count=FindingSeverityCounts(
                                critical=0, high=0, medium=0
                            ),
                        )
                    ],
                    lifecycle_policy=None,
                )
            ],
            rules=[],
        )
        ecr_client.audit_config = {}

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            self.set_mocked_audit_info(),
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
                == f"ECR repository {repository_name} has imageTag {latest_tag} without a scan."
            )
            assert result[0].resource_id == repository_name
            assert result[0].resource_arn == repository_arn
