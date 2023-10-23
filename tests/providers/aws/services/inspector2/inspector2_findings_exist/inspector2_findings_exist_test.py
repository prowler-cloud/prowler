from unittest import mock

from boto3 import session

from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info
from prowler.providers.aws.services.ecr.ecr_service import Repository
from prowler.providers.aws.services.inspector2.inspector2_service import (
    Inspector,
    InspectorFinding,
)
from prowler.providers.common.models import Audit_Metadata

AWS_REGION = "us-east-1"
AWS_ACCOUNT_ID = "123456789012"
FINDING_ARN = (
    "arn:aws:inspector2:us-east-1:123456789012:finding/0e436649379db5f327e3cf5bb4421d76"
)


class Test_inspector2_findings_exist:
    def set_mocked_audit_info(self):
        audit_info = AWS_Audit_Info(
            session_config=None,
            original_session=None,
            audit_session=session.Session(
                profile_name=None,
                botocore_session=None,
            ),
            audited_account=AWS_ACCOUNT_ID,
            audited_account_arn=f"arn:aws:iam::{AWS_ACCOUNT_ID}:root",
            audited_user_id=None,
            audited_partition="aws",
            audited_identity_arn=None,
            profile=None,
            profile_region=None,
            credentials=None,
            assumed_role_info=None,
            audited_regions=[AWS_REGION],
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

    def test_inspector2_disabled(self):
        # Mock the inspector2 client
        inspector2_client = mock.MagicMock
        awslambda_client = mock.MagicMock
        ecr_client = mock.MagicMock
        ec2_client = mock.MagicMock
        ec2_client.audit_info = self.set_mocked_audit_info()
        ecr_client.audit_info = self.set_mocked_audit_info()
        awslambda_client.audit_info = self.set_mocked_audit_info()
        inspector2_client.audit_info = self.set_mocked_audit_info()
        inspector2_client.audited_account = AWS_ACCOUNT_ID
        inspector2_client.audited_account_arn = f"arn:aws:iam::{AWS_ACCOUNT_ID}:root"
        inspector2_client.region = AWS_REGION
        inspector2_client.inspectors = [
            Inspector(
                id=AWS_ACCOUNT_ID, status="DISABLED", region=AWS_REGION, findings=[]
            )
        ]
        with mock.patch(
            "prowler.providers.aws.services.inspector2.inspector2_service.Inspector2",
            new=inspector2_client,
        ):
            with mock.patch(
                "prowler.providers.aws.services.ecr.ecr_service.ECR",
                new=ecr_client,
            ):
                with mock.patch(
                    "prowler.providers.aws.services.ec2.ec2_service.EC2",
                    new=ec2_client,
                ):
                    with mock.patch(
                        "prowler.providers.aws.services.awslambda.awslambda_service.Lambda",
                        new=awslambda_client,
                    ):
                        # Test Check
                        from prowler.providers.aws.services.inspector2.inspector2_findings_exist.inspector2_findings_exist import (
                            inspector2_findings_exist,
                        )

                        check = inspector2_findings_exist()
                        result = check.execute()

                        assert len(result) == 1
                        assert result[0].status == "FAIL"
                        assert result[0].status_extended == "Inspector2 is not enabled."
                        assert result[0].resource_id == AWS_ACCOUNT_ID
                        assert (
                            result[0].resource_arn
                            == f"arn:aws:iam::{AWS_ACCOUNT_ID}:root"
                        )
                        assert result[0].region == AWS_REGION

    def test_enabled_no_finding(self):
        # Mock the inspector2 client
        inspector2_client = mock.MagicMock
        awslambda_client = mock.MagicMock
        ecr_client = mock.MagicMock
        ec2_client = mock.MagicMock
        ec2_client.audit_info = self.set_mocked_audit_info()
        ecr_client.audit_info = self.set_mocked_audit_info()
        awslambda_client.audit_info = self.set_mocked_audit_info()
        inspector2_client.audit_info = self.set_mocked_audit_info()
        inspector2_client.audited_account = AWS_ACCOUNT_ID
        inspector2_client.audited_account_arn = f"arn:aws:iam::{AWS_ACCOUNT_ID}:root"
        inspector2_client.region = AWS_REGION
        inspector2_client.inspectors = [
            Inspector(
                id=AWS_ACCOUNT_ID, status="ENABLED", region=AWS_REGION, findings=[]
            )
        ]
        with mock.patch(
            "prowler.providers.aws.services.inspector2.inspector2_service.Inspector2",
            new=inspector2_client,
        ):
            with mock.patch(
                "prowler.providers.aws.services.ecr.ecr_service.ECR",
                new=ecr_client,
            ):
                with mock.patch(
                    "prowler.providers.aws.services.ec2.ec2_service.EC2",
                    new=ec2_client,
                ):
                    with mock.patch(
                        "prowler.providers.aws.services.awslambda.awslambda_service.Lambda",
                        new=awslambda_client,
                    ):
                        # Test Check
                        from prowler.providers.aws.services.inspector2.inspector2_findings_exist.inspector2_findings_exist import (
                            inspector2_findings_exist,
                        )

                        check = inspector2_findings_exist()
                        result = check.execute()

                        assert len(result) == 1
                        assert result[0].status == "PASS"
                        assert (
                            result[0].status_extended
                            == "Inspector2 is enabled with no findings."
                        )
                        assert result[0].resource_id == AWS_ACCOUNT_ID
                        assert (
                            result[0].resource_arn
                            == f"arn:aws:iam::{AWS_ACCOUNT_ID}:root"
                        )
                        assert result[0].region == AWS_REGION

    def test_enabled_with_no_active_finding(self):
        # Mock the inspector2 client
        inspector2_client = mock.MagicMock
        awslambda_client = mock.MagicMock
        ecr_client = mock.MagicMock
        ec2_client = mock.MagicMock
        ec2_client.audit_info = self.set_mocked_audit_info()
        ecr_client.audit_info = self.set_mocked_audit_info()
        awslambda_client.audit_info = self.set_mocked_audit_info()
        inspector2_client.audit_info = self.set_mocked_audit_info()
        inspector2_client.audited_account = AWS_ACCOUNT_ID
        inspector2_client.audited_account_arn = f"arn:aws:iam::{AWS_ACCOUNT_ID}:root"
        inspector2_client.region = AWS_REGION
        inspector2_client.inspectors = [
            Inspector(
                id=AWS_ACCOUNT_ID,
                region=AWS_REGION,
                status="ENABLED",
                findings=[
                    InspectorFinding(
                        arn=FINDING_ARN,
                        region=AWS_REGION,
                        severity="MEDIUM",
                        status="NOT_ACTIVE",
                        title="CVE-2022-40897 - setuptools",
                    )
                ],
            )
        ]

        with mock.patch(
            "prowler.providers.aws.services.inspector2.inspector2_service.Inspector2",
            new=inspector2_client,
        ):
            with mock.patch(
                "prowler.providers.aws.services.ecr.ecr_service.ECR",
                new=ecr_client,
            ):
                with mock.patch(
                    "prowler.providers.aws.services.ec2.ec2_service.EC2",
                    new=ec2_client,
                ):
                    with mock.patch(
                        "prowler.providers.aws.services.awslambda.awslambda_service.Lambda",
                        new=awslambda_client,
                    ):
                        # Test Check
                        from prowler.providers.aws.services.inspector2.inspector2_findings_exist.inspector2_findings_exist import (
                            inspector2_findings_exist,
                        )

                        check = inspector2_findings_exist()
                        result = check.execute()

                        assert len(result) == 1
                        assert result[0].status == "PASS"
                        assert (
                            result[0].status_extended
                            == "Inspector2 is enabled with no active findings."
                        )
                        assert result[0].resource_id == AWS_ACCOUNT_ID
                        assert (
                            result[0].resource_arn
                            == f"arn:aws:iam::{AWS_ACCOUNT_ID}:root"
                        )
                        assert result[0].region == AWS_REGION

    def test_enabled_with_active_finding(self):
        # Mock the inspector2 client
        inspector2_client = mock.MagicMock
        awslambda_client = mock.MagicMock
        ecr_client = mock.MagicMock
        ec2_client = mock.MagicMock
        ec2_client.audit_info = self.set_mocked_audit_info()
        ecr_client.audit_info = self.set_mocked_audit_info()
        awslambda_client.audit_info = self.set_mocked_audit_info()
        inspector2_client.audit_info = self.set_mocked_audit_info()
        inspector2_client.audited_account = AWS_ACCOUNT_ID
        inspector2_client.audited_account_arn = f"arn:aws:iam::{AWS_ACCOUNT_ID}:root"
        inspector2_client.region = AWS_REGION
        inspector2_client.inspectors = [
            Inspector(
                id=AWS_ACCOUNT_ID,
                region=AWS_REGION,
                status="ENABLED",
                findings=[
                    InspectorFinding(
                        arn=FINDING_ARN,
                        region=AWS_REGION,
                        severity="MEDIUM",
                        status="ACTIVE",
                        title="CVE-2022-40897 - setuptools",
                    )
                ],
            )
        ]

        with mock.patch(
            "prowler.providers.aws.services.inspector2.inspector2_service.Inspector2",
            new=inspector2_client,
        ):
            with mock.patch(
                "prowler.providers.aws.services.ecr.ecr_service.ECR",
                new=ecr_client,
            ):
                with mock.patch(
                    "prowler.providers.aws.services.ec2.ec2_service.EC2",
                    new=ec2_client,
                ):
                    with mock.patch(
                        "prowler.providers.aws.services.awslambda.awslambda_service.Lambda",
                        new=awslambda_client,
                    ):
                        # Test Check
                        from prowler.providers.aws.services.inspector2.inspector2_findings_exist.inspector2_findings_exist import (
                            inspector2_findings_exist,
                        )

                        check = inspector2_findings_exist()
                        result = check.execute()

                        assert len(result) == 1
                        assert result[0].status == "FAIL"
                        assert (
                            result[0].status_extended
                            == "There are 1 ACTIVE Inspector2 findings."
                        )
                        assert result[0].resource_id == AWS_ACCOUNT_ID
                        assert (
                            result[0].resource_arn
                            == f"arn:aws:iam::{AWS_ACCOUNT_ID}:root"
                        )
                        assert result[0].region == AWS_REGION

    def test_enabled_with_active_and_closed_findings(self):
        # Mock the inspector2 client
        inspector2_client = mock.MagicMock
        awslambda_client = mock.MagicMock
        ecr_client = mock.MagicMock
        ec2_client = mock.MagicMock
        ec2_client.audit_info = self.set_mocked_audit_info()
        ecr_client.audit_info = self.set_mocked_audit_info()
        awslambda_client.audit_info = self.set_mocked_audit_info()
        inspector2_client.audit_info = self.set_mocked_audit_info()
        inspector2_client.audited_account = AWS_ACCOUNT_ID
        inspector2_client.audited_account_arn = f"arn:aws:iam::{AWS_ACCOUNT_ID}:root"
        inspector2_client.region = AWS_REGION
        inspector2_client.inspectors = [
            Inspector(
                id=AWS_ACCOUNT_ID,
                region=AWS_REGION,
                status="ENABLED",
                findings=[
                    InspectorFinding(
                        arn=FINDING_ARN,
                        region=AWS_REGION,
                        severity="MEDIUM",
                        status="ACTIVE",
                        title="CVE-2022-40897 - setuptools",
                    ),
                    InspectorFinding(
                        arn=FINDING_ARN,
                        region=AWS_REGION,
                        severity="MEDIUM",
                        status="CLOSED",
                        title="CVE-2022-27404 - freetype",
                    ),
                ],
            )
        ]

        with mock.patch(
            "prowler.providers.aws.services.inspector2.inspector2_service.Inspector2",
            new=inspector2_client,
        ):
            with mock.patch(
                "prowler.providers.aws.services.ecr.ecr_service.ECR",
                new=ecr_client,
            ):
                with mock.patch(
                    "prowler.providers.aws.services.ec2.ec2_service.EC2",
                    new=ec2_client,
                ):
                    with mock.patch(
                        "prowler.providers.aws.services.awslambda.awslambda_service.Lambda",
                        new=awslambda_client,
                    ):
                        # Test Check
                        from prowler.providers.aws.services.inspector2.inspector2_findings_exist.inspector2_findings_exist import (
                            inspector2_findings_exist,
                        )

                        check = inspector2_findings_exist()
                        result = check.execute()

                        assert len(result) == 1
                        assert result[0].status == "FAIL"
                        assert (
                            result[0].status_extended
                            == "There are 1 ACTIVE Inspector2 findings."
                        )
                        assert result[0].resource_id == AWS_ACCOUNT_ID
                        assert (
                            result[0].resource_arn
                            == f"arn:aws:iam::{AWS_ACCOUNT_ID}:root"
                        )
                        assert result[0].region == AWS_REGION

    def test_inspector2_disabled_ignoring(self):
        # Mock the inspector2 client
        inspector2_client = mock.MagicMock
        awslambda_client = mock.MagicMock
        awslambda_client.functions = {}
        ecr_client = mock.MagicMock
        ecr_client.registries = {}
        ecr_client.registries[AWS_REGION] = mock.MagicMock
        ecr_client.registries[AWS_REGION].repositories = []
        ec2_client = mock.MagicMock
        ec2_client.instances = []
        ec2_client.audit_info = self.set_mocked_audit_info()
        ecr_client.audit_info = self.set_mocked_audit_info()
        awslambda_client.audit_info = self.set_mocked_audit_info()
        inspector2_client.audit_info = self.set_mocked_audit_info()
        inspector2_client.audit_info.ignore_unused_services = True
        inspector2_client.audited_account = AWS_ACCOUNT_ID
        inspector2_client.audited_account_arn = f"arn:aws:iam::{AWS_ACCOUNT_ID}:root"
        inspector2_client.region = AWS_REGION
        inspector2_client.inspectors = [
            Inspector(
                id=AWS_ACCOUNT_ID, status="DISABLED", region=AWS_REGION, findings=[]
            )
        ]
        with mock.patch(
            "prowler.providers.aws.services.inspector2.inspector2_service.Inspector2",
            new=inspector2_client,
        ):
            with mock.patch(
                "prowler.providers.aws.services.ecr.ecr_service.ECR",
                new=ecr_client,
            ):
                with mock.patch(
                    "prowler.providers.aws.services.ec2.ec2_service.EC2",
                    new=ec2_client,
                ):
                    with mock.patch(
                        "prowler.providers.aws.services.awslambda.awslambda_service.Lambda",
                        new=awslambda_client,
                    ):
                        # Test Check
                        from prowler.providers.aws.services.inspector2.inspector2_findings_exist.inspector2_findings_exist import (
                            inspector2_findings_exist,
                        )

                        check = inspector2_findings_exist()
                        result = check.execute()

                        assert len(result) == 0

    def test_inspector2_disabled_ignoring_with_resources(self):
        # Mock the inspector2 client
        inspector2_client = mock.MagicMock
        awslambda_client = mock.MagicMock
        awslambda_client.functions = {}
        ecr_client = mock.MagicMock
        ecr_client.registries = {}
        ecr_client.registries[AWS_REGION] = mock.MagicMock
        repository_name = "test_repo"
        repository_arn = (
            f"arn:aws:ecr:eu-west-1:{AWS_ACCOUNT_ID}:repository/{repository_name}"
        )
        repo_policy_public = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "ECRRepositoryPolicy",
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": f"arn:aws:iam::{AWS_ACCOUNT_ID}:user/username"
                    },
                    "Action": ["ecr:DescribeImages", "ecr:DescribeRepositories"],
                }
            ],
        }
        ecr_client.registries[AWS_REGION].repositories = [
            Repository(
                name=repository_name,
                arn=repository_arn,
                region=AWS_REGION,
                scan_on_push=True,
                policy=repo_policy_public,
                images_details=None,
                lifecycle_policy="test-policy",
            )
        ]
        ec2_client = mock.MagicMock
        ec2_client.instances = []
        ec2_client.audit_info = self.set_mocked_audit_info()
        ecr_client.audit_info = self.set_mocked_audit_info()
        awslambda_client.audit_info = self.set_mocked_audit_info()
        inspector2_client.audit_info = self.set_mocked_audit_info()
        inspector2_client.audit_info.ignore_unused_services = True
        inspector2_client.audited_account = AWS_ACCOUNT_ID
        inspector2_client.audited_account_arn = f"arn:aws:iam::{AWS_ACCOUNT_ID}:root"
        inspector2_client.region = AWS_REGION
        inspector2_client.inspectors = [
            Inspector(
                id=AWS_ACCOUNT_ID, status="DISABLED", region=AWS_REGION, findings=[]
            )
        ]
        with mock.patch(
            "prowler.providers.aws.services.inspector2.inspector2_service.Inspector2",
            new=inspector2_client,
        ):
            with mock.patch(
                "prowler.providers.aws.services.ecr.ecr_service.ECR",
                new=ecr_client,
            ):
                with mock.patch(
                    "prowler.providers.aws.services.ec2.ec2_service.EC2",
                    new=ec2_client,
                ):
                    with mock.patch(
                        "prowler.providers.aws.services.awslambda.awslambda_service.Lambda",
                        new=awslambda_client,
                    ):
                        # Test Check
                        from prowler.providers.aws.services.inspector2.inspector2_findings_exist.inspector2_findings_exist import (
                            inspector2_findings_exist,
                        )

                        check = inspector2_findings_exist()
                        result = check.execute()
                        assert len(result) == 1
                        assert result[0].status == "FAIL"
                        assert result[0].status_extended == "Inspector2 is not enabled."
                        assert result[0].resource_id == AWS_ACCOUNT_ID
                        assert (
                            result[0].resource_arn
                            == f"arn:aws:iam::{AWS_ACCOUNT_ID}:root"
                        )
                        assert result[0].region == AWS_REGION
