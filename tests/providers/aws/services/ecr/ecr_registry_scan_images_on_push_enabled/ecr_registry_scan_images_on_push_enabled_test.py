from re import search
from unittest import mock

from boto3 import session

from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info
from prowler.providers.aws.services.ecr.ecr_service import (
    Registry,
    Repository,
    ScanningRule,
)
from prowler.providers.common.models import Audit_Metadata
from tests.providers.aws.audit_info_utils import (
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_audit_info,
)

# Mock Test Region
AWS_REGION = "eu-west-1"
AWS_ACCOUNT_NUMBER = "123456789012"
repository_name = "test_repo"
repository_arn = (
    f"arn:aws:ecr:eu-west-1:{AWS_ACCOUNT_NUMBER}:repository/{repository_name}"
)


class Test_ecr_registry_scan_images_on_push_enabled:
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

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1]),
        ), mock.patch(
            "prowler.providers.aws.services.ecr.ecr_registry_scan_images_on_push_enabled.ecr_registry_scan_images_on_push_enabled.ecr_client",
            ecr_client,
        ):
            from prowler.providers.aws.services.ecr.ecr_registry_scan_images_on_push_enabled.ecr_registry_scan_images_on_push_enabled import (
                ecr_registry_scan_images_on_push_enabled,
            )

            check = ecr_registry_scan_images_on_push_enabled()
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

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1]),
        ), mock.patch(
            "prowler.providers.aws.services.ecr.ecr_registry_scan_images_on_push_enabled.ecr_registry_scan_images_on_push_enabled.ecr_client",
            ecr_client,
        ):
            from prowler.providers.aws.services.ecr.ecr_registry_scan_images_on_push_enabled.ecr_registry_scan_images_on_push_enabled import (
                ecr_registry_scan_images_on_push_enabled,
            )

            check = ecr_registry_scan_images_on_push_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_registry_scan_on_push_enabled(self):
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
                    policy="",
                    images_details=None,
                    lifecycle_policy="",
                )
            ],
            rules=[
                ScanningRule(
                    scan_frequency="SCAN_ON_PUSH",
                    scan_filters=[{"filter": "*", "filterType": "WILDCARD"}],
                )
            ],
        )

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1]),
        ), mock.patch(
            "prowler.providers.aws.services.ecr.ecr_registry_scan_images_on_push_enabled.ecr_registry_scan_images_on_push_enabled.ecr_client",
            ecr_client,
        ):
            from prowler.providers.aws.services.ecr.ecr_registry_scan_images_on_push_enabled.ecr_registry_scan_images_on_push_enabled import (
                ecr_registry_scan_images_on_push_enabled,
            )

            check = ecr_registry_scan_images_on_push_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert search("with scan on push", result[0].status_extended)
            assert result[0].resource_id == AWS_ACCOUNT_NUMBER
            assert result[0].region == AWS_REGION

    def test_scan_on_push_enabled_with_filters(self):
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
                    policy="",
                    images_details=None,
                    lifecycle_policy="",
                )
            ],
            rules=[
                ScanningRule(
                    scan_frequency="SCAN_ON_PUSH",
                    scan_filters=[{"filter": "test", "filterType": "WILDCARD"}],
                )
            ],
        )

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1]),
        ), mock.patch(
            "prowler.providers.aws.services.ecr.ecr_registry_scan_images_on_push_enabled.ecr_registry_scan_images_on_push_enabled.ecr_client",
            ecr_client,
        ):
            from prowler.providers.aws.services.ecr.ecr_registry_scan_images_on_push_enabled.ecr_registry_scan_images_on_push_enabled import (
                ecr_registry_scan_images_on_push_enabled,
            )

            check = ecr_registry_scan_images_on_push_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert search(
                "scanning with scan on push but with repository filters",
                result[0].status_extended,
            )
            assert result[0].resource_id == AWS_ACCOUNT_NUMBER
            assert result[0].region == AWS_REGION

    def test_scan_on_push_disabled(self):
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
                    policy="",
                    images_details=None,
                    lifecycle_policy="",
                )
            ],
            rules=[],
        )

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1]),
        ), mock.patch(
            "prowler.providers.aws.services.ecr.ecr_registry_scan_images_on_push_enabled.ecr_registry_scan_images_on_push_enabled.ecr_client",
            ecr_client,
        ):
            from prowler.providers.aws.services.ecr.ecr_registry_scan_images_on_push_enabled.ecr_registry_scan_images_on_push_enabled import (
                ecr_registry_scan_images_on_push_enabled,
            )

            check = ecr_registry_scan_images_on_push_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert search("scanning without scan on push", result[0].status_extended)
            assert result[0].resource_id == AWS_ACCOUNT_NUMBER
            assert result[0].region == AWS_REGION
