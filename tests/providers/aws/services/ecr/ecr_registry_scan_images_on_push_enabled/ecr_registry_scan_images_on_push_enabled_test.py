from re import search
from unittest import mock

from prowler.providers.aws.services.ecr.ecr_service import (
    Registry,
    Repository,
    ScanningRule,
)
from tests.providers.aws.audit_info_utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_provider,
)

repository_name = "test_repo"
repository_arn = (
    f"arn:aws:ecr:eu-west-1:{AWS_ACCOUNT_NUMBER}:repository/{repository_name}"
)


class Test_ecr_registry_scan_images_on_push_enabled:
    def test_no_registries(self):
        ecr_client = mock.MagicMock
        ecr_client.registries = {}

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=set_mocked_aws_provider(),
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
        ecr_client.registries[AWS_REGION_EU_WEST_1] = Registry(
            id=AWS_ACCOUNT_NUMBER,
            region=AWS_REGION_EU_WEST_1,
            scan_type="BASIC",
            repositories=[],
            rules=[],
        )

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=set_mocked_aws_provider(),
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
        ecr_client.registries[AWS_REGION_EU_WEST_1] = Registry(
            id=AWS_ACCOUNT_NUMBER,
            region=AWS_REGION_EU_WEST_1,
            scan_type="BASIC",
            repositories=[
                Repository(
                    name=repository_name,
                    arn=repository_arn,
                    region=AWS_REGION_EU_WEST_1,
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
            "prowler.providers.common.common.get_global_provider",
            return_value=set_mocked_aws_provider(),
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
            assert result[0].region == AWS_REGION_EU_WEST_1

    def test_scan_on_push_enabled_with_filters(self):
        ecr_client = mock.MagicMock
        ecr_client.registries = {}
        ecr_client.registries[AWS_REGION_EU_WEST_1] = Registry(
            id=AWS_ACCOUNT_NUMBER,
            region=AWS_REGION_EU_WEST_1,
            scan_type="BASIC",
            repositories=[
                Repository(
                    name=repository_name,
                    arn=repository_arn,
                    region=AWS_REGION_EU_WEST_1,
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
            "prowler.providers.common.common.get_global_provider",
            return_value=set_mocked_aws_provider(),
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
            assert result[0].region == AWS_REGION_EU_WEST_1

    def test_scan_on_push_disabled(self):
        ecr_client = mock.MagicMock
        ecr_client.registries = {}
        ecr_client.registries[AWS_REGION_EU_WEST_1] = Registry(
            id=AWS_ACCOUNT_NUMBER,
            region=AWS_REGION_EU_WEST_1,
            scan_type="BASIC",
            repositories=[
                Repository(
                    name=repository_name,
                    arn=repository_arn,
                    region=AWS_REGION_EU_WEST_1,
                    scan_on_push=True,
                    policy="",
                    images_details=None,
                    lifecycle_policy="",
                )
            ],
            rules=[],
        )

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=set_mocked_aws_provider(),
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
            assert result[0].region == AWS_REGION_EU_WEST_1
