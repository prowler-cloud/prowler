from re import search
from unittest import mock
from uuid import uuid4

from prowler.providers.aws.services.workspaces.workspaces_service import WorkSpace
from tests.providers.aws.utils import AWS_ACCOUNT_NUMBER, AWS_REGION_EU_WEST_1

WORKSPACE_ID = str(uuid4())
WORKSPACE_ARN = f"arn:aws:workspaces:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:workspace/{WORKSPACE_ID}"


class Test_workspaces_volume_encryption_enabled:
    def test_no_workspaces(self):
        workspaces_client = mock.MagicMock
        workspaces_client.workspaces = []
        with mock.patch(
            "prowler.providers.aws.services.workspaces.workspaces_service.WorkSpaces",
            workspaces_client,
        ), mock.patch(
            "prowler.providers.aws.services.workspaces.workspaces_client.workspaces_client",
            workspaces_client,
        ):
            from prowler.providers.aws.services.workspaces.workspaces_volume_encryption_enabled.workspaces_volume_encryption_enabled import (
                workspaces_volume_encryption_enabled,
            )

            check = workspaces_volume_encryption_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_workspaces_encrypted(self):
        workspaces_client = mock.MagicMock
        workspaces_client.workspaces = []
        workspaces_client.workspaces.append(
            WorkSpace(
                id=WORKSPACE_ID,
                arn=WORKSPACE_ARN,
                region=AWS_REGION_EU_WEST_1,
                user_volume_encryption_enabled=True,
                root_volume_encryption_enabled=True,
                subnet_id="subnet-12345678",
            )
        )
        with mock.patch(
            "prowler.providers.aws.services.workspaces.workspaces_service.WorkSpaces",
            workspaces_client,
        ), mock.patch(
            "prowler.providers.aws.services.workspaces.workspaces_client.workspaces_client",
            workspaces_client,
        ):
            from prowler.providers.aws.services.workspaces.workspaces_volume_encryption_enabled.workspaces_volume_encryption_enabled import (
                workspaces_volume_encryption_enabled,
            )

            check = workspaces_volume_encryption_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert search(
                "without root or user unencrypted volumes", result[0].status_extended
            )
            assert result[0].resource_id == WORKSPACE_ID
            assert result[0].resource_arn == WORKSPACE_ARN
            assert result[0].region == AWS_REGION_EU_WEST_1

    def test_workspaces_user_not_encrypted(self):
        workspaces_client = mock.MagicMock
        workspaces_client.workspaces = []
        workspaces_client.workspaces.append(
            WorkSpace(
                id=WORKSPACE_ID,
                arn=WORKSPACE_ARN,
                region=AWS_REGION_EU_WEST_1,
                user_volume_encryption_enabled=False,
                root_volume_encryption_enabled=True,
                subnet_id="subnet-12345678",
            )
        )
        with mock.patch(
            "prowler.providers.aws.services.workspaces.workspaces_service.WorkSpaces",
            workspaces_client,
        ), mock.patch(
            "prowler.providers.aws.services.workspaces.workspaces_client.workspaces_client",
            workspaces_client,
        ):
            from prowler.providers.aws.services.workspaces.workspaces_volume_encryption_enabled.workspaces_volume_encryption_enabled import (
                workspaces_volume_encryption_enabled,
            )

            check = workspaces_volume_encryption_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert search("user unencrypted volumes", result[0].status_extended)
            assert result[0].resource_id == WORKSPACE_ID
            assert result[0].resource_arn == WORKSPACE_ARN
            assert result[0].region == AWS_REGION_EU_WEST_1

    def test_workspaces_root_not_encrypted(self):
        workspaces_client = mock.MagicMock
        workspaces_client.workspaces = []
        workspaces_client.workspaces.append(
            WorkSpace(
                id=WORKSPACE_ID,
                arn=WORKSPACE_ARN,
                region=AWS_REGION_EU_WEST_1,
                user_volume_encryption_enabled=True,
                root_volume_encryption_enabled=False,
                subnet_id="subnet-12345678",
            )
        )
        with mock.patch(
            "prowler.providers.aws.services.workspaces.workspaces_service.WorkSpaces",
            workspaces_client,
        ), mock.patch(
            "prowler.providers.aws.services.workspaces.workspaces_client.workspaces_client",
            workspaces_client,
        ):
            from prowler.providers.aws.services.workspaces.workspaces_volume_encryption_enabled.workspaces_volume_encryption_enabled import (
                workspaces_volume_encryption_enabled,
            )

            check = workspaces_volume_encryption_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert search("root unencrypted volumes", result[0].status_extended)
            assert result[0].resource_id == WORKSPACE_ID
            assert result[0].resource_arn == WORKSPACE_ARN
            assert result[0].region == AWS_REGION_EU_WEST_1

    def test_workspaces_user_and_root_not_encrypted(self):
        workspaces_client = mock.MagicMock
        workspaces_client.workspaces = []
        workspaces_client.workspaces.append(
            WorkSpace(
                id=WORKSPACE_ID,
                arn=WORKSPACE_ARN,
                region=AWS_REGION_EU_WEST_1,
                user_volume_encryption_enabled=False,
                root_volume_encryption_enabled=False,
                subnet_id="subnet-12345678",
            )
        )
        with mock.patch(
            "prowler.providers.aws.services.workspaces.workspaces_service.WorkSpaces",
            workspaces_client,
        ), mock.patch(
            "prowler.providers.aws.services.workspaces.workspaces_client.workspaces_client",
            workspaces_client,
        ):
            from prowler.providers.aws.services.workspaces.workspaces_volume_encryption_enabled.workspaces_volume_encryption_enabled import (
                workspaces_volume_encryption_enabled,
            )

            check = workspaces_volume_encryption_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert search(
                "with root and user unencrypted volumes", result[0].status_extended
            )
            assert result[0].resource_id == WORKSPACE_ID
            assert result[0].resource_arn == WORKSPACE_ARN
            assert result[0].region == AWS_REGION_EU_WEST_1
