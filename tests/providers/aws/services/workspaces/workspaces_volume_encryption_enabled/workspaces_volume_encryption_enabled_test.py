from re import search
from unittest import mock
from uuid import uuid4

from prowler.providers.aws.services.workspaces.workspaces_service import WorkSpace

AWS_REGION = "eu-west-1"
AWS_ACCOUNT_NUMBER = "123456789012"

workspace_id = str(uuid4())


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
                id=workspace_id,
                region=AWS_REGION,
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
            assert result[0].resource_id == workspace_id
            assert result[0].resource_arn == ""

    def test_workspaces_user_not_encrypted(self):
        workspaces_client = mock.MagicMock
        workspaces_client.workspaces = []
        workspaces_client.workspaces.append(
            WorkSpace(
                id=workspace_id,
                region=AWS_REGION,
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
            assert result[0].resource_id == workspace_id
            assert result[0].resource_arn == ""

    def test_workspaces_root_not_encrypted(self):
        workspaces_client = mock.MagicMock
        workspaces_client.workspaces = []
        workspaces_client.workspaces.append(
            WorkSpace(
                id=workspace_id,
                region=AWS_REGION,
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
            assert result[0].resource_id == workspace_id
            assert result[0].resource_arn == ""

    def test_workspaces_user_and_root_not_encrypted(self):
        workspaces_client = mock.MagicMock
        workspaces_client.workspaces = []
        workspaces_client.workspaces.append(
            WorkSpace(
                id=workspace_id,
                region=AWS_REGION,
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
            assert result[0].resource_id == workspace_id
            assert result[0].resource_arn == ""
