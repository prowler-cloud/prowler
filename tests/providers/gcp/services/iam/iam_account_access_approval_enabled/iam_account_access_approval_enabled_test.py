from re import search
from unittest import mock

from tests.providers.gcp.gcp_fixtures import GCP_PROJECT_ID, set_mocked_gcp_provider


class Test_iam_account_access_approval_enabled:
    def test_iam_no_settings(self):
        accessapproval_client = mock.MagicMock
        accessapproval_client.settings = {}
        accessapproval_client.project_ids = [GCP_PROJECT_ID]
        accessapproval_client.region = "global"

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=set_mocked_gcp_provider(),
        ), mock.patch(
            "prowler.providers.gcp.services.iam.iam_account_access_approval_enabled.iam_account_access_approval_enabled.accessapproval_client",
            new=accessapproval_client,
        ):
            from prowler.providers.gcp.services.iam.iam_account_access_approval_enabled.iam_account_access_approval_enabled import (
                iam_account_access_approval_enabled,
            )

            check = iam_account_access_approval_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert search(
                "does not have Access Approval enabled",
                result[0].status_extended,
            )
            assert result[0].resource_id == GCP_PROJECT_ID
            assert result[0].project_id == GCP_PROJECT_ID
            assert result[0].location == "global"

    def test_iam_project_with_settings(self):
        from prowler.providers.gcp.services.iam.iam_service import Setting

        accessapproval_client = mock.MagicMock
        accessapproval_client.settings = {
            GCP_PROJECT_ID: Setting(name="test", project_id=GCP_PROJECT_ID)
        }
        accessapproval_client.project_ids = [GCP_PROJECT_ID]
        accessapproval_client.region = "global"

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=set_mocked_gcp_provider(),
        ), mock.patch(
            "prowler.providers.gcp.services.iam.iam_account_access_approval_enabled.iam_account_access_approval_enabled.accessapproval_client",
            new=accessapproval_client,
        ):
            from prowler.providers.gcp.services.iam.iam_account_access_approval_enabled.iam_account_access_approval_enabled import (
                iam_account_access_approval_enabled,
            )

            check = iam_account_access_approval_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert search(
                "has Access Approval enabled",
                result[0].status_extended,
            )
            assert result[0].resource_id == GCP_PROJECT_ID
            assert result[0].project_id == GCP_PROJECT_ID
            assert result[0].location == "global"
