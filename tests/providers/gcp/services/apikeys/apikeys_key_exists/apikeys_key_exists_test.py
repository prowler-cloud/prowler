from re import search
from unittest import mock

from tests.providers.gcp.gcp_fixtures import GCP_PROJECT_ID, set_mocked_gcp_provider


class Test_apikeys_key_exists:
    def test_apikeys_no_keys(self):
        apikeys_client = mock.MagicMock
        apikeys_client.project_ids = [GCP_PROJECT_ID]
        apikeys_client.keys = []
        apikeys_client.region = "global"

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=set_mocked_gcp_provider(),
        ), mock.patch(
            "prowler.providers.gcp.services.apikeys.apikeys_key_exists.apikeys_key_exists.apikeys_client",
            new=apikeys_client,
        ):
            from prowler.providers.gcp.services.apikeys.apikeys_key_exists.apikeys_key_exists import (
                apikeys_key_exists,
            )

            check = apikeys_key_exists()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert search(
                f"Project {GCP_PROJECT_ID} does not have active API Keys.",
                result[0].status_extended,
            )
            assert result[0].resource_id == GCP_PROJECT_ID

    def test_one_compliant_key(self):
        from prowler.providers.gcp.services.apikeys.apikeys_service import Key

        key = Key(
            name="test",
            id="123",
            creation_time="2023-06-01T11:21:41.627509Z",
            restrictions={},
            project_id=GCP_PROJECT_ID,
        )

        apikeys_client = mock.MagicMock
        apikeys_client.project_ids = [GCP_PROJECT_ID]
        apikeys_client.keys = [key]
        apikeys_client.region = "global"

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=set_mocked_gcp_provider(),
        ), mock.patch(
            "prowler.providers.gcp.services.apikeys.apikeys_key_exists.apikeys_key_exists.apikeys_client",
            new=apikeys_client,
        ):
            from prowler.providers.gcp.services.apikeys.apikeys_key_exists.apikeys_key_exists import (
                apikeys_key_exists,
            )

            check = apikeys_key_exists()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert search(
                f"Project {GCP_PROJECT_ID} has active API Keys.",
                result[0].status_extended,
            )
            assert result[0].resource_id == GCP_PROJECT_ID
