from re import search
from unittest import mock

from tests.providers.gcp.gcp_fixtures import GCP_PROJECT_ID, set_mocked_gcp_provider


class Test_apikeys_api_restrictions_configured:
    def test_apikeys_no_keys(self):
        apikeys_client = mock.MagicMock
        apikeys_client.keys = []

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_gcp_provider(),
        ), mock.patch(
            "prowler.providers.gcp.services.apikeys.apikeys_api_restrictions_configured.apikeys_api_restrictions_configured.apikeys_client",
            new=apikeys_client,
        ):
            from prowler.providers.gcp.services.apikeys.apikeys_api_restrictions_configured.apikeys_api_restrictions_configured import (
                apikeys_api_restrictions_configured,
            )

            check = apikeys_api_restrictions_configured()
            result = check.execute()
            assert len(result) == 0

    def test_one_compliant_key(self):
        from prowler.providers.gcp.services.apikeys.apikeys_service import Key

        key = Key(
            name="test",
            id="123",
            creation_time="2023-06-01T11:21:41.627509Z",
            restrictions={
                "apiTargets": [
                    {"service": "dns.googleapis.com"},
                    {"service": "oslogin.googleapis.com"},
                ]
            },
            project_id=GCP_PROJECT_ID,
        )

        apikeys_client = mock.MagicMock
        apikeys_client.project_ids = [GCP_PROJECT_ID]
        apikeys_client.keys = [key]
        apikeys_client.region = "global"

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_gcp_provider(),
        ), mock.patch(
            "prowler.providers.gcp.services.apikeys.apikeys_api_restrictions_configured.apikeys_api_restrictions_configured.apikeys_client",
            new=apikeys_client,
        ):
            from prowler.providers.gcp.services.apikeys.apikeys_api_restrictions_configured.apikeys_api_restrictions_configured import (
                apikeys_api_restrictions_configured,
            )

            check = apikeys_api_restrictions_configured()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert search(
                f"API key {key.name} has restrictions configured.",
                result[0].status_extended,
            )
            assert result[0].resource_id == key.id

    def test_one_key_without_restrictions(self):
        from prowler.providers.gcp.services.apikeys.apikeys_service import Key

        key = Key(
            name="test",
            id="123",
            creation_time="2022-06-05T11:21:41.627509Z",
            restrictions={},
            project_id=GCP_PROJECT_ID,
        )

        apikeys_client = mock.MagicMock
        apikeys_client.project_ids = [GCP_PROJECT_ID]
        apikeys_client.keys = [key]
        apikeys_client.region = "global"

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_gcp_provider(),
        ), mock.patch(
            "prowler.providers.gcp.services.apikeys.apikeys_api_restrictions_configured.apikeys_api_restrictions_configured.apikeys_client",
            new=apikeys_client,
        ):
            from prowler.providers.gcp.services.apikeys.apikeys_api_restrictions_configured.apikeys_api_restrictions_configured import (
                apikeys_api_restrictions_configured,
            )

            check = apikeys_api_restrictions_configured()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert search(
                f"API key {key.name} doens't have restrictions configured.",
                result[0].status_extended,
            )
            assert result[0].resource_id == key.id

    def test_one_key_with_cloudapis_restriction(self):
        from prowler.providers.gcp.services.apikeys.apikeys_service import Key

        key = Key(
            name="test",
            id="123",
            creation_time="2022-06-05T11:21:41.627509Z",
            restrictions={
                "apiTargets": [
                    {"service": "dns.googleapis.com"},
                    {"service": "oslogin.googleapis.com"},
                    {"service": "cloudapis.googleapis.com"},
                ]
            },
            project_id=GCP_PROJECT_ID,
        )

        apikeys_client = mock.MagicMock
        apikeys_client.project_ids = [GCP_PROJECT_ID]
        apikeys_client.keys = [key]
        apikeys_client.region = "global"

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_gcp_provider(),
        ), mock.patch(
            "prowler.providers.gcp.services.apikeys.apikeys_api_restrictions_configured.apikeys_api_restrictions_configured.apikeys_client",
            new=apikeys_client,
        ):
            from prowler.providers.gcp.services.apikeys.apikeys_api_restrictions_configured.apikeys_api_restrictions_configured import (
                apikeys_api_restrictions_configured,
            )

            check = apikeys_api_restrictions_configured()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert search(
                f"API key {key.name} doens't have restrictions configured.",
                result[0].status_extended,
            )
            assert result[0].resource_id == key.id
