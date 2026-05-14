from re import search
from unittest import mock

from prowler.providers.gcp.services.apikeys.apikeys_service import Key
from prowler.providers.gcp.services.serviceusage.serviceusage_service import Service
from tests.providers.gcp.gcp_fixtures import GCP_PROJECT_ID, set_mocked_gcp_provider


class Test_apikeys_api_restricted_with_gemini_api:
    def test_unrestricted_key_gemini_disabled(self):
        key = Key(
            name="test",
            id="123",
            creation_time="2026-02-01T11:21:41.627509Z",
            restrictions={},
            project_id=GCP_PROJECT_ID,
        )

        apikeys_client = mock.MagicMock()
        apikeys_client.project_ids = [GCP_PROJECT_ID]
        apikeys_client.keys = [key]
        apikeys_client.region = "global"

        serviceusage_client = mock.MagicMock()
        serviceusage_client.active_services = {GCP_PROJECT_ID: []}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.apikeys.apikeys_api_restricted_with_gemini_api.apikeys_api_restricted_with_gemini_api.apikeys_client",
                new=apikeys_client,
            ),
            mock.patch(
                "prowler.providers.gcp.services.apikeys.apikeys_api_restricted_with_gemini_api.apikeys_api_restricted_with_gemini_api.serviceusage_client",
                new=serviceusage_client,
            ),
        ):
            from prowler.providers.gcp.services.apikeys.apikeys_api_restricted_with_gemini_api.apikeys_api_restricted_with_gemini_api import (
                apikeys_api_restricted_with_gemini_api,
            )

            check = apikeys_api_restricted_with_gemini_api()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert search(
                "Gemini .* API is not enabled",
                result[0].status_extended,
            )
            assert result[0].resource_id == key.id

    def test_no_keys(self):
        apikeys_client = mock.MagicMock()
        apikeys_client.project_ids = [GCP_PROJECT_ID]
        apikeys_client.keys = []
        apikeys_client.region = "global"

        serviceusage_client = mock.MagicMock()
        serviceusage_client.active_services = {
            GCP_PROJECT_ID: [
                Service(
                    name="generativelanguage.googleapis.com",
                    title="Gemini API",
                    project_id=GCP_PROJECT_ID,
                )
            ]
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.apikeys.apikeys_api_restricted_with_gemini_api.apikeys_api_restricted_with_gemini_api.apikeys_client",
                new=apikeys_client,
            ),
            mock.patch(
                "prowler.providers.gcp.services.apikeys.apikeys_api_restricted_with_gemini_api.apikeys_api_restricted_with_gemini_api.serviceusage_client",
                new=serviceusage_client,
            ),
        ):
            from prowler.providers.gcp.services.apikeys.apikeys_api_restricted_with_gemini_api.apikeys_api_restricted_with_gemini_api import (
                apikeys_api_restricted_with_gemini_api,
            )

            check = apikeys_api_restricted_with_gemini_api()
            result = check.execute()

            assert len(result) == 0

    def test_key_restricted_to_gemini_only(self):
        key = Key(
            name="test",
            id="123",
            creation_time="2026-02-01T11:21:41.627509Z",
            restrictions={
                "apiTargets": [
                    {"service": "generativelanguage.googleapis.com"},
                ]
            },
            project_id=GCP_PROJECT_ID,
        )

        apikeys_client = mock.MagicMock()
        apikeys_client.project_ids = [GCP_PROJECT_ID]
        apikeys_client.keys = [key]
        apikeys_client.region = "global"

        serviceusage_client = mock.MagicMock()
        serviceusage_client.active_services = {
            GCP_PROJECT_ID: [
                Service(
                    name="generativelanguage.googleapis.com",
                    title="Gemini API",
                    project_id=GCP_PROJECT_ID,
                )
            ]
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.apikeys.apikeys_api_restricted_with_gemini_api.apikeys_api_restricted_with_gemini_api.apikeys_client",
                new=apikeys_client,
            ),
            mock.patch(
                "prowler.providers.gcp.services.apikeys.apikeys_api_restricted_with_gemini_api.apikeys_api_restricted_with_gemini_api.serviceusage_client",
                new=serviceusage_client,
            ),
        ):
            from prowler.providers.gcp.services.apikeys.apikeys_api_restricted_with_gemini_api.apikeys_api_restricted_with_gemini_api import (
                apikeys_api_restricted_with_gemini_api,
            )

            check = apikeys_api_restricted_with_gemini_api()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert search(
                f"API key {key.name} has restrictions configured",
                result[0].status_extended,
            )
            assert result[0].resource_id == key.id

    def test_key_restricted_to_bigquery_and_gemini(self):
        key = Key(
            name="test",
            id="123",
            creation_time="2026-02-01T11:21:41.627509Z",
            restrictions={
                "apiTargets": [
                    {"service": "bigquery.googleapis.com"},
                    {"service": "generativelanguage.googleapis.com"},
                ]
            },
            project_id=GCP_PROJECT_ID,
        )

        apikeys_client = mock.MagicMock()
        apikeys_client.project_ids = [GCP_PROJECT_ID]
        apikeys_client.keys = [key]
        apikeys_client.region = "global"

        serviceusage_client = mock.MagicMock()
        serviceusage_client.active_services = {
            GCP_PROJECT_ID: [
                Service(
                    name="bigquery.googleapis.com",
                    title="BigQuery API",
                    project_id=GCP_PROJECT_ID,
                ),
                Service(
                    name="generativelanguage.googleapis.com",
                    title="Gemini API",
                    project_id=GCP_PROJECT_ID,
                ),
            ]
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.apikeys.apikeys_api_restricted_with_gemini_api.apikeys_api_restricted_with_gemini_api.apikeys_client",
                new=apikeys_client,
            ),
            mock.patch(
                "prowler.providers.gcp.services.apikeys.apikeys_api_restricted_with_gemini_api.apikeys_api_restricted_with_gemini_api.serviceusage_client",
                new=serviceusage_client,
            ),
        ):
            from prowler.providers.gcp.services.apikeys.apikeys_api_restricted_with_gemini_api.apikeys_api_restricted_with_gemini_api import (
                apikeys_api_restricted_with_gemini_api,
            )

            check = apikeys_api_restricted_with_gemini_api()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert search(
                f"API key {key.name} has access to Gemini",
                result[0].status_extended,
            )
            assert result[0].resource_id == key.id

    def test_key_restricted_to_bigquery_only(self):
        key = Key(
            name="test",
            id="123",
            creation_time="2026-02-01T11:21:41.627509Z",
            restrictions={
                "apiTargets": [
                    {"service": "bigquery.googleapis.com"},
                ]
            },
            project_id=GCP_PROJECT_ID,
        )

        apikeys_client = mock.MagicMock()
        apikeys_client.project_ids = [GCP_PROJECT_ID]
        apikeys_client.keys = [key]
        apikeys_client.region = "global"

        serviceusage_client = mock.MagicMock()
        serviceusage_client.active_services = {
            GCP_PROJECT_ID: [
                Service(
                    name="bigquery.googleapis.com",
                    title="BigQuery API",
                    project_id=GCP_PROJECT_ID,
                ),
                Service(
                    name="generativelanguage.googleapis.com",
                    title="Gemini API",
                    project_id=GCP_PROJECT_ID,
                ),
            ]
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.apikeys.apikeys_api_restricted_with_gemini_api.apikeys_api_restricted_with_gemini_api.apikeys_client",
                new=apikeys_client,
            ),
            mock.patch(
                "prowler.providers.gcp.services.apikeys.apikeys_api_restricted_with_gemini_api.apikeys_api_restricted_with_gemini_api.serviceusage_client",
                new=serviceusage_client,
            ),
        ):
            from prowler.providers.gcp.services.apikeys.apikeys_api_restricted_with_gemini_api.apikeys_api_restricted_with_gemini_api import (
                apikeys_api_restricted_with_gemini_api,
            )

            check = apikeys_api_restricted_with_gemini_api()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert search(
                f"API key {key.name} has restrictions configured",
                result[0].status_extended,
            )
            assert result[0].resource_id == key.id

    def test_key_restricted_to_cloudapis(self):
        key = Key(
            name="test",
            id="123",
            creation_time="2026-02-01T11:21:41.627509Z",
            restrictions={
                "apiTargets": [
                    {"service": "cloudapis.googleapis.com"},
                ]
            },
            project_id=GCP_PROJECT_ID,
        )

        apikeys_client = mock.MagicMock()
        apikeys_client.project_ids = [GCP_PROJECT_ID]
        apikeys_client.keys = [key]
        apikeys_client.region = "global"

        serviceusage_client = mock.MagicMock()
        serviceusage_client.active_services = {
            GCP_PROJECT_ID: [
                Service(
                    name="generativelanguage.googleapis.com",
                    title="Gemini API",
                    project_id=GCP_PROJECT_ID,
                )
            ]
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.apikeys.apikeys_api_restricted_with_gemini_api.apikeys_api_restricted_with_gemini_api.apikeys_client",
                new=apikeys_client,
            ),
            mock.patch(
                "prowler.providers.gcp.services.apikeys.apikeys_api_restricted_with_gemini_api.apikeys_api_restricted_with_gemini_api.serviceusage_client",
                new=serviceusage_client,
            ),
        ):
            from prowler.providers.gcp.services.apikeys.apikeys_api_restricted_with_gemini_api.apikeys_api_restricted_with_gemini_api import (
                apikeys_api_restricted_with_gemini_api,
            )

            check = apikeys_api_restricted_with_gemini_api()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert search(
                f"API key {key.name} does not have restrictions configured",
                result[0].status_extended,
            )
            assert result[0].resource_id == key.id

    def test_two_keys_one_restricted_one_unrestricted(self):
        key_restricted = Key(
            name="restricted-key",
            id="123",
            creation_time="2026-02-01T11:21:41.627509Z",
            restrictions={
                "apiTargets": [
                    {"service": "bigquery.googleapis.com"},
                ]
            },
            project_id=GCP_PROJECT_ID,
        )

        key_unrestricted = Key(
            name="unrestricted-key",
            id="456",
            creation_time="2026-02-01T11:21:41.627509Z",
            restrictions={},
            project_id=GCP_PROJECT_ID,
        )

        apikeys_client = mock.MagicMock()
        apikeys_client.project_ids = [GCP_PROJECT_ID]
        apikeys_client.keys = [key_restricted, key_unrestricted]
        apikeys_client.region = "global"

        serviceusage_client = mock.MagicMock()
        serviceusage_client.active_services = {
            GCP_PROJECT_ID: [
                Service(
                    name="generativelanguage.googleapis.com",
                    title="Gemini API",
                    project_id=GCP_PROJECT_ID,
                )
            ]
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_gcp_provider(),
            ),
            mock.patch(
                "prowler.providers.gcp.services.apikeys.apikeys_api_restricted_with_gemini_api.apikeys_api_restricted_with_gemini_api.apikeys_client",
                new=apikeys_client,
            ),
            mock.patch(
                "prowler.providers.gcp.services.apikeys.apikeys_api_restricted_with_gemini_api.apikeys_api_restricted_with_gemini_api.serviceusage_client",
                new=serviceusage_client,
            ),
        ):
            from prowler.providers.gcp.services.apikeys.apikeys_api_restricted_with_gemini_api.apikeys_api_restricted_with_gemini_api import (
                apikeys_api_restricted_with_gemini_api,
            )

            check = apikeys_api_restricted_with_gemini_api()
            result = check.execute()

            assert len(result) == 2

            assert result[0].status == "PASS"
            assert result[0].resource_id == key_restricted.id

            assert result[1].status == "FAIL"
            assert search(
                f"API key {key_unrestricted.name} does not have restrictions configured",
                result[1].status_extended,
            )
            assert result[1].resource_id == key_unrestricted.id
