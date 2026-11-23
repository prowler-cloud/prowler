from unittest.mock import MagicMock, patch

from googleapiclient.errors import HttpError

from prowler.providers.gcp.services.appengine.appengine_service import AppEngine
from tests.providers.gcp.gcp_fixtures import (
    GCP_PROJECT_ID,
    GCP_US_CENTER1_LOCATION,
    mock_is_api_active,
    set_mocked_gcp_provider,
)


def _make_appengine_client(versions, app_error=None):
    client = MagicMock()
    apps = client.apps()
    if app_error:
        apps.get().execute.side_effect = app_error
    else:
        apps.get().execute.return_value = {
            "id": GCP_PROJECT_ID,
            "locationId": GCP_US_CENTER1_LOCATION,
        }
    apps.services().list().execute.return_value = {"services": [{"id": "default"}]}
    apps.services().list_next.return_value = None
    apps.services().versions().list().execute.return_value = {"versions": versions}
    apps.services().versions().list_next.return_value = None
    return client


def _patched_service(client):
    return (
        patch(
            "prowler.providers.gcp.lib.service.service.GCPService.__is_api_active__",
            new=mock_is_api_active,
        ),
        patch(
            "prowler.providers.gcp.lib.service.service.GCPService.__generate_client__",
            new=lambda *_, **__: client,
        ),
    )


class TestAppEngineService:
    def test_get_versions(self):
        client = _make_appengine_client(
            [
                {
                    "name": f"apps/{GCP_PROJECT_ID}/services/default/versions/v1",
                    "id": "v1",
                    "runtime": "php82",
                    "env": "standard",
                    "servingStatus": "SERVING",
                },
                {
                    "id": "v2",
                    "runtime": "php",
                    "env": "flexible",
                    "servingStatus": "STOPPED",
                },
            ]
        )
        api_active, generate_client = _patched_service(client)
        with api_active, generate_client:
            appengine = AppEngine(set_mocked_gcp_provider(project_ids=[GCP_PROJECT_ID]))

        assert len(appengine.versions) == 2
        first = appengine.versions[0]
        assert first.id == f"apps/{GCP_PROJECT_ID}/services/default/versions/v1"
        assert first.name == "default/v1"
        assert first.version_id == "v1"
        assert first.service == "default"
        assert first.project_id == GCP_PROJECT_ID
        assert first.location == GCP_US_CENTER1_LOCATION
        assert first.runtime == "php82"
        assert first.env == "standard"
        assert first.serving_status == "SERVING"
        second = appengine.versions[1]
        assert second.id == f"apps/{GCP_PROJECT_ID}/services/default/versions/v2"
        assert second.env == "flexible"
        assert second.serving_status == "STOPPED"

    def test_project_without_application(self):
        response = MagicMock(status=404)
        client = _make_appengine_client([], app_error=HttpError(response, b"not found"))
        api_active, generate_client = _patched_service(client)
        with api_active, generate_client:
            appengine = AppEngine(set_mocked_gcp_provider(project_ids=[GCP_PROJECT_ID]))

        assert appengine.versions == []
