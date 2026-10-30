from unittest import mock

import requests

from prowler.providers.supabase.services.storage import storage_service
from tests.providers.supabase.supabase_fixtures import (
    ORGANIZATION_SLUG,
    PROJECT_NAME,
    PROJECT_REF,
    set_mocked_supabase_provider,
)


def _response(status_code=200, payload=None):
    response = mock.MagicMock(status_code=status_code, headers={})
    response.json.return_value = payload
    if status_code >= 400:
        response.raise_for_status.side_effect = requests.HTTPError(
            f"{status_code} error"
        )
    return response


class TestStorageService:
    def test_collects_buckets_with_visibility(self):
        provider = set_mocked_supabase_provider()
        routes = {
            "/v1/projects": _response(
                payload=[
                    {
                        "ref": PROJECT_REF,
                        "name": PROJECT_NAME,
                        "organization_slug": ORGANIZATION_SLUG,
                    }
                ]
            ),
            f"/v1/projects/{PROJECT_REF}/storage/buckets": _response(
                payload=[
                    {"id": "avatars", "name": "avatars", "public": True},
                    {"id": "invoices", "name": "invoices", "public": False},
                ]
            ),
        }
        provider.session.http_session.get.side_effect = lambda url, timeout=30: routes[
            url.replace("https://api.supabase.com", "")
        ]

        service = storage_service.Storage(provider)

        assert set(service.buckets) == {
            f"{PROJECT_REF}:avatars",
            f"{PROJECT_REF}:invoices",
        }
        avatars = service.buckets[f"{PROJECT_REF}:avatars"]
        assert avatars.public is True
        assert avatars.name == "avatars"
        assert avatars.project_name == PROJECT_NAME
        assert service.buckets[f"{PROJECT_REF}:invoices"].public is False
