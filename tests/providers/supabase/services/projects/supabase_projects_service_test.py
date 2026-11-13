from unittest import mock

import pytest
import requests

from prowler.providers.supabase.exceptions.exceptions import (
    SupabaseAuthenticationError,
    SupabaseInsufficientPermissionsError,
    SupabaseRateLimitError,
)
from prowler.providers.supabase.services.projects import projects_service
from tests.providers.supabase.supabase_fixtures import (
    ORGANIZATION_NAME,
    ORGANIZATION_SLUG,
    PROJECT_NAME,
    PROJECT_REF,
    PROJECT_REGION,
    set_mocked_supabase_provider,
)

PROJECT_LIST = [
    {
        "ref": PROJECT_REF,
        "name": PROJECT_NAME,
        "organization_slug": ORGANIZATION_SLUG,
        "region": PROJECT_REGION,
        "status": "ACTIVE_HEALTHY",
    },
    {
        "ref": "zzzzzzzzzzzzzzzzzzzz",
        "name": "sandbox",
        "organization_slug": ORGANIZATION_SLUG,
        "region": "us-east-1",
        "status": "INACTIVE",
    },
]


def _response(status_code=200, payload=None):
    response = mock.MagicMock(status_code=status_code, headers={})
    response.json.return_value = payload
    if status_code >= 400:
        response.raise_for_status.side_effect = requests.HTTPError(
            f"{status_code} error"
        )
    return response


def _routes(overrides=None):
    """Return a side effect answering each Management API path."""
    routes = {
        "/v1/projects": _response(payload=PROJECT_LIST),
        f"/v1/projects/{PROJECT_REF}/ssl-enforcement": _response(
            payload={"currentConfig": {"database": True}, "appliedSuccessfully": True}
        ),
        f"/v1/projects/{PROJECT_REF}/network-restrictions": _response(
            payload={
                "entitlement": "allowed",
                "config": {
                    "dbAllowedCidrs": ["203.0.113.0/24"],
                    "dbAllowedCidrsV6": [],
                },
                "status": "applied",
            }
        ),
        f"/v1/projects/{PROJECT_REF}/postgrest": _response(
            payload={"db_schema": "public", "max_rows": 1000, "jwt_secret": "x"}
        ),
        f"/v1/projects/{PROJECT_REF}/database/backups": _response(
            payload={"pitr_enabled": False, "walg_enabled": True, "backups": []}
        ),
        f"/v1/projects/{PROJECT_REF}/api-keys/legacy": _response(
            payload={"enabled": True}
        ),
    }
    routes.update(overrides or {})

    def side_effect(url, timeout=30):
        path = url.replace("https://api.supabase.com", "")
        return routes.get(path, _response(status_code=500, payload={}))

    return side_effect


class TestProjectsService:
    def test_collects_project_settings(self):
        provider = set_mocked_supabase_provider()
        provider.session.http_session.get.side_effect = _routes()

        service = projects_service.Projects(provider)

        assert set(service.projects) == {PROJECT_REF, "zzzzzzzzzzzzzzzzzzzz"}
        project = service.projects[PROJECT_REF]
        assert project.name == PROJECT_NAME
        assert project.organization_name == ORGANIZATION_NAME
        assert project.region == PROJECT_REGION
        assert project.ssl_enforced is True
        assert project.network_restrictions_entitled is True
        assert project.allowed_cidrs == ["203.0.113.0/24"]
        assert project.allowed_cidrs_restricted is True
        assert project.postgrest_max_rows == 1000
        assert project.pitr_enabled is False
        assert project.legacy_api_keys_enabled is True
        assert "jwt_secret" not in project.model_dump()

    def test_unavailable_endpoints_leave_settings_unknown(self):
        provider = set_mocked_supabase_provider()
        provider.session.http_session.get.side_effect = _routes(
            {
                f"/v1/projects/{PROJECT_REF}/ssl-enforcement": _response(
                    status_code=500, payload={}
                )
            }
        )

        with mock.patch("prowler.providers.supabase.lib.service.service.time.sleep"):
            service = projects_service.Projects(provider)

        project = service.projects[PROJECT_REF]
        assert project.ssl_enforced is None
        assert project.pitr_enabled is False

    def test_project_filter_by_ref_or_name(self):
        provider = set_mocked_supabase_provider()
        provider.filter_projects = ["sandbox"]
        provider.session.http_session.get.side_effect = _routes()

        service = projects_service.Projects(provider)

        assert list(service.projects) == ["zzzzzzzzzzzzzzzzzzzz"]

    def test_whole_internet_cidr_is_not_restricted(self):
        project = projects_service.SupabaseProject(
            id=PROJECT_REF,
            name=PROJECT_NAME,
            project_ref=PROJECT_REF,
            project_name=PROJECT_NAME,
            organization_slug=ORGANIZATION_SLUG,
            organization_name=ORGANIZATION_NAME,
            allowed_cidrs=["0.0.0.0/0"],
            allowed_cidrs_v6=["::/0"],
        )

        assert project.allowed_cidrs_restricted is False

    @pytest.mark.parametrize(
        ("status_code", "exception"),
        [
            (401, SupabaseAuthenticationError),
            (403, SupabaseInsufficientPermissionsError),
            (429, SupabaseRateLimitError),
        ],
    )
    def test_authorization_errors_propagate(self, status_code, exception):
        provider = set_mocked_supabase_provider()
        provider.session.http_session.get.return_value = mock.MagicMock(
            status_code=status_code, headers={"X-RateLimit-Reset": "0"}
        )

        with pytest.raises(exception):
            projects_service.Projects(provider)
