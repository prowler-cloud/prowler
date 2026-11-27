from unittest import mock

import requests

from prowler.providers.supabase.services.database import database_service
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


def _provider_with_lints(lints):
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
        f"/v1/projects/{PROJECT_REF}/advisors/security": _response(
            payload={"lints": lints}
        ),
    }
    provider.session.http_session.get.side_effect = lambda url, timeout=30: routes[
        url.replace("https://api.supabase.com", "")
    ]
    return provider


class TestDatabaseService:
    def test_collects_security_advisor_lints(self):
        provider = _provider_with_lints(
            [
                {
                    "name": "rls_disabled_in_public",
                    "title": "RLS Disabled in Public",
                    "level": "ERROR",
                    "metadata": {"schema": "public", "name": "orders", "type": "table"},
                    "detail": "Table public.orders is public, but RLS has not been enabled.",
                    "remediation": "https://supabase.com/docs/guides/database/database-linter?lint=0013_rls_disabled_in_public",
                },
                {
                    "name": "vulnerable_postgres_version",
                    "title": "Vulnerable Postgres version",
                    "level": "WARN",
                    "metadata": {"type": "compliance"},
                },
            ]
        )

        service = database_service.Database(provider)

        database = service.databases[PROJECT_REF]
        assert database.advisor_available is True
        assert [lint.name for lint in database.lints] == [
            "rls_disabled_in_public",
            "vulnerable_postgres_version",
        ]
        rls = database.lints_named("rls_disabled_in_public")[0]
        assert rls.qualified_name == "public.orders"
        assert rls.object_type == "table"
        assert (
            database.lints_named("vulnerable_postgres_version")[0].qualified_name == ""
        )

    def test_advisor_unavailable_marks_database(self):
        provider = _provider_with_lints(
            [{"name": "project_not_active", "title": "Project not active"}]
        )

        service = database_service.Database(provider)

        database = service.databases[PROJECT_REF]
        assert database.advisor_available is False
        assert database.lints == []
