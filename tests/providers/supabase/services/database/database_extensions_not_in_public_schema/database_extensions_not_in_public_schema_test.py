from unittest import mock

from prowler.providers.supabase.services.database.database_service import (
    SupabaseDatabase,
    SupabaseDatabaseLint,
)
from tests.providers.supabase.supabase_fixtures import (
    ORGANIZATION_NAME,
    ORGANIZATION_SLUG,
    PROJECT_NAME,
    PROJECT_REF,
    PROJECT_REGION,
    set_mocked_supabase_provider,
)

CHECK_PATH = "prowler.providers.supabase.services.database.database_extensions_not_in_public_schema.database_extensions_not_in_public_schema"


def _database(lints=(), advisor_available=True):
    return SupabaseDatabase(
        id=PROJECT_REF,
        name=PROJECT_NAME,
        project_ref=PROJECT_REF,
        project_name=PROJECT_NAME,
        organization_slug=ORGANIZATION_SLUG,
        organization_name=ORGANIZATION_NAME,
        region=PROJECT_REGION,
        advisor_available=advisor_available,
        lints=list(lints),
    )


def _run(database_client):
    with (
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_supabase_provider(),
        ),
        mock.patch(f"{CHECK_PATH}.database_client", new=database_client),
    ):
        from prowler.providers.supabase.services.database.database_extensions_not_in_public_schema.database_extensions_not_in_public_schema import (
            database_extensions_not_in_public_schema,
        )

        return database_extensions_not_in_public_schema().execute()


class Test_database_extensions_not_in_public_schema:
    def test_no_databases(self):
        database_client = mock.MagicMock
        database_client.databases = {}

        assert len(_run(database_client)) == 0

    def test_project_without_lint_passes(self):
        database_client = mock.MagicMock
        database_client.databases = {
            PROJECT_REF: _database(
                lints=[SupabaseDatabaseLint(name="unrelated_lint", title="Unrelated")]
            )
        }

        result = _run(database_client)
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert (
            result[0].status_extended
            == f"Project {PROJECT_NAME} has no extension installed in the public schema."
        )
        assert result[0].resource_id == PROJECT_REF
        assert result[0].resource_name == PROJECT_NAME
        assert result[0].region == PROJECT_REGION

    def test_flagged_extension_fails(self):
        database_client = mock.MagicMock
        database_client.databases = {
            PROJECT_REF: _database(
                lints=[
                    SupabaseDatabaseLint(
                        name="extension_in_public",
                        title="Lint title",
                        level="ERROR",
                        schema_name="public",
                        object_name="pg_net",
                        object_type="extension",
                    )
                ]
            )
        }

        result = _run(database_client)
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == f"Extension public.pg_net in project {PROJECT_NAME} is installed in the public schema and its functions are exposed through the Data API."
        )
        assert result[0].resource_id == f"{PROJECT_REF}:public.pg_net"
        assert result[0].resource_name == "public.pg_net"
        assert result[0].organization_slug == ORGANIZATION_SLUG

    def test_unavailable_advisor_is_skipped(self):
        database_client = mock.MagicMock
        database_client.databases = {PROJECT_REF: _database(advisor_available=False)}

        assert len(_run(database_client)) == 0
