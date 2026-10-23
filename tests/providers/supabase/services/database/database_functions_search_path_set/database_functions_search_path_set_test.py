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

CHECK_PATH = "prowler.providers.supabase.services.database.database_functions_search_path_set.database_functions_search_path_set"


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
        from prowler.providers.supabase.services.database.database_functions_search_path_set.database_functions_search_path_set import (
            database_functions_search_path_set,
        )

        return database_functions_search_path_set().execute()


class Test_database_functions_search_path_set:
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
            == f"Project {PROJECT_NAME} has no function with a mutable search_path."
        )
        assert result[0].resource_id == PROJECT_REF
        assert result[0].resource_name == PROJECT_NAME
        assert result[0].region == PROJECT_REGION

    def test_flagged_function_fails(self):
        database_client = mock.MagicMock
        database_client.databases = {
            PROJECT_REF: _database(
                lints=[
                    SupabaseDatabaseLint(
                        name="function_search_path_mutable",
                        title="Lint title",
                        level="ERROR",
                        schema_name="public",
                        object_name="handle_new_user",
                        object_type="function",
                    )
                ]
            )
        }

        result = _run(database_client)
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == f"Function public.handle_new_user in project {PROJECT_NAME} has a mutable search_path and can be hijacked through schema shadowing."
        )
        assert result[0].resource_id == f"{PROJECT_REF}:public.handle_new_user"
        assert result[0].resource_name == "public.handle_new_user"
        assert result[0].organization_slug == ORGANIZATION_SLUG

    def test_unavailable_advisor_is_skipped(self):
        database_client = mock.MagicMock
        database_client.databases = {PROJECT_REF: _database(advisor_available=False)}

        assert len(_run(database_client)) == 0
