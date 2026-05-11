from unittest import mock

from prowler.providers.lovable.services.apps.apps_service import LovableApp
from tests.providers.lovable.lovable_fixtures import (
    WORKSPACE_ID,
    set_mocked_lovable_provider,
)


def _make_app(**overrides) -> LovableApp:
    base = dict(
        id="app_1",
        name="App 1",
        slug="app-1",
        workspace_id=WORKSPACE_ID,
        visibility="public",
        is_published=True,
        published_url="https://app.lovable.app",
        has_supabase_backing=True,
        rls_enabled_on_all_tables=True,
        tables_without_rls=[],
    )
    base.update(overrides)
    return LovableApp(**base)


class Test_apps_supabase_rls_enabled_on_all_tables:
    def _run(self, apps_dict):
        apps_client = mock.MagicMock
        apps_client.apps = apps_dict

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_lovable_provider(),
            ),
            mock.patch(
                "prowler.providers.lovable.services.apps.apps_supabase_rls_enabled_on_all_tables.apps_supabase_rls_enabled_on_all_tables.apps_client",
                new=apps_client,
            ),
        ):
            from prowler.providers.lovable.services.apps.apps_supabase_rls_enabled_on_all_tables.apps_supabase_rls_enabled_on_all_tables import (
                apps_supabase_rls_enabled_on_all_tables,
            )

            check = apps_supabase_rls_enabled_on_all_tables()
            return check.execute()

    def test_pass_when_all_tables_have_rls(self):
        app = _make_app(rls_enabled_on_all_tables=True, tables_without_rls=[])
        findings = self._run({app.id: app})

        assert len(findings) == 1
        assert findings[0].status == "PASS"
        assert "Row Level Security" in findings[0].status_extended

    def test_fail_when_tables_missing_rls(self):
        app = _make_app(
            rls_enabled_on_all_tables=False,
            tables_without_rls=["public.users", "public.orders"],
        )
        findings = self._run({app.id: app})

        assert findings[0].status == "FAIL"
        assert "public.users" in findings[0].status_extended
        assert "public.orders" in findings[0].status_extended

    def test_manual_when_no_supabase_backing(self):
        app = _make_app(has_supabase_backing=False)
        findings = self._run({app.id: app})

        assert findings[0].status == "MANUAL"

    def test_no_findings_when_no_apps(self):
        findings = self._run({})
        assert findings == []
