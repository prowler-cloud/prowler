from unittest import mock

from prowler.providers.lovable.services.published.published_service import (
    PublishedAppInspection,
)
from tests.providers.lovable.lovable_fixtures import set_mocked_lovable_provider


def _inspection(**overrides) -> PublishedAppInspection:
    base = dict(
        app_id="app_1",
        app_name="App 1",
        workspace_id="ws_1",
        published_url="https://app.lovable.app",
        reachable=True,
        is_https=True,
        status_code=200,
        headers={"content-type": "text/html"},
        bundles_inspected=["https://app.lovable.app/assets/main.js"],
        leaked_secrets=[],
        id="app_1",
        name="App 1",
    )
    base.update(overrides)
    return PublishedAppInspection(**base)


class Test_published_app_no_secrets_in_frontend_bundle:
    def _run(self, inspections):
        published_client = mock.MagicMock
        published_client.inspections = inspections

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_lovable_provider(),
            ),
            mock.patch(
                "prowler.providers.lovable.services.published.published_app_no_secrets_in_frontend_bundle.published_app_no_secrets_in_frontend_bundle.published_client",
                new=published_client,
            ),
        ):
            from prowler.providers.lovable.services.published.published_app_no_secrets_in_frontend_bundle.published_app_no_secrets_in_frontend_bundle import (
                published_app_no_secrets_in_frontend_bundle,
            )

            check = published_app_no_secrets_in_frontend_bundle()
            return check.execute()

    def test_pass_when_no_secrets_detected(self):
        inspection = _inspection(leaked_secrets=[])
        findings = self._run({inspection.app_id: inspection})

        assert len(findings) == 1
        assert findings[0].status == "PASS"

    def test_fail_when_supabase_jwt_leaked(self):
        inspection = _inspection(
            leaked_secrets=[
                {
                    "type": "supabase_jwt",
                    "bundle": "https://app.lovable.app/assets/main.js",
                    "match_preview": "eyJh...abcd",
                }
            ]
        )
        findings = self._run({inspection.app_id: inspection})

        assert findings[0].status == "FAIL"
        assert "1 supabase_jwt" in findings[0].status_extended

    def test_manual_when_app_unreachable(self):
        inspection = _inspection(reachable=False)
        findings = self._run({inspection.app_id: inspection})

        assert findings[0].status == "MANUAL"
