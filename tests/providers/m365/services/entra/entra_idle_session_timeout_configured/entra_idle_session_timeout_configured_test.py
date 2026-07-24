from unittest import mock

from prowler.providers.m365.services.entra.entra_service import (
    ActivityBasedTimeoutPolicy,
)
from tests.providers.m365.m365_fixtures import set_mocked_m365_provider

CHECK_MODULE_PATH = "prowler.providers.m365.services.entra.entra_idle_session_timeout_configured.entra_idle_session_timeout_configured"


class Test_entra_idle_session_timeout_configured:
    def _run(self, policies):
        entra_client = mock.MagicMock
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_m365_provider(),
            ),
            mock.patch(f"{CHECK_MODULE_PATH}.entra_client", new=entra_client),
        ):
            from prowler.providers.m365.services.entra.entra_idle_session_timeout_configured.entra_idle_session_timeout_configured import (
                entra_idle_session_timeout_configured,
            )

            entra_client.activity_based_timeout_policies = policies
            return entra_idle_session_timeout_configured().execute()

    def test_no_policies(self):
        result = self._run([])
        assert len(result) == 1
        assert result[0].status == "FAIL"

    def test_within_limit(self):
        result = self._run(
            [
                ActivityBasedTimeoutPolicy(
                    id="p1",
                    display_name="Timeout",
                    web_session_idle_timeout_seconds=3 * 60 * 60,
                )
            ]
        )
        assert len(result) == 1
        assert result[0].status == "PASS"

    def test_exceeds_limit(self):
        result = self._run(
            [
                ActivityBasedTimeoutPolicy(
                    id="p1",
                    web_session_idle_timeout_seconds=5 * 60 * 60,
                )
            ]
        )
        assert len(result) == 1
        assert result[0].status == "FAIL"
