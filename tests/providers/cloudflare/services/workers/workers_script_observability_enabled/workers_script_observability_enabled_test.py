from unittest import mock

from prowler.providers.cloudflare.services.workers.workers_service import (
    CloudflareWorkerScript,
)
from tests.providers.cloudflare.cloudflare_fixtures import (
    ACCOUNT_ID,
    set_mocked_cloudflare_provider,
)

SCRIPT_NAME = "my-worker"
CHECK_PATH = "prowler.providers.cloudflare.services.workers.workers_script_observability_enabled.workers_script_observability_enabled"


def _run(scripts):
    workers_client = mock.MagicMock()
    workers_client.scripts = scripts
    with (
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_cloudflare_provider(),
        ),
        mock.patch(f"{CHECK_PATH}.workers_client", new=workers_client),
    ):
        from prowler.providers.cloudflare.services.workers.workers_script_observability_enabled.workers_script_observability_enabled import (
            workers_script_observability_enabled,
        )

        return workers_script_observability_enabled().execute()


def _script(**kwargs):
    return CloudflareWorkerScript(
        id=SCRIPT_NAME, name=SCRIPT_NAME, account_id=ACCOUNT_ID, **kwargs
    )


class Test_workers_script_observability_enabled:
    def test_no_scripts(self):
        assert _run([]) == []

    def test_unknown_status_skipped(self):
        assert _run([_script()]) == []

    def test_pass(self):
        result = _run(
            [_script(observability_enabled=True, observability_logs_enabled=True)]
        )
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert result[0].status_extended == "Worker my-worker has Workers Logs enabled."
        assert result[0].resource_id == SCRIPT_NAME
        assert result[0].resource_name == SCRIPT_NAME
        assert result[0].account_id == ACCOUNT_ID
        assert result[0].region == "global"

    def test_fail(self):
        result = _run(
            [_script(observability_enabled=True, observability_logs_enabled=False)]
        )
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == "Worker my-worker does not have Workers Logs enabled."
        )
