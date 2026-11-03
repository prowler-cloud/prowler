from types import SimpleNamespace
from unittest import mock

from prowler.providers.cloudflare.services.workers.workers_service import (
    CloudflareWorkerScript,
)
from tests.providers.cloudflare.cloudflare_fixtures import (
    ACCOUNT_ID,
    ACCOUNT_NAME,
    set_mocked_cloudflare_provider,
)

SCRIPT_NAME = "my-worker"
CHECK_PATH = "prowler.providers.cloudflare.services.workers.workers_script_workers_dev_disabled.workers_script_workers_dev_disabled"


def _run(scripts, list_failed=(), settings_failed=(), subdomain_failed=()):
    workers_client = mock.MagicMock()
    workers_client.scripts = scripts
    workers_client.list_failed_accounts = set(list_failed)
    workers_client.settings_failed_accounts = set(settings_failed)
    workers_client.subdomain_failed_accounts = set(subdomain_failed)
    workers_client.provider = SimpleNamespace(
        identity=SimpleNamespace(
            accounts=[SimpleNamespace(id=ACCOUNT_ID, name=ACCOUNT_NAME)]
        )
    )
    with (
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_cloudflare_provider(),
        ),
        mock.patch(f"{CHECK_PATH}.workers_client", new=workers_client),
    ):
        from prowler.providers.cloudflare.services.workers.workers_script_workers_dev_disabled.workers_script_workers_dev_disabled import (
            workers_script_workers_dev_disabled,
        )

        return workers_script_workers_dev_disabled().execute()


def _script(**kwargs):
    return CloudflareWorkerScript(
        id=f"{ACCOUNT_ID}/{SCRIPT_NAME}",
        name=SCRIPT_NAME,
        account_id=ACCOUNT_ID,
        **kwargs,
    )


class Test_workers_script_workers_dev_disabled:
    def test_no_scripts(self):
        assert _run([]) == []

    def test_unknown_status_skipped(self):
        assert _run([_script()]) == []

    def test_retrieval_failed_one_account_manual(self):
        result = _run([_script(), _script()], subdomain_failed=[ACCOUNT_ID])
        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert result[0].resource_id == ACCOUNT_ID
        assert result[0].resource_name == ACCOUNT_NAME
        assert result[0].region == "global"
        assert "Workers Scripts Read" in result[0].status_extended

    def test_listing_failed_manual(self):
        result = _run([], list_failed=[ACCOUNT_ID])
        assert [r.status for r in result] == ["MANUAL"]

    def test_pass(self):
        result = _run([_script(workers_dev_enabled=False)])
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert (
            result[0].status_extended
            == "Worker my-worker has the workers.dev route disabled."
        )
        assert result[0].resource_id == f"{ACCOUNT_ID}/{SCRIPT_NAME}"
        assert result[0].resource_name == SCRIPT_NAME
        assert result[0].account_id == ACCOUNT_ID
        assert result[0].region == "global"

    def test_fail(self):
        result = _run([_script(workers_dev_enabled=True)])
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == "Worker my-worker is publicly reachable on its workers.dev subdomain."
        )
