from types import SimpleNamespace
from unittest import mock

from prowler.providers.cloudflare.services.workers.workers_service import (
    CloudflareWorkerScript,
    Workers,
)
from tests.providers.cloudflare.cloudflare_fixtures import (
    ACCOUNT_ID,
    set_mocked_cloudflare_provider,
)

SCRIPT_NAME = "my-worker"


def _build_provider(settings=None, subdomain=None, settings_error=None):
    provider = set_mocked_cloudflare_provider()
    client = provider.session.client
    client.workers.scripts.list.return_value = [
        SimpleNamespace(
            id=SCRIPT_NAME,
            created_on=None,
            modified_on=None,
            logpush=False,
            placement=SimpleNamespace(mode="smart"),
        ),
        # Duplicate entries must be ignored
        SimpleNamespace(id=SCRIPT_NAME),
    ]
    if settings_error:
        client.workers.scripts.script_and_version_settings.get.side_effect = (
            settings_error
        )
    else:
        client.workers.scripts.script_and_version_settings.get.return_value = settings
    if isinstance(subdomain, Exception):
        client.workers.scripts.subdomain.get.side_effect = subdomain
    else:
        client.workers.scripts.subdomain.get.return_value = subdomain
    return provider


class TestWorkersService:
    def test_service_lists_scripts_with_details(self):
        settings = SimpleNamespace(
            compatibility_date="2025-01-01",
            logpush=True,
            observability=SimpleNamespace(
                enabled=True, logs=SimpleNamespace(enabled=False)
            ),
            bindings=[
                SimpleNamespace(type="plain_text", name="API_URL", text="https://x"),
                SimpleNamespace(type="secret_text", name="TOKEN"),
                SimpleNamespace(type="kv_namespace", name="KV", namespace_id="ns"),
            ],
        )
        subdomain = SimpleNamespace(enabled=True, previews_enabled=False)
        provider = _build_provider(settings=settings, subdomain=subdomain)

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=provider,
        ):
            workers = Workers(provider)

        assert workers.service == "workers"
        assert len(workers.scripts) == 1
        script = workers.scripts[0]
        assert script.id == SCRIPT_NAME
        assert script.name == SCRIPT_NAME
        assert script.account_id == ACCOUNT_ID
        assert script.placement_mode == "smart"
        assert script.logpush is True
        assert script.compatibility_date == "2025-01-01"
        assert script.observability_enabled is True
        assert script.observability_logs_enabled is False
        assert script.plain_text_bindings == {"API_URL": "https://x"}
        assert script.workers_dev_enabled is True
        assert script.previews_enabled is False
        provider.session.client.workers.scripts.list.assert_called_once_with(
            account_id=ACCOUNT_ID
        )

    def test_logs_follow_observability_when_not_configured(self):
        settings = SimpleNamespace(
            observability=SimpleNamespace(enabled=True, logs=None), bindings=None
        )
        provider = _build_provider(
            settings=settings,
            subdomain=SimpleNamespace(enabled=False, previews_enabled=False),
        )
        workers = Workers(provider)

        script = workers.scripts[0]
        assert script.observability_enabled is True
        assert script.observability_logs_enabled is True
        assert script.plain_text_bindings == {}

    def test_errors_leave_details_unknown(self):
        provider = _build_provider(
            settings_error=Exception("settings boom"),
            subdomain=Exception("no workers.dev subdomain"),
        )
        workers = Workers(provider)

        script = workers.scripts[0]
        assert script.observability_enabled is None
        assert script.workers_dev_enabled is None
        assert script.previews_enabled is None

    def test_list_error_returns_no_scripts(self):
        provider = set_mocked_cloudflare_provider()
        provider.session.client.workers.scripts.list.side_effect = Exception("boom")
        workers = Workers(provider)
        assert workers.scripts == []

    def test_model_defaults(self):
        script = CloudflareWorkerScript(
            id=SCRIPT_NAME, name=SCRIPT_NAME, account_id=ACCOUNT_ID
        )
        assert script.observability_enabled is None
        assert script.workers_dev_enabled is None
        assert script.previews_enabled is None
        assert script.plain_text_bindings == {}
