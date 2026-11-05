import json
from types import SimpleNamespace
from unittest import mock

from prowler.lib.utils.utils import SecretsScanError
from prowler.providers.cloudflare.services.workers.workers_service import (
    CloudflareWorkerScript,
)
from tests.providers.cloudflare.cloudflare_fixtures import (
    ACCOUNT_ID,
    ACCOUNT_NAME,
    set_mocked_cloudflare_provider,
)

SCRIPT_NAME = "my-worker"
CHECK_PATH = "prowler.providers.cloudflare.services.workers.workers_script_no_secrets_in_plain_text_bindings.workers_script_no_secrets_in_plain_text_bindings"


SCANNED_PAYLOADS = {}


def _run(scripts, scan_result=None, scan_error=None, settings_failed=()):
    workers_client = mock.MagicMock()
    workers_client.scripts = scripts
    workers_client.audit_config = {"secrets_ignore_patterns": []}
    workers_client.list_failed_accounts = set()
    workers_client.settings_failed_accounts = set(settings_failed)
    workers_client.provider = SimpleNamespace(
        identity=SimpleNamespace(
            accounts=[SimpleNamespace(id=ACCOUNT_ID, name=ACCOUNT_NAME)]
        )
    )
    SCANNED_PAYLOADS.clear()

    def fake_scan(payloads, **_kwargs):
        # consume the generator like the real scanner and record what it sent
        SCANNED_PAYLOADS.update(dict(payloads))
        if scan_error:
            raise scan_error
        return scan_result or {}

    with (
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_cloudflare_provider(),
        ),
        mock.patch(f"{CHECK_PATH}.workers_client", new=workers_client),
        mock.patch(
            f"{CHECK_PATH}.detect_secrets_scan_batch", side_effect=fake_scan
        ) as scan_mock,
    ):
        from prowler.providers.cloudflare.services.workers.workers_script_no_secrets_in_plain_text_bindings.workers_script_no_secrets_in_plain_text_bindings import (
            workers_script_no_secrets_in_plain_text_bindings,
        )

        return workers_script_no_secrets_in_plain_text_bindings().execute(), scan_mock


def _script(bindings):
    return CloudflareWorkerScript(
        id=f"{ACCOUNT_ID}/{SCRIPT_NAME}",
        name=SCRIPT_NAME,
        account_id=ACCOUNT_ID,
        plain_text_bindings=bindings,
    )


class Test_workers_script_no_secrets_in_plain_text_bindings:
    def test_no_scripts(self):
        result, _ = _run([])
        assert result == []

    def test_no_bindings_pass(self):
        result, _ = _run([_script({})])
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert (
            result[0].status_extended
            == f"No secrets found in Worker {SCRIPT_NAME} plain text bindings."
        )
        assert result[0].resource_id == f"{ACCOUNT_ID}/{SCRIPT_NAME}"
        assert result[0].account_id == ACCOUNT_ID

    def test_bindings_without_secrets_pass(self):
        result, _ = _run([_script({"API_URL": "https://api.example.com"})])
        assert len(result) == 1
        assert result[0].status == "PASS"

    def test_secret_in_binding_fail(self):
        bindings = {"API_URL": "https://api.example.com", "DB_PASSWORD": "x"}
        scan_result = {
            0: [
                {
                    "type": "Generic Password",
                    "line_number": 3,
                    "filename": "0",
                    "hashed_secret": "abc",
                    "is_verified": False,
                }
            ]
        }
        result, _ = _run([_script(bindings)], scan_result=scan_result)
        # the scanner receives the bindings as indented JSON, keyed by index
        assert SCANNED_PAYLOADS == {0: json.dumps(bindings, indent=2)}
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == f"Potential secret found in Worker {SCRIPT_NAME} plain text bindings -> Generic Password in binding DB_PASSWORD."
        )

    def test_settings_failed_one_account_manual(self):
        script = CloudflareWorkerScript(
            id=f"{ACCOUNT_ID}/{SCRIPT_NAME}", name=SCRIPT_NAME, account_id=ACCOUNT_ID
        )
        result, _ = _run([script, _script({})], settings_failed=[ACCOUNT_ID])
        assert [r.status for r in result] == ["MANUAL", "PASS"]
        assert result[0].resource_id == ACCOUNT_ID
        assert "Workers Scripts Read" in result[0].status_extended

    def test_unknown_bindings_skipped(self):
        # bindings could not be retrieved: no false "no secrets found" PASS
        script = CloudflareWorkerScript(
            id=SCRIPT_NAME, name=SCRIPT_NAME, account_id=ACCOUNT_ID
        )
        result, scan_mock = _run([script])
        assert result == []

    def test_out_of_range_line_number_does_not_crash(self):
        scan_result = {
            0: [
                {
                    "type": "Generic Secret",
                    "line_number": 1,
                    "filename": "0",
                    "hashed_secret": "abc",
                    "is_verified": False,
                }
            ]
        }
        result, _ = _run([_script({"TOKEN": "x"})], scan_result=scan_result)
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == f"Potential secret found in Worker {SCRIPT_NAME} plain text bindings -> Generic Secret."
        )

    def test_scan_error_manual(self):
        result, _ = _run(
            [_script({"DB_PASSWORD": "x"}), _script({})],
            scan_error=SecretsScanError("scanner missing"),
        )
        assert len(result) == 2
        assert result[0].status == "MANUAL"
        assert "scanner missing" in result[0].status_extended
        assert result[1].status == "PASS"
