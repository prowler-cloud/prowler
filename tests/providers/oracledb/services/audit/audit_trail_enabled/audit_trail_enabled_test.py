from unittest import mock
from unittest.mock import MagicMock

from tests.providers.oracledb.oracledb_fixtures import (
    ORACLEDB_DATABASE_NAME,
    set_mocked_oracledb_provider,
)

CHECK_CLIENT = (
    "prowler.providers.oracledb.services.audit."
    "audit_trail_enabled."
    "audit_trail_enabled.audit_client"
)


def _run_check(client):
    with (
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_oracledb_provider(),
        ),
        mock.patch(CHECK_CLIENT, new=client),
    ):
        from prowler.providers.oracledb.services.audit.audit_trail_enabled.audit_trail_enabled import (
            audit_trail_enabled,
        )

        return audit_trail_enabled().execute()


def _build_client(
    audit_trail=None,
    audit_sys_operations=None,
    unified_auditing=False,
    enabled_unified_policies=None,
):
    client = MagicMock()
    client.database_name = ORACLEDB_DATABASE_NAME
    client.audit_trail = audit_trail
    client.audit_sys_operations = audit_sys_operations
    client.unified_auditing = unified_auditing
    client.enabled_unified_policies = enabled_unified_policies or []
    return client


class Test_audit_trail_enabled:
    def test_pass_with_unified_auditing(self):
        findings = _run_check(_build_client(unified_auditing=True))
        assert len(findings) == 1
        assert findings[0].status == "PASS"
        assert "Unified Auditing" in findings[0].status_extended

    def test_pass_with_traditional_auditing(self):
        findings = _run_check(_build_client(audit_trail="DB"))
        assert len(findings) == 1
        assert findings[0].status == "PASS"
        assert "AUDIT_TRAIL=DB" in findings[0].status_extended

    def test_fail_when_auditing_disabled(self):
        findings = _run_check(_build_client(audit_trail="NONE"))
        assert len(findings) == 1
        assert findings[0].status == "FAIL"
        assert "auditing disabled" in findings[0].status_extended

    def test_fail_when_audit_trail_unknown(self):
        findings = _run_check(_build_client())
        assert len(findings) == 1
        assert findings[0].status == "FAIL"
