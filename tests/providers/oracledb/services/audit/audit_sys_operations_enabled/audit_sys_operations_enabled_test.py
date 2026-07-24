from unittest import mock
from unittest.mock import MagicMock

from tests.providers.oracledb.oracledb_fixtures import (
    ORACLEDB_DATABASE_NAME,
    set_mocked_oracledb_provider,
)

CHECK_CLIENT = (
    "prowler.providers.oracledb.services.audit."
    "audit_sys_operations_enabled."
    "audit_sys_operations_enabled.audit_client"
)


def _run_check(client):
    with (
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_oracledb_provider(),
        ),
        mock.patch(CHECK_CLIENT, new=client),
    ):
        from prowler.providers.oracledb.services.audit.audit_sys_operations_enabled.audit_sys_operations_enabled import (
            audit_sys_operations_enabled,
        )

        return audit_sys_operations_enabled().execute()


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


class Test_audit_sys_operations_enabled:
    def test_pass_when_enabled(self):
        findings = _run_check(_build_client(audit_sys_operations="TRUE"))
        assert len(findings) == 1
        assert findings[0].status == "PASS"
        assert "AUDIT_SYS_OPERATIONS=TRUE" in findings[0].status_extended

    def test_fail_when_disabled(self):
        findings = _run_check(_build_client(audit_sys_operations="FALSE"))
        assert len(findings) == 1
        assert findings[0].status == "FAIL"
        assert "AUDIT_SYS_OPERATIONS=FALSE" in findings[0].status_extended

    def test_fail_when_unknown(self):
        findings = _run_check(_build_client())
        assert len(findings) == 1
        assert findings[0].status == "FAIL"
