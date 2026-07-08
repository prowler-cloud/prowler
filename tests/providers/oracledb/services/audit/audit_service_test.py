from prowler.providers.oracledb.models import OracledbSession
from prowler.providers.oracledb.services.audit.audit_service import Audit
from tests.providers.oracledb.oracledb_fixtures import (
    ORACLEDB_DSN,
    ORACLEDB_USER,
    set_mocked_connection,
    set_mocked_oracledb_provider,
)


def _build_audit_service(fetchall_results):
    provider = set_mocked_oracledb_provider(
        session=OracledbSession(
            user=ORACLEDB_USER,
            dsn=ORACLEDB_DSN,
            connection=set_mocked_connection(fetchall_results=fetchall_results),
        )
    )
    return Audit(provider)


class TestAuditService:
    def test_reads_audit_configuration(self):
        service = _build_audit_service(
            [
                [("audit_trail", "DB"), ("audit_sys_operations", "TRUE")],
                [("TRUE",)],
                [("ORA_SECURECONFIG",), ("ORA_LOGON_FAILURES",)],
            ]
        )

        assert service.audit_trail == "DB"
        assert service.audit_sys_operations == "TRUE"
        assert service.unified_auditing is True
        assert service.enabled_unified_policies == [
            "ORA_LOGON_FAILURES",
            "ORA_SECURECONFIG",
        ]

    def test_unified_auditing_disabled(self):
        service = _build_audit_service(
            [
                [("audit_trail", "NONE"), ("audit_sys_operations", "FALSE")],
                [("FALSE",)],
                [],
            ]
        )

        assert service.audit_trail == "NONE"
        assert service.unified_auditing is False
        assert service.enabled_unified_policies == []

    def test_query_error_leaves_defaults(self):
        service = _build_audit_service(
            [Exception("ORA-00942: table or view does not exist")] * 3
        )

        assert service.audit_trail is None
        assert service.audit_sys_operations is None
        assert service.unified_auditing is False
        assert service.enabled_unified_policies == []
