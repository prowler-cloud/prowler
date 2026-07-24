from typing import Optional

from prowler.lib.logger import logger
from prowler.providers.oracledb.lib.service.service import OracledbService
from prowler.providers.oracledb.oracledb_provider import OracledbProvider


class Audit(OracledbService):
    """Oracle Database auditing service.

    Reads the auditing initialization parameters, the Unified Auditing
    option and the enabled unified audit policies, mirroring the auditing
    findings of the Oracle Database Security Assessment Tool (DBSAT).
    """

    def __init__(self, provider: OracledbProvider):
        super().__init__(__class__.__name__, provider)
        self.audit_trail: Optional[str] = None
        self.audit_sys_operations: Optional[str] = None
        self._get_audit_parameters()
        self.unified_auditing = self._get_unified_auditing()
        self.enabled_unified_policies = self._list_enabled_unified_policies()

    def _get_audit_parameters(self):
        """Read the AUDIT_TRAIL and AUDIT_SYS_OPERATIONS parameters."""
        logger.info("Audit - Reading auditing initialization parameters...")
        try:
            rows = self._execute_query(
                "SELECT name, value FROM v$parameter "
                "WHERE name IN ('audit_trail', 'audit_sys_operations')"
            )
            for name, value in rows:
                if name == "audit_trail":
                    self.audit_trail = value
                elif name == "audit_sys_operations":
                    self.audit_sys_operations = value
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _get_unified_auditing(self) -> bool:
        """Return True when the database runs with pure Unified Auditing."""
        logger.info("Audit - Reading the Unified Auditing option...")
        try:
            rows = self._execute_query(
                "SELECT value FROM v$option WHERE parameter = 'Unified Auditing'"
            )
            if rows:
                return rows[0][0] == "TRUE"
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        return False

    def _list_enabled_unified_policies(self) -> list[str]:
        """List the enabled unified audit policies."""
        logger.info("Audit - Listing enabled unified audit policies...")
        policies = []
        try:
            rows = self._execute_query(
                "SELECT DISTINCT policy_name FROM audit_unified_enabled_policies"
            )
            policies = sorted(row[0] for row in rows)
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        return policies
