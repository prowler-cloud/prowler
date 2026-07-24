from prowler.lib.check.models import Check, CheckReportOracledb
from prowler.providers.oracledb.services.users.users_client import users_client

RESERVED_TABLESPACES = ("SYSTEM", "SYSAUX")


class users_default_tablespace_not_system(Check):
    """Check that application users do not default to SYSTEM or SYSAUX."""

    def execute(self) -> list[CheckReportOracledb]:
        """Execute the check logic.

        Returns:
            A list of reports, one per non-Oracle-maintained user.
        """
        findings = []
        for user in users_client.users:
            if user.oracle_maintained:
                continue
            report = CheckReportOracledb(
                metadata=self.metadata(),
                resource=user,
                resource_name=user.name,
                resource_id=user.name,
            )
            if user.default_tablespace in RESERVED_TABLESPACES:
                report.status = "FAIL"
                report.status_extended = (
                    f"User {user.name} uses reserved tablespace "
                    f"{user.default_tablespace} as its default tablespace."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"User {user.name} uses tablespace "
                    f"{user.default_tablespace} as its default tablespace."
                )
            findings.append(report)
        return findings
