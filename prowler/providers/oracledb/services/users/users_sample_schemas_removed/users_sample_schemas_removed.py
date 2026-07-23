from prowler.lib.check.models import Check, CheckReportOracledb
from prowler.providers.oracledb.services.users.users_client import users_client
from prowler.providers.oracledb.services.users.users_service import SAMPLE_SCHEMAS


class users_sample_schemas_removed(Check):
    """Check that Oracle sample schemas are not installed in the database."""

    def execute(self) -> list[CheckReportOracledb]:
        """Execute the check logic.

        Returns:
            A single report for the audited database.
        """
        findings = []
        sample_users = sorted(
            user.name for user in users_client.users if user.name in SAMPLE_SCHEMAS
        )
        report = CheckReportOracledb(
            metadata=self.metadata(),
            resource={},
            resource_name=users_client.database_name,
            resource_id=users_client.database_name,
        )
        if sample_users:
            report.status = "FAIL"
            report.status_extended = (
                f"Database {users_client.database_name} has sample schemas "
                f"installed: {', '.join(sample_users)}."
            )
        else:
            report.status = "PASS"
            report.status_extended = (
                f"Database {users_client.database_name} has no sample "
                "schemas installed."
            )
        findings.append(report)
        return findings
