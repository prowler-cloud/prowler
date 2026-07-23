from prowler.lib.check.models import Check, CheckReportOracledb
from prowler.providers.oracledb.services.encryption.encryption_client import (
    encryption_client,
)


class encryption_tablespaces_encrypted(Check):
    """Check that permanent tablespaces are encrypted with TDE."""

    def execute(self) -> list[CheckReportOracledb]:
        """Execute the check logic.

        Returns:
            A list of reports, one per permanent application tablespace.
        """
        findings = []
        for tablespace in encryption_client.tablespaces:
            if not tablespace.is_user_permanent:
                continue
            report = CheckReportOracledb(
                metadata=self.metadata(),
                resource=tablespace,
                resource_name=tablespace.name,
                resource_id=tablespace.name,
            )
            if tablespace.encrypted:
                report.status = "PASS"
                report.status_extended = (
                    f"Tablespace {tablespace.name} is encrypted with TDE."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Tablespace {tablespace.name} is not encrypted with TDE."
                )
            findings.append(report)
        return findings
