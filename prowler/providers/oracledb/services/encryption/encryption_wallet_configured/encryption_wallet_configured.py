from prowler.lib.check.models import Check, CheckReportOracledb
from prowler.providers.oracledb.services.encryption.encryption_client import (
    encryption_client,
)


class encryption_wallet_configured(Check):
    """Check that a TDE keystore is configured and open."""

    def execute(self) -> list[CheckReportOracledb]:
        """Execute the check logic.

        Returns:
            A single report for the audited database.
        """
        findings = []
        report = CheckReportOracledb(
            metadata=self.metadata(),
            resource={},
            resource_name=encryption_client.database_name,
            resource_id=encryption_client.database_name,
        )
        open_wallets = [
            wallet for wallet in encryption_client.wallets if wallet.status == "OPEN"
        ]
        if open_wallets:
            report.status = "PASS"
            report.status_extended = (
                f"Database {encryption_client.database_name} has an open TDE "
                f"keystore ({open_wallets[0].wrl_type}, "
                f"{open_wallets[0].wallet_type})."
            )
        else:
            statuses = (
                ", ".join(
                    sorted({wallet.status for wallet in encryption_client.wallets})
                )
                or "NOT_AVAILABLE"
            )
            report.status = "FAIL"
            report.status_extended = (
                f"Database {encryption_client.database_name} does not have an "
                f"open TDE keystore (status: {statuses})."
            )
        findings.append(report)
        return findings
