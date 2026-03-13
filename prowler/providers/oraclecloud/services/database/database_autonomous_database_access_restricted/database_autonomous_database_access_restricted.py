from prowler.lib.check.models import Check, Check_Report_OCI
from prowler.providers.oraclecloud.services.database.database_client import (
    database_client,
)


class database_autonomous_database_access_restricted(Check):
    """Ensure Oracle Autonomous Shared Database (ADB) access is restricted or deployed within a VCN (CIS 2.8)"""

    def execute(self):
        findings = []

        for adb in database_client.autonomous_databases:
            report = Check_Report_OCI(
                metadata=self.metadata(),
                resource=adb,
                region=adb.region,
                compartment_id=adb.compartment_id,
                resource_id=adb.id,
                resource_name=adb.display_name,
            )

            # Check if database has no whitelisted IPs and no subnet (unrestricted public access)
            if not adb.whitelisted_ips and not adb.subnet_id:
                report.status = "FAIL"
                report.status_extended = f"Autonomous Database {adb.display_name} has unrestricted public access with no whitelisted IPs and is not deployed in a VCN."
            # Check if database has whitelisted IPs containing 0.0.0.0/0
            elif adb.whitelisted_ips and "0.0.0.0/0" in adb.whitelisted_ips:
                report.status = "FAIL"
                report.status_extended = f"Autonomous Database {adb.display_name} has unrestricted public access with IP range 0.0.0.0/0 in whitelisted IPs."
            else:
                report.status = "PASS"
                if adb.subnet_id:
                    report.status_extended = f"Autonomous Database {adb.display_name} is deployed within a VCN."
                else:
                    report.status_extended = f"Autonomous Database {adb.display_name} has restricted public access with whitelisted IPs."

            findings.append(report)

        return findings
