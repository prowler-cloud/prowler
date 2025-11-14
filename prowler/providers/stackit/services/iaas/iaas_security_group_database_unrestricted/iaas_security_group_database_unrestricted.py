from prowler.lib.check.models import Check, CheckReportStackIT
from prowler.providers.stackit.services.iaas.iaas_client import iaas_client

# Database ports to check
DATABASE_PORTS = {
    3306: "MySQL",
    5432: "PostgreSQL",
    27017: "MongoDB",
    6379: "Redis",
    1433: "SQL Server",
    5984: "CouchDB",
}


class iaas_security_group_database_unrestricted(Check):
    """
    Check if IaaS security groups allow unrestricted database access.

    This check verifies that security groups do not allow database ports
    (MySQL, PostgreSQL, MongoDB, Redis, SQL Server, CouchDB) access
    from the public internet (0.0.0.0/0 or ::/0).
    """

    def execute(self):
        """
        Execute the check for all security groups in the StackIT project.

        Returns:
            list: A list of CheckReportStackIT findings
        """
        findings = []

        for security_group in iaas_client.security_groups:
            # Only check security groups that are actively in use
            if not security_group.in_use:
                continue
            exposed_databases = []

            # Check each ingress rule
            for rule in security_group.rules:
                # Only check ingress TCP rules that are unrestricted
                if rule.is_ingress() and rule.is_tcp() and rule.is_unrestricted():
                    # Check if rule allows any database ports
                    for port, db_name in DATABASE_PORTS.items():
                        if rule.includes_port(port):
                            exposed_databases.append(f"{db_name} (port {port})")

            # Create a finding report for this security group
            report = CheckReportStackIT(
                metadata=self.metadata(),
                resource=security_group,
            )

            if exposed_databases:
                report.status = "FAIL"
                databases_list = ", ".join(exposed_databases)
                report.status_extended = (
                    f"Security group '{security_group.name}' allows unrestricted database access "
                    f"to: {databases_list} from the internet."
                )
            else:
                report.status = "PASS"
                report.status_extended = f"Security group '{security_group.name}' does not allow unrestricted database access."

            report.resource_id = security_group.id
            report.resource_name = security_group.name
            report.location = security_group.region

            findings.append(report)

        return findings
