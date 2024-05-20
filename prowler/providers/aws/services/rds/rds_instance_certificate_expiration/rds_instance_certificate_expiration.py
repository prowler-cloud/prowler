from datetime import UTC, datetime

from dateutil import parser, relativedelta

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.rds.rds_client import rds_client


class rds_instance_certificate_expiration(Check):
    # RDS Certificates with an expiration greater than 3 months the check will PASS with a severity of informational if greater than 6 months and a severity of low if between 3 and 6 months.
    # RDS Certificates that expires in less than 3 months the check will FAIL with a severity of medium.
    # RDS Certificates that expires in less than a month the check will FAIL with a severity of high.
    # RDS Certificates that are expired the check will FAIL with a severity of critical.
    def execute(self):
        findings = []
        for db_instance in rds_client.db_instances:
            report = Check_Report_AWS(self.metadata())
            report.region = db_instance.region
            report.resource_id = db_instance.id
            report.resource_arn = db_instance.arn
            report.resource_tags = db_instance.tags
            report.status = "FAIL"
            report.check_metadata.Severity = "critical"
            report.status_extended = (
                f"RDS Instance {db_instance.id} certificate has expired."
            )

            # Check only RDS DB instances that support parameter group encryption
            for cert in db_instance.cert:
                if cert["CustomerOverride"] == 0:
                    valid_till = parser.parse(cert["ValidTill"])
                    if valid_till > datetime.now(UTC) + relativedelta.relativedelta(
                        months=6
                    ):
                        report.status = "PASS"
                        report.check_metadata.Severity = "informational"
                        report.status_extended = f"RDS Instance {db_instance.id} certificate has over 6 months of validity left."
                    elif valid_till < datetime.now(UTC) + relativedelta.relativedelta(
                        months=6
                    ) and valid_till > datetime.now(UTC) + relativedelta.relativedelta(
                        months=3
                    ):
                        report.status = "PASS"
                        report.check_metadata.Severity = "low"
                        report.status_extended = f"RDS Instance {db_instance.id} certificate has between 3 and 6 months of validity."
                    elif valid_till < datetime.now(UTC) + relativedelta.relativedelta(
                        months=3
                    ) and valid_till > datetime.now(UTC) + relativedelta.relativedelta(
                        months=1
                    ):
                        report.status = "FAIL"
                        report.check_metadata.Severity = "medium"
                        report.status_extended = f"RDS Instance {db_instance.id} certificate less than 3 months of validity."
                    elif valid_till < datetime.now(UTC) + relativedelta.relativedelta(
                        months=1
                    ) and valid_till > datetime.now(UTC):
                        report.status = "FAIL"
                        report.check_metadata.Severity = "high"
                        report.status_extended = f"RDS Instance {db_instance.id} certificate less than 1 month of validity."
                    else:
                        report.status = "FAIL"
                        report.check_metadata.Severity = "critical"
                        report.status_extended = (
                            f"RDS Instance {db_instance.id} certificate has expired."
                        )
                else:
                    customer_override_valid_till = parser.parse(
                        cert["CustomerOverrideValidTill"]
                    )
                    if customer_override_valid_till > datetime.now(
                        UTC
                    ) + relativedelta.relativedelta(months=6):
                        report.status = "PASS"
                        report.check_metadata.Severity = "informational"
                        report.status_extended = f"RDS Instance {db_instance.id} custom certificate has over 6 months of validity left."
                    elif customer_override_valid_till < datetime.now(
                        UTC
                    ) + relativedelta.relativedelta(
                        months=6
                    ) and customer_override_valid_till > datetime.now(
                        UTC
                    ) + relativedelta.relativedelta(
                        months=3
                    ):
                        report.status = "PASS"
                        report.check_metadata.Severity = "low"
                        report.status_extended = f"RDS Instance {db_instance.id} custom certificate has between 3 and 6 months of validity."
                    elif customer_override_valid_till < datetime.now(
                        UTC
                    ) + relativedelta.relativedelta(
                        months=3
                    ) and customer_override_valid_till > datetime.now(
                        UTC
                    ) + relativedelta.relativedelta(
                        months=1
                    ):
                        report.status = "FAIL"
                        report.check_metadata.Severity = "medium"
                        report.status_extended = f"RDS Instance {db_instance.id} custom certificate less than 3 months of validity."
                    elif customer_override_valid_till < datetime.now(
                        UTC
                    ) + relativedelta.relativedelta(
                        months=1
                    ) and customer_override_valid_till > datetime.now(
                        UTC
                    ):
                        report.status = "FAIL"
                        report.check_metadata.Severity = "high"
                        report.status_extended = f"RDS Instance {db_instance.id} custom certificate less than 1 month of validity."
                    else:
                        report.status = "FAIL"
                        report.check_metadata.Severity = "critical"
                        report.status_extended = f"RDS Instance {db_instance.id} custom certificate has expired."
            findings.append(report)

        return findings
