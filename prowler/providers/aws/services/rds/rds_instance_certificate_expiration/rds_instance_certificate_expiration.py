from datetime import datetime

from dateutil import parser, relativedelta

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.rds.rds_client import rds_client


class rds_instance_certificate_expiration(Check):
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
                    if valid_till > datetime.utcnow() + relativedelta.relativedelta(
                        months=6
                    ):
                        report.status = "PASS"
                        report.check_metadata.Severity = "informational"
                        report.status_extended = f"RDS Instance {db_instance.id} certificate has over 6 months of validity left."
                    elif valid_till < datetime.utcnow() + relativedelta.relativedelta(
                        months=6
                    ) and valid_till > datetime.utcnow() + relativedelta.relativedelta(
                        months=3
                    ):
                        report.status = "PASS"
                        report.check_metadata.Severity = "informational"
                        report.status_extended = f"RDS Instance {db_instance.id} certificate has between 3 and 6 months of validity."
                    elif (
                        valid_till
                        < datetime.utcnow() + relativedelta.relativedelta(months=3)
                        and valid_till > datetime.utcnow()
                    ):
                        report.status = "FAIL"
                        report.check_metadata.Severity = "medium"
                        report.status_extended = f"RDS Instance {db_instance.id} certificate less then 3 months of validity."
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
                    if (
                        customer_override_valid_till
                        > datetime.utcnow() + relativedelta.relativedelta(months=6)
                    ):
                        report.status = "PASS"
                        report.check_metadata.Severity = "informational"
                        report.status_extended = f"RDS Instance {db_instance.id} custom certificate has over 6 months of validity left."
                    elif (
                        customer_override_valid_till
                        < datetime.utcnow() + relativedelta.relativedelta(months=6)
                        and customer_override_valid_till
                        > datetime.utcnow() + relativedelta.relativedelta(months=3)
                    ):
                        report.status = "PASS"
                        report.check_metadata.Severity = "informational"
                        report.status_extended = f"RDS Instance {db_instance.id} custom certificate has between 3 and 6 months of validity."
                    elif (
                        customer_override_valid_till
                        < datetime.utcnow() + relativedelta.relativedelta(months=3)
                        and customer_override_valid_till > datetime.utcnow()
                    ):
                        report.status = "FAIL"
                        report.check_metadata.Severity = "medium"
                        report.status_extended = f"RDS Instance {db_instance.id} custom certificate less then 3 months of validity."
                    else:
                        report.status = "FAIL"
                        report.check_metadata.Severity = "critical"
                        report.status_extended = f"RDS Instance {db_instance.id} custom certificate has expired."
            findings.append(report)

        return findings
