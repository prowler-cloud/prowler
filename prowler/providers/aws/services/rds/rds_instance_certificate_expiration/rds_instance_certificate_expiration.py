from datetime import datetime

from dateutil import relativedelta
from pytz import utc

from prowler.lib.check.models import Check, Check_Report_AWS, Severity
from prowler.providers.aws.services.rds.rds_client import rds_client


class rds_instance_certificate_expiration(Check):
    # RDS Certificates with an expiration greater than 3 months the check will PASS with a severity of informational if greater than 6 months and a severity of low if between 3 and 6 months.
    # RDS Certificates that expires in less than 3 months the check will FAIL with a severity of medium.
    # RDS Certificates that expires in less than a month the check will FAIL with a severity of high.
    # RDS Certificates that are expired the check will FAIL with a severity of critical.
    def execute(self):
        findings = []
        for db_instance_arn, db_instance in rds_client.db_instances.items():
            report = Check_Report_AWS(self.metadata())
            report.region = db_instance.region
            report.resource_id = db_instance.id
            report.resource_arn = db_instance_arn
            report.resource_tags = db_instance.tags
            report.status = "FAIL"
            report.check_metadata.Severity = Severity.critical
            report.status_extended = (
                f"RDS Instance {db_instance.id} certificate has expired."
            )

            # Check only RDS DB instances that support parameter group encryption
            for cert in db_instance.cert:
                if not cert.customer_override:
                    if cert.valid_till > datetime.now(
                        utc
                    ) + relativedelta.relativedelta(months=6):
                        report.status = "PASS"
                        report.check_metadata.Severity = Severity.informational
                        report.status_extended = f"RDS Instance {db_instance.id} certificate has over 6 months of validity left."
                    elif cert.valid_till < datetime.now(
                        utc
                    ) + relativedelta.relativedelta(
                        months=6
                    ) and cert.valid_till > datetime.now(
                        utc
                    ) + relativedelta.relativedelta(
                        months=3
                    ):
                        report.status = "PASS"
                        report.check_metadata.Severity = Severity.low
                        report.status_extended = f"RDS Instance {db_instance.id} certificate has between 3 and 6 months of validity."
                    elif cert.valid_till < datetime.now(
                        utc
                    ) + relativedelta.relativedelta(
                        months=3
                    ) and cert.valid_till > datetime.now(
                        utc
                    ) + relativedelta.relativedelta(
                        months=1
                    ):
                        report.status = "FAIL"
                        report.check_metadata.Severity = Severity.medium
                        report.status_extended = f"RDS Instance {db_instance.id} certificate less than 3 months of validity."
                    elif cert.valid_till < datetime.now(
                        utc
                    ) + relativedelta.relativedelta(
                        months=1
                    ) and cert.valid_till > datetime.now(
                        utc
                    ):
                        report.status = "FAIL"
                        report.check_metadata.Severity = Severity.high
                        report.status_extended = f"RDS Instance {db_instance.id} certificate less than 1 month of validity."
                    else:
                        report.status = "FAIL"
                        report.check_metadata.Severity = Severity.critical
                        report.status_extended = (
                            f"RDS Instance {db_instance.id} certificate has expired."
                        )
                else:
                    if cert.valid_till > datetime.now(
                        utc
                    ) + relativedelta.relativedelta(months=6):
                        report.status = "PASS"
                        report.check_metadata.Severity = Severity.informational
                        report.status_extended = f"RDS Instance {db_instance.id} custom certificate has over 6 months of validity left."
                    elif cert.valid_till < datetime.now(
                        utc
                    ) + relativedelta.relativedelta(
                        months=6
                    ) and cert.valid_till > datetime.now(
                        utc
                    ) + relativedelta.relativedelta(
                        months=3
                    ):
                        report.status = "PASS"
                        report.check_metadata.Severity = Severity.low
                        report.status_extended = f"RDS Instance {db_instance.id} custom certificate has between 3 and 6 months of validity."
                    elif cert.valid_till < datetime.now(
                        utc
                    ) + relativedelta.relativedelta(
                        months=3
                    ) and cert.valid_till > datetime.now(
                        utc
                    ) + relativedelta.relativedelta(
                        months=1
                    ):
                        report.status = "FAIL"
                        report.check_metadata.Severity = Severity.medium
                        report.status_extended = f"RDS Instance {db_instance.id} custom certificate less than 3 months of validity."
                    elif cert.valid_till < datetime.now(
                        utc
                    ) + relativedelta.relativedelta(
                        months=1
                    ) and cert.valid_till > datetime.now(
                        utc
                    ):
                        report.status = "FAIL"
                        report.check_metadata.Severity = Severity.high
                        report.status_extended = f"RDS Instance {db_instance.id} custom certificate less than 1 month of validity."
                    else:
                        report.status = "FAIL"
                        report.check_metadata.Severity = Severity.critical
                        report.status_extended = f"RDS Instance {db_instance.id} custom certificate has expired."
            findings.append(report)

        return findings
