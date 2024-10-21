from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.redshift.redshift_client import redshift_client

class redshift_cluster_configuration_check(Check):
    def execute(self):
        findings = []

        # Iterate over all Redshift clusters
        for cluster in redshift_client.clusters:
            report = Check_Report_AWS(self.metadata())
            report.region = cluster.region
            report.resource_id = cluster.id
            report.resource_arn = cluster.arn
            report.resource_tags = cluster.tags

            # Check if the cluster is encrypted with KMS
            if cluster.encrypted and cluster.kms_key_id:
                encryption_status = "PASS"
                encryption_status_extended = f"Redshift cluster {cluster.id} is encrypted with KMS key {cluster.kms_key_id}."
            else:
                encryption_status = "FAIL"
                encryption_status_extended = f"Redshift cluster {cluster.id} is not encrypted with KMS."

            # Check if audit logging is enabled
            if cluster.logging_enabled:
                logging_status = "PASS"
                logging_status_extended = f"Audit logging is enabled for Redshift cluster {cluster.id}."
            else:
                logging_status = "FAIL"
                logging_status_extended = f"Audit logging is NOT enabled for Redshift cluster {cluster.id}."

            # Combine results for encryption and logging checks
            if encryption_status == "PASS" and logging_status == "PASS":
                report.status = "PASS"
                report.status_extended = f"{encryption_status_extended} {logging_status_extended}"
            else:
                report.status = "FAIL"
                report.status_extended = f"{encryption_status_extended} {logging_status_extended}"

            # Append the report to the findings list
            findings.append(report)

        return findings
