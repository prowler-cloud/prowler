from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.redshift.redshift_client import redshift_client

class redshift_require_tls_ssl(Check):
    def execute(self):
        findings = []

        # Iterate through Redshift clusters
        for cluster in redshift_client.clusters:
            report = Check_Report_AWS(self.metadata())
            report.region = cluster.region
            report.resource_id = cluster.id
            report.resource_arn = cluster.arn

            # Check if require_ssl parameter is set to true
            require_ssl = False
            for param_group in cluster.parameter_groups:
                parameters = redshift_client._describe_cluster_parameters(param_group["ParameterGroupName"], redshift_client.regional_clients[cluster.region])
                if parameters.get("require_ssl", "false").lower() == "true":
                    require_ssl = True
                    break

            if require_ssl:
                report.status = "PASS"
                report.status_extended = f"Redshift cluster {cluster.id} requires TLS/SSL for connections."
            else:
                report.status = "FAIL"
                report.status_extended = f"Redshift cluster {cluster.id} does not require TLS/SSL for connections."

            findings.append(report)

        return findings
