from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.dms.dms_client import dms_client

class dms_endpoint_ssl_enabled(Check):
    def execute(self):
        findings = []
        for endpoint_id, endpoint in dms_client.endpoints.items():
            report = Check_Report_AWS(self.metadata())
            report.resource_id = endpoint_id
            report.resource_arn = f"arn:{dms_client.audited_partition}:dms:{dms_client.audited_region}:{dms_client.audited_account}:endpoint:{endpoint_id}"
            report.region = dms_client.audited_region
            
            if endpoint.ssl_mode == 'none':
                report.status = "FAIL"
                report.status_extended = f"DMS Endpoint {endpoint_id} is not using SSL."
            else:
                report.status = "PASS"
                report.status_extended = f"DMS Endpoint {endpoint_id} is using SSL with mode: {endpoint.ssl_mode}."
            
            findings.append(report)
            
        return findings