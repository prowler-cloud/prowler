import shodan

from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.lib.logger import logger
from prowler.providers.gcp.services.compute.compute_client import compute_client


class compute_public_address_shodan(Check):
    def execute(self):
        findings = []
        shodan_api_key = compute_client.audit_config.get("shodan_api_key")
        if shodan_api_key:
            api = shodan.Shodan(shodan_api_key)
            for address in compute_client.addresses:
                if address.type == "EXTERNAL":
                    report = Check_Report_GCP(self.metadata())
                    report.project_id = address.project_id
                    report.resource_id = address.id
                    report.location = address.region
                    try:
                        shodan_info = api.host(address.ip)
                        report.status = "FAIL"
                        report.status_extended = f"Public Address {address.ip} listed in Shodan with open ports {str(shodan_info['ports'])} and ISP {shodan_info['isp']} in {shodan_info['country_name']}. More info at https://www.shodan.io/host/{address.ip}."
                        findings.append(report)
                    except shodan.APIError as error:
                        if "No information available for that IP" in error.value:
                            report.status = "PASS"
                            report.status_extended = (
                                f"Public Address {address.ip} is not listed in Shodan."
                            )
                            findings.append(report)
                            continue
                        else:
                            logger.error(f"Unknown Shodan API Error: {error.value}")

        else:
            logger.error(
                "No Shodan API Key -- Please input a Shodan API Key with -N/--shodan or in config.yaml"
            )
        return findings
