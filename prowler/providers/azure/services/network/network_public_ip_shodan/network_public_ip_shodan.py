import shodan

from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.lib.logger import logger
from prowler.providers.azure.services.network.network_client import network_client


class network_public_ip_shodan(Check):
    def execute(self):
        findings = []
        shodan_api_key = network_client.audit_config.get("shodan_api_key")
        if shodan_api_key:
            api = shodan.Shodan(shodan_api_key)
            for subscription, public_ips in network_client.public_ip_addresses.items():
                for ip in public_ips:
                    report = Check_Report_Azure(self.metadata())
                    report.subscription = subscription
                    report.resource_name = ip.name
                    report.resource_id = ip.id
                    report.location = ip.location
                    try:
                        shodan_info = api.host(ip.ip_address)
                        report.status = "FAIL"
                        report.status_extended = f"Public IP {ip.ip_address} listed in Shodan with open ports {str(shodan_info['ports'])} and ISP {shodan_info['isp']} in {shodan_info['country_name']}. More info at https://www.shodan.io/host/{ip.ip_address}."
                        findings.append(report)
                    except shodan.APIError as error:
                        if "No information available for that IP" in error.value:
                            report.status = "PASS"
                            report.status_extended = (
                                f"Public IP {ip.ip_address} is not listed in Shodan."
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
